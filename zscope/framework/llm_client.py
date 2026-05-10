"""
Enhanced LLM client with model fallback support.
"""

import ast
import random
import re
import json
import logging
import time
from typing import Any, Callable, Dict, List, Optional, cast

import requests

from ..common.utils import extract_json_blocks

logger = logging.getLogger(__name__)


class LLMClient:
    """
    OpenAI-compatible LLM client with model fallback support.
    """

    def __init__(
        self,
        api_key: str,
        base_url: str,
        models: List[str],
        timeout: int = 120,
        max_retries: int = 2,
        max_tokens: int = 4096
    ):
        """
        Initialize LLM client.
        
        Args:
            api_key: API key
            base_url: API base URL
            models: List of model names in order of priority
            timeout: Request timeout in seconds
            max_retries: Retries per model
        """
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.models = models
        self.timeout = timeout
        self.max_retries = max_retries
        self.max_tokens = max_tokens
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            }
        )

    def chat_completion(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.1,
        max_tokens: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Send chat completion request with model fallback.
        """
        last_error = None
        
        for model in self.models:
            logger.info(f"Using model: {model}")
            
            payload = {
                "model": model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens or self.max_tokens,
            }

            if tools:
                payload["tools"] = tools
                payload["tool_choice"] = "auto"
            
            # Force streaming to bypass middle-proxy timeouts (e.g. 504 on 120s limit)
            payload["stream"] = True

            for attempt in range(self.max_retries + 1):
                try:
                    url = self.base_url
                    if "/chat/completions" not in url:
                        url = f"{self.base_url}/chat/completions"
                    
                    response = self.session.post(
                        url, json=payload, timeout=self.timeout, stream=True
                    )

                    if response.status_code == 200:
                        content_pieces = []
                        reasoning_pieces = []
                        tool_calls_map = {}
                        finish_reason = "stop"
                        
                        for line in response.iter_lines():
                            if line:
                                decoded_line = line.decode('utf-8')
                                if decoded_line.startswith("data: "):
                                    data_str = decoded_line[6:]
                                    if data_str.strip() == "[DONE]":
                                        break
                                    try:
                                        chunk = json.loads(data_str)
                                        choices = chunk.get("choices", [])
                                        if choices:
                                            delta = choices[0].get("delta", {})
                                            
                                            if "content" in delta and delta["content"]:
                                                content_pieces.append(delta["content"])
                                                
                                            if "reasoning_content" in delta and delta["reasoning_content"]:
                                                reasoning_pieces.append(delta["reasoning_content"])
                                                
                                            if "tool_calls" in delta and delta["tool_calls"]:
                                                for tc in delta["tool_calls"]:
                                                    idx = tc.get("index")
                                                    if idx not in tool_calls_map:
                                                        tool_calls_map[idx] = tc
                                                    else:
                                                        if "function" in tc:
                                                            if "name" in tc["function"] and tc["function"]["name"]:
                                                                tool_calls_map[idx].setdefault("function", {})["name"] = tc["function"]["name"]
                                                            if "arguments" in tc["function"] and tc["function"]["arguments"]:
                                                                tool_calls_map[idx].setdefault("function", {}).setdefault("arguments", "")
                                                                tool_calls_map[idx]["function"]["arguments"] += tc["function"]["arguments"]
                                                                
                                            if choices[0].get("finish_reason"):
                                                finish_reason = choices[0]["finish_reason"]
                                    except json.JSONDecodeError:
                                        pass
                                        
                        assembled_message: Dict[str, Any] = {"role": "assistant"}
                        if tool_calls_map:
                            assembled_message["tool_calls"] = [tool_calls_map[i] for i in sorted(tool_calls_map.keys())]
                            if content_pieces:
                                assembled_message["content"] = "".join(content_pieces)
                        else:
                            assembled_message["content"] = "".join(content_pieces)
                            
                        if reasoning_pieces:
                            assembled_message["reasoning_content"] = "".join(reasoning_pieces)
                            
                        # Estimate single API call cost and log prominently
                        prompt_tokens = LLMClient.estimate_tokens(messages)
                        completion_tokens = LLMClient.estimate_tokens([assembled_message])
                        
                        logger.info(
                            f"[LLM API Trace] Model: {model} | "
                            f"Prompt ≈ {prompt_tokens:,} tk | "
                            f"Completion ≈ {completion_tokens:,} tk | "
                            f"Total ≈ {prompt_tokens + completion_tokens:,} tk"
                        )
                            
                        return {
                            "choices": [{
                                "message": assembled_message,
                                "finish_reason": finish_reason
                            }]
                        }
                    
                    error_msg = f"HTTP {response.status_code}: {response.text}"
                    logger.warning(f"Model {model} failed (attempt {attempt + 1}): {error_msg}")
                    
                    if response.status_code >= 500 or response.status_code == 429:
                        # Capped exponential backoff with jitter
                        wait_time = min(2**attempt, 10) + random.uniform(0, 3)
                        logger.warning(f"Rate limited or server error, waiting {wait_time:.1f}s...")
                        time.sleep(wait_time)
                        continue
                    else:
                        last_error = error_msg
                        break # Try next model
                        
                except Exception as e:
                    wait_time = min(2**attempt, 10) + random.uniform(0, 3)
                    is_last = attempt >= self.max_retries
                    if is_last:
                        logger.warning(f"Model {model} request error (attempt {attempt + 1}/{self.max_retries + 1}, final): {e}")
                    else:
                        logger.warning(f"Model {model} request error (attempt {attempt + 1}/{self.max_retries + 1}, retrying in {wait_time:.1f}s): {e}")
                    last_error = str(e)
                    time.sleep(wait_time)
                    continue
            
            logger.info(f"Falling back from model {model}...")
            
        raise Exception(f"All models failed. Last error: {last_error}")
    def _get_combined_content(self, conversation: List[Dict[str, Any]]) -> str:
        """Helper to combine all assistant generated text in case an auto-continue loop happened"""
        content_chunks = []
        for msg in conversation:
            if msg.get("role") == "assistant" and msg.get("content"):
                content_chunks.append(msg.get("content", ""))
        return "".join(content_chunks)

    @staticmethod
    def estimate_tokens(conversation: List[Dict[str, Any]]) -> int:
        """Estimate the total token count of a conversation.
        
        Uses a simple heuristic: ~3.5 chars per token for CJK-heavy text,
        ~4 chars per token for ASCII. This avoids a tiktoken dependency.
        """
        total_chars = 0
        for msg in conversation:
            content = msg.get("content") or ""
            if isinstance(content, str):
                total_chars += len(content)
            # Count tool call arguments as part of the context
            for tc in msg.get("tool_calls", []):
                args = tc.get("function", {}).get("arguments", "")
                if isinstance(args, str):
                    total_chars += len(args)
            # Count reasoning_content if present (e.g. DeepSeek R1)
            rc = msg.get("reasoning_content") or ""
            if isinstance(rc, str):
                total_chars += len(rc)
        # Heuristic: average 3.8 chars per token for mixed CJK/ASCII codebases
        return int(total_chars / 3.8)

    def run_conversation_with_tools(
        self,
        messages: List[Dict[str, Any]],
        tools_schema: List[Dict[str, Any]],
        tool_executor: Callable[[str, Dict[str, Any]], Dict[str, Any]],
        max_iterations: int = 50,
    ) -> Dict[str, Any]:
        """
        Run a conversation loop with tool calling support.
        """
        conversation = messages.copy()
        iterations = 0

        while iterations < max_iterations:
            iterations += 1
            ctx_tokens = self.estimate_tokens(conversation)
            logger.info(f"Conversation iteration {iterations}/{max_iterations} | context ≈ {ctx_tokens:,} tokens")

            # Call LLM
            response = self.chat_completion(conversation, tools=tools_schema)

            # Extract assistant message
            choice = response.get("choices", [{}])[0]
            message = choice.get("message", {})
            finish_reason = choice.get("finish_reason")

            # Add assistant message to conversation
            conversation.append(message)

            # Check if done
            if finish_reason == "stop":
                content = self._get_combined_content(conversation)
                final_tokens = self.estimate_tokens(conversation)
                logger.info(f"Conversation complete: {iterations} iterations, final context ≈ {final_tokens:,} tokens")
                return {"content": content, "conversation": conversation, "iterations": iterations, "context_tokens": final_tokens}
                
            if finish_reason == "length":
                logger.warning(f"Model {self.models[0] if self.models else 'unknown'} output truncated! Prompting to continue...")
                conversation.append({"role": "user", "content": "请继续"})
                continue

            # Handle tool calls
            tool_calls = message.get("tool_calls", [])
            
            # --- XML Fallback (For GLM/Minimax models that emit raw text invoke tags) ---
            content = message.get("content", "")
            if not tool_calls and "<invoke name=" in content:
                import uuid
                invokes = re.finditer(r'<invoke name="([^"]+)">([\s\S]*?)(?:</invoke>|$)', content)
                for match in invokes:
                    xml_func_name = match.group(1)
                    xml_param_str = match.group(2)
                    xml_args = {}
                    for param_match in re.finditer(r'<parameter name="([^"]+)">([\s\S]*?)(?=(?:</parameter>|<parameter|</invoke>|$))', xml_param_str):
                        # Attempt to cast numeric strings to int if applicable, else keep string
                        xml_val: Any = param_match.group(2).strip()
                        xml_val = re.sub(r'</.*$', '', str(xml_val), flags=re.DOTALL).strip()
                        if str(xml_val).isdigit():
                            xml_val = int(xml_val)
                        xml_args[param_match.group(1)] = xml_val
                        
                    tool_calls.append({
                        "id": f"call_xml_{uuid.uuid4().hex[:10]}",
                        "type": "function",
                        "function": {
                            "name": xml_func_name,
                            "arguments": json.dumps(xml_args, ensure_ascii=False)
                        }
                    })
                # If we synthetically built tool calls, we should ensure the LLM knows it made them.
                if tool_calls and "tool_calls" not in message:
                    message["tool_calls"] = tool_calls
            # --------------------------------------------------------------------------

            if not tool_calls:
                content = self._get_combined_content(conversation)
                final_tokens = self.estimate_tokens(conversation)
                logger.info(f"Conversation complete (no more tool calls): {iterations} iterations, final context ≈ {final_tokens:,} tokens")
                return {"content": content, "conversation": conversation, "iterations": iterations, "context_tokens": final_tokens}

            # Execute each tool call
            for tool_call in tool_calls:
                tool_id = tool_call.get("id")
                function = tool_call.get("function", {})
                func_name = function.get("name")
                func_args_str = function.get("arguments", "{}")

                logger.info(f"Tool call: {func_name}")

                try:
                    func_args = self._parse_tool_args(func_args_str)
                    
                    # VERY IMPORTANT: Re-serialize the corrected dict back into the conversation history
                    # so that strict upstreams like GLM-4/5 do not throw 400 Bad Request on "Expecting ','"
                    function["arguments"] = json.dumps(func_args, ensure_ascii=False)
                    
                    result = tool_executor(func_name, func_args)

                    conversation.append({
                        "role": "tool",
                        "tool_call_id": tool_id,
                        "content": json.dumps(result, ensure_ascii=False),
                    })

                except Exception as e:
                    logger.error(f"Tool execution failed: {e}")
                    conversation.append({
                        "role": "tool",
                        "tool_call_id": tool_id,
                        "content": json.dumps({"error": str(e)}),
                    })

        if iterations >= max_iterations:
            logger.warning(f"Conversation reached max iterations ({max_iterations}). Possible loop.")
            # Log the last 2 assistant messages and tool results for debugging
            history_summary = []
            for msg in conversation[-4:]:
                role = msg.get("role")
                if role == "assistant":
                    content = msg.get("content") or "Tool Call"
                    history_summary.append(f"Assistant: {content[:100]}...")
                elif role == "tool":
                    content_preview = str(msg.get("content", ""))
                    history_summary.append(f"Tool Result: {content_preview[:100]}...")
            logger.debug(f"Last steps: {history_summary}")

        final_tokens = self.estimate_tokens(conversation)
        logger.info(f"Conversation ended (truncated={iterations >= max_iterations}): {iterations} iterations, final context ≈ {final_tokens:,} tokens")
        return {
            "content": conversation[-1].get("content", "") if not message.get("tool_calls") else "",
            "conversation": conversation,
            "iterations": iterations,
            "truncated": iterations >= max_iterations,
            "context_tokens": final_tokens,
        }

    def _parse_tool_args(self, func_args_str: Any) -> Dict[str, Any]:
        """Parse tool arguments, with fallbacks for slightly malformed JSON."""
        if isinstance(func_args_str, dict):
            return cast(Dict[str, Any], func_args_str)
        if func_args_str is None:
            return {}
        try:
            return cast(Dict[str, Any], json.loads(str(func_args_str)))
        except json.JSONDecodeError as exc:
            stripped = func_args_str.strip()
            if not stripped:
                return {}

            try:
                parsed = ast.literal_eval(stripped)
                if isinstance(parsed, dict):
                    logger.warning("Recovered tool arguments via literal_eval.")
                    return cast(Dict[str, Any], parsed)
            except (ValueError, SyntaxError):
                pass

            sanitized = self._sanitize_tool_args(stripped)
            if sanitized != stripped:
                for candidate in (sanitized, self._pythonize_json_literals(sanitized)):
                    try:
                        parsed = json.loads(candidate)
                        if isinstance(parsed, dict):
                            logger.warning("Recovered tool arguments via sanitized JSON.")
                            return cast(Dict[str, Any], parsed)
                    except json.JSONDecodeError:
                        try:
                            parsed = ast.literal_eval(candidate)
                            if isinstance(parsed, dict):
                                logger.warning("Recovered tool arguments via sanitized literal_eval.")
                                return cast(Dict[str, Any], parsed)
                        except (ValueError, SyntaxError):
                            continue

            pythonized = self._pythonize_json_literals(stripped)
            if pythonized != stripped:
                try:
                    parsed = ast.literal_eval(pythonized)
                    if isinstance(parsed, dict):
                        logger.warning("Recovered tool arguments via pythonized literal_eval.")
                        return cast(Dict[str, Any], parsed)
                except (ValueError, SyntaxError):
                    pass

            for json_candidate in extract_json_blocks(str(func_args_str)):
                if isinstance(json_candidate, dict):
                    logger.warning("Recovered tool arguments from JSON block.")
                    return cast(Dict[str, Any], json_candidate)

            fallback = self._extract_tool_args_fallback(stripped)
            if fallback is not None:
                logger.warning("Recovered tool arguments via heuristic fallback.")
                return fallback

            logger.error(
                "Invalid tool arguments JSON. Raw payload: %s",
                self._truncate_tool_args_for_log(func_args_str),
            )
            raise ValueError(f"Invalid tool arguments JSON: {exc}") from exc

    @staticmethod
    def _truncate_tool_args_for_log(value: Any, limit: int = 500) -> str:
        """Return a safely truncated string for logging invalid tool args."""
        if value is None:
            return "<empty>"
        if not isinstance(value, str):
            value = repr(value)
        if len(value) <= limit:
            return str(value)
        return f"{value[:limit]}…(truncated)"

    @staticmethod
    def _sanitize_tool_args(text: str) -> str:
        """Attempt to normalize JSON-like tool argument strings."""
        sanitized = text.strip()
        sanitized = re.sub(r",\s*([}\]])", r"\1", sanitized)
        sanitized = re.sub(r"([{,]\s*)([A-Za-z_][A-Za-z0-9_]*)(\s*):", r'\1"\2"\3:', sanitized)
        return sanitized

    @staticmethod
    def _pythonize_json_literals(text: str) -> str:
        """Swap JSON literals for Python equivalents for literal_eval."""
        pythonized = re.sub(r"\bnull\b", "None", text, flags=re.IGNORECASE)
        pythonized = re.sub(r"\btrue\b", "True", pythonized, flags=re.IGNORECASE)
        pythonized = re.sub(r"\bfalse\b", "False", pythonized, flags=re.IGNORECASE)
        return pythonized

    @staticmethod
    def _extract_tool_args_fallback(text: str) -> Optional[Dict[str, Any]]:
        """Extract common tool args from malformed JSON-like strings."""
        if not isinstance(text, str) or "file_path" not in text:
            return None

        file_match = re.search(r'"file_path"\s*:\s*"([^"]+)"', text)
        if not file_match:
            file_match = re.search(r"'file_path'\s*:\s*'([^']+)'", text)
        if not file_match:
            return None
        file_path = file_match.group(1)
        has_start_line = re.search(r'["\']start_line["\']\s*:', text) is not None
        has_end_line = re.search(r'["\']end_line["\']\s*:', text) is not None

        def extract_int(key: str) -> Optional[int]:
            direct = re.search(rf'"{key}"\s*:\s*([0-9]+)', text)
            if not direct:
                direct = re.search(rf"'{key}'\s*:\s*([0-9]+)", text)
            if direct:
                return int(direct.group(1))
            token = re.search(rf'"{key}"\s*:\s*([^,\n}}]+)', text)
            if not token:
                token = re.search(rf"'{key}'\s*:\s*([^,\n}}]+)", text)
            if token:
                digits = re.search(r"\d+", token.group(1))
                if digits:
                    return int(digits.group(0))
            return None

        start_line = extract_int("start_line")
        end_line = extract_int("end_line")

        if start_line is None and end_line is None:
            if has_start_line or has_end_line:
                return {"file_path": file_path, "start_line": None, "end_line": None}
            return None
        if start_line is None:
            start_line = end_line
        if end_line is None:
            end_line = start_line

        return {"file_path": file_path, "start_line": start_line, "end_line": end_line}
