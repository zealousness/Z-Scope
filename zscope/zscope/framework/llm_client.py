"""
Enhanced LLM client with model fallback support.
"""

import json
import logging
import time
from typing import List, Dict, Any, Optional

import requests

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
        max_retries: int = 2
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
        max_tokens: int = 4096,
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
                "max_tokens": max_tokens,
            }

            if tools:
                payload["tools"] = tools
                payload["tool_choice"] = "auto"

            for attempt in range(self.max_retries + 1):
                try:
                    url = f"{self.base_url}/chat/completions"
                    response = self.session.post(
                        url, json=payload, timeout=self.timeout
                    )

                    if response.status_code == 200:
                        return response.json()
                    
                    error_msg = f"HTTP {response.status_code}: {response.text}"
                    logger.warning(f"Model {model} failed (attempt {attempt + 1}): {error_msg}")
                    
                    if response.status_code >= 500:
                        time.sleep(2**attempt)
                        continue
                    else:
                        last_error = error_msg
                        break # Try next model
                        
                except Exception as e:
                    logger.warning(f"Model {model} request error: {e}")
                    last_error = str(e)
                    time.sleep(2**attempt)
                    continue
            
            logger.info(f"Falling back from model {model}...")
            
        raise Exception(f"All models failed. Last error: {last_error}")

    def run_conversation_with_tools(
        self,
        messages: List[Dict[str, Any]],
        tools_schema: List[Dict[str, Any]],
        tool_executor: callable,
        max_iterations: int = 50,
    ) -> Dict[str, Any]:
        """
        Run a conversation loop with tool calling support.
        """
        conversation = messages.copy()
        iterations = 0

        while iterations < max_iterations:
            iterations += 1
            logger.info(f"Conversation iteration {iterations}/{max_iterations}")

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
                content = message.get("content", "")
                return {"content": content, "conversation": conversation, "iterations": iterations}

            # Handle tool calls
            tool_calls = message.get("tool_calls", [])
            if not tool_calls:
                content = message.get("content", "")
                return {"content": content, "conversation": conversation, "iterations": iterations}

            # Execute each tool call
            for tool_call in tool_calls:
                tool_id = tool_call.get("id")
                function = tool_call.get("function", {})
                func_name = function.get("name")
                func_args_str = function.get("arguments", "{}")

                logger.info(f"Tool call: {func_name}")

                try:
                    func_args = json.loads(func_args_str)
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

        return {
            "content": "",
            "conversation": conversation,
            "iterations": iterations,
            "truncated": True,
        }
