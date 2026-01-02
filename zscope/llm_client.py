"""
LLM client with OpenAI-compatible API support and tool calling.
"""

import json
import logging
import time
from typing import List, Dict, Any, Optional

import requests

from .config import LLMConfig

logger = logging.getLogger(__name__)


class LLMClient:
    """
    OpenAI-compatible LLM client with tool/function calling support.
    """

    def __init__(self, config: LLMConfig):
        """Initialize LLM client."""
        self.config = config
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {config.api_key}",
                "Content-Type": "application/json",
            }
        )

    def chat_completion(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Send chat completion request to LLM.

        Args:
            messages: List of message dicts with 'role' and 'content'
            tools: Optional list of tool definitions
            temperature: Override default temperature
            max_tokens: Override default max_tokens

        Returns:
            API response dict

        Raises:
            Exception: If API call fails after retries
        """
        url = f"{self.config.base_url.rstrip('/')}/chat/completions"

        payload = {
            "model": self.config.model or "gpt-4",
            "messages": messages,
            "temperature": temperature or self.config.temperature,
            "max_tokens": max_tokens or self.config.max_tokens,
        }

        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        # Retry logic
        for attempt in range(self.config.max_retries):
            try:
                logger.debug(f"Sending chat completion request (attempt {attempt + 1})")
                response = self.session.post(
                    url, json=payload, timeout=self.config.timeout
                )

                if response.status_code == 200:
                    return response.json()
                elif response.status_code >= 500:
                    # Server error - retry
                    logger.warning(
                        f"Server error {response.status_code}, retrying in {2 ** attempt}s"
                    )
                    time.sleep(2**attempt)
                    continue
                else:
                    # Client error - don't retry
                    response.raise_for_status()

            except requests.exceptions.Timeout:
                logger.warning(f"Request timeout (attempt {attempt + 1})")
                if attempt < self.config.max_retries - 1:
                    time.sleep(2**attempt)
                    continue
                raise
            except requests.exceptions.RequestException as e:
                logger.error(f"Request failed: {e}")
                if attempt < self.config.max_retries - 1:
                    time.sleep(2**attempt)
                    continue
                raise

        raise Exception(f"LLM API call failed after {self.config.max_retries} retries")

    def run_conversation_with_tools(
        self,
        messages: List[Dict[str, Any]],
        tools_schema: List[Dict[str, Any]],
        tool_executor: callable,
        max_iterations: int = 50,
    ) -> Dict[str, Any]:
        """
        Run a conversation loop with tool calling support.

        Args:
            messages: Initial messages
            tools_schema: Tool definitions
            tool_executor: Callable that takes (tool_name, arguments) and returns result dict
            max_iterations: Maximum number of turns

        Returns:
            Final assistant message content and conversation history
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
                logger.info("Conversation finished (stop)")
                content = message.get("content", "")
                return {"content": content, "conversation": conversation, "iterations": iterations}

            # Handle tool calls
            tool_calls = message.get("tool_calls", [])
            if not tool_calls:
                # No tool calls and not finished - unusual but handle gracefully
                logger.warning("No tool calls and finish_reason != stop")
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
                    # Parse arguments
                    func_args = json.loads(func_args_str)

                    # Execute tool
                    result = tool_executor(func_name, func_args)

                    # Add tool response to conversation
                    tool_message = {
                        "role": "tool",
                        "tool_call_id": tool_id,
                        "content": json.dumps(result, ensure_ascii=False),
                    }
                    conversation.append(tool_message)

                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse tool arguments: {e}")
                    error_message = {
                        "role": "tool",
                        "tool_call_id": tool_id,
                        "content": json.dumps({"error": f"Invalid JSON arguments: {str(e)}"}),
                    }
                    conversation.append(error_message)

                except Exception as e:
                    logger.error(f"Tool execution failed: {e}", exc_info=True)
                    error_message = {
                        "role": "tool",
                        "tool_call_id": tool_id,
                        "content": json.dumps({"error": f"Tool execution error: {str(e)}"}),
                    }
                    conversation.append(error_message)

        logger.warning(f"Reached max iterations ({max_iterations})")
        # Return last assistant message
        last_content = ""
        for msg in reversed(conversation):
            if msg.get("role") == "assistant" and msg.get("content"):
                last_content = msg["content"]
                break

        return {
            "content": last_content,
            "conversation": conversation,
            "iterations": iterations,
            "truncated": True,
        }
