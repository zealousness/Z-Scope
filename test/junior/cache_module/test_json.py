import json
import sys

payload = {
    "model": "glm-5",
    "messages": [
        {"role": "system", "content": "You are the Vulnerability Analyzer for Z-SCOPE..."},
        {"role": "user", "content": "Target Function: func\nTask: task\nCode:\n```c\nint x=0;\n```"}
    ],
    "temperature": 0.1,
    "max_tokens": 8192,
    "stream": True,
    "tools": [
        {
            "type": "function",
            "function": {
                "name": "get_function_impl",
                "description": "...',",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "func_name": {"type": "string", "description": "The name of the function"},
                        "max_lines": {"type": "integer", "default": 200}
                    },
                    "required": ["func_name"]
                }
            }
        }
    ],
    "tool_choice": "auto"
}

j = json.dumps(payload)
print(f"Char 35-45: {j[35:45]}")
print(f"Char 37: {j[37]}")
