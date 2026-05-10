import json
from pathlib import Path

def export_conversation():
    log_file = Path(r"C:\Users\10273\.gemini\antigravity\brain\d323964a-3918-433d-84fa-f48f993acebe\.system_generated\logs\overview.txt")
    output_file = Path(r"c:\Users\10273\home\work\Z-Scope\conversation_export.md")
    
    if not log_file.exists():
        print(f"Log file not found: {log_file}")
        return

    with open(log_file, "r", encoding="utf-8") as f, open(output_file, "w", encoding="utf-8") as out:
        out.write("# Conversation Export\n\n")
        
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            
            source = data.get("source", "")
            msg_type = data.get("type", "")
            created_at = data.get("created_at", "")
            
            if source == "USER_EXPLICIT" and msg_type in ["USER_INPUT", "CODE_ACTION"]:
                out.write(f"## 👤 User [{created_at}]\n\n")
                content = data.get("content", "")
                out.write(f"{content}\n\n---\n\n")
                
            elif source == "MODEL" and msg_type == "PLANNER_RESPONSE":
                content = data.get("content", "")
                tool_calls = data.get("tool_calls", [])
                
                if content or tool_calls:
                    out.write(f"## 🤖 AI [{created_at}]\n\n")
                    
                    if content:
                        out.write(f"{content}\n\n")
                    
                    if tool_calls:
                        out.write("### Tool Calls\n")
                        for tc in tool_calls:
                            name = tc.get("name", "unknown_tool")
                            args = tc.get("args", {})
                            out.write(f"- **{name}**: `{json.dumps(args, ensure_ascii=False)}`\n")
                        out.write("\n")
                    
                    out.write("---\n\n")

    print(f"Exported successfully to {output_file}")

if __name__ == "__main__":
    export_conversation()
