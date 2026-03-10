import re
import json
import uuid

content = """
<invoke name="get_function_impl">
<parameter name="func_name">VosSyslogForwardCfgImport
<parameter name="max_lines">50

</minimax:tool_call>
"""

tool_calls = []
if "<invoke name=" in content:
    invokes = re.finditer(r'<invoke name="([^"]+)">([\s\S]*?)(?:</invoke>|$)', content)
    for match in invokes:
        xml_func_name = match.group(1)
        xml_param_str = match.group(2)
        xml_args = {}
        for param_match in re.finditer(r'<parameter name="([^"]+)">([\s\S]*?)(?=(?:</parameter>|<parameter|</invoke>|$))', xml_param_str):
            val = param_match.group(2).strip()
            val = re.sub(r'</.*$', '', val, flags=re.DOTALL).strip()
            if val.isdigit():
                val = int(val)
            xml_args[param_match.group(1)] = val
            
        tool_calls.append({
            "id": f"call_xml_{uuid.uuid4().hex[:10]}",
            "type": "function",
            "function": {
                "name": xml_func_name,
                "arguments": json.dumps(xml_args, ensure_ascii=False)
            }
        })

print(json.dumps(tool_calls, indent=2))
