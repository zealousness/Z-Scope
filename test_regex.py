import re
import ast
import json

stdout = '\x1b[33mval\x1b[0m \x1b[36mres1\x1b[0m: \x1b[32mString\x1b[0m = "[{\\"name\\":\\"<module>\\"}]"\n'
print('Raw:', repr(stdout))

ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
clean_stdout = ansi_escape.sub('', stdout).strip()
print('Clean:', repr(clean_stdout))

match = re.search(r'val\s+res\d+\s*:\s*String\s*=\s*(.*)', clean_stdout, re.DOTALL)
if match:
    print('Match Group 1:', repr(match.group(1)))
    scala_literal = match.group(1).strip()
    try:
        if scala_literal.startswith('"""') and scala_literal.endswith('"""'):
            json_str = scala_literal[3:-3]
        else:
            json_str = ast.literal_eval(scala_literal)
        print('JSON string parsed from AST:', repr(json_str))
        res = json.loads(json_str)
        print('Final JSON:', res)
    except Exception as e:
        print('AST/JSON parse failed:', e)
else:
    print('Regex failed to match!')
