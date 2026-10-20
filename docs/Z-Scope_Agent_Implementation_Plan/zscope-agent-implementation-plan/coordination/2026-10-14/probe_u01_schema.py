"""Inspect concrete parser/schema discrepancies using dummy project documents."""

from pathlib import Path
import copy
import json
import re
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
sys.path.insert(0, str(ROOT / ".coordination/20261014/workspaces/u01-config"))
from zscope.config.v3 import parse_user_config_v3, public_json_schema

directory = HERE / "review-repro" / (sys.argv[1] if len(sys.argv) > 1 else "u01-schema")
if directory.exists():
    raise SystemExit("evidence directory exists; preserve prior proof and choose a new name")
directory.mkdir(parents=True)
base = {
    "config_version": 3,
    "llms": {"default": {"base_urls": ["http://localhost/v1"], "models": ["unit-model"], "api_key": "unit-key"}},
    "project": {"root": ".", "language": "c_cpp", "platform": "linux_user", "targets": [{"id": "app", "compile_commands": "compile_commands.json"}]},
    "scan": {"preset": "quick", "focus": ["memory"], "reproduction": "auto"},
}
schema = public_json_schema()
cases = []
for name in ("stop_at_pattern", "focus_duplicates", "stop_requires_timezone", "cpp_requires_database"):
    document = copy.deepcopy(base)
    if name == "stop_at_pattern":
        document["execution"] = {"timezone": "Asia/Taipei", "stop_at": "prefix08:00suffix"}
        pattern = schema["properties"]["execution"]["properties"]["stop_at"]["pattern"]
        observation = {"schema_pattern": pattern, "pattern_search_accepts": re.search(pattern, document["execution"]["stop_at"]) is not None}
    elif name == "focus_duplicates":
        document["scan"]["focus"] = ["memory", "memory"]
        observation = {"schema_uniqueItems": schema["properties"]["scan"]["properties"]["focus"].get("uniqueItems")}
    elif name == "stop_requires_timezone":
        document["execution"] = {"stop_at": "08:00"}
        section = schema["properties"]["execution"]
        observation = {"schema_required": section.get("required", []), "schema_dependentRequired": section.get("dependentRequired"), "schema_allOf": section.get("allOf")}
    else:
        document["project"]["targets"] = [{"id": "app"}]
        section = schema["properties"]["project"]
        observation = {"schema_target_required": section["properties"]["targets"]["items"].get("required"), "schema_allOf": section.get("allOf")}
    path = directory / (name + ".json")
    path.write_text(json.dumps(document) + "\n", encoding="utf-8")
    try:
        model = parse_user_config_v3(str(path))
        observation.update({"parser_accepted": True, "parsed_focus": list(model.scan.focus)})
    except ValueError as error:
        observation.update({"parser_accepted": False, "parser_error": str(error)})
    cases.append({"case": name, **observation})
proof = {"synthetic_only": True, "kind": "actual_parser_and_generated_schema_inspection_not_full_jsonschema_validator", "cases": cases}
(directory / "review.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(json.dumps(proof, ensure_ascii=False))
