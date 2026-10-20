"""Read only whitelisted non-secret provider/model fields; never print config bodies."""

from __future__ import annotations

import json
from pathlib import Path
import re
from urllib.parse import urlsplit, urlunsplit

ROOT = Path(r"C:\Users\10273")
HERE = Path(__file__).resolve().parent
ALLOW = {"provider", "providerid", "model", "modelid", "baseurl", "base_url", "base-url", "apibaseurl", "endpoint"}
SECRET = re.compile(r"key|secret|token|password|credential|authorization|headers", re.I)
FIELDS = re.compile(r"^\s*([a-zA-Z_][\w-]*)\s*:\s*(.*?)\s*$")


def safe(value: str) -> str:
    value = value.strip().strip("'\"")
    if value.startswith(("http://", "https://")):
        url = urlsplit(value)
        host = url.hostname or ""
        if url.port:
            host += ":" + str(url.port)
        return urlunsplit((url.scheme, host, url.path, "", ""))
    return value[:250]


def main() -> None:
    paths = [
        ROOT / ".dsh/settings.yaml.imported",
        ROOT / ".dsh/settings.yaml",
        ROOT / ".dsh/profiles/acp/cordis.yml",
        ROOT / ".dsh/profiles/acp/cordis.patch.yml",
        ROOT / ".dsh/profiles/desktop/cordis.patch.yml",
        ROOT / ".agent-bridge/agents.toml",
    ]
    findings = []
    for path in paths:
        if not path.is_file():
            findings.append({"path": str(path), "exists": False})
            continue
        fields = []
        # Do not collect, decode, hash, or print any credential/headers field.
        with path.open(encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, 1):
                match = FIELDS.match(line)
                if not match:
                    continue
                name, value = match.groups()
                if name.lower() in ALLOW and not SECRET.search(name):
                    fields.append({"line": line_no, "field": name, "value": safe(value)})
        findings.append({"path": str(path), "exists": True, "non_secret_fields": fields})
    value = {"schema": "zscope.provider-read-audit.v1", "files": findings, "changes": "none", "note": "only selected route/model fields; no credential/config body emitted"}
    zcode_paths = [ROOT / ".zcode/v2/config.json", ROOT / ".zcode/v2/setting.json"]
    def route_fields(obj, parents=()):
        result = []
        if isinstance(obj, dict):
            for name, field in obj.items():
                if SECRET.search(str(name)):
                    continue
                if str(name).lower() in ALLOW and isinstance(field, (str, int, float, bool)):
                    result.append({"field": ".".join((*parents, str(name))), "value": safe(str(field))})
                elif isinstance(field, (dict, list)):
                    result.extend(route_fields(field, (*parents, str(name))))
        elif isinstance(obj, list):
            for index, field in enumerate(obj):
                result.extend(route_fields(field, (*parents, str(index))))
        return result
    value["zcode_non_secret_routes"] = [
        {"path": str(path), "non_secret_fields": route_fields(json.loads(path.read_text(encoding="utf-8")))}
        for path in zcode_paths if path.is_file()
    ]
    (HERE / "provider-audit.json").write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(value, ensure_ascii=False))


if __name__ == "__main__":
    main()
