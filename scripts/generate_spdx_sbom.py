#!/usr/bin/env python3
"""Generate a deterministic SPDX 2.3 inventory for release asset files."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha1(path: Path) -> str:
    return hashlib.sha1(path.read_bytes(), usedforsecurity=False).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--name", default="zscope")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    files: List[Dict[str, Any]] = []
    relationships = []
    package_sha1s: List[str] = []
    for index, path in enumerate(
        sorted(item for item in root.rglob("*") if item.is_file()), start=1
    ):
        spdx_id = f"SPDXRef-File-{index}"
        package_sha1s.append(sha1(path))
        files.append(
            {
                "SPDXID": spdx_id,
                "fileName": f"./{path.relative_to(root).as_posix()}",
                "checksums": [{"algorithm": "SHA256", "checksumValue": sha256(path)}],
                "licenseConcluded": "NOASSERTION",
                "licenseInfoInFiles": ["NOASSERTION"],
                "copyrightText": "NOASSERTION",
            }
        )
        relationships.append(
            {
                "spdxElementId": "SPDXRef-Package-ZScope",
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": spdx_id,
            }
        )
    namespace_hash = hashlib.sha256(f"{args.name}:{args.version}".encode()).hexdigest()[:24]
    verification_code = hashlib.sha1(
        "".join(sorted(package_sha1s)).encode("ascii"), usedforsecurity=False
    ).hexdigest()
    created = datetime.fromtimestamp(int(os.environ.get("SOURCE_DATE_EPOCH", "0")), tz=timezone.utc)
    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{args.name}-{args.version}",
        "documentNamespace": (
            f"https://zscope.example/spdx/{args.name}/{args.version}/{namespace_hash}"
        ),
        "creationInfo": {
            "created": created.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "creators": ["Tool: zscope-generate-spdx-sbom"],
        },
        "packages": [
            {
                "name": args.name,
                "SPDXID": "SPDXRef-Package-ZScope",
                "versionInfo": args.version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": True,
                "packageVerificationCode": {"packageVerificationCodeValue": verification_code},
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "MIT",
                "copyrightText": "NOASSERTION",
            }
        ],
        "files": files,
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-Package-ZScope",
            },
            *relationships,
        ],
    }
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
