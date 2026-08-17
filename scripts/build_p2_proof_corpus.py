#!/usr/bin/env python3
"""Regenerate the committed P2 proof corpus from its deterministic builder."""

from __future__ import annotations

import json
from pathlib import Path

try:
    from scripts.p2_proof_corpus import build_corpus
except ModuleNotFoundError:  # Direct ``python scripts/...`` execution.
    from p2_proof_corpus import build_corpus


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "tests" / "fixtures" / "p2_proof_kernel" / "corpus.json"


def main() -> int:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(build_corpus(), ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(OUTPUT.relative_to(ROOT).as_posix())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
