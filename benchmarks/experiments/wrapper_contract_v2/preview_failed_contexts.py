"""Preview source derivation for failed models, without generating model responses."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from zscope.config.user_config_store import UserConfigStore
from zscope.framework.llm_client import LLMClient
from zscope.retrieval.code_index import CodeIndex
from zscope.semantics.contract_compiler import compile_snapshot, deterministic_contract_snapshot
from zscope.semantics.defaults import default_local_pattern_semantics
from zscope.semantics.inference import LocalPatternSemanticBuilder
from zscope.snapshots.modeling_input import build_semantic_model_input


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--publication", type=Path, required=True)
    parser.add_argument("--workbook", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    def forbidden(*_args, **_kwargs):
        raise AssertionError("This preview cannot call an LLM")

    LLMClient.chat_completion = forbidden
    source = args.source.resolve()
    index = CodeIndex(source, include_paths=[source / p for p in ("src", "include", "internal")])
    store = UserConfigStore(args.workbook.resolve())
    semantics = default_local_pattern_semantics()
    semantics.merge(LocalPatternSemanticBuilder(None, store, None, []).semantics_from_user_config())
    publication = json.loads(args.publication.read_text(encoding="utf-8"))
    rows = []
    try:
        for failed in publication["failed_models"]:
            symbol = json.loads(failed["symbol"])
            context = build_semantic_model_input(index, symbol["name"], file_path=symbol["file_path"])
            static = deterministic_contract_snapshot(context, semantics.contracts)
            proposed = {"interface_contracts": failed.get("raw_interface_contracts") or []}
            errors = compile_snapshot(proposed, context, semantics.contracts)
            rows.append({
                "symbol": symbol, "context": context,
                "context_backend": "regex source retrieval; compiler parses the complete source",
                "deterministic": static is not None,
                "contracts": proposed["interface_contracts"], "remaining_errors": errors,
            })
    finally:
        index.close()
    result = {
        "llm_calls": 0, "release_eligible": False,
        "contract_version": semantics.contracts.version,
        "note": "Source derivation preview only. No terminal payload or successful model snapshot is synthesized; no workbook is changed. Native Clang input and a new model response are not exercised here.",
        "rows": rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for row in rows:
        print(json.dumps({"name": row["symbol"]["name"], "deterministic": row["deterministic"], "roles": [c["role"] for c in row["contracts"]], "errors": row["remaining_errors"]}))


if __name__ == "__main__":
    main()
