"""Offline, lossless replay of a frozen ownership/refutation audit (no LLM)."""

from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
from types import SimpleNamespace

from zscope.config.user_config_store import UserConfigStore
from zscope.core.candidates.evidence import SemanticOverlayCompiler
from zscope.core.validation.review_checks import ReviewClaimChecker, checked_receipt
from zscope.retrieval.validation_facts import scan_compiler_facts
from zscope.semantics.defaults import default_local_pattern_semantics
from zscope.semantics.inference import LocalPatternSemanticBuilder


class FrozenIndex:
    """Read-only archived index; never starts indexing or changes the fixture."""

    def __init__(self, source):
        self.project_root = self.source_root = source
        self.connection = sqlite3.connect(
            (source / ".zscope_knowledge/code_knowledge.db").as_uri() + "?mode=ro", uri=True
        )
        self.connection.row_factory = sqlite3.Row
        self._db = SimpleNamespace(_conn=self.connection)
        self.definitions = [
            dict(r)
            for r in self.connection.execute("SELECT * FROM functions WHERE is_declaration=0")
        ]

    def get_function_impl(self, name, **kwargs):
        rows = [r for r in self.definitions if r["name"] == name.split("@")[0]]
        hint = kwargs.get("file_path")
        rows = [
            r
            for r in rows
            if not hint or r["file_path"] == hint or hint.endswith("/" + r["file_path"])
        ]
        unique = {(r["file_path"], r["start_line"]): r for r in rows}
        if len(unique) != 1:
            return None
        row = next(iter(unique.values()))
        lines = (self.source_root / row["file_path"]).read_text(encoding="utf-8").splitlines()
        return {
            "function": row["name"],
            "func_name": row["name"],
            "file": row["file_path"],
            "file_path": row["file_path"],
            "signature": row["signature"],
            "start_line": row["start_line"],
            "end_line": row["end_line"],
            "code": "\n".join(
                f"{n} | {lines[n-1]}" for n in range(row["start_line"], row["end_line"] + 1)
            ),
            "truncated": False,
        }

    def get_callees(self, name, **kwargs):
        return [
            dict(r)
            for r in self.connection.execute(
                "SELECT * FROM call_edges WHERE caller_name=?", (name,)
            )
        ]

    def get_callers(self, name, **kwargs):
        return [
            dict(r)
            for r in self.connection.execute(
                "SELECT * FROM call_edges WHERE callee_name=?", (name,)
            )
        ]

    def get_function_program_facts(self, name, file_path=""):
        from zscope.retrieval.clang_backend import ClangBackend

        return ClangBackend.get_function_program_facts(self, name, file_path)


def static_review(user_config, semantics, index):
    from zscope.semantics.contracts import ApiContract, ContractRegistry
    from zscope.semantics.contract_compiler import compile_snapshot
    from zscope.semantics.contract_review import review_roots

    proposals = user_config.workbook.read_rows().get("contract_review", [])
    snapshots = []
    for row in proposals:
        raw = row.get("contract")
        raw = json.loads(raw) if isinstance(raw, str) else raw
        if row.get("status") == "pending" and isinstance(raw, dict):
            snapshots.append({"interface_contracts": [deepcopy(raw)]})
    registry = ContractRegistry()
    for contract in semantics.contracts.contracts:
        registry.add(contract)
    diagnostics = []
    for snapshot in snapshots:
        raw = snapshot["interface_contracts"][0]
        symbol = raw.get("symbol", {})
        name = symbol.get("name", "")
        impl = index.get_function_impl(name, file_path=symbol.get("file_path"))
        if not impl:
            diagnostics.append(
                {"symbol": name, "reason": "canonical_function_or_macro_context_missing"}
            )
            continue
        snapshot.update(impl)
    # Static fixed point only; pending roots are never granted human authority.
    rebuilt = []
    versions = set()
    for _ in range(len(snapshots) + 1):
        if registry.version in versions:
            break
        versions.add(registry.version)
        changed = False
        for snapshot in snapshots:
            if not snapshot.get("code"):
                continue
            errors = compile_snapshot(snapshot, snapshot, registry)
            if errors:
                diagnostics.append({"symbol": snapshot["func_name"], "errors": errors})
            for raw in snapshot.get("interface_contracts", []):
                contract = ApiContract.from_row({"contract": raw})
                if contract and contract.effects_trusted and contract not in registry.contracts:
                    registry.add(contract)
                    rebuilt.append(contract.to_dict())
                    changed = True
        if not changed:
            break
    roots = review_roots(snapshots, registry)
    roots.update(
        original_proposals=proposals,
        normalized_snapshots=snapshots,
        original_pending_propositions=len(snapshots),
        original_pending_symbols=len(
            {r.get("symbol_name") for r in proposals if r.get("status") == "pending"}
        ),
        static_contracts=rebuilt,
        diagnostics=diagnostics,
        manual_confirmations=0,
        note="Missing canonical macro/type/ABI context remains unresolved; no claim of a globally minimum human set.",
    )
    return roots


def replay_generators(index, semantics, overlay, output):
    from zscope.core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator
    from zscope.core.candidates.regex import RegexCandidateGenerator
    from zscope.core.candidates.graph import GraphCandidateGenerator
    from zscope.rules.catalog import RuleCatalog, EffectiveRuleSet

    catalog = RuleCatalog.builtin()
    base = EffectiveRuleSet.build(catalog, language="c_cpp", backend="unified")
    names = sorted({r["name"] for r in index.definitions})
    impls = [impl for name in names if (impl := index.get_function_impl(name))]
    arms = []
    for added in [None, *sorted(base.disabled_ids)]:
        policy = EffectiveRuleSet.build(
            catalog,
            language="c_cpp",
            backend="unified",
            enabled_ids=[added] if added else [],
            disabled_ids=(
                [d.id for d in catalog if d.language == "c_cpp" and d.id != added] if added else []
            ),
        ).policy
        engines = [
            (
                "clang",
                ClangAstCfgCandidateGenerator(
                    semantics,
                    overlay,
                    rule_policy=policy,
                    program_facts_provider=index.get_function_program_facts,
                ),
            ),
            ("regex", RegexCandidateGenerator(semantics, rule_policy=policy)),
        ]
        rows = []
        for label, engine in engines:
            for impl in impls:
                candidates = engine.generate_issues(impl["function"], impl["code"], impl["file"])
                rows.extend(
                    {"engine": label, "candidate": c}
                    for c in candidates
                    if added is None or c.get("rule") == added
                )
        graph = GraphCandidateGenerator(index, semantics, overlay, policy)
        rows.extend(
            {"engine": "graph", "candidate": c}
            for c in graph.generate_for_functions(names, max_functions=len(names) + 1)
            if added is None or c.get("rule") == added
        )
        arms.append(
            {
                "enabled_extra": added,
                "candidates": rows,
                "graph_query_errors": graph.last_query_errors,
                "qualification": "not_qualified; discovery replay does not prove accuracy",
                "default_changed": False,
            }
        )
        print("generator replay", added or "default", len(rows), flush=True)
        arm_path = output / ("arm-" + (added or "default") + ".json")
        arm_path.write_text(
            json.dumps(arms[-1], ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    return {
        "scope": "archived program facts, current contracts; one disabled detector per independent arm",
        "functions": len(impls),
        "arms": arms,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--checks-only",
        action="store_true",
        help="Only rerun the fixed compiler claims; omit independent generator/protocol experiments",
    )
    args = parser.parse_args()
    audit, output = args.audit.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if (output / "results.json").exists():
        raise SystemExit(
            "Refusing to overwrite a completed replay; choose another output directory"
        )

    def read(name):
        return json.loads((audit / name).read_text(encoding="utf-8"))

    manifest = read("manifest.json")
    source = Path(manifest["source"])
    selected = [
        r
        for r in read("fp-attribution.json")
        if r["group"]
        in {"ownership_query_without_objects", "model_rejected_without_program_refutation"}
    ]
    originals = {r["identity"]: r for r in read("effective-fp.json")}
    frozen_rules = {r["id"]: r for r in read("frozen-rule-policy.json")["rules"]}
    workbook = output / "user_config.xlsx"
    shutil.copy2(audit / "user_config.xlsx", workbook)
    user_config = UserConfigStore(workbook)
    semantics = default_local_pattern_semantics()
    semantics.merge(
        LocalPatternSemanticBuilder(None, user_config, None, []).semantics_from_user_config()
    )
    semantics.merge_overlay(SemanticOverlayCompiler(user_config).compile())
    store = scan_compiler_facts(
        SimpleNamespace(), source, source / "build/compile_commands.json", output / "facts"
    )
    checker = ReviewClaimChecker(store, semantics.contracts)
    repo = Path(__file__).resolve().parents[1]
    code_hashes = {
        str(p.relative_to(repo)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (repo / "zscope").rglob("*.py")
    }
    rows = []
    for attribution in selected:
        original = originals[attribution["identity"]]
        candidate = deepcopy(original["issue"])
        rule = str(candidate.get("rule_id") or candidate.get("rule") or "")
        # Revision comes from the archived effective catalog, never a guess.
        if candidate.get("rule_revision") is None and rule in frozen_rules:
            candidate["rule_revision"] = frozen_rules[rule]["revision"]
        candidate["review_checked_proofs_enabled"] = True
        result = checker.check(candidate)
        receipt = checked_receipt(candidate)
        row = {
            "attribution": attribution,
            "original": original,
            "replayed_candidate": candidate,
            "check": result,
            "accepted_refutation": receipt is not None,
            "transition": "program_refuted" if receipt else "needs_review",
        }
        rows.append(row)
        with (output / "progress.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(
                json.dumps(
                    {
                        "index": attribution["issue_index"],
                        "function": attribution["function"],
                        "transition": row["transition"],
                        "reason": result.get("reason"),
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
        print(attribution["issue_index"], row["transition"], result.get("reason"), flush=True)
    result = {
        "scope": "offline compiler refutation replay; no LLM, truth or full scan",
        "audit": str(audit),
        "source": str(source),
        "contract_version": semantics.contracts.version,
        "inputs": {
            name: hashlib.sha256((audit / name).read_bytes()).hexdigest()
            for name in [
                "manifest.json",
                "fp-attribution.json",
                "effective-fp.json",
                "user_config.xlsx",
                "frozen-rule-policy.json",
            ]
        },
        "implementation": code_hashes,
        "counts": dict(Counter(r["transition"] for r in rows)),
        "rows": rows,
    }
    (output / "results.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    if args.checks_only:
        return
    index = FrozenIndex(source)
    try:
        for name, value in [
            ("root-review.json", lambda: static_review(user_config, semantics, index)),
            (
                "generators.json",
                lambda: replay_generators(
                    index, semantics, SemanticOverlayCompiler(user_config).compile(), output
                ),
            ),
        ]:
            (output / name).write_text(
                json.dumps(value(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
            )
    finally:
        index.connection.close()


if __name__ == "__main__":
    main()
