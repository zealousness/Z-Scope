"""Compare builtin / automatic / configured native-local candidate coverage.

No model or answer files are read. This is a diagnostic ablation, not a formal
unified benchmark or a proof of globally minimal configuration.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import time

from zscope.config.config import ConfigLoader
from zscope.core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator
from zscope.core.candidates.function_facts import numbered_source_fragment
from zscope.orchestration.instance_semantics_context import freeze_instance_context
from zscope.orchestration.primitive_discovery import _stream_function_work
from zscope.retrieval.code_index import CodeIndex
from zscope.semantics.automatic import align_project_identities, configuration_requirements
from zscope.semantics.instance_semantics import materialize_effect_semantics
from zscope.semantics.models import LocalPatternSemantics


def audit(config, index):
    started = time.monotonic()
    settle = getattr(index, "settle_native_facts", None)
    if callable(settle):
        settle()
    scopes, gaps, work, _ = _stream_function_work(index, Path(config.project.project_root))
    inventory_seconds = time.monotonic() - started
    representatives = {s.build_context_id: s for s in scopes}
    frozen = freeze_instance_context(
        config=config,
        code_index=index,
        semantics_path=config.project.semantics_file,
        scopes=list(representatives.values()),
        allow_unbound_primitive_proposals=True,
    )
    if frozen.unavailable:
        raise ValueError(dict(frozen.unavailable))
    frozen.require_all()
    freeze_seconds = time.monotonic() - started - inventory_seconds
    arm_rows = {name: [] for name in ("builtin", "automatic", "configured")}
    timings = dict.fromkeys(arm_rows, 0.0)
    derivations = {}
    contracts = {}
    for build, functions in work.items():
        snapshot = frozen.snapshots[representatives[build].identity]
        full, overlay = materialize_effect_semantics(snapshot)
        derivations[build] = overlay["automatic_derivation"]
        contracts[build] = {
            "automatic": overlay["automatic_contracts"],
            "configured": overlay["project_contracts"],
        }
        for arm in arm_rows:
            began = time.monotonic()
            semantics = LocalPatternSemantics()
            semantics.type_aliases = dict(full.type_aliases)
            semantics.contracts.build_context_id = build
            semantics.contracts.shadowed_symbols = set(full.contracts.shadowed_symbols)
            # The configured registry can override an automatic effect. Rebuild
            # the automatic arm from its own immutable payload, not that view.
            raw = json.loads(bytes(snapshot.effect_payload))
            rows = [
                c
                for c in raw["contracts"]
                if c["symbol"]["name"] not in semantics.contracts.shadowed_symbols
            ]
            if arm != "builtin":
                rows += overlay["automatic_contracts"]
            if arm == "configured":
                rows += align_project_identities(
                    overlay["automatic_contracts"], overlay["project_contracts"]
                )
            from zscope.semantics.contracts import ApiContract, ApiPair, SymbolIdentity

            for row in rows:
                contract = ApiContract.from_row({"contract": deepcopy(row)})
                assert contract is not None
                semantics.contracts.add(contract)
                semantics.add_api(contract.role, contract.symbol.name, contract.source)
            for row in raw["pairs"]:
                acquire, release = SymbolIdentity.from_value(
                    row["acquire"]
                ), SymbolIdentity.from_value(row["release"])
                if not ({acquire.name, release.name} & semantics.contracts.shadowed_symbols):
                    semantics.contracts.pairs.append(
                        ApiPair(acquire, release, source="builtin_defaults")
                    )
            for scope, impl, facts, name, _signature in functions:
                generator = ClangAstCfgCandidateGenerator(
                    semantics=semantics,
                    restrict_to_semantics=True,
                    program_facts_provider=lambda *args, f=facts, **kwargs: deepcopy(f),
                )
                source = numbered_source_fragment(impl["code"], start_line=impl["start_line"])
                candidates = generator.generate_issues(name, source, scope.source)
                # Record exact call effects as well as findings. Absence of a
                # candidate alone is not evidence of equal semantic coverage.
                arm_rows[arm].append(
                    {
                        "build_context_id": build,
                        "usr": scope.usr,
                        "name": name,
                        "candidates": candidates,
                        "calls": generator.last_semantic_events,
                    }
                )
            timings[arm] += time.monotonic() - began
    frozen.require_all()

    def identities(rows):
        return sorted(
            {
                (
                    r["build_context_id"],
                    r["usr"],
                    str(c.get("rule_id") or c.get("rule")),
                    str(c.get("location")),
                    str(c.get("source")),
                    str(c.get("sink")),
                    str(c.get("variable") or c.get("resource") or ""),
                )
                for r in rows
                for c in r["candidates"]
            }
        )

    sets = {name: set(identities(rows)) for name, rows in arm_rows.items()}
    return {
        "schema": "zscope.configuration-ablation.v1",
        "llm_calls": 0,
        "tokens": 0,
        "scope": "clang_native_local_candidates_and_call_effects",
        "formal_eligible": False,
        "minimum_configuration_proven": False,
        "input_gaps": gaps,
        "functions": sum(len(v) for v in work.values()),
        "builds": len(work),
        "derivations": derivations,
        "contracts": contracts,
        "arms": arm_rows,
        "configuration_requirements": {
            b: configuration_requirements(v["configured"], v["automatic"])
            for b, v in contracts.items()
        },
        "arm_seconds": timings,
        "wall_seconds": time.monotonic() - started,
        "inventory_seconds": inventory_seconds,
        "semantics_freeze_seconds": freeze_seconds,
        "candidate_counts": {k: len(v) for k, v in sets.items()},
        "automatic_added": sorted(sets["automatic"] - sets["builtin"]),
        "automatic_removed": sorted(sets["builtin"] - sets["automatic"]),
        "configured_added": sorted(sets["configured"] - sets["automatic"]),
        "configured_removed": sorted(sets["automatic"] - sets["configured"]),
        "reference_sha256": hashlib.sha256(
            Path(config.project.semantics_file).read_bytes()
        ).hexdigest(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists")
    config = ConfigLoader.load(str(args.config))
    root = Path(config.project.project_root)
    indexing = deepcopy(config.indexing)
    indexing.backend = "clang"
    # Uncompiled platform/demo files may have navigation fallback; the audit
    # below admits only exact native compilation bodies, never those views.
    indexing.clang_frontend = "auto"
    index = CodeIndex(
        root,
        config.project.compile_commands_path,
        source_root=root,
        indexing_config=indexing,
        include_paths=config.project.include_paths,
        exclude_paths=config.project.exclude_paths,
        wait_for_cpg=True,
        defer_svf=True,
    )
    try:
        result = audit(config, index)
    finally:
        index.close()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2, default=str) + "\n")
    print(
        json.dumps(
            {
                k: result[k]
                for k in [
                    "functions",
                    "builds",
                    "candidate_counts",
                    "arm_seconds",
                    "wall_seconds",
                    "llm_calls",
                ]
            }
        )
    )


if __name__ == "__main__":
    main()
