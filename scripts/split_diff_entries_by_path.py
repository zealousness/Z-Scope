"""Extract a path-scoped shard from entry_functions_diff.json."""

from __future__ import annotations

import argparse
import json
import re
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence, Tuple


def _load_json(path: Path) -> Dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    if not isinstance(data.get("functions"), list):
        raise ValueError(f"JSON must contain a functions array: {path}")
    return data


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _norm_path(value: Any, *, ignore_case: bool = False) -> str:
    text = str(value or "").strip().replace("\\", "/")
    text = re.sub(r"/+", "/", text)
    if text.startswith("./"):
        text = text[2:]
    if len(text) > 1:
        text = text.rstrip("/")
    return text.casefold() if ignore_case else text


def _path_variants(value: Any, project_root: Path, *, ignore_case: bool = False) -> List[str]:
    raw = str(value or "").strip()
    if not raw:
        return []
    variants = {_norm_path(raw, ignore_case=ignore_case)}
    path = Path(raw)
    try:
        if path.is_absolute():
            variants.add(_norm_path(path.resolve(), ignore_case=ignore_case))
            try:
                variants.add(_norm_path(path.resolve().relative_to(project_root.resolve()), ignore_case=ignore_case))
            except ValueError:
                pass
        else:
            variants.add(_norm_path((project_root / path).resolve(), ignore_case=ignore_case))
    except OSError:
        pass
    return [item for item in variants if item]


def _target_variants(paths: Sequence[str], project_root: Path, *, ignore_case: bool = False) -> List[str]:
    variants: List[str] = []
    seen: set[str] = set()
    for path in paths:
        for variant in _path_variants(path, project_root, ignore_case=ignore_case):
            if variant in seen:
                continue
            seen.add(variant)
            variants.append(variant)
    return variants


def _is_under_path(candidate: Any, target_variants: Sequence[str], project_root: Path, *, ignore_case: bool = False) -> bool:
    for candidate_path in _path_variants(candidate, project_root, ignore_case=ignore_case):
        for target in target_variants:
            if candidate_path == target or candidate_path.startswith(f"{target}/"):
                return True
    return False


def _changed_functions_from_entry(entry: Dict[str, Any]) -> List[Dict[str, Any]]:
    focus = entry.get("diff_focus")
    if not isinstance(focus, dict):
        return []
    changed = focus.get("changed_functions")
    if not isinstance(changed, list):
        return []
    return [item for item in changed if isinstance(item, dict)]


def _entry_matches_path(
    entry: Dict[str, Any],
    target_variants: Sequence[str],
    project_root: Path,
    *,
    match_mode: str,
    ignore_case: bool = False,
) -> bool:
    entry_path_match = _is_under_path(
        entry.get("file_path"),
        target_variants,
        project_root,
        ignore_case=ignore_case,
    )
    changed_path_match = any(
        _is_under_path(
            changed.get("file_path"),
            target_variants,
            project_root,
            ignore_case=ignore_case,
        )
        for changed in _changed_functions_from_entry(entry)
    )
    if match_mode == "entry":
        return entry_path_match
    if match_mode == "changed":
        return changed_path_match
    return entry_path_match or changed_path_match


def _entry_key(entry: Dict[str, Any]) -> Tuple[str, str]:
    return (str(entry.get("function_name") or ""), str(entry.get("file_path") or ""))


def _changed_key(item: Dict[str, Any]) -> Tuple[str, str]:
    return (str(item.get("function_name") or ""), str(item.get("file_path") or ""))


def _coverage_summary(function_coverage: Sequence[Dict[str, Any]], entry_count: int) -> Dict[str, Any]:
    statuses = {
        "scanned_as_root": 0,
        "covered_by_entry": 0,
        "context_only": 0,
        "triage_only": 0,
        "unresolved": 0,
    }
    for item in function_coverage:
        status = str(item.get("coverage_status") or "unresolved")
        if status not in statuses:
            status = "unresolved"
        statuses[status] += 1
    return {
        "changed_total": len(function_coverage),
        "scan_entry_count": entry_count,
        "covered_by_scan": statuses["scanned_as_root"] + statuses["covered_by_entry"],
        "context_only": statuses["context_only"],
        "triage_only": statuses["triage_only"],
        "unresolved": statuses["unresolved"],
        "by_status": statuses,
    }


def _ids_from_entries(entries: Iterable[Dict[str, Any]]) -> set[str]:
    ids: set[str] = set()
    for entry in entries:
        focus = entry.get("diff_focus")
        if not isinstance(focus, dict):
            continue
        for item in focus.get("analysis_obligation_ids") or []:
            clean = str(item or "").strip()
            if clean:
                ids.add(clean)
    return ids


def _keys_from_entry_changed_functions(entries: Iterable[Dict[str, Any]]) -> set[Tuple[str, str]]:
    keys: set[Tuple[str, str]] = set()
    for entry in entries:
        for changed in _changed_functions_from_entry(entry):
            key = _changed_key(changed)
            if key[0]:
                keys.add(key)
    return keys


def _filter_by_changed_keys(items: Any, changed_keys: set[Tuple[str, str]]) -> List[Dict[str, Any]]:
    if not isinstance(items, list):
        return []
    result: List[Dict[str, Any]] = []
    seen: set[Tuple[str, str]] = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        key = _changed_key(item)
        if key in changed_keys and key not in seen:
            result.append(deepcopy(item))
            seen.add(key)
    return result


def _filter_changed_files(
    files: Any,
    target_variants: Sequence[str],
    project_root: Path,
    *,
    ignore_case: bool = False,
) -> List[str]:
    if not isinstance(files, list):
        return []
    result: List[str] = []
    seen: set[str] = set()
    for item in files:
        text = str(item or "")
        if _is_under_path(text, target_variants, project_root, ignore_case=ignore_case):
            key = _norm_path(text, ignore_case=ignore_case)
            if key not in seen:
                result.append(text)
                seen.add(key)
    return result


def _filter_obligations(
    obligations: Any,
    obligation_ids: set[str],
    changed_keys: set[Tuple[str, str]],
    entry_names: set[str],
) -> List[Dict[str, Any]]:
    if not isinstance(obligations, list):
        return []
    result: List[Dict[str, Any]] = []
    for item in obligations:
        if not isinstance(item, dict):
            continue
        oid = str(item.get("id") or "")
        root = str(item.get("root_function") or "")
        changed = item.get("changed_functions") if isinstance(item.get("changed_functions"), list) else []
        has_changed = any(isinstance(ch, dict) and _changed_key(ch) in changed_keys for ch in changed)
        if oid in obligation_ids or root in entry_names or has_changed:
            result.append(deepcopy(item))
    return result


def _filter_diff_impact(
    diff_impact: Any,
    selected_entries: Sequence[Dict[str, Any]],
    target_variants: Sequence[str],
    project_root: Path,
    *,
    ignore_case: bool = False,
) -> Dict[str, Any]:
    if not isinstance(diff_impact, dict):
        return {}

    selected_entry_names = {str(entry.get("function_name") or "") for entry in selected_entries}
    selected_entry_names.discard("")
    obligation_ids = _ids_from_entries(selected_entries)
    changed_keys = _keys_from_entry_changed_functions(selected_entries)

    function_coverage = _filter_by_changed_keys(diff_impact.get("function_coverage"), changed_keys)
    if not function_coverage and isinstance(diff_impact.get("function_coverage"), list):
        function_coverage = [
            deepcopy(item)
            for item in diff_impact.get("function_coverage") or []
            if isinstance(item, dict) and str(item.get("scan_entry") or "") in selected_entry_names
        ]
        changed_keys.update(_changed_key(item) for item in function_coverage if _changed_key(item)[0])

    filtered = deepcopy(diff_impact)
    filtered["changed_files"] = _filter_changed_files(
        diff_impact.get("changed_files"),
        target_variants,
        project_root,
        ignore_case=ignore_case,
    )
    filtered["changed_headers"] = _filter_changed_files(
        diff_impact.get("changed_headers"),
        target_variants,
        project_root,
        ignore_case=ignore_case,
    )
    filtered["changed_functions"] = _filter_by_changed_keys(
        diff_impact.get("changed_functions"),
        changed_keys,
    )
    filtered["analysis_obligations"] = _filter_obligations(
        diff_impact.get("analysis_obligations"),
        obligation_ids,
        changed_keys,
        selected_entry_names,
    )
    filtered["function_coverage"] = function_coverage
    filtered["coverage_summary"] = _coverage_summary(function_coverage, len(selected_entries))
    filtered["entry_count"] = len(selected_entries)
    notes = list(filtered.get("notes") or [])
    notes.append("This file is a path-scoped shard generated from entry_functions_diff.json.")
    filtered["notes"] = notes
    return filtered


def _default_output_path(input_path: Path, module_paths: Sequence[str]) -> Path:
    stem = input_path.stem
    joined = "__".join(path.replace("\\", "/") for path in module_paths)
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", joined).strip("_")
    if len(safe) > 96:
        safe = f"{safe[:96].rstrip('_')}_plus"
    return input_path.with_name(f"{stem}_{safe or 'path_shard'}.json")


def split_entries_by_path(
    input_path: Path,
    module_paths: Sequence[str],
    output_path: Path,
    *,
    project_root: Path,
    match_mode: str = "any",
    ignore_case: bool = False,
    allow_empty: bool = False,
) -> Dict[str, Any]:
    data = _load_json(input_path)
    module_paths = [str(path).strip() for path in module_paths if str(path).strip()]
    target_variants = _target_variants(module_paths, project_root, ignore_case=ignore_case)
    if not target_variants:
        raise ValueError("at least one module path is required")

    functions = data.get("functions") or []
    selected = [
        deepcopy(entry)
        for entry in functions
        if isinstance(entry, dict)
        and _entry_matches_path(
            entry,
            target_variants,
            project_root,
            match_mode=match_mode,
            ignore_case=ignore_case,
        )
    ]
    if not selected and not allow_empty:
        raise ValueError(f"No entries matched paths: {', '.join(module_paths)}")

    output = deepcopy(data)
    output["description"] = (
        f"Path-scoped shard of {input_path.name}: {', '.join(module_paths)}. "
        f"Matched {len(selected)} of {len(functions)} function entries."
    )
    output["functions"] = selected
    if "diff_impact" in data:
        output["diff_impact"] = _filter_diff_impact(
            data.get("diff_impact"),
            selected,
            target_variants,
            project_root,
            ignore_case=ignore_case,
        )

    _write_json(output_path, output)
    return {
        "input": str(input_path),
        "output": str(output_path),
        "module_paths": list(module_paths),
        "match_mode": match_mode,
        "input_entries": len(functions),
        "output_entries": len(selected),
        "changed_total": (output.get("diff_impact") or {}).get("coverage_summary", {}).get("changed_total", 0),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "module_paths",
        nargs="+",
        help="One or more path prefixes to extract, e.g. src/net src/fs or /repo/src/net.",
    )
    parser.add_argument(
        "-i",
        "--input",
        type=Path,
        default=Path("entry_functions_diff.json"),
        help="Input entry_functions_diff.json path. Defaults to ./entry_functions_diff.json.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Output JSON path. Defaults to entry_functions_diff_<module_paths>.json next to input.",
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path("."),
        help="Project root used to normalize absolute and relative paths. Defaults to current directory.",
    )
    parser.add_argument(
        "--match",
        choices=("any", "entry", "changed"),
        default="any",
        help="any: entry file or covered changed file matches; entry: only entry file; changed: only covered changed file.",
    )
    parser.add_argument("--ignore-case", action="store_true", help="Use case-insensitive path matching.")
    parser.add_argument("--allow-empty", action="store_true", help="Write an empty shard instead of failing on no matches.")
    args = parser.parse_args()

    input_path = args.input.resolve()
    output_path = args.output.resolve() if args.output else _default_output_path(input_path, args.module_paths).resolve()
    try:
        summary = split_entries_by_path(
            input_path,
            args.module_paths,
            output_path,
            project_root=args.project_root.resolve(),
            match_mode=args.match,
            ignore_case=args.ignore_case,
            allow_empty=args.allow_empty,
        )
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
