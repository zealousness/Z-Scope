#!/usr/bin/env python3
"""Generate Z-SCOPE benchmark metrics.md in one command."""

from __future__ import annotations

import argparse
import json
import re
import tempfile
from pathlib import Path
from typing import Iterable, Optional

from extract_efficiency_metrics import extract
from render_metrics_markdown import render


RUN_ID_RE = re.compile(r"(?:unified|global_model)_(?P<date>\d{8})_(?P<time>\d{6})")


def _existing_file(run_dir: Path, names: Iterable[str]) -> Path:
    for name in names:
        path = run_dir / name
        if path.exists():
            return path
    expected = ", ".join(names)
    raise FileNotFoundError(f"none of {expected} found under {run_dir}")


def infer_conversation_dir(run_dir: Path) -> Path:
    match = RUN_ID_RE.search(run_dir.name)
    if not match:
        raise ValueError(
            f"cannot infer conversation directory from run id {run_dir.name!r}; "
            "pass --conversation-dir explicitly"
        )

    conversations_root = run_dir.parent.parent / ".zscope_conversations"
    if not conversations_root.exists():
        raise FileNotFoundError(f"conversation root not found: {conversations_root}")

    prefix = f"run_{match.group('date')}_{match.group('time')}_"
    matches = sorted(path for path in conversations_root.glob(prefix + "*") if path.is_dir())
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        newest = max(matches, key=lambda path: path.stat().st_mtime)
        return newest

    same_day = sorted(
        path for path in conversations_root.glob(f"run_{match.group('date')}_*") if path.is_dir()
    )
    if same_day:
        log_path = run_dir / "zscope_run.log"
        target_mtime = log_path.stat().st_mtime if log_path.exists() else run_dir.stat().st_mtime
        return min(same_day, key=lambda path: abs(path.stat().st_mtime - target_mtime))

    raise FileNotFoundError(
        f"no conversation directory matching {prefix}* under {conversations_root}; "
        "pass --conversation-dir explicitly"
    )


def link_required_inputs(source_run_dir: Path, temp_run_dir: Path) -> None:
    metric_file = _existing_file(source_run_dir, ("metrics.json", "global_model_metrics.json"))
    (temp_run_dir / metric_file.name).symlink_to(metric_file)
    for name in ("zscope_batch_report.json", "zscope_run.log", "build_cpg.log"):
        source = source_run_dir / name
        if source.exists():
            (temp_run_dir / name).symlink_to(source)


def generate_metrics_md(
    run_dir: Path,
    *,
    conversation_dir: Optional[Path] = None,
    output: Optional[Path] = None,
    model: str = "GLM-5",
) -> Path:
    run_dir = run_dir.resolve()
    conversation_dir = (conversation_dir or infer_conversation_dir(run_dir)).resolve()
    output = (output or (run_dir / "metrics.md")).resolve()

    with tempfile.TemporaryDirectory(prefix=f"{run_dir.name}.metrics.") as temp_name:
        temp_run_dir = Path(temp_name)
        link_required_inputs(run_dir, temp_run_dir)
        efficiency = extract(temp_run_dir, conversation_dir)
        (temp_run_dir / "efficiency_metrics.json").write_text(
            json.dumps(efficiency, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        output.write_text(render(temp_run_dir, model=model), encoding="utf-8")

    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--conversation-dir", type=Path)
    parser.add_argument("--model", default="GLM-5")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    output = generate_metrics_md(
        args.run_dir,
        conversation_dir=args.conversation_dir,
        output=args.output,
        model=args.model,
    )
    print(output)


if __name__ == "__main__":
    main()
