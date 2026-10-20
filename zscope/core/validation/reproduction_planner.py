"""Session-owned reproduction from a real compilation instance and program entry.

The initial automatic strategy builds a TU containing its own main. It never
calls an arbitrary internal function with invented initialization or arguments.
Unsupported inputs remain explicit gaps for later harness strategies.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shlex
import shutil
import sys
from threading import RLock
from typing import Any, Mapping
from uuid import uuid4

from ...retrieval.build_context import context_input_status
from ...retrieval.indexing_identity import digest_json, file_digest
from .dynamic_reproduction import (
    BuildSpec,
    DynamicReproductionError,
    DynamicReproductionPolicy,
    ExecutionPlan,
    SANITIZER_FAMILY_TOKENS,
    attempt_dynamic_reproduction,
    bind_candidate,
    build_execution_plan,
    families_match,
)


class SessionReproductionPlanner:
    def __init__(self, config: Any, code_index: Any = None):
        self.config = config
        self.code_index = code_index
        self.root = Path(config.project.project_root).resolve()
        self.artifact_root = (
            Path(config.analysis.snapshot_dir).resolve() / "reproductions" / uuid4().hex
        )
        self._lock = RLock()
        self._plans: dict[str, ExecutionPlan] = {}

    def attach_index(self, code_index: Any) -> None:
        with self._lock:
            if self.code_index is not None and self.code_index is not code_index:
                raise ValueError("reproduction_session_index_changed")
            self.code_index = code_index

    def attempt(self, issue: dict[str, Any], policy: DynamicReproductionPolicy) -> None:
        if not policy.enabled:
            return
        # Plan/build directories and receipts belong to this scan. Serialize the
        # initial strategy; entry workers cannot overwrite another witness.
        with self._lock:
            try:
                plan = self.plan(issue, policy)
            except (DynamicReproductionError, OSError, ValueError) as exc:
                issue["dynamic_reproduction_attempt"] = {
                    "status": "plan_unavailable",
                    "reason": str(exc),
                }
                return
            if plan is None:
                return
            outcome = attempt_dynamic_reproduction(issue, policy=policy, provider=lambda *_: plan)
            if outcome is not None:
                self._write(Path(plan.run_cwd) / "result.json", outcome.to_dict())
            issue.setdefault("dynamic_reproduction_attempt", {})[
                "artifact_directory"
            ] = plan.run_cwd

    def plan(
        self, issue: dict[str, Any], policy: DynamicReproductionPolicy
    ) -> ExecutionPlan | None:
        if sys.platform != "linux":
            raise DynamicReproductionError("automatic_reproduction_requires_linux")
        family = str(issue.get("defect_class") or issue.get("category") or "")
        kinds = [kind for kind in SANITIZER_FAMILY_TOKENS if families_match(kind, family)]
        if not kinds:
            raise DynamicReproductionError("defect_family_has_no_sanitizer_strategy")
        sanitizer = "tsan" if set(kinds) <= {"data-race", "lock-order-inversion"} else "asan"
        getter = getattr(self.code_index, "get_build_contexts", None)
        contexts = getter() if callable(getter) else []
        location = str(issue.get("location") or issue.get("file_path") or issue.get("file") or "")
        path = Path(re.sub(r":\d+(?::\d+)?$", "", location))
        path = (path if path.is_absolute() else self.root / path).resolve()
        selected = str(issue.get("build_context_id") or "")
        contexts = [
            context
            for context in contexts
            if (not selected or context.get("build_context_id") == selected)
            and str(path) in context.get("dependencies", {})
        ]
        if len(contexts) != 1:
            raise DynamicReproductionError("ambiguous_or_missing_build_context")
        context = contexts[0]
        status = context_input_status(context)
        if status != "current":
            raise DynamicReproductionError(status)
        context_id = str(context["build_context_id"])
        command = context["command"]
        source = Path(command["source"])
        facts = self.code_index.get_function_program_facts(
            "main", source.relative_to(self.root).as_posix(), build_context_id=context_id
        )
        if not facts.get("complete") or len(facts.get("functions", [])) != 1:
            raise DynamicReproductionError("standalone_program_entry_unavailable")
        arguments = self._arguments(command)
        compiler = shutil.which(arguments[0])
        if not compiler or not re.fullmatch(
            r"(?:clang\+\+|clang|gcc|g\+\+|cc|c\+\+)(?:-\d+)?", Path(arguments[0]).name
        ):
            raise DynamicReproductionError("unsupported_compiler_driver")
        issue.setdefault(
            "project_id", str(getattr(self.config.project, "project_id", "") or self.root)
        )
        issue.setdefault("source_revision", digest_json(context["dependencies"]))
        issue.setdefault("dependency_code_hash", digest_json(context["dependencies"]))
        issue["build_context_id"] = context_id
        binding = bind_candidate(issue)
        from ...semantics.resource_identity import native_heap_witness

        candidate_facts = self.code_index.get_function_program_facts(
            str(issue.get("function") or "main"),
            path.relative_to(self.root).as_posix(),
            build_context_id=context_id,
        )
        object_witness = native_heap_witness(
            candidate_facts,
            name=binding.object_identity,
            site_file=str(path),
            site_line=binding.site_line,
        )
        key = digest_json({"binding": binding.to_dict(), "sanitizer": sanitizer})
        if key in self._plans:
            return self._plans[key]
        directory = self.artifact_root / key
        directory.mkdir(parents=True, exist_ok=True)
        binary = directory / "program"
        build_arguments = self._build_arguments(arguments, command, compiler, binary, sanitizer)
        dependencies = dict(context["dependencies"])
        dependencies.update(command.get("response_files") or {})
        dependencies[compiler] = file_digest(Path(compiler))
        inputs = sorted(dependencies)
        plan = build_execution_plan(
            binding,
            provider_kind=sanitizer,
            provider_name=f"{sanitizer}-runner",
            provider_version="1",
            run_argv=[str(binary)],
            run_cwd=str(directory),
            # The original main is the harness. No synthetic initialization,
            # stub, copied implementation or business-source modification.
            harness_ref=str(source),
            harness_digest=dependencies[str(source)],
            binary_path=str(binary),
            binary_digest="",
            toolchain_id=digest_json({"driver": compiler, "digest": dependencies[compiler]}),
            build_configuration=digest_json({"context": context_id, "argv": build_arguments}),
            input_refs=inputs,
            input_digests=[dependencies[path] for path in inputs],
            env_allowlist={
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                **command.get("environment", {}),
            },
            timeout_seconds=policy.timeout_seconds,
            memory_limit_mb=policy.memory_limit_mb,
            isolation=policy.isolation,
            max_replays=policy.max_replays,
            build=BuildSpec(
                tuple(build_arguments), command["directory"], policy.build_timeout_seconds
            ),
            allowed_exec_roots=tuple(
                sorted(
                    {
                        str(directory),
                        command["directory"],
                        *(str(Path(path).parent) for path in inputs),
                    }
                )
            ),
            object_witness=object_witness,
            require_exact_object=True,
        )
        self._write(directory / "plan.json", plan.to_dict())
        self._plans[key] = plan
        return plan

    @staticmethod
    def _write(path: Path, value: Mapping[str, Any]) -> None:
        temp = path.with_suffix(path.suffix + ".tmp")
        temp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        temp.replace(path)

    @staticmethod
    def _arguments(command: Mapping[str, Any]) -> list[str]:
        def expand(arguments: list[str], seen: frozenset[str]) -> list[str]:
            result = []
            for arg in arguments:
                if not arg.startswith("@"):
                    result.append(arg)
                    continue
                path = Path(arg[1:])
                path = (path if path.is_absolute() else Path(command["directory"]) / path).resolve()
                if str(path) in seen or len(seen) >= 16:
                    raise DynamicReproductionError("recursive_response_file")
                result.extend(
                    expand(shlex.split(path.read_text(encoding="utf-8")), seen | {str(path)})
                )
            return result

        return expand(list(command["arguments"]), frozenset())

    @staticmethod
    def _build_arguments(
        arguments: list[str],
        command: Mapping[str, Any],
        compiler: str,
        binary: Path,
        sanitizer: str,
    ) -> list[str]:
        # Only true optimization levels are replaced by the plan's -O0. Anything
        # else starting with "-O" (e.g. the -ObjC/-ObjC++ language modes) carries
        # program semantics and must survive the rewrite.
        optimization_level = re.compile(r"-O(?:[0-9]+|s|z|g|fast|none)?")
        result = [compiler]
        pending = False
        for argument in arguments[1:]:
            if pending:
                pending = False
                continue
            if argument in {"-o", "-MF", "-MT", "-MQ", "-dependency-file"}:
                pending = True
                continue
            if argument in {"-c", "-MD", "-MMD", "-MP", "-MG"}:
                continue
            if optimization_level.fullmatch(argument):
                continue
            if argument.startswith(("-fsanitize=", "-fno-sanitize=")):
                # The plan's sanitizer replaces the original selection.
                continue
            if argument.startswith(("-fsanitize", "-fno-sanitize")):
                # Modifier flags were chosen for the original sanitizer
                # configuration and could mask or alter the plan's own
                # sanitizer semantics; the strategy stays an explicit gap
                # instead of building something the plan does not describe.
                raise DynamicReproductionError("unsupported_sanitizer_option:" + argument)
            if argument.startswith(("-MF", "-MT", "-MQ")):
                continue
            if argument.startswith(
                (
                    "-save-temps",
                    "-fprofile",
                    "--coverage",
                    "-coverage",
                    "-MJ",
                    "-serialize-diagnostics",
                    "-ftime-trace",
                    "-fsyntax-only",
                    "-emit-llvm",
                    "-objcmt-",
                    "-fsave-optimization-record",
                    "-foptimization-record-file",
                    "-fmodule-output",
                )
            ) or argument in {"-E", "-S", "-M", "-MM"}:
                raise DynamicReproductionError("unsupported_build_mode:" + argument)
            # Lowercase "-o*" is an output specification to clang/gcc drivers
            # (both parse "-objc" as "-o bjc"); the registered semantic options
            # starting with "object"/"order_" pass through untouched.
            if argument.startswith("-o") and not argument.startswith(("-object", "-order_")):
                continue
            result.append(argument)
        if pending:
            raise DynamicReproductionError("incomplete_build_arguments")
        result.extend(
            [
                f"-fsanitize={'thread' if sanitizer == 'tsan' else 'address'}",
                "-g",
                "-O0",
                "-fno-omit-frame-pointer",
                "-o",
                str(binary),
            ]
        )
        return result
