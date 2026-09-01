"""Answer-free P6 single-point replay over open synthetic C programs.

The replay is deliberately separate from the benchmark producer.  It creates a
small public C project, runs the ordinary balanced scanner with one model call
in flight, and checks only source-independent protocol invariants.  Neither the
result projection nor a failure diagnostic retains source, prompts, provider
responses, or process output.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import threading
from functools import wraps
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence, cast

import yaml

from zscope.benchmarking.provider_runtime import (
    P6_API_KEY_ENVIRONMENT_KEY,
    P6_PROVIDER_BASE_URL,
    P6_PROVIDER_MODEL,
    ProviderRuntimeContract,
    load_explicit_api_key_file,
    reject_conflicting_provider_identity_environment,
    require_p6_provider_contract,
)
from zscope.core.validation.authority import TERMINAL_AUTHORITY_DECISION_V4
from zscope.core.validation.proof_kernel.closure import PROMOTION_CERTIFICATE_VERSION


REPLAY_SCHEMA_VERSION = "zscope.p6-synthetic-replay.v1"
REPLAY_SUITE_VERSION = "zscope.p6-synthetic-suite.v1"
REPLAY_MAX_INFLIGHT = 1
REPLAY_MAX_TRANSPORT_RETRIES = 1
REPLAY_MAX_CONTRACT_REGENERATIONS = 1

_SCANNER_BOOTSTRAP = (
    "import sys;"
    "from zscope.benchmarking.p6_synthetic_replay import install_replay_call_guards as guard;"
    "guard();"
    "from zscope.cli.cli import main;"
    "main.main(args=sys.argv[1:],prog_name='zscope',standalone_mode=True)"
)

_PUBLIC_FAILURE_CLASSES = frozenset(
    {
        "input_binding_failure",
        "provider_credentials_unavailable",
        "provider_identity_mismatch",
        "provider_identity_override_attempt",
        "provider_transport_exhausted",
        "provider_protocol_incompatible",
        "provider_usage_unverifiable",
        "toolchain_preflight_failed",
        "anonymous_qualification_failed",
        "terminal_state_inconsistent",
        "accounting_conservation_failure",
        "internal_failure",
    }
)
_PUBLIC_STAGES = frozenset(
    {
        "input",
        "provider",
        "toolchain",
        "scan",
        "proof",
        "semantic",
        "usage",
        "conservation",
        "complete",
        "internal",
    }
)

# Build sensitive marker spellings at runtime so the public scenario corpus and
# generated artifacts do not themselves look like an answer-bearing input.
_FORBIDDEN_MARKERS = (
    "ground" + "_" + "tr" + "uth",
    "tr" + "uth",
    "expect" + "ed",
    "scor" + "er",
    "test" + "/" + "range",
    "range" + "-",
    "range" + "_",
    "fix" + "ture",
)


class SyntheticReplayError(RuntimeError):
    """Fixed-class failure that never exposes the causal body."""

    MESSAGE = "P6 synthetic replay failed"

    def __init__(self, stage: str, failure_class: str, count: int = 1) -> None:
        if stage not in _PUBLIC_STAGES:
            stage = "internal"
        if failure_class not in _PUBLIC_FAILURE_CLASSES:
            failure_class = "internal_failure"
        self.stage = stage
        self.failure_class = failure_class
        self.count = max(1, int(count or 1))
        super().__init__(self.MESSAGE)

    def public_line(self) -> str:
        return (
            f"stage={self.stage}; class={self.failure_class}:{self.count}; " f"count={self.count}"
        )


@dataclass(frozen=True)
class SyntheticScenario:
    scenario_id: str
    source_name: str
    vulnerable_entry: str
    protected_entry: str
    source: str

    def model_input(self) -> dict[str, Any]:
        """Return exactly the material made available to the scanner."""

        return {
            "scenario_id": self.scenario_id,
            "source_name": self.source_name,
            "source": self.source,
            "entries": [self.vulnerable_entry, self.protected_entry],
        }


@dataclass(frozen=True)
class SyntheticReplayWorkspace:
    root: Path
    project_root: Path
    config_path: Path
    report_path: Path
    usage_events_path_glob: str
    source_config_sha256: str
    runtime_config_sha256: str
    provider_contract: ProviderRuntimeContract
    scenarios: tuple[SyntheticScenario, ...]


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_text_lf(path: Path, value: str) -> None:
    with Path(path).open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(value)


def _canonical_sha256(value: Any) -> str:
    return _sha256_bytes(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )


def _strict_json(path: Path) -> Any:
    def reject_duplicates(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    return json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)


def assert_answer_free_payload(value: Any) -> None:
    """Recursively reject answer-bearing markers before launching the scanner."""

    def visit(item: Any) -> None:
        if isinstance(item, Mapping):
            for key, child in item.items():
                visit(str(key))
                visit(child)
            return
        if isinstance(item, (list, tuple, set, frozenset)):
            for child in item:
                visit(child)
            return
        if isinstance(item, Path):
            item = item.as_posix()
        if isinstance(item, bytes):
            try:
                item = item.decode("utf-8", errors="strict")
            except UnicodeError as exc:
                raise SyntheticReplayError("input", "input_binding_failure") from exc
        if not isinstance(item, str):
            return
        normalized = item.replace("\\", "/").casefold()
        if any(marker in normalized for marker in _FORBIDDEN_MARKERS):
            raise SyntheticReplayError("input", "input_binding_failure")

    visit(value)


def install_replay_call_guards() -> None:
    """Install pre-call bounds for the isolated scanner process.

    The generated config supplies one endpoint and one ordinary retry.  The
    guard disables the client's separate auth/client-response retry lanes and
    refuses a second contract-regeneration call for the same validation
    cluster before that call can reach the provider.
    """

    from zscope.framework.llm_client import LLMClient

    original = LLMClient.chat_completion
    if getattr(original, "_p6_synthetic_guard", False):
        return
    lock = threading.Lock()
    regeneration_counts: dict[str, int] = {}

    @wraps(original)
    def bounded(self: Any, *args: Any, **kwargs: Any) -> Any:
        endpoints = list(getattr(self, "_base_url_states", ()) or ())
        endpoint_urls = [str(getattr(value, "url", "")).rstrip("/") for value in endpoints]
        if (
            int(getattr(self, "max_retries", -1)) != REPLAY_MAX_TRANSPORT_RETRIES
            or getattr(self, "retry_until_available", None) is not False
            or endpoint_urls != [P6_PROVIDER_BASE_URL]
            or list(getattr(self, "models", ()) or ()) != [P6_PROVIDER_MODEL]
        ):
            raise RuntimeError("P6 synthetic replay call contract rejected")
        label = str(kwargs.get("trace_label") or "")
        if "call_kind=contract_regeneration" in label:
            match = re.search(r"validation_cluster_uid=([^;]+)", label)
            cluster = str(match.group(1) if match else "unattributed").strip()
            with lock:
                count = regeneration_counts.get(cluster, 0)
                if count >= REPLAY_MAX_CONTRACT_REGENERATIONS:
                    raise RuntimeError("P6 synthetic replay regeneration limit reached")
                regeneration_counts[cluster] = count + 1
        return original(self, *args, **kwargs)

    setattr(bounded, "_p6_synthetic_guard", True)
    LLMClient.TRANSIENT_AUTH_RETRY_LIMIT = 0
    LLMClient.TRANSIENT_CLIENT_RESPONSE_RETRY_LIMIT = 0
    setattr(LLMClient, "chat_completion", bounded)


def synthetic_scenarios() -> tuple[SyntheticScenario, ...]:
    """Return neutral, public C pairs with no labels embedded in source."""

    return (
        SyntheticScenario(
            scenario_id="syn-01",
            source_name="unit_01.c",
            vulnerable_entry="p6_s01_a",
            protected_entry="p6_s01_b",
            source=r"""#include <stddef.h>
#include <stdlib.h>

static volatile unsigned char s01_sink;

int p6_s01_a(size_t n) {
    unsigned char *p = (unsigned char *)malloc(n ? n : 1U);
    if (p == NULL) return -1;
    p[0] = (unsigned char)n;
    s01_sink ^= p[0];
    return 0;
}

int p6_s01_b(size_t n) {
    unsigned char *p = (unsigned char *)malloc(n ? n : 1U);
    if (p == NULL) return -1;
    p[0] = (unsigned char)n;
    s01_sink ^= p[0];
    free(p);
    return 0;
}
""",
        ),
        SyntheticScenario(
            scenario_id="syn-02",
            source_name="unit_02.c",
            vulnerable_entry="p6_s02_a",
            protected_entry="p6_s02_b",
            source=r"""#include <stddef.h>
#include <string.h>

int p6_s02_a(const unsigned char *src, size_t n) {
    unsigned char local[16] = {0};
    memcpy(local, src, n);
    return (int)local[0];
}

int p6_s02_b(const unsigned char *src, size_t n) {
    unsigned char local[16] = {0};
    if (n > sizeof(local)) return -1;
    memcpy(local, src, n);
    return (int)local[0];
}
""",
        ),
        SyntheticScenario(
            scenario_id="syn-03",
            source_name="unit_03.c",
            vulnerable_entry="p6_s03_a",
            protected_entry="p6_s03_b",
            source=r"""#include <stddef.h>
#include <stdlib.h>

static volatile unsigned char s03_sink;

int p6_s03_a(size_t n) {
    unsigned char *p = (unsigned char *)calloc(n ? n : 1U, 1U);
    if (p == NULL) return -1;
    s03_sink ^= p[0];
    return 0;
}

void *p6_s03_b(size_t n) {
    return calloc(n ? n : 1U, 1U);
}
""",
        ),
        SyntheticScenario(
            scenario_id="syn-04",
            source_name="unit_04.c",
            vulnerable_entry="p6_s04_a",
            protected_entry="p6_s04_b",
            source=r"""#include <pthread.h>

static int s04_counter_a;
static int s04_counter_b;
static pthread_mutex_t s04_lock = PTHREAD_MUTEX_INITIALIZER;

static void *s04_worker_a(void *unused) {
    (void)unused;
    s04_counter_a++;
    return NULL;
}

static void *s04_worker_b(void *unused) {
    (void)unused;
    (void)pthread_mutex_lock(&s04_lock);
    s04_counter_b++;
    (void)pthread_mutex_unlock(&s04_lock);
    return NULL;
}

int p6_s04_a(void) {
    pthread_t first;
    pthread_t second;
    if (pthread_create(&first, NULL, s04_worker_a, NULL) != 0) return -1;
    if (pthread_create(&second, NULL, s04_worker_a, NULL) != 0) {
        (void)pthread_join(first, NULL);
        return -1;
    }
    (void)pthread_join(first, NULL);
    (void)pthread_join(second, NULL);
    return s04_counter_a;
}

int p6_s04_b(void) {
    pthread_t first;
    pthread_t second;
    if (pthread_create(&first, NULL, s04_worker_b, NULL) != 0) return -1;
    if (pthread_create(&second, NULL, s04_worker_b, NULL) != 0) {
        (void)pthread_join(first, NULL);
        return -1;
    }
    (void)pthread_join(first, NULL);
    (void)pthread_join(second, NULL);
    return s04_counter_b;
}
""",
        ),
        SyntheticScenario(
            scenario_id="syn-05",
            source_name="unit_05.c",
            vulnerable_entry="p6_s05_a",
            protected_entry="p6_s05_b",
            source=r"""#include <stddef.h>

int p6_s05_a(const int *values, size_t count, size_t index) {
    (void)count;
    return values[index];
}

int p6_s05_b(const int *values, size_t count, size_t index) {
    if (index >= count) return -1;
    return values[index];
}
""",
        ),
    )


def _entry_list(scenarios: Iterable[SyntheticScenario]) -> dict[str, Any]:
    functions: list[dict[str, str]] = []
    for scenario in scenarios:
        for function_name in (scenario.vulnerable_entry, scenario.protected_entry):
            functions.append(
                {
                    "function_name": function_name,
                    "file_path": scenario.source_name,
                }
            )
    return {"functions": functions}


def _header(scenarios: Iterable[SyntheticScenario]) -> str:
    declarations = {
        "p6_s01_a": "int p6_s01_a(size_t n);",
        "p6_s01_b": "int p6_s01_b(size_t n);",
        "p6_s02_a": "int p6_s02_a(const unsigned char *src, size_t n);",
        "p6_s02_b": "int p6_s02_b(const unsigned char *src, size_t n);",
        "p6_s03_a": "int p6_s03_a(size_t n);",
        "p6_s03_b": "void *p6_s03_b(size_t n);",
        "p6_s04_a": "int p6_s04_a(void);",
        "p6_s04_b": "int p6_s04_b(void);",
        "p6_s05_a": "int p6_s05_a(const int *values, size_t count, size_t index);",
        "p6_s05_b": "int p6_s05_b(const int *values, size_t count, size_t index);",
    }
    selected = {
        value
        for scenario in scenarios
        for value in (scenario.vulnerable_entry, scenario.protected_entry)
    }
    lines = ["#ifndef P6_SYNTHETIC_API_H", "#define P6_SYNTHETIC_API_H", "#include <stddef.h>"]
    lines.extend(declarations[name] for name in sorted(selected))
    lines.extend(["#endif", ""])
    return "\n".join(lines)


def _derived_runtime_config(
    raw: Mapping[str, Any],
    *,
    project_root: Path,
) -> dict[str, Any]:
    result = cast(dict[str, Any], json.loads(json.dumps(raw)))
    result["project"] = {
        "id": "p6-synthetic-replay",
        "root": str(project_root.resolve()),
        "source_root": ".",
        "language": "c_cpp",
        "compile_commands_path": "build/compile_commands.json",
        "include_paths": ["."],
        "exclude_paths": ["build", ".zscope_knowledge", ".zscope_snapshots"],
        "entry_functions_list": "entry_functions.json",
        "entry_discovery": {
            "enabled": False,
            "interface_files": ["api.h"],
            "max_entries": 10,
            "max_functions": 64,
        },
    }
    scan = result.setdefault("scan", {})
    scan["task"] = "Analyze security-relevant program behavior using supplied source and evidence."
    scan["depth"] = "balanced"
    scan["llm_profiles"] = {
        "modeling": "default",
        "analysis": "default",
        "validation": "default",
    }
    concurrency = result.setdefault("concurrency", {})
    for key in (
        "entry_workers",
        "validator_workers",
        "investigator_workers",
        "evidence_completion_workers",
        "index_workers",
        "svf_workers",
        "llm_max_inflight",
    ):
        concurrency[key] = REPLAY_MAX_INFLIGHT
    profile = result["llms"]["default"]
    profile["base_url_max_concurrent_requests"] = REPLAY_MAX_INFLIGHT
    profile["max_retries"] = REPLAY_MAX_TRANSPORT_RETRIES
    profile["retry_until_available"] = False
    return result


def materialize_replay_workspace(
    *,
    root: Path,
    source_config_path: Path,
) -> SyntheticReplayWorkspace:
    root = Path(root)
    source_config_path = Path(source_config_path)
    if not root.is_absolute() or not source_config_path.is_absolute():
        raise SyntheticReplayError("input", "input_binding_failure")
    if root.is_symlink() or (root.exists() and (not root.is_dir() or any(root.iterdir()))):
        raise SyntheticReplayError("input", "input_binding_failure")
    try:
        contract = require_p6_provider_contract(source_config_path)
    except Exception as exc:
        raise SyntheticReplayError("provider", "provider_identity_mismatch") from exc
    try:
        source_config_bytes = source_config_path.read_bytes()
        if _sha256_bytes(source_config_bytes) != contract.config_sha256:
            raise SyntheticReplayError("input", "input_binding_failure")
        raw = yaml.safe_load(source_config_bytes.decode("utf-8-sig"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise SyntheticReplayError("input", "input_binding_failure") from exc
    if not isinstance(raw, Mapping):
        raise SyntheticReplayError("input", "input_binding_failure")
    scenarios = synthetic_scenarios()
    project_root = root / "project"
    build_root = project_root / "build"
    project_root.mkdir(parents=True, exist_ok=False)
    build_root.mkdir()
    for scenario in scenarios:
        _write_text_lf(project_root / scenario.source_name, scenario.source)
    _write_text_lf(project_root / "api.h", _header(scenarios))
    _write_text_lf(
        project_root / "entry_functions.json",
        json.dumps(_entry_list(scenarios), ensure_ascii=False, sort_keys=True, indent=2) + "\n",
    )
    compile_commands = []
    for scenario in scenarios:
        source_path = (project_root / scenario.source_name).resolve()
        object_path = (build_root / (Path(scenario.source_name).stem + ".o")).resolve()
        compile_commands.append(
            {
                "directory": str(project_root.resolve()),
                "file": str(source_path),
                "arguments": [
                    "cc",
                    "-std=c11",
                    "-Werror",
                    "-Wall",
                    "-Wextra",
                    "-pthread",
                    "-I",
                    str(project_root.resolve()),
                    "-c",
                    str(source_path),
                    "-o",
                    str(object_path),
                ],
            }
        )
    _write_text_lf(
        build_root / "compile_commands.json",
        json.dumps(compile_commands, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
    )
    runtime = _derived_runtime_config(raw, project_root=project_root)
    # This is the last material boundary before any child can reach the model.
    assert_answer_free_payload(
        {
            "suite": [scenario.model_input() for scenario in scenarios],
            "runtime": runtime,
            "entry_list": _entry_list(scenarios),
        }
    )
    config_path = root / "replay.yaml"
    _write_text_lf(config_path, yaml.safe_dump(runtime, allow_unicode=True, sort_keys=False))
    try:
        runtime_contract = ProviderRuntimeContract.from_config_file(config_path)
    except Exception as exc:
        raise SyntheticReplayError("provider", "provider_identity_mismatch") from exc
    if (
        runtime_contract.base_url != contract.base_url
        or runtime_contract.model != contract.model
        or runtime_contract.response_model != contract.response_model
        or runtime_contract.required_environment_keys != contract.required_environment_keys
    ):
        raise SyntheticReplayError("provider", "provider_identity_mismatch")
    return SyntheticReplayWorkspace(
        root=root,
        project_root=project_root,
        config_path=config_path,
        report_path=project_root / "zscope_batch_report.json",
        usage_events_path_glob="llm_usage_events_*.jsonl",
        source_config_sha256=contract.config_sha256,
        runtime_config_sha256=_sha256_file(config_path),
        provider_contract=runtime_contract,
        scenarios=scenarios,
    )


def compile_synthetic_project(
    workspace: SyntheticReplayWorkspace,
    *,
    runner: Callable[..., subprocess.CompletedProcess[Any]] = subprocess.run,
) -> None:
    commands = _strict_json(workspace.project_root / "build" / "compile_commands.json")
    if not isinstance(commands, list) or len(commands) != len(workspace.scenarios):
        raise SyntheticReplayError("toolchain", "toolchain_preflight_failed")
    for row in commands:
        arguments = row.get("arguments") if isinstance(row, Mapping) else None
        if not isinstance(arguments, list) or not all(
            isinstance(value, str) for value in arguments
        ):
            raise SyntheticReplayError("toolchain", "toolchain_preflight_failed")
        result = runner(
            arguments,
            cwd=workspace.project_root,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if int(result.returncode) != 0:
            raise SyntheticReplayError("toolchain", "toolchain_preflight_failed")


def _scanner_command(workspace: SyntheticReplayWorkspace) -> list[str]:
    return [
        sys.executable,
        "-c",
        _SCANNER_BOOTSTRAP,
        "--config",
        str(workspace.config_path),
        "--scan-depth",
        "balanced",
        "--exit-policy",
        "confirmed",
        "--p6-pilot",
    ]


def execute_scanner(
    workspace: SyntheticReplayWorkspace,
    *,
    api_key: str,
    runner: Callable[..., subprocess.CompletedProcess[Any]] = subprocess.run,
) -> None:
    if not api_key:
        raise SyntheticReplayError("provider", "provider_credentials_unavailable")
    command = _scanner_command(workspace)
    runtime_payload = _strict_json(workspace.project_root / "entry_functions.json")
    source_payload = {
        scenario.source_name: (workspace.project_root / scenario.source_name).read_text(
            encoding="utf-8"
        )
        for scenario in workspace.scenarios
    }
    environment = dict(os.environ)
    try:
        reject_conflicting_provider_identity_environment(
            workspace.provider_contract,
            environment,
        )
    except Exception as exc:
        raise SyntheticReplayError("provider", "provider_identity_override_attempt") from exc
    environment.pop("Z_SCOPE_LLM_BASE_URL", None)
    environment.pop("Z_SCOPE_LLM_MODEL", None)
    environment[P6_API_KEY_ENVIRONMENT_KEY] = api_key
    # Keep this recursive check immediately adjacent to the only scanner
    # launch.  The credential is intentionally absent from the inspected and
    # persisted payload.
    assert_answer_free_payload(
        {
            "command": command,
            "provider": workspace.provider_contract.as_dict(),
            "runtime_config_sha256": workspace.runtime_config_sha256,
            "entries": runtime_payload,
            "sources": source_payload,
        }
    )
    completed = runner(
        command,
        cwd=workspace.root,
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if int(completed.returncode) not in {0, 1} or not workspace.report_path.is_file():
        raise SyntheticReplayError("scan", "internal_failure")


def _entry_matches(value: Any, symbol: str) -> bool:
    text = str(value or "")
    if text == symbol:
        return True
    return any(part == symbol for part in re.split(r"(?:::|\|)", text))


def _row_mentions_entry(row: Mapping[str, Any], symbol: str) -> bool:
    for key in (
        "analyzed_from",
        "reported_from_entry",
        "entry_identity",
        "entry_function",
        "entry_key",
        "function",
    ):
        if _entry_matches(row.get(key), symbol):
            return True
    issue = row.get("issue")
    return isinstance(issue, Mapping) and _row_mentions_entry(issue, symbol)


def _usage_events(workspace: SyntheticReplayWorkspace) -> tuple[Path, list[dict[str, Any]]]:
    roots = sorted(
        (workspace.project_root / ".zscope_snapshots").glob(workspace.usage_events_path_glob)
    )
    if len(roots) != 1:
        raise SyntheticReplayError("usage", "provider_usage_unverifiable")
    rows: list[dict[str, Any]] = []
    seen_sequences: set[int] = set()
    for line in roots[0].read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise SyntheticReplayError("usage", "provider_usage_unverifiable") from exc
        if not isinstance(value, dict):
            raise SyntheticReplayError("usage", "provider_usage_unverifiable")
        sequence = value.get("sequence")
        if (
            not isinstance(sequence, int)
            or isinstance(sequence, bool)
            or sequence in seen_sequences
        ):
            raise SyntheticReplayError("usage", "provider_usage_unverifiable")
        seen_sequences.add(sequence)
        rows.append(value)
    if not rows or sorted(seen_sequences) != list(range(1, len(rows) + 1)):
        raise SyntheticReplayError("usage", "provider_usage_unverifiable")
    return roots[0], rows


def _validate_usage(
    report: Mapping[str, Any],
    events: Sequence[Mapping[str, Any]],
    contract: ProviderRuntimeContract,
) -> dict[str, int]:
    summary = report.get("summary")
    llm_usage = summary.get("llm_usage") if isinstance(summary, Mapping) else None
    scan_usage = llm_usage.get("scan_token_usage") if isinstance(llm_usage, Mapping) else None
    attribution = scan_usage.get("usage_attribution") if isinstance(scan_usage, Mapping) else None
    totals = attribution.get("totals") if isinstance(attribution, Mapping) else None
    if not all(isinstance(value, Mapping) for value in (scan_usage, attribution, totals)):
        raise SyntheticReplayError("usage", "provider_usage_unverifiable")
    assert isinstance(scan_usage, Mapping)
    assert isinstance(totals, Mapping)
    if (
        scan_usage.get("depth") != "balanced"
        or scan_usage.get("telemetry_complete") is not True
        or int(scan_usage.get("active_reservation_count") or 0) != 0
        or int(scan_usage.get("reserved_tokens") or 0) != 0
        or int(totals.get("request_count") or 0) != len(events)
        or int(totals.get("successful_calls") or 0) != len(events)
        or int(totals.get("provider_reported_calls") or 0) != len(events)
        or int(totals.get("estimated_or_conservative_calls") or 0) != 0
        or int(totals.get("failed_or_unknown_calls") or 0) != 0
        or int(totals.get("budget_violation_count") or 0) != 0
    ):
        raise SyntheticReplayError("usage", "accounting_conservation_failure")
    prompt_total = 0
    completion_total = 0
    token_total = 0
    by_cluster_retry: dict[str, int] = {}
    by_cluster_regeneration: dict[str, int] = {}
    for event in events:
        requested = event.get("requested_model")
        response = event.get("provider_response_model")
        if requested != contract.model or not contract.accepts_response_model(response):
            raise SyntheticReplayError("provider", "provider_identity_mismatch")
        prompt = event.get("prompt_tokens")
        completion = event.get("completion_tokens")
        total = event.get("total_tokens")
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in (prompt, completion, total)
        ):
            raise SyntheticReplayError("usage", "provider_usage_unverifiable")
        prompt_tokens = cast(int, prompt)
        completion_tokens = cast(int, completion)
        total_tokens = cast(int, total)
        if (
            total_tokens != prompt_tokens + completion_tokens
            or event.get("provider_reported") is not True
        ):
            raise SyntheticReplayError("usage", "accounting_conservation_failure")
        if event.get("outcome") != "success" or event.get("conservative_charge") is not False:
            raise SyntheticReplayError("usage", "accounting_conservation_failure")
        cluster = str(event.get("validation_cluster_uid") or event.get("candidate_uid") or "")
        if event.get("retry") is True:
            by_cluster_retry[cluster] = by_cluster_retry.get(cluster, 0) + 1
        if str(event.get("call_kind") or "") == "contract_regeneration":
            by_cluster_regeneration[cluster] = by_cluster_regeneration.get(cluster, 0) + 1
        prompt_total += prompt_tokens
        completion_total += completion_tokens
        token_total += total_tokens
    if any(value > REPLAY_MAX_TRANSPORT_RETRIES for value in by_cluster_retry.values()):
        raise SyntheticReplayError("provider", "provider_transport_exhausted")
    if any(value > REPLAY_MAX_CONTRACT_REGENERATIONS for value in by_cluster_regeneration.values()):
        raise SyntheticReplayError("provider", "provider_protocol_incompatible")
    if (
        int(totals.get("prompt_tokens") or 0) != prompt_total
        or int(totals.get("completion_tokens") or 0) != completion_total
        or int(totals.get("total_tokens") or 0) != token_total
    ):
        raise SyntheticReplayError("usage", "accounting_conservation_failure")
    return {
        "physical_call_count": len(events),
        "prompt_tokens": prompt_total,
        "completion_tokens": completion_total,
        "total_tokens": token_total,
        "transport_retry_count": sum(by_cluster_retry.values()),
        "contract_regeneration_count": sum(by_cluster_regeneration.values()),
        "tool_call_count": sum(int(event.get("tool_call_count") or 0) for event in events),
    }


def _validate_report_conservation(
    workspace: SyntheticReplayWorkspace,
    report: Mapping[str, Any],
    events: Sequence[Mapping[str, Any]],
    usage: Mapping[str, int],
) -> tuple[dict[str, Any], Path]:
    summary = report.get("summary")
    run_manifest = report.get("run_manifest")
    issues = report.get("issues")
    terminal_states = report.get("candidate_terminal_states")
    if (
        not isinstance(summary, Mapping)
        or not isinstance(run_manifest, Mapping)
        or not isinstance(issues, list)
        or not isinstance(terminal_states, list)
    ):
        raise SyntheticReplayError("conservation", "accounting_conservation_failure")
    invariant = run_manifest.get("report_invariant_status")
    decision_trace = run_manifest.get("decision_trace")
    if (
        run_manifest.get("validation_queue_drained") is not True
        or not isinstance(invariant, Mapping)
        or invariant.get("valid") is not True
        or not isinstance(decision_trace, Mapping)
        or decision_trace.get("complete") is not True
        or decision_trace.get("errors") not in ([], ())
    ):
        raise SyntheticReplayError("conservation", "accounting_conservation_failure")
    manifest_path = Path(str(decision_trace.get("manifest_path") or ""))
    if not manifest_path.is_absolute():
        manifest_path = workspace.project_root / manifest_path
    try:
        resolved_manifest = manifest_path.resolve(strict=True)
        resolved_project = workspace.project_root.resolve(strict=True)
    except OSError as exc:
        raise SyntheticReplayError("conservation", "accounting_conservation_failure") from exc
    if (
        resolved_project not in resolved_manifest.parents
        or resolved_manifest.is_symlink()
        or not resolved_manifest.is_file()
    ):
        raise SyntheticReplayError("conservation", "accounting_conservation_failure")
    try:
        trace_manifest = _strict_json(resolved_manifest)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise SyntheticReplayError("conservation", "accounting_conservation_failure") from exc
    if not isinstance(trace_manifest, Mapping):
        raise SyntheticReplayError("conservation", "accounting_conservation_failure")
    trace_binding = trace_manifest.get("llm_usage_events")
    if (
        trace_manifest.get("complete") is not True
        or trace_manifest.get("errors") not in ([], ())
        or not isinstance(trace_binding, Mapping)
        or trace_binding.get("available") is not True
        or trace_binding.get("conservation_valid") is not True
        or trace_binding.get("provider_usage_coverage") != 1.0
        or trace_binding.get("missing_call_ids") not in ([], ())
        or trace_binding.get("unreferenced_call_ids") not in ([], ())
        or trace_binding.get("duplicate_call_ids") not in ([], ())
    ):
        raise SyntheticReplayError("conservation", "accounting_conservation_failure")
    bound_manifest_sha = str(decision_trace.get("manifest_sha256") or "")
    if bound_manifest_sha and bound_manifest_sha != str(
        trace_manifest.get("manifest_sha256") or ""
    ):
        raise SyntheticReplayError("conservation", "accounting_conservation_failure")
    event_count = len(events)
    token_total = int(usage["total_tokens"])
    tool_total = int(usage["tool_call_count"])
    summary_usage = summary.get("llm_usage")
    scan_usage = (
        summary_usage.get("scan_token_usage") if isinstance(summary_usage, Mapping) else None
    )
    attribution = scan_usage.get("usage_attribution") if isinstance(scan_usage, Mapping) else None
    totals = attribution.get("totals") if isinstance(attribution, Mapping) else None
    if not isinstance(totals, Mapping):
        raise SyntheticReplayError("conservation", "accounting_conservation_failure")
    dimensions = {
        "call": (event_count, int(totals.get("request_count") or 0)),
        "token": (token_total, int(trace_binding.get("usage_token_total") or 0)),
        "tool": (tool_total, int(totals.get("tool_call_count") or 0)),
        "trace": (event_count, int(trace_binding.get("referenced_call_count") or 0)),
        "finding": (len(issues), int(summary.get("total_issues") or 0)),
        "terminal": (
            len(terminal_states),
            int(run_manifest.get("terminal_outcome_count") or 0),
        ),
    }
    if (
        int(trace_binding.get("event_count") or 0) != event_count
        or int(trace_binding.get("trace_token_total") or 0) != token_total
        or any(numerator != denominator for numerator, denominator in dimensions.values())
    ):
        raise SyntheticReplayError("conservation", "accounting_conservation_failure")
    return (
        {
            name: {
                "numerator": numerator,
                "denominator": denominator,
                "conserved": True,
            }
            for name, (numerator, denominator) in dimensions.items()
        },
        resolved_manifest,
    )


def _complete_v4_confirmation(row: Mapping[str, Any]) -> bool:
    issue = row.get("issue") if isinstance(row.get("issue"), Mapping) else row
    assert isinstance(issue, Mapping)
    certificate = issue.get("proof_kernel_promotion_certificate")
    closure = issue.get("proof_kernel_closure_evaluation")
    authority = issue.get("terminal_authority_decision")
    if not isinstance(authority, Mapping):
        authority = issue.get("proof_kernel_terminal_authority_decision")
    return bool(
        isinstance(certificate, Mapping)
        and certificate.get("schema_version") == PROMOTION_CERTIFICATE_VERSION
        and certificate.get("disposition") == "confirmed"
        and certificate.get("integrity_status") == "verified"
        and isinstance(closure, Mapping)
        and closure.get("complete") is True
        and closure.get("disposition") == "confirmed"
        and isinstance(authority, Mapping)
        and authority.get("schema_version") == TERMINAL_AUTHORITY_DECISION_V4
        and authority.get("terminal") is True
        and authority.get("disposition") == "confirmed"
    )


def validate_replay_report(
    workspace: SyntheticReplayWorkspace,
) -> dict[str, Any]:
    try:
        report = _strict_json(workspace.report_path)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise SyntheticReplayError("scan", "internal_failure") from exc
    if not isinstance(report, Mapping):
        raise SyntheticReplayError("scan", "internal_failure")
    summary = report.get("summary")
    terminal_states = report.get("candidate_terminal_states")
    functions = report.get("function_results")
    if (
        not isinstance(summary, Mapping)
        or not isinstance(terminal_states, list)
        or not isinstance(functions, list)
        or int(summary.get("functions_failed") or 0) != 0
        or int(summary.get("functions_completed") or 0) != len(workspace.scenarios) * 2
    ):
        raise SyntheticReplayError("scan", "anonymous_qualification_failed")
    for state in terminal_states:
        if not isinstance(state, Mapping):
            raise SyntheticReplayError("scan", "terminal_state_inconsistent")
        if state.get("candidate_disposition") == "confirmed" and not _complete_v4_confirmation(
            state
        ):
            raise SyntheticReplayError("proof", "terminal_state_inconsistent")
    scenario_rows: list[dict[str, Any]] = []
    for scenario in workspace.scenarios:
        vulnerable_scanned = any(
            isinstance(row, Mapping)
            and _entry_matches(row.get("function"), scenario.vulnerable_entry)
            and not row.get("error")
            for row in functions
        )
        protected_scanned = any(
            isinstance(row, Mapping)
            and _entry_matches(row.get("function"), scenario.protected_entry)
            and not row.get("error")
            for row in functions
        )
        vulnerable_confirmed = [
            row
            for row in terminal_states
            if isinstance(row, Mapping)
            and row.get("candidate_disposition") == "confirmed"
            and _row_mentions_entry(row, scenario.vulnerable_entry)
        ]
        protected_confirmed = [
            row
            for row in terminal_states
            if isinstance(row, Mapping)
            and row.get("candidate_disposition") == "confirmed"
            and _row_mentions_entry(row, scenario.protected_entry)
        ]
        passed = bool(
            vulnerable_scanned
            and protected_scanned
            and vulnerable_confirmed
            and not protected_confirmed
        )
        scenario_rows.append(
            {
                "scenario_id": scenario.scenario_id,
                "entries_scanned": int(vulnerable_scanned) + int(protected_scanned),
                "vulnerable_confirmation_count": len(vulnerable_confirmed),
                "protected_confirmation_count": len(protected_confirmed),
                "passed": passed,
            }
        )
    failed_count = sum(1 for row in scenario_rows if row["passed"] is not True)
    if failed_count:
        raise SyntheticReplayError("semantic", "anonymous_qualification_failed", failed_count)
    usage_path, events = _usage_events(workspace)
    usage = _validate_usage(report, events, workspace.provider_contract)
    conservation, trace_manifest_path = _validate_report_conservation(
        workspace,
        report,
        events,
        usage,
    )
    usage_result: dict[str, Any] = {**usage, "conservation": conservation}
    result = {
        "schema_version": REPLAY_SCHEMA_VERSION,
        "suite_version": REPLAY_SUITE_VERSION,
        "passed": True,
        "formal_evidence": False,
        "release_eligible": False,
        "provider": {
            "base_url": P6_PROVIDER_BASE_URL,
            "model": P6_PROVIDER_MODEL,
            "identity_sha256": workspace.provider_contract.identity_sha256,
        },
        "runtime": {
            "llm_max_inflight": REPLAY_MAX_INFLIGHT,
            "base_url_max_concurrent_requests": REPLAY_MAX_INFLIGHT,
            "max_transport_retries": REPLAY_MAX_TRANSPORT_RETRIES,
            "max_contract_regenerations": REPLAY_MAX_CONTRACT_REGENERATIONS,
            "source_config_sha256": workspace.source_config_sha256,
            "runtime_config_sha256": workspace.runtime_config_sha256,
        },
        "scenario_count": len(scenario_rows),
        "scenarios": scenario_rows,
        "usage": usage_result,
        "bindings": {
            "report_sha256": _sha256_file(workspace.report_path),
            "usage_events_sha256": _sha256_file(usage_path),
            "decision_trace_manifest_sha256": _sha256_file(trace_manifest_path),
            "scenario_suite_sha256": _canonical_sha256(
                [scenario.model_input() for scenario in workspace.scenarios]
            ),
        },
        "failure": None,
    }
    assert_answer_free_payload(result)
    return result


def run_synthetic_replay(
    *,
    source_config_path: Path,
    api_key_file: Path,
    work_root: Path,
    compile_runner: Callable[..., subprocess.CompletedProcess[Any]] = subprocess.run,
    scan_runner: Callable[..., subprocess.CompletedProcess[Any]] = subprocess.run,
) -> dict[str, Any]:
    if not sys.platform.startswith("linux"):
        raise SyntheticReplayError("toolchain", "toolchain_preflight_failed")
    if not Path(api_key_file).is_absolute():
        raise SyntheticReplayError("provider", "provider_credentials_unavailable")
    try:
        credential = load_explicit_api_key_file(Path(api_key_file))
    except Exception as exc:
        raise SyntheticReplayError("provider", "provider_credentials_unavailable") from exc
    workspace = materialize_replay_workspace(
        root=Path(work_root),
        source_config_path=Path(source_config_path),
    )
    compile_synthetic_project(workspace, runner=compile_runner)
    execute_scanner(
        workspace,
        api_key=credential[P6_API_KEY_ENVIRONMENT_KEY],
        runner=scan_runner,
    )
    return validate_replay_report(workspace)


def failure_result(error: SyntheticReplayError) -> dict[str, Any]:
    return {
        "schema_version": REPLAY_SCHEMA_VERSION,
        "suite_version": REPLAY_SUITE_VERSION,
        "passed": False,
        "formal_evidence": False,
        "release_eligible": False,
        "scenario_count": len(synthetic_scenarios()),
        "failure": {
            "stage": error.stage,
            "failure_class": error.failure_class,
            "failure_count": error.count,
        },
    }


__all__ = [
    "REPLAY_MAX_CONTRACT_REGENERATIONS",
    "REPLAY_MAX_INFLIGHT",
    "REPLAY_MAX_TRANSPORT_RETRIES",
    "REPLAY_SCHEMA_VERSION",
    "REPLAY_SUITE_VERSION",
    "SyntheticReplayError",
    "SyntheticReplayWorkspace",
    "assert_answer_free_payload",
    "compile_synthetic_project",
    "execute_scanner",
    "failure_result",
    "install_replay_call_guards",
    "materialize_replay_workspace",
    "run_synthetic_replay",
    "synthetic_scenarios",
    "validate_replay_report",
]
