"""Answer-free P6 single-point replay over open synthetic C programs.

The replay is deliberately separate from the benchmark producer.  It creates a
small public C project, runs the ordinary balanced scanner with one model call
in flight, and checks only source-independent protocol invariants.  Neither the
result projection nor a failure diagnostic retains source, prompts, provider
responses, or process output.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import shutil
import stat
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
from zscope.core.validation.authority import (
    TERMINAL_AUTHORITY_DECISION_V4,
    TerminalAuthorityEvaluator,
)
from zscope.core.validation.function_ir import FunctionIRGraph, graph_from_mapping
from zscope.core.validation.proof_kernel.models import function_summary_from_graph
from zscope.core.validation.proof_kernel.registry import qualified_race_options
from zscope.core.validation.proof_kernel.registry import (
    function_ir_compound_wrappers,
    qualified_bounds_options,
    qualified_resource_leak_options,
)
from zscope.retrieval.clang_tooling_evidence import ClangToolingEvidenceProvider
from zscope.orchestration.decision_trace import (
    verify_coverage_trace,
    verify_decision_trace,
)
from zscope.orchestration.candidate_envelope import (
    occurrence_uid_for,
    validation_cluster_uid_for,
)


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
    proof_family: str
    subject_uid: str
    source_callee: str = ""
    sink_callee: str = ""
    creator_function_uid: str = ""
    worker_function_uids: tuple[str, ...] = ()

    def model_input(self) -> dict[str, Any]:
        """Return exactly the material made available to the scanner."""

        return {
            "scenario_id": self.scenario_id,
            "source_name": self.source_name,
            "source": self.source,
            "entries": [self.vulnerable_entry, self.protected_entry],
        }

    def proof_contract(self) -> dict[str, Any]:
        """Return the public, answer-free post-scan proof binding.

        This contract is deliberately not materialized in the scanner project
        or prompt.  It is derived from the open synthetic source and used only
        after the report has frozen, so a generic sealed proof cannot stand in
        for the scenario-specific resource, bounds, or race obligation.
        """

        return {
            "scenario_id": self.scenario_id,
            "source_name": self.source_name,
            "proof_family": self.proof_family,
            "subject_uid": self.subject_uid,
            "source_callee": self.source_callee,
            "sink_callee": self.sink_callee,
            "creator_function_uid": self.creator_function_uid,
            "worker_function_uids": list(self.worker_function_uids),
            "source_sha256": _sha256_bytes(self.source.encode("utf-8")),
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


def _strict_json_text(value: str) -> Any:
    def reject_duplicates(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def reject_nonfinite(_value: str) -> Any:
        raise ValueError("non-finite JSON number")

    return json.loads(
        value,
        object_pairs_hook=reject_duplicates,
        parse_constant=reject_nonfinite,
    )


def _strict_json(path: Path) -> Any:
    return _strict_json_text(Path(path).read_text(encoding="utf-8"))


def _has_lexical_link_component(path: Path) -> bool:
    """Return true when any existing lexical component is a link.

    Calling ``resolve()`` first erases the only evidence that a manifest or
    content-addressed object was reached through a symlink.  Walk the supplied
    spelling before resolution so a link at the file, directory, or trace-root
    level fails closed.
    """

    try:
        absolute = Path(path).absolute()
        cursor = Path(absolute.anchor)
        for component in absolute.parts[1:]:
            cursor = cursor / component
            mode = cursor.lstat().st_mode
            if stat.S_ISLNK(mode) or cursor.is_symlink():
                return True
    except (OSError, ValueError):
        return True
    return False


def _regular_file_under(root: Path, path: Path) -> Path | None:
    """Resolve one lexically link-free regular file below ``root``."""

    raw_root = Path(root)
    raw_path = Path(path)
    if _has_lexical_link_component(raw_root) or _has_lexical_link_component(raw_path):
        return None
    try:
        resolved_root = raw_root.resolve(strict=True)
        resolved_path = raw_path.resolve(strict=True)
    except (OSError, ValueError):
        return None
    if (
        resolved_path == resolved_root
        or resolved_root not in resolved_path.parents
        or not resolved_path.is_file()
        or _has_lexical_link_component(resolved_path)
    ):
        return None
    return resolved_path


# A replay validator process starts with an empty cache, so every real report
# causes Clang to execute.  The cache only avoids hundreds of identical Clang
# subprocesses in one focused test process.  It is keyed by source bytes,
# function, executable identity, and a path-normalized compile contract.  A
# changed source or command therefore cannot reuse an earlier extraction.
_CLANG_SUMMARY_CACHE_LOCK = threading.Lock()
_CLANG_SUMMARY_CACHE: dict[tuple[str, str, str, str], tuple[dict[str, Any], dict[str, Any]]] = {}


def _clang_executable() -> str:
    if shutil.which("clang"):
        return "clang"
    for version in range(22, 9, -1):
        candidate = f"clang-{version}"
        if shutil.which(candidate):
            return candidate
    return ""


def _normalized_clang_contract(
    evidence: Mapping[str, Any],
    *,
    workspace: SyntheticReplayWorkspace,
    source_path: Path,
) -> str:
    replacements = (
        (str(workspace.project_root.resolve()), "<PROJECT>"),
        (workspace.project_root.resolve().as_posix(), "<PROJECT>"),
        (str(source_path.resolve()), "<SOURCE>"),
        (source_path.resolve().as_posix(), "<SOURCE>"),
    )

    def normalize(value: Any) -> Any:
        if isinstance(value, Mapping):
            return {str(key): normalize(child) for key, child in value.items()}
        if isinstance(value, (list, tuple)):
            return [normalize(child) for child in value]
        if not isinstance(value, str):
            return value
        result = value
        for old, new in replacements:
            if old:
                result = result.replace(old, new)
        return result

    return _canonical_sha256(
        {
            "clang_path": evidence.get("clang_path"),
            "ast_dump_command": normalize(evidence.get("ast_dump_command")),
            "cfg_dump_command": normalize(evidence.get("cfg_dump_command")),
        }
    )


def _extract_scenario_function_graph(
    workspace: SyntheticReplayWorkspace,
    scenario: SyntheticScenario,
    function: str,
    *,
    graph_file: str = "",
) -> FunctionIRGraph | None:
    """Re-extract one scenario function through the real Clang provider.

    The sealed FunctionSummary is never treated as an AST/CFG authority.  This
    helper executes the same product provider against the materialized compile
    database and reconstructs FunctionIR from the resulting typed AST and real
    CFG summaries.  Tests intentionally use this helper too, so their success
    proofs cannot be assembled from hand-authored pseudo IR.
    """

    if function not in {
        scenario.vulnerable_entry,
        scenario.protected_entry,
        scenario.creator_function_uid,
        *scenario.worker_function_uids,
    }:
        return None
    expected_source = workspace.project_root / scenario.source_name
    source_path = _regular_file_under(workspace.project_root, expected_source)
    if source_path is None:
        return None
    source_sha256 = _sha256_file(source_path)
    if source_sha256 != _sha256_bytes(scenario.source.encode("utf-8")):
        return None
    compile_commands = _regular_file_under(
        workspace.project_root,
        workspace.project_root / "build" / "compile_commands.json",
    )
    clang_path = _clang_executable()
    if compile_commands is None or not clang_path:
        return None
    prepared_provider = ClangToolingEvidenceProvider(
        compile_commands,
        clang_path=clang_path,
        execute=False,
    )
    prepared = prepared_provider.collect_for_function(
        func_name=function,
        file_path=str(source_path),
    )
    if prepared.get("status") != "command_prepared_not_executed":
        return None
    command_sha256 = _normalized_clang_contract(
        prepared,
        workspace=workspace,
        source_path=source_path,
    )
    cache_key = (source_sha256, function, clang_path, command_sha256)
    with _CLANG_SUMMARY_CACHE_LOCK:
        cached = _CLANG_SUMMARY_CACHE.get(cache_key)
        if cached is None:
            executed_provider = ClangToolingEvidenceProvider(
                compile_commands,
                clang_path=clang_path,
                execute=True,
            )
            executed = executed_provider.collect_for_function(
                func_name=function,
                file_path=str(source_path),
            )
            ast_dump = executed.get("ast_dump")
            cfg_dump = executed.get("cfg_dump")
            if (
                executed.get("status") != "executed"
                or not isinstance(ast_dump, Mapping)
                or not isinstance(cfg_dump, Mapping)
                or ast_dump.get("ok") is not True
                or cfg_dump.get("ok") is not True
                or executed.get("code_snapshot_sha256") != source_sha256
            ):
                return None
            cached = (copy.deepcopy(dict(ast_dump)), copy.deepcopy(dict(cfg_dump)))
            _CLANG_SUMMARY_CACHE[cache_key] = cached
        ast_dump, cfg_dump = copy.deepcopy(cached)
    evidence = dict(prepared)
    evidence.update(
        {
            "status": "executed",
            "execution_enabled": True,
            "code_snapshot_sha256": source_sha256,
            "resolved_source_file": str(source_path),
            "ast_dump": ast_dump,
            "cfg_dump": cfg_dump,
        }
    )
    persisted_file = graph_file or str(source_path)
    try:
        graph = FunctionIRGraph.from_clang_evidence(
            evidence,
            function=function,
            file=persisted_file,
        )
    except (TypeError, ValueError):
        return None
    if (
        graph is None
        or not graph.coverage_complete
        or graph.unresolved_dynamic_edges
        or not graph.ast_value_coverage_complete
        or graph.code_snapshot_sha256 != source_sha256
        or not re.fullmatch(r"[0-9a-f]{64}", graph.backend_sha256)
        or not re.fullmatch(r"[0-9a-f]{64}", graph.ir_sha256)
    ):
        return None
    return graph


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
            proof_family="leak",
            subject_uid="p",
            source_callee="malloc",
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
            proof_family="bounds",
            subject_uid="received",
            source_callee="recv",
            sink_callee="memcpy",
            source=r"""#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

int p6_s02_a(int fd, unsigned char *dst) {
    unsigned char received_bytes[64] = {0};
    ssize_t received = recv(fd, received_bytes, sizeof(received_bytes), 0);
    memcpy(dst, received_bytes, received);
    return 0;
}

int p6_s02_b(int fd, unsigned char *dst, size_t dst_capacity) {
    unsigned char received_bytes[64] = {0};
    ssize_t received = recv(fd, received_bytes, sizeof(received_bytes), 0);
    if (received < 0 || (size_t)received > dst_capacity) return -1;
    memcpy(dst, received_bytes, received);
    return 0;
}
""",
        ),
        SyntheticScenario(
            scenario_id="syn-03",
            source_name="unit_03.c",
            vulnerable_entry="p6_s03_a",
            protected_entry="p6_s03_b",
            proof_family="leak",
            subject_uid="p",
            source_callee="calloc",
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
            proof_family="race",
            subject_uid="g_s04_counter_a",
            source_callee="pthread_create",
            creator_function_uid="p6_s04_a",
            worker_function_uids=("s04_worker_a_left", "s04_worker_a_right"),
            source=r"""#include <pthread.h>

static int g_s04_counter_a;
static int g_s04_counter_b;
static pthread_mutex_t s04_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t s04_thread_a_left;
static pthread_t s04_thread_a_right;
static pthread_t s04_thread_b_left;
static pthread_t s04_thread_b_right;

static void *s04_worker_a_left(void *unused) {
    g_s04_counter_a++;
    return unused;
}

static void *s04_worker_a_right(void *unused) {
    g_s04_counter_a++;
    return unused;
}

static void *s04_worker_b_left(void *unused) {
    pthread_mutex_lock(&s04_lock);
    g_s04_counter_b++;
    pthread_mutex_unlock(&s04_lock);
    return unused;
}

static void *s04_worker_b_right(void *unused) {
    pthread_mutex_lock(&s04_lock);
    g_s04_counter_b++;
    pthread_mutex_unlock(&s04_lock);
    return unused;
}

int p6_s04_a(void) {
    pthread_create(&s04_thread_a_left, NULL, s04_worker_a_left, NULL);
    pthread_create(&s04_thread_a_right, NULL, s04_worker_a_right, NULL);
    return 0;
}

int p6_s04_b(void) {
    pthread_create(&s04_thread_b_left, NULL, s04_worker_b_left, NULL);
    pthread_create(&s04_thread_b_right, NULL, s04_worker_b_right, NULL);
    return 0;
}
""",
        ),
        SyntheticScenario(
            scenario_id="syn-05",
            source_name="unit_05.c",
            vulnerable_entry="p6_s05_a",
            protected_entry="p6_s05_b",
            proof_family="bounds",
            subject_uid="received",
            source_callee="read",
            sink_callee="write",
            source=r"""#include <stddef.h>
#include <sys/types.h>
#include <unistd.h>

int p6_s05_a(int input_fd, int output_fd) {
    unsigned char buffer[64] = {0};
    ssize_t received = read(input_fd, buffer, sizeof(buffer));
    write(output_fd, buffer, received);
    return 0;
}

int p6_s05_b(int input_fd, int output_fd) {
    unsigned char buffer[64] = {0};
    ssize_t received = read(input_fd, buffer, sizeof(buffer));
    if (received < 0) return -1;
    write(output_fd, buffer, received);
    return 0;
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
        "p6_s02_a": "int p6_s02_a(int fd, unsigned char *dst);",
        "p6_s02_b": "int p6_s02_b(int fd, unsigned char *dst, size_t dst_capacity);",
        "p6_s03_a": "int p6_s03_a(size_t n);",
        "p6_s03_b": "void *p6_s03_b(size_t n);",
        "p6_s04_a": "int p6_s04_a(void);",
        "p6_s04_b": "int p6_s04_b(void);",
        "p6_s05_a": "int p6_s05_a(int input_fd, int output_fd);",
        "p6_s05_b": "int p6_s05_b(int input_fd, int output_fd);",
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
    """Match one symbol against a name or canonical callable identity.

    Canonical entry identities include a portable path and, when available,
    the complete source signature.  Matching an arbitrary substring is unsafe:
    ``parse`` must not inherit an occurrence belonging to ``parse_header``.
    Accept only an exact identity component or an exact callable token followed
    by ``(``.
    """

    text = " ".join(str(value or "").strip().split())
    symbol = str(symbol or "").strip()
    if not text or not symbol:
        return False
    if text == symbol:
        return True
    components = [part.strip() for part in re.split(r"(?:::|\|)", text)]
    if symbol in components:
        return True
    callable_pattern = re.compile(
        rf"(?<![A-Za-z0-9_$]){re.escape(symbol)}\s*\(",
    )
    return any(callable_pattern.search(part) is not None for part in components)


def _path_entry_values(value: Any) -> Iterable[Any]:
    """Yield only the entry endpoint from canonical call/entry paths."""

    if not isinstance(value, (list, tuple)):
        return
    for path in value:
        if isinstance(path, (list, tuple)) and path:
            yield path[0]
        elif isinstance(path, Mapping):
            for key in (
                "entry_identity",
                "reported_from_entry",
                "entry_function",
                "entry_key",
                "function",
            ):
                if key in path:
                    yield path.get(key)


def _row_entry_values(row: Mapping[str, Any]) -> Iterable[Any]:
    """Yield the explicitly attributed entries carried by one report row."""

    for key in (
        "analyzed_from",
        "reported_from_entry",
        "entry_identity",
        "entry_function",
        "entry_key",
        "function",
    ):
        if key in row:
            yield row.get(key)

    entries = row.get("entries")
    if isinstance(entries, (list, tuple)):
        for entry in entries:
            if isinstance(entry, Mapping):
                yield from _row_entry_values(entry)
            else:
                yield entry

    for key in ("entry_paths", "call_paths"):
        yield from _path_entry_values(row.get(key))

    occurrences = row.get("occurrences")
    if isinstance(occurrences, (list, tuple)):
        for occurrence in occurrences:
            if isinstance(occurrence, Mapping):
                yield from _row_entry_values(occurrence)


def _row_mentions_entry(row: Mapping[str, Any], symbol: str) -> bool:
    binding = _validated_occurrence_binding(row)
    if binding is None:
        return False
    return any(_entry_matches(value, symbol) for value in binding.entries)


def _usage_events(workspace: SyntheticReplayWorkspace) -> tuple[Path, list[dict[str, Any]]]:
    roots = sorted(
        (workspace.project_root / ".zscope_snapshots").glob(workspace.usage_events_path_glob)
    )
    if len(roots) != 1:
        raise SyntheticReplayError("usage", "provider_usage_unverifiable")
    usage_path = _regular_file_under(workspace.project_root, roots[0])
    if usage_path is None:
        raise SyntheticReplayError("usage", "provider_usage_unverifiable")
    rows: list[dict[str, Any]] = []
    seen_sequences: set[int] = set()
    for line in usage_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            value = _strict_json_text(line)
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
    return usage_path, rows


_USAGE_EVENT_KEYS = frozenset(
    {
        "schema_version",
        "sequence",
        "call_id",
        "reservation_id",
        "agent",
        "stage",
        "candidate_uid",
        "audit_unit_uid",
        "validation_cluster_uid",
        "llm_ref",
        "call_kind",
        "outcome",
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "reserved_total_tokens",
        "provider_reported",
        "conservative_charge",
        "budget_violation",
        "attribution",
        "budget_stage",
        "model",
        "requested_model",
        "provider_response_model",
        "call_chain_id",
        "attempt_index",
        "logical_operation_id",
        "reason",
        "finish_reason",
        "cached_prompt_tokens",
        "reasoning_tokens",
        "retry",
        "repair",
        "tool_call_count",
        "new_fact_count",
        "duration_ms",
    }
)
_USAGE_ATTRIBUTION_KEYS = frozenset(
    {
        "schema_version",
        "stage",
        "agent",
        "skill",
        "entry_identity",
        "audit_unit_uid",
        "candidate_uid",
        "finding_uid",
        "validation_cluster_uid",
        "llm_ref",
        "call_kind",
    }
)
_USAGE_STRING_FIELDS = frozenset(
    {
        "call_id",
        "reservation_id",
        "agent",
        "stage",
        "candidate_uid",
        "audit_unit_uid",
        "validation_cluster_uid",
        "llm_ref",
        "call_kind",
        "outcome",
        "budget_stage",
        "model",
        "requested_model",
        "provider_response_model",
        "call_chain_id",
        "logical_operation_id",
        "reason",
        "finish_reason",
    }
)
_USAGE_INTEGER_FIELDS = frozenset(
    {
        "sequence",
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "reserved_total_tokens",
        "attempt_index",
        "cached_prompt_tokens",
        "reasoning_tokens",
        "tool_call_count",
        "new_fact_count",
        "duration_ms",
    }
)
_USAGE_BOOLEAN_FIELDS = frozenset(
    {
        "provider_reported",
        "conservative_charge",
        "budget_violation",
        "retry",
        "repair",
    }
)


def _strict_nonnegative_integer(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return cast(int, value)


def _strict_usage_event(event: Mapping[str, Any]) -> None:
    if (
        set(event) != _USAGE_EVENT_KEYS
        or event.get("schema_version") != "zscope.llm-usage-event.v3"
    ):
        raise SyntheticReplayError("usage", "provider_usage_unverifiable")
    if any(not isinstance(event.get(field), str) for field in _USAGE_STRING_FIELDS):
        raise SyntheticReplayError("usage", "provider_usage_unverifiable")
    if any(
        _strict_nonnegative_integer(event.get(field)) is None for field in _USAGE_INTEGER_FIELDS
    ):
        raise SyntheticReplayError("usage", "provider_usage_unverifiable")
    if any(not isinstance(event.get(field), bool) for field in _USAGE_BOOLEAN_FIELDS):
        raise SyntheticReplayError("usage", "provider_usage_unverifiable")
    attribution = event.get("attribution")
    if (
        not isinstance(attribution, Mapping)
        or set(attribution) != _USAGE_ATTRIBUTION_KEYS
        or attribution.get("schema_version") != "zscope.llm-usage-attribution.v1"
        or any(not isinstance(value, str) for value in attribution.values())
    ):
        raise SyntheticReplayError("usage", "provider_usage_unverifiable")
    mirrored = {
        "agent": "agent",
        "candidate_uid": "candidate_uid",
        "audit_unit_uid": "audit_unit_uid",
        "validation_cluster_uid": "validation_cluster_uid",
        "llm_ref": "llm_ref",
        "call_kind": "call_kind",
    }
    if any(event.get(outer) != attribution.get(inner) for outer, inner in mirrored.items()):
        raise SyntheticReplayError("usage", "provider_usage_unverifiable")
    cluster_uid = str(event.get("validation_cluster_uid") or "")
    audit_uid = str(event.get("audit_unit_uid") or "")
    if bool(cluster_uid) == bool(audit_uid):
        raise SyntheticReplayError("usage", "provider_usage_unverifiable")
    if (
        not event.get("call_id")
        or event.get("reservation_id") != event.get("call_id")
        or not event.get("call_chain_id")
        or not event.get("logical_operation_id")
        or int(event.get("sequence") or 0) <= 0
        or int(event.get("attempt_index") or 0) <= 0
        or int(event.get("reserved_total_tokens") or 0) < int(event.get("total_tokens") or 0)
        or int(event.get("cached_prompt_tokens") or 0) > int(event.get("prompt_tokens") or 0)
        or int(event.get("reasoning_tokens") or 0) > int(event.get("completion_tokens") or 0)
    ):
        raise SyntheticReplayError("usage", "provider_usage_unverifiable")


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
    assert isinstance(attribution, Mapping)
    assert isinstance(totals, Mapping)
    if (
        scan_usage.get("depth") != "balanced"
        or scan_usage.get("telemetry_complete") is not True
        or _strict_nonnegative_integer(scan_usage.get("active_reservation_count")) != 0
        or _strict_nonnegative_integer(scan_usage.get("reserved_tokens")) != 0
        or not isinstance(attribution.get("provider_usage_coverage"), float)
        or attribution.get("provider_usage_coverage") != 1.0
    ):
        raise SyntheticReplayError("usage", "provider_usage_unverifiable")
    prompt_total = 0
    completion_total = 0
    token_total = 0
    seen_call_ids: set[str] = set()
    call_chains: dict[str, list[Mapping[str, Any]]] = {}
    by_scope_regeneration: dict[tuple[str, str], int] = {}
    for event in events:
        _strict_usage_event(event)
        requested = event.get("requested_model")
        response = event.get("provider_response_model")
        if (
            requested != contract.model
            or event.get("model") != contract.model
            or not contract.accepts_response_model(response)
        ):
            raise SyntheticReplayError("provider", "provider_identity_mismatch")
        call_id = str(event.get("call_id") or "")
        if not call_id or call_id in seen_call_ids:
            raise SyntheticReplayError("usage", "provider_usage_unverifiable")
        seen_call_ids.add(call_id)
        prompt_tokens = cast(int, event["prompt_tokens"])
        completion_tokens = cast(int, event["completion_tokens"])
        total_tokens = cast(int, event["total_tokens"])
        if (
            total_tokens != prompt_tokens + completion_tokens
            or event.get("provider_reported") is not True
        ):
            raise SyntheticReplayError("usage", "accounting_conservation_failure")
        if (
            event.get("outcome") != "success"
            or event.get("conservative_charge") is not False
            or event.get("budget_violation") is not False
        ):
            raise SyntheticReplayError("usage", "accounting_conservation_failure")
        chain_uid = cast(str, event["call_chain_id"])
        call_chains.setdefault(chain_uid, []).append(event)
        if str(event.get("call_kind") or "") == "contract_regeneration":
            scope_uid = str(
                event.get("validation_cluster_uid") or event.get("audit_unit_uid") or ""
            )
            logical_operation_uid = cast(str, event["logical_operation_id"])
            key = (scope_uid, logical_operation_uid)
            by_scope_regeneration[key] = by_scope_regeneration.get(key, 0) + 1
        prompt_total += prompt_tokens
        completion_total += completion_tokens
        token_total += total_tokens
    retry_count = 0
    for chain_events in call_chains.values():
        attempts = [cast(int, value["attempt_index"]) for value in chain_events]
        scopes = {
            (
                str(value.get("validation_cluster_uid") or ""),
                str(value.get("audit_unit_uid") or ""),
                str(value.get("candidate_uid") or ""),
                str(value.get("logical_operation_id") or ""),
                str(value.get("requested_model") or ""),
            )
            for value in chain_events
        }
        if (
            len(scopes) != 1
            or sorted(attempts) != list(range(1, len(attempts) + 1))
            or len(attempts) > REPLAY_MAX_TRANSPORT_RETRIES + 1
            or any(
                value.get("retry") is not (cast(int, value["attempt_index"]) > 1)
                for value in chain_events
            )
        ):
            raise SyntheticReplayError("provider", "provider_transport_exhausted")
        retry_count += max(0, len(attempts) - 1)
    if any(value > REPLAY_MAX_CONTRACT_REGENERATIONS for value in by_scope_regeneration.values()):
        raise SyntheticReplayError("provider", "provider_protocol_incompatible")

    total_fields = {
        "request_count": len(events),
        "successful_calls": len(events),
        "provider_reported_calls": len(events),
        "estimated_or_conservative_calls": 0,
        "failed_or_unknown_calls": 0,
        "budget_violation_count": 0,
        "prompt_tokens": prompt_total,
        "completion_tokens": completion_total,
        "total_tokens": token_total,
        "tool_call_count": sum(cast(int, event["tool_call_count"]) for event in events),
    }
    if any(
        _strict_nonnegative_integer(totals.get(key)) != value for key, value in total_fields.items()
    ):
        raise SyntheticReplayError("usage", "accounting_conservation_failure")
    return {
        "physical_call_count": len(events),
        "prompt_tokens": prompt_total,
        "completion_tokens": completion_total,
        "total_tokens": token_total,
        "transport_retry_count": retry_count,
        "contract_regeneration_count": sum(by_scope_regeneration.values()),
        "tool_call_count": total_fields["tool_call_count"],
    }


def _trace_artifact_path(root: Path, relative: Any) -> Path:
    value = Path(str(relative or ""))
    if not str(value) or value.is_absolute() or ".." in value.parts:
        raise SyntheticReplayError("conservation", "accounting_conservation_failure")
    resolved = _regular_file_under(Path(root), Path(root) / value)
    if resolved is None:
        raise SyntheticReplayError("conservation", "accounting_conservation_failure")
    return resolved


def _strict_content_record(path: Path) -> Mapping[str, Any]:
    try:
        value = _strict_json(path)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise SyntheticReplayError("conservation", "accounting_conservation_failure") from exc
    if not isinstance(value, Mapping):
        raise SyntheticReplayError("conservation", "accounting_conservation_failure")
    body = dict(value)
    supplied = str(body.pop("sha256", "") or "")
    if not re.fullmatch(r"[0-9a-f]{64}", supplied) or _canonical_sha256(body) != supplied:
        raise SyntheticReplayError("conservation", "accounting_conservation_failure")
    if path.stem != supplied:
        raise SyntheticReplayError("conservation", "accounting_conservation_failure")
    return value


_EVIDENCE_RECORD_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "producer",
        "dependency_hashes",
        "locations",
        "payload",
        "sha256",
    }
)
_MODEL_RECORD_KEYS = frozenset(
    {
        "schema_version",
        "call_identity",
        "stage",
        "validation_cluster_uid",
        "structured_input",
        "structured_output",
        "call_ids",
        "tool_call_ids",
        "prompt_revision",
        "prompt_hash",
        "sha256",
    }
)


def _strict_evidence_record(path: Path) -> Mapping[str, Any]:
    value = _strict_content_record(path)
    dependencies = _strict_string_array(value.get("dependency_hashes"))
    if (
        set(value) != _EVIDENCE_RECORD_KEYS
        or value.get("schema_version") != "zscope.evidence-object.v1"
        or not isinstance(value.get("kind"), str)
        or not value.get("kind")
        or not isinstance(value.get("producer"), str)
        or not value.get("producer")
        or any(re.fullmatch(r"[0-9a-f]{64}", item) is None for item in dependencies)
        or not isinstance(value.get("locations"), list)
        or any(not isinstance(item, Mapping) for item in cast(list[Any], value.get("locations")))
    ):
        raise SyntheticReplayError("conservation", "accounting_conservation_failure")
    return value


def _strict_model_record(path: Path) -> Mapping[str, Any]:
    value = _strict_content_record(path)
    if (
        set(value) != _MODEL_RECORD_KEYS
        or value.get("schema_version") != "zscope.model-event.v1"
        or any(
            not isinstance(value.get(key), str)
            for key in (
                "call_identity",
                "stage",
                "validation_cluster_uid",
                "prompt_revision",
                "prompt_hash",
            )
        )
        or not value.get("call_identity")
        or not value.get("stage")
        or not value.get("validation_cluster_uid")
        or not isinstance(value.get("structured_input"), (Mapping, list))
        or not isinstance(value.get("structured_output"), (Mapping, list))
    ):
        raise SyntheticReplayError("conservation", "accounting_conservation_failure")
    _strict_string_array(value.get("call_ids"))
    _strict_string_array(value.get("tool_call_ids"))
    return value


def _strict_trace_refs(value: Any) -> tuple[set[str], set[str]]:
    refs = _strict_string_array(value)
    evidence: set[str] = set()
    models: set[str] = set()
    for ref in refs:
        match = re.fullmatch(r"(evidence_objects|model_events)/([0-9a-f]{64})\.json", ref)
        if match is None:
            raise SyntheticReplayError("conservation", "accounting_conservation_failure")
        target = evidence if match.group(1) == "evidence_objects" else models
        target.add(match.group(2))
    return evidence, models


def _strict_trace_document(path: Path, *, coverage: bool) -> Mapping[str, Any]:
    try:
        value = _strict_json(path)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise SyntheticReplayError("conservation", "accounting_conservation_failure") from exc
    if not isinstance(value, Mapping):
        raise SyntheticReplayError("conservation", "accounting_conservation_failure")
    valid, _reason = verify_coverage_trace(value) if coverage else verify_decision_trace(value)
    if not valid:
        raise SyntheticReplayError("conservation", "accounting_conservation_failure")
    return value


def _strict_string_array(value: Any) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise SyntheticReplayError("conservation", "accounting_conservation_failure")
    if value != sorted(set(value)):
        raise SyntheticReplayError("conservation", "accounting_conservation_failure")
    return list(value)


_TRACE_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "scan_uid",
        "identity",
        "trace_count",
        "coverage_trace_count",
        "evidence_object_count",
        "model_event_count",
        "traces",
        "coverage_traces",
        "evidence_object_sha256",
        "model_event_sha256",
        "errors",
        "error_counts",
        "llm_usage_events",
        "complete",
        "manifest_sha256",
    }
)


def _validate_report_conservation(
    workspace: SyntheticReplayWorkspace,
    report: Mapping[str, Any],
    events: Sequence[Mapping[str, Any]],
    usage: Mapping[str, int],
    *,
    usage_path: Path,
) -> tuple[dict[str, Any], Path, Mapping[str, Any]]:
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
    resolved_manifest = _regular_file_under(workspace.project_root, manifest_path)
    if resolved_manifest is None:
        raise SyntheticReplayError("conservation", "accounting_conservation_failure")
    try:
        trace_manifest = _strict_json(resolved_manifest)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise SyntheticReplayError("conservation", "accounting_conservation_failure") from exc
    if not isinstance(trace_manifest, Mapping):
        raise SyntheticReplayError("conservation", "accounting_conservation_failure")
    if set(trace_manifest) != _TRACE_MANIFEST_KEYS:
        raise SyntheticReplayError("conservation", "accounting_conservation_failure")
    manifest_body = dict(trace_manifest)
    manifest_sha256 = str(manifest_body.pop("manifest_sha256", "") or "")
    if not manifest_sha256 or _canonical_sha256(manifest_body) != manifest_sha256:
        raise SyntheticReplayError("conservation", "accounting_conservation_failure")
    trace_binding = trace_manifest.get("llm_usage_events")
    scan_uid = trace_manifest.get("scan_uid")
    identity = trace_manifest.get("identity")
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
        or not isinstance(scan_uid, str)
        or not scan_uid
        or not isinstance(identity, Mapping)
        or not identity
    ):
        raise SyntheticReplayError("conservation", "accounting_conservation_failure")
    bound_manifest_sha = str(decision_trace.get("manifest_sha256") or "")
    if not bound_manifest_sha or bound_manifest_sha != str(
        trace_manifest.get("manifest_sha256") or ""
    ):
        raise SyntheticReplayError("conservation", "accounting_conservation_failure")

    trace_rows = trace_manifest.get("traces")
    coverage_rows = trace_manifest.get("coverage_traces")
    evidence_hashes = trace_manifest.get("evidence_object_sha256")
    model_hashes = trace_manifest.get("model_event_sha256")
    if (
        trace_manifest.get("schema_version") != "zscope.decision-trace-manifest.v3"
        or not isinstance(trace_rows, Mapping)
        or not isinstance(coverage_rows, Mapping)
        or not isinstance(evidence_hashes, list)
        or not isinstance(model_hashes, list)
        or int(trace_manifest.get("trace_count") or 0) != len(trace_rows)
        or int(trace_manifest.get("coverage_trace_count") or 0) != len(coverage_rows)
        or int(trace_manifest.get("evidence_object_count") or 0) != len(evidence_hashes)
        or int(trace_manifest.get("model_event_count") or 0) != len(model_hashes)
        or decision_trace.get("schema_version") != trace_manifest.get("schema_version")
        or decision_trace.get("trace_count") != trace_manifest.get("trace_count")
        or decision_trace.get("coverage_trace_count") != trace_manifest.get("coverage_trace_count")
        or decision_trace.get("evidence_object_count")
        != trace_manifest.get("evidence_object_count")
        or decision_trace.get("model_event_count") != trace_manifest.get("model_event_count")
    ):
        raise SyntheticReplayError("conservation", "accounting_conservation_failure")
    evidence_ids = _strict_string_array(evidence_hashes)
    model_ids = _strict_string_array(model_hashes)
    if any(re.fullmatch(r"[0-9a-f]{64}", value) is None for value in (*evidence_ids, *model_ids)):
        raise SyntheticReplayError("conservation", "accounting_conservation_failure")

    terminal_by_cluster: dict[str, Mapping[str, Any]] = {}
    for raw in terminal_states:
        if not isinstance(raw, Mapping):
            raise SyntheticReplayError("conservation", "accounting_conservation_failure")
        issue = _confirmation_issue(raw)
        cluster_uid = str(issue.get("validation_cluster_uid") or "")
        candidate_uid = str(issue.get("candidate_uid") or "")
        if not cluster_uid or not candidate_uid or cluster_uid in terminal_by_cluster:
            raise SyntheticReplayError("conservation", "accounting_conservation_failure")
        terminal_by_cluster[cluster_uid] = raw
    if set(map(str, trace_rows)) != set(terminal_by_cluster):
        raise SyntheticReplayError("conservation", "accounting_conservation_failure")

    issue_by_cluster: dict[str, Mapping[str, Any]] = {}
    for raw in issues:
        if not isinstance(raw, Mapping):
            raise SyntheticReplayError("conservation", "accounting_conservation_failure")
        issue = _confirmation_issue(raw)
        cluster_uid = str(issue.get("validation_cluster_uid") or "")
        if (
            not cluster_uid
            or cluster_uid not in terminal_by_cluster
            or cluster_uid in issue_by_cluster
        ):
            raise SyntheticReplayError("conservation", "accounting_conservation_failure")
        terminal_issue = _confirmation_issue(terminal_by_cluster[cluster_uid])
        if dict(issue) != dict(terminal_issue):
            raise SyntheticReplayError("conservation", "accounting_conservation_failure")
        issue_by_cluster[cluster_uid] = raw

    trace_root = resolved_manifest.parent
    traced_call_ids: list[str] = []
    traced_tool_call_ids: list[str] = []
    trace_token_total = 0
    referenced_model_ids: set[str] = set()
    referenced_evidence_ids: set[str] = set()
    model_bindings: dict[str, tuple[str, str, tuple[str, ...], tuple[str, ...]]] = {}
    traced_candidate_uids: set[str] = set()
    usage_by_call = {str(value.get("call_id") or ""): value for value in events}
    for cluster_uid, raw_projection in sorted(trace_rows.items(), key=lambda item: str(item[0])):
        if not isinstance(raw_projection, Mapping):
            raise SyntheticReplayError("conservation", "accounting_conservation_failure")
        projection = raw_projection
        trace_path = _trace_artifact_path(trace_root, projection.get("path"))
        trace = _strict_trace_document(trace_path, coverage=False)
        terminal_issue = _confirmation_issue(terminal_by_cluster[str(cluster_uid)])
        candidate_uid = str(terminal_issue.get("candidate_uid") or "")
        occurrence_uids = _strict_string_array(terminal_issue.get("occurrence_uids"))
        candidate_uids = _strict_string_array(trace.get("candidate_uids"))
        if (
            trace.get("validation_cluster_uid") != str(cluster_uid)
            or candidate_uids != [candidate_uid]
            or traced_candidate_uids.intersection(candidate_uids)
            or trace.get("occurrence_uids") != occurrence_uids
            or trace.get("scan_uid") != scan_uid
            or trace.get("identity") != identity
            or trace.get("trace_root_sha256") != projection.get("trace_root_sha256")
            or trace.get("document_sha256") != projection.get("document_sha256")
            or int(projection.get("event_count") or 0) != len(trace.get("events") or [])
            or trace.get("terminal_disposition") != terminal_issue.get("candidate_disposition")
            or terminal_issue.get("decision_trace_ref") != projection.get("path")
            or terminal_issue.get("decision_trace_sha256") != trace.get("document_sha256")
            or terminal_issue.get("terminal_event_uid") != trace.get("terminal_event_uid")
        ):
            raise SyntheticReplayError("conservation", "accounting_conservation_failure")
        traced_candidate_uids.update(candidate_uids)
        raw_trace_events = trace.get("events")
        if not isinstance(raw_trace_events, list):
            raise SyntheticReplayError("conservation", "accounting_conservation_failure")
        terminal_indexes = [
            index
            for index, value in enumerate(raw_trace_events)
            if isinstance(value, Mapping)
            and value.get("event_uid") == trace.get("terminal_event_uid")
        ]
        if len(terminal_indexes) != 1:
            raise SyntheticReplayError("conservation", "accounting_conservation_failure")
        terminal_index = terminal_indexes[0]
        for index, raw_event in enumerate(raw_trace_events):
            if not isinstance(raw_event, Mapping):
                raise SyntheticReplayError("conservation", "accounting_conservation_failure")
            calls = _strict_string_array(raw_event.get("call_ids"))
            tools = _strict_string_array(raw_event.get("tool_call_ids"))
            token_delta = raw_event.get("token_delta")
            if isinstance(token_delta, bool) or not isinstance(token_delta, int) or token_delta < 0:
                raise SyntheticReplayError("conservation", "accounting_conservation_failure")
            traced_call_ids.extend(calls)
            traced_tool_call_ids.extend(tools)
            trace_token_total += token_delta
            event_evidence: set[str] = set()
            event_models: set[str] = set()
            for key in ("input_refs", "output_refs"):
                evidence_refs, model_refs = _strict_trace_refs(raw_event.get(key))
                event_evidence.update(evidence_refs)
                event_models.update(model_refs)
            referenced_evidence_ids.update(event_evidence)
            for model_id in event_models:
                if model_id in model_bindings:
                    raise SyntheticReplayError("conservation", "accounting_conservation_failure")
                model_bindings[model_id] = (
                    str(cluster_uid),
                    str(raw_event.get("stage") or ""),
                    tuple(calls),
                    tuple(tools),
                )
            referenced_model_ids.update(event_models)
            for call_id in calls:
                usage_event = usage_by_call.get(call_id)
                if (
                    not isinstance(usage_event, Mapping)
                    or usage_event.get("validation_cluster_uid") != str(cluster_uid)
                    or usage_event.get("audit_unit_uid") != ""
                ):
                    raise SyntheticReplayError("conservation", "accounting_conservation_failure")
            if (
                index > terminal_index
                and terminal_issue.get("candidate_disposition") == "confirmed"
                and (calls or tools or token_delta)
            ):
                raise SyntheticReplayError("conservation", "accounting_conservation_failure")

    for unit_uid, raw_projection in sorted(coverage_rows.items(), key=lambda item: str(item[0])):
        if not isinstance(raw_projection, Mapping):
            raise SyntheticReplayError("conservation", "accounting_conservation_failure")
        coverage_path = _trace_artifact_path(trace_root, raw_projection.get("path"))
        coverage = _strict_trace_document(coverage_path, coverage=True)
        raw_coverage_events = coverage.get("events")
        if (
            coverage.get("audit_unit_uid") != str(unit_uid)
            or coverage.get("scan_uid") != scan_uid
            or coverage.get("trace_root_sha256") != raw_projection.get("trace_root_sha256")
            or coverage.get("document_sha256") != raw_projection.get("document_sha256")
            or not isinstance(raw_coverage_events, list)
            or int(raw_projection.get("event_count") or 0) != len(raw_coverage_events)
        ):
            raise SyntheticReplayError("conservation", "accounting_conservation_failure")
        for raw_event in raw_coverage_events:
            if not isinstance(raw_event, Mapping):
                raise SyntheticReplayError("conservation", "accounting_conservation_failure")
            calls = _strict_string_array(raw_event.get("call_ids"))
            token_delta = raw_event.get("token_delta")
            if isinstance(token_delta, bool) or not isinstance(token_delta, int) or token_delta < 0:
                raise SyntheticReplayError("conservation", "accounting_conservation_failure")
            traced_call_ids.extend(calls)
            trace_token_total += token_delta
            evidence_refs, model_refs = _strict_trace_refs(raw_event.get("evidence_refs"))
            if model_refs:
                raise SyntheticReplayError("conservation", "accounting_conservation_failure")
            referenced_evidence_ids.update(evidence_refs)
            for call_id in calls:
                usage_event = usage_by_call.get(call_id)
                if (
                    not isinstance(usage_event, Mapping)
                    or usage_event.get("audit_unit_uid") != str(unit_uid)
                    or usage_event.get("validation_cluster_uid") != ""
                ):
                    raise SyntheticReplayError("conservation", "accounting_conservation_failure")

    usage_call_ids = [str(value.get("call_id") or "") for value in events]
    if (
        any(not value for value in usage_call_ids)
        or len(traced_call_ids) != len(set(traced_call_ids))
        or set(traced_call_ids) != set(usage_call_ids)
        or len(traced_tool_call_ids) != len(set(traced_tool_call_ids))
        or len(traced_tool_call_ids) != int(usage["tool_call_count"])
        or trace_token_total != int(usage["total_tokens"])
    ):
        raise SyntheticReplayError("conservation", "accounting_conservation_failure")

    for digest in evidence_ids:
        _strict_evidence_record(_trace_artifact_path(trace_root, f"evidence_objects/{digest}.json"))
    for digest in model_ids:
        model = _strict_model_record(
            _trace_artifact_path(trace_root, f"model_events/{digest}.json")
        )
        binding = model_bindings.get(digest)
        if binding is None:
            raise SyntheticReplayError("conservation", "accounting_conservation_failure")
        cluster_uid, stage, call_ids, tool_call_ids = binding
        if (
            model.get("validation_cluster_uid") != cluster_uid
            or model.get("stage") != stage
            or model.get("call_ids") != list(call_ids)
            or model.get("tool_call_ids") != list(tool_call_ids)
        ):
            raise SyntheticReplayError("conservation", "accounting_conservation_failure")
    if referenced_model_ids != set(model_ids) or referenced_evidence_ids != set(evidence_ids):
        raise SyntheticReplayError("conservation", "accounting_conservation_failure")

    try:
        relative_usage_path = usage_path.resolve(strict=True).relative_to(trace_root).as_posix()
    except (OSError, ValueError) as exc:
        raise SyntheticReplayError("conservation", "accounting_conservation_failure") from exc
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
        "trace": (event_count, len(traced_call_ids)),
        "finding": (len(issues), int(summary.get("total_issues") or 0)),
        "terminal": (
            len(terminal_states),
            int(run_manifest.get("terminal_outcome_count") or 0),
        ),
    }
    if (
        trace_binding.get("path") != relative_usage_path
        or trace_binding.get("file_sha256") != _sha256_file(usage_path)
        or int(trace_binding.get("event_count") or 0) != event_count
        or int(trace_binding.get("referenced_call_count") or 0) != len(traced_call_ids)
        or trace_binding.get("referenced_call_ids") != sorted(usage_call_ids)
        or int(trace_binding.get("trace_token_total") or 0) != trace_token_total
        or int(trace_binding.get("usage_token_total") or 0) != token_total
        or int(trace_binding.get("trace_token_total") or 0) != token_total
        or int(trace_manifest.get("trace_count") or 0) != len(terminal_states)
        or int(summary.get("total_issues") or 0) != len(issues)
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
        trace_manifest,
    )


def _confirmation_issue(row: Mapping[str, Any]) -> Mapping[str, Any]:
    issue = row.get("issue")
    return issue if isinstance(issue, Mapping) else row


def _validation_cluster_contract(issue: Mapping[str, Any]) -> Any:
    pack = issue.get("evidence_pack")
    pack = pack if isinstance(pack, Mapping) else {}
    ticket = issue.get("ticket")
    ticket = ticket if isinstance(ticket, Mapping) else {}
    ticket_evidence = ticket.get("evidence")
    ticket_evidence = ticket_evidence if isinstance(ticket_evidence, Mapping) else {}
    for carrier in (issue, pack, ticket_evidence):
        for key in ("validator_contract", "validation_requirements"):
            value = carrier.get(key)
            if value:
                return value
    return None


@dataclass(frozen=True)
class _ValidatedOccurrenceBinding:
    candidate_uid: str
    validation_cluster_uid: str
    occurrence_uids: tuple[str, ...]
    entries: tuple[str, ...]
    occurrences: tuple[tuple[str, tuple[tuple[str, ...], ...]], ...]


def _validated_occurrence_binding(
    row: Mapping[str, Any],
) -> _ValidatedOccurrenceBinding | None:
    """Validate the canonical candidate-to-entry occurrence projection.

    Entry names and call-path text are report provenance, not proof authority.
    Accept them only through a complete CandidateOccurrence whose deterministic
    identity binds the exact candidate, entry and paths.  The wrapper and issue
    projections must agree byte-for-byte on their lifecycle identities.
    """

    issue = _confirmation_issue(row)
    candidate_uid = str(issue.get("candidate_uid") or "")
    cluster_uid = str(issue.get("validation_cluster_uid") or "")
    decision_evidence_hash = str(issue.get("decision_evidence_hash") or "")
    obligation_uid = str(issue.get("obligation_uid") or "")
    decision_context_version = str(issue.get("decision_context_version") or "")
    if not all(
        (
            candidate_uid,
            cluster_uid,
            decision_evidence_hash,
            obligation_uid,
            decision_context_version,
        )
    ):
        return None
    if (
        validation_cluster_uid_for(
            candidate_uid,
            decision_evidence_hash=decision_evidence_hash,
            validator_contract=_validation_cluster_contract(issue),
            obligation_uid=obligation_uid,
            decision_context_version=decision_context_version,
        )
        != cluster_uid
    ):
        return None

    raw_occurrences = issue.get("occurrences")
    if not isinstance(raw_occurrences, list) or not raw_occurrences:
        return None
    occurrence_uids: list[str] = []
    entries: list[str] = []
    flattened_paths: list[list[str]] = []
    bound_occurrences: list[tuple[str, tuple[tuple[str, ...], ...]]] = []
    for raw in raw_occurrences:
        if not isinstance(raw, Mapping):
            return None
        occurrence_uid = str(raw.get("occurrence_uid") or "")
        entry_identity = str(raw.get("entry_identity") or "")
        raw_paths = raw.get("call_paths")
        if not occurrence_uid or not entry_identity or not isinstance(raw_paths, list):
            return None
        paths: list[list[str]] = []
        for raw_path in raw_paths:
            if not isinstance(raw_path, list) or any(
                not isinstance(value, str) or not value for value in raw_path
            ):
                return None
            paths.append(list(raw_path))
        if (
            occurrence_uid_for(
                candidate_uid,
                entry=entry_identity,
                entry_paths=paths,
            )
            != occurrence_uid
        ):
            return None
        occurrence_uids.append(occurrence_uid)
        entries.append(entry_identity)
        flattened_paths.extend(paths)
        bound_occurrences.append(
            (
                entry_identity,
                tuple(tuple(value) for value in paths),
            )
        )

    sorted_uids = sorted(set(occurrence_uids))
    sorted_entries = sorted(set(entries))
    if len(sorted_uids) != len(occurrence_uids):
        return None
    if (
        issue.get("occurrence_uid") != sorted_uids[0]
        or issue.get("occurrence_uids") != sorted_uids
        or issue.get("alias_occurrence_uids") != sorted_uids[1:]
        or issue.get("occurrence_count") != len(sorted_uids)
        or issue.get("entries") != sorted_entries
        or issue.get("entry_count") != len(sorted_entries)
        or issue.get("entry_paths") != flattened_paths
    ):
        return None

    if issue is not row:
        if (
            row.get("validation_cluster_uid") != cluster_uid
            or row.get("primary_occurrence_uid") != sorted_uids[0]
            or row.get("occurrence_uids") != sorted_uids
            or row.get("alias_occurrence_uids") != sorted_uids[1:]
        ):
            return None
    for carrier in (issue, row):
        for key in ("reported_from_entry", "entry_identity"):
            if key in carrier and str(carrier.get(key) or "") not in sorted_entries:
                return None
    return _ValidatedOccurrenceBinding(
        candidate_uid=candidate_uid,
        validation_cluster_uid=cluster_uid,
        occurrence_uids=tuple(sorted_uids),
        entries=tuple(sorted_entries),
        occurrences=tuple(bound_occurrences),
    )


_QUALIFIED_RACE_PREDICATES = frozenset(
    {
        "qualified_race_shared_object_identity",
        "qualified_race_conflicting_accesses",
        "qualified_race_cross_thread_reachability",
        "qualified_race_empty_locksets",
        "qualified_race_no_happens_before",
    }
)
_QUALIFIED_BOUNDS_PREDICATES = frozenset(
    {
        "qualified_bounds_source_controllable",
        "qualified_bounds_path_complete",
        "qualified_bounds_sink_contract",
        "qualified_bounds_range_violation",
    }
)
_QUALIFIED_LEAK_PREDICATES = frozenset(
    {
        "qualified_leak_acquisition_identity",
        "qualified_leak_exit_outstanding",
        "qualified_leak_transfer_excluded",
    }
)


def _scenario_source_path(
    workspace: SyntheticReplayWorkspace,
    scenario: SyntheticScenario,
    raw_file: Any,
) -> Path | None:
    project_root = workspace.project_root
    expected_raw = project_root / scenario.source_name
    expected = _regular_file_under(project_root, expected_raw)
    if expected is None:
        return None
    try:
        candidate = Path(str(raw_file or ""))
        candidate = candidate if candidate.is_absolute() else project_root / candidate
    except ValueError:
        return None
    resolved = _regular_file_under(project_root, candidate)
    return resolved if resolved == expected else None


def _fresh_summary_matches(
    workspace: SyntheticReplayWorkspace,
    scenario: SyntheticScenario,
    summary: Mapping[str, Any],
    *,
    cross_thread_function_ir: Mapping[str, Any] | None = None,
) -> FunctionIRGraph | None:
    function_uid = str(summary.get("function_uid") or "")
    source_path = _scenario_source_path(workspace, scenario, summary.get("file"))
    if source_path is None:
        return None
    graph = _extract_scenario_function_graph(
        workspace,
        scenario,
        function_uid,
        graph_file=str(summary.get("file") or source_path),
    )
    if graph is None:
        return None
    expected = function_summary_from_graph(
        graph,
        function_uid=function_uid,
        wrapper_summaries=function_ir_compound_wrappers(
            graph,
            cross_thread_function_ir=cross_thread_function_ir,
        ),
    )
    # Persisted JSON normalizes tuples from the in-memory IR into arrays.  Use
    # canonical JSON equality so that this representation-only round trip is
    # accepted while any extra key or changed value still fails closed.
    return graph if _canonical_sha256(summary) == _canonical_sha256(expected) else None


def _proof_binds_scenario(
    workspace: SyntheticReplayWorkspace,
    row: Mapping[str, Any],
    scenario: SyntheticScenario,
) -> bool:
    """Bind a terminal proof to one public synthetic source contract.

    TerminalAuthority proves that one sealed obligation closed; it does not by
    itself prove that the obligation describes the scenario being counted.
    Recompute the qualified compound option from the sealed FunctionSummary,
    require its concrete source snapshot, family, subject and API identities,
    and compare every governed clause parameter with that one option.
    """

    issue = _confirmation_issue(row)
    authority_input = issue.get("proof_kernel_input")
    if not isinstance(authority_input, Mapping):
        return False
    proof_ir = authority_input.get("proof_ir")
    obligation = authority_input.get("proof_obligation")
    if not isinstance(proof_ir, Mapping) or not isinstance(obligation, Mapping):
        return False
    raw_functions = proof_ir.get("functions")
    if not isinstance(raw_functions, list) or len(raw_functions) != 1:
        return False
    summary = raw_functions[0]
    if not isinstance(summary, Mapping):
        return False
    source_path = _scenario_source_path(workspace, scenario, summary.get("file"))
    if source_path is None:
        return False
    source_sha256 = _sha256_file(source_path)
    if (
        source_sha256 != _sha256_bytes(scenario.source.encode("utf-8"))
        or summary.get("code_sha256") != source_sha256
        or str(obligation.get("subject_uid") or "") != scenario.subject_uid
    ):
        return False

    family = str(obligation.get("defect_family") or "").strip().lower().replace("-", "_")
    normalized_family = ""
    if any(value in family for value in ("race", "concurr", "thread", "lock")):
        normalized_family = "race"
    elif any(value in family for value in ("leak", "resource", "ownership", "acquire")):
        normalized_family = "leak"
    elif any(value in family for value in ("bound", "overflow", "length", "range")):
        normalized_family = "bounds"
    if normalized_family != scenario.proof_family:
        return False

    raw_clauses = obligation.get("confirmation_clauses")
    if not isinstance(raw_clauses, list) or any(
        not isinstance(value, Mapping) for value in raw_clauses
    ):
        return False
    clauses = cast(list[Mapping[str, Any]], raw_clauses)
    events = {
        str(value.get("event_uid") or ""): value
        for value in summary.get("events") or []
        if isinstance(value, Mapping) and str(value.get("event_uid") or "")
    }

    def event_callee(value: Mapping[str, Any] | None) -> str:
        if not isinstance(value, Mapping):
            return ""
        attributes = value.get("attributes")
        if not isinstance(attributes, Mapping):
            return ""
        return str(attributes.get("callee") or "").lower()

    expected_predicates: frozenset[str]
    fixed_parameters: Mapping[str, Any]
    if scenario.proof_family == "bounds":
        if str(summary.get("function_uid") or "") != scenario.vulnerable_entry:
            return False
        if _fresh_summary_matches(workspace, scenario, summary) is None:
            return False
        bounds_matches = [
            value
            for value in qualified_bounds_options(summary)
            if value.get("value_uid") == scenario.subject_uid
        ]
        if len(bounds_matches) != 1:
            return False
        fixed_parameters = bounds_matches[0]
        source_event = events.get(str(fixed_parameters.get("source_event_uid") or ""))
        sink_event = events.get(str(fixed_parameters.get("sink_event_uid") or ""))
        if not (
            isinstance(source_event, Mapping)
            and isinstance(sink_event, Mapping)
            and event_callee(source_event) == scenario.source_callee
            and event_callee(sink_event) == scenario.sink_callee
        ):
            return False
        expected_predicates = _QUALIFIED_BOUNDS_PREDICATES
    elif scenario.proof_family == "leak":
        if str(summary.get("function_uid") or "") != scenario.vulnerable_entry:
            return False
        if _fresh_summary_matches(workspace, scenario, summary) is None:
            return False
        leak_matches: list[Mapping[str, Any]] = []
        for value in qualified_resource_leak_options(summary):
            fixed = value.get("fixed_parameters")
            actual = value.get("actual")
            if (
                isinstance(fixed, Mapping)
                and isinstance(actual, Mapping)
                and str(fixed.get("resource_uid") or "") == scenario.subject_uid
                and actual.get("outstanding_on_reachable_exit") is True
                and actual.get("ownership_transfer_excluded") is True
            ):
                leak_matches.append(value)
        if len(leak_matches) != 1:
            return False
        raw_fixed_parameters = leak_matches[0].get("fixed_parameters")
        if not isinstance(raw_fixed_parameters, Mapping):
            return False
        fixed_parameters = raw_fixed_parameters
        acquisition = events.get(str(fixed_parameters.get("acquisition_event_uid") or ""))
        if not (
            isinstance(acquisition, Mapping) and event_callee(acquisition) == scenario.source_callee
        ):
            return False
        expected_predicates = _QUALIFIED_LEAK_PREDICATES
    elif scenario.proof_family == "race":
        if str(summary.get("function_uid") or "") not in set(scenario.worker_function_uids):
            return False
        wrappers = [
            value
            for value in summary.get("wrapper_summaries") or []
            if isinstance(value, Mapping)
            and value.get("summary_kind") == "cross_thread_function_ir"
        ]
        if len(wrappers) != 1:
            return False
        wrapper = wrappers[0]
        if (
            _fresh_summary_matches(
                workspace,
                scenario,
                summary,
                cross_thread_function_ir=wrapper,
            )
            is None
        ):
            return False
        raw_worker_graphs = wrapper.get("worker_graphs")
        raw_creator_graph = wrapper.get("creator_graph")
        if (
            not isinstance(raw_creator_graph, Mapping)
            or not isinstance(raw_worker_graphs, list)
            or len(raw_worker_graphs) != 2
            or any(not isinstance(value, Mapping) for value in raw_worker_graphs)
        ):
            return False
        raw_graphs = [raw_creator_graph, *cast(list[Mapping[str, Any]], raw_worker_graphs)]
        expected_function_set = {
            scenario.creator_function_uid,
            *scenario.worker_function_uids,
        }
        if {str(value.get("function") or "") for value in raw_graphs} != expected_function_set:
            return False
        for raw_graph in raw_graphs:
            function = str(raw_graph.get("function") or "")
            try:
                sealed_graph = graph_from_mapping(raw_graph)
            except (TypeError, ValueError):
                return False
            fresh_graph = _extract_scenario_function_graph(
                workspace,
                scenario,
                function,
                graph_file=str(raw_graph.get("file") or ""),
            )
            if (
                _canonical_sha256(raw_graph) != _canonical_sha256(sealed_graph.to_dict())
                or fresh_graph is None
                or _canonical_sha256(sealed_graph.to_dict())
                != _canonical_sha256(fresh_graph.to_dict())
            ):
                return False
        object_binding = wrapper.get("object_binding")
        if not isinstance(object_binding, Mapping):
            return False
        declaration_path = _scenario_source_path(
            workspace,
            scenario,
            object_binding.get("declaration_file"),
        )
        declaration_line = next(
            (
                index
                for index, line in enumerate(scenario.source.splitlines(), start=1)
                if re.search(rf"\b{re.escape(scenario.subject_uid)}\b", line)
            ),
            0,
        )
        if declaration_path is None or object_binding.get("declaration_line") != declaration_line:
            return False
        race_matches = qualified_race_options(summary)
        if len(race_matches) != 1:
            return False
        fixed_parameters = cast(Mapping[str, Any], race_matches[0].get("fixed_parameters") or {})
        workers = {
            str(fixed_parameters.get("left_function_uid") or ""),
            str(fixed_parameters.get("right_function_uid") or ""),
        }
        if (
            str(fixed_parameters.get("object_uid") or "") != scenario.subject_uid
            or str(fixed_parameters.get("creator_function_uid") or "")
            != scenario.creator_function_uid
            or workers != set(scenario.worker_function_uids)
        ):
            return False
        expected_predicates = _QUALIFIED_RACE_PREDICATES
    else:
        return False

    compound_clauses = [
        value for value in clauses if str(value.get("predicate_id") or "").startswith("qualified_")
    ]
    return bool(
        {str(value.get("predicate_id") or "") for value in compound_clauses} == expected_predicates
        and all(
            dict(value.get("parameters") or {}) == dict(fixed_parameters)
            for value in compound_clauses
        )
    )


def _proof_origin_binds_occurrences(
    issue: Mapping[str, Any],
    binding: _ValidatedOccurrenceBinding,
) -> bool:
    """Bind canonical report occurrences to the revalidated sealed Proof IR.

    Candidate/cluster/occurrence hashes only prove that report-controlled
    fields agree with each other.  They do not prove that the attributed entry
    produced the terminal proof.  TerminalAuthority has already regenerated
    and checked ``proof_kernel_input`` before this helper is called; derive the
    only permitted function origin from that sealed input and fail closed on
    multiple summaries, malformed cross-thread envelopes, or ambiguous paths.

    A function-local proof is attributable only to that exact function.  A
    qualified race proof is attributable to its sealed creator entry and must
    end at the candidate worker in the forward call-path direction.
    """

    authority_input = issue.get("proof_kernel_input")
    if not isinstance(authority_input, Mapping):
        return False
    proof_ir = authority_input.get("proof_ir")
    obligation = authority_input.get("proof_obligation")
    if not isinstance(proof_ir, Mapping) or not isinstance(obligation, Mapping):
        return False
    raw_functions = proof_ir.get("functions")
    if not isinstance(raw_functions, list) or len(raw_functions) != 1:
        return False
    summary = raw_functions[0]
    if not isinstance(summary, Mapping):
        return False
    proof_function = str(summary.get("function_uid") or "").strip()
    if not proof_function:
        return False

    clauses: list[Mapping[str, Any]] = []
    for key in ("confirmation_clauses", "counterproof_clauses", "open_clauses"):
        raw_clauses = obligation.get(key)
        if not isinstance(raw_clauses, list) or any(
            not isinstance(value, Mapping) for value in raw_clauses
        ):
            return False
        clauses.extend(cast(list[Mapping[str, Any]], raw_clauses))
    predicates = {str(value.get("predicate_id") or "") for value in clauses}
    race_predicates = predicates.intersection(_QUALIFIED_RACE_PREDICATES)

    wrappers = summary.get("wrapper_summaries")
    if not isinstance(wrappers, list):
        return False
    cross_thread_wrappers = [
        value
        for value in wrappers
        if isinstance(value, Mapping) and value.get("summary_kind") == "cross_thread_function_ir"
    ]

    if race_predicates:
        # A terminal race proof must carry the complete governed predicate set
        # and exactly one product-sealed cross-thread graph.  The registry
        # recomputation validates its digest, embedded FunctionIR graphs,
        # creator edges, candidate worker, object identity and qualification.
        if race_predicates != _QUALIFIED_RACE_PREDICATES or len(cross_thread_wrappers) != 1:
            return False
        options = qualified_race_options(summary)
        if len(options) != 1:
            return False
        wrapper = cross_thread_wrappers[0]
        creator_graph = wrapper.get("creator_graph")
        raw_workers = wrapper.get("worker_graphs")
        if not isinstance(creator_graph, Mapping) or not isinstance(raw_workers, list):
            return False
        creator = str(creator_graph.get("function") or "").strip()
        candidate = str(wrapper.get("candidate_function_uid") or "").strip()
        worker_functions = {
            str(value.get("function") or "").strip()
            for value in raw_workers
            if isinstance(value, Mapping)
        }
        fixed_parameters = options[0].get("fixed_parameters")
        if (
            not creator
            or not candidate
            or candidate != proof_function
            or candidate not in worker_functions
            or len(worker_functions) != len(raw_workers)
            or not isinstance(fixed_parameters, Mapping)
            or str(fixed_parameters.get("creator_function_uid") or "") != creator
            or candidate
            not in {
                str(fixed_parameters.get("left_function_uid") or ""),
                str(fixed_parameters.get("right_function_uid") or ""),
            }
        ):
            return False
        for entry, paths in binding.occurrences:
            if not _entry_matches(entry, creator) or not paths:
                return False
            if any(
                not path
                or not _entry_matches(path[0], creator)
                or not _entry_matches(path[-1], candidate)
                for path in paths
            ):
                return False
        return True

    # A non-race proof cannot borrow an incidental cross-thread wrapper to
    # widen its attribution domain.  Unknown or mixed provenance stays closed.
    if cross_thread_wrappers:
        return False
    for entry, paths in binding.occurrences:
        if not _entry_matches(entry, proof_function) or not paths:
            return False
        if any(
            not path
            or not _entry_matches(path[0], proof_function)
            or not _entry_matches(path[-1], proof_function)
            for path in paths
        ):
            return False
    return True


def _trace_binds_occurrences(
    workspace: SyntheticReplayWorkspace,
    row: Mapping[str, Any],
    binding: _ValidatedOccurrenceBinding,
    *,
    trace_manifest_path: Path,
    trace_manifest: Mapping[str, Any],
) -> bool:
    issue = _confirmation_issue(row)
    traces = trace_manifest.get("traces")
    projection = traces.get(binding.validation_cluster_uid) if isinstance(traces, Mapping) else None
    if not isinstance(projection, Mapping):
        return False
    relative_path = str(projection.get("path") or "")
    issue_trace_ref = str(issue.get("decision_trace_ref") or "")
    if not relative_path or issue_trace_ref != relative_path:
        return False
    trace_path = _regular_file_under(
        trace_manifest_path.parent,
        trace_manifest_path.parent / relative_path,
    )
    if trace_path is None:
        return False
    try:
        trace = _strict_json(trace_path)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        return False
    if not isinstance(trace, Mapping):
        return False
    trace_body = dict(trace)
    document_sha256 = str(trace_body.pop("document_sha256", "") or "")
    if not document_sha256 or _canonical_sha256(trace_body) != document_sha256:
        return False
    trace_candidate_uids = trace.get("candidate_uids")
    if not isinstance(trace_candidate_uids, list) or any(
        not isinstance(value, str) or not value for value in trace_candidate_uids
    ):
        return False
    return bool(
        trace.get("validation_cluster_uid") == binding.validation_cluster_uid
        and trace_candidate_uids == [binding.candidate_uid]
        and trace.get("occurrence_uids") == list(binding.occurrence_uids)
        and trace.get("scan_uid") == trace_manifest.get("scan_uid")
        and trace.get("identity") == trace_manifest.get("identity")
        and trace.get("trace_root_sha256") == projection.get("trace_root_sha256")
        and trace.get("terminal_disposition") == "confirmed"
        and projection.get("document_sha256") == document_sha256
        and issue.get("decision_trace_sha256") == document_sha256
    )


def _complete_v4_confirmation(
    workspace: SyntheticReplayWorkspace,
    row: Mapping[str, Any],
    *,
    trace_manifest_path: Path,
    trace_manifest: Mapping[str, Any],
    scenario: SyntheticScenario | None = None,
) -> bool:
    """Independently replay the exact v4 proof chain for a confirmation.

    Schema tags and mutually consistent caller-supplied hashes are not proof.
    The evaluator regenerates provider certificates and Checker results from
    the sealed authority input, reduces closure again, and requires both
    persisted authority projections to equal that deterministic result.
    """

    issue = _confirmation_issue(row)
    occurrence_binding = _validated_occurrence_binding(row)
    if occurrence_binding is None or not _trace_binds_occurrences(
        workspace,
        row,
        occurrence_binding,
        trace_manifest_path=trace_manifest_path,
        trace_manifest=trace_manifest,
    ):
        return False
    required = (
        "proof_kernel_input",
        "proof_kernel_frozen_state",
        "proof_kernel_closure_evaluation",
        "proof_kernel_promotion_certificate",
    )
    if any(not isinstance(issue.get(key), Mapping) for key in required):
        return False
    recorded = issue.get("terminal_authority_decision")
    engine_recorded = issue.get("proof_kernel_terminal_authority_decision")
    if not (
        isinstance(recorded, Mapping)
        and recorded.get("schema_version") == TERMINAL_AUTHORITY_DECISION_V4
        and isinstance(engine_recorded, Mapping)
        and engine_recorded.get("schema_version") == TERMINAL_AUTHORITY_DECISION_V4
        and dict(recorded) == dict(engine_recorded)
    ):
        return False
    try:
        evaluator = TerminalAuthorityEvaluator()
        # Proof providers and checker adapters are permitted to normalize their
        # input while evaluating it.  Replay validation must remain a read-only
        # operation over the frozen report, so each evaluator receives its own
        # deep copy of the sealed issue.
        audited = evaluator.evaluate(copy.deepcopy(dict(issue)), operation="audit").to_dict()
        replayed = evaluator.replay(copy.deepcopy(dict(issue)), {})
    except Exception:
        return False
    if audited != replayed or audited != dict(recorded):
        return False
    if not (
        audited.get("terminal") is True
        and audited.get("disposition") == "confirmed"
        and audited.get("integrity_status") == "verified"
        and isinstance(audited.get("promotion_certificate"), Mapping)
    ):
        return False
    if not _proof_origin_binds_occurrences(issue, occurrence_binding):
        return False
    if scenario is not None and not _proof_binds_scenario(workspace, row, scenario):
        return False

    cluster_uid = str(issue.get("validation_cluster_uid") or "")
    evidence_pack = issue.get("evidence_pack")
    pack_cluster_uid = str(
        evidence_pack.get("validation_cluster_uid") if isinstance(evidence_pack, Mapping) else ""
    )
    return bool(
        cluster_uid
        and audited.get("validation_cluster_uid") == cluster_uid
        and (not pack_cluster_uid or pack_cluster_uid == cluster_uid)
        and str(issue.get("candidate_disposition") or "confirmed").lower() == "confirmed"
    )


_FUNCTION_RESULT_KEYS = frozenset(
    {
        "function",
        "entry_key",
        "entry_identity",
        "entry_file_path",
        "entry_signature",
        "verdict",
        "issue_count",
        "audit_observation_count",
        "duration_seconds",
        "entry_budget_seconds",
        "entry_budget_exceeded",
        "entry_budget_overrun_seconds",
        "budget_exhaustion_policy",
        "context_tokens",
        "cumulative_prompt_tokens",
        "cumulative_completion_tokens",
        "cumulative_total_tokens",
        "validation_performance",
        "error",
    }
)


def _validated_function_result_set(
    workspace: SyntheticReplayWorkspace,
    functions: Sequence[Any],
) -> bool:
    expected = {
        entry
        for scenario in workspace.scenarios
        for entry in (scenario.vulnerable_entry, scenario.protected_entry)
    }
    if len(functions) != len(expected):
        return False
    matched: set[str] = set()
    for raw in functions:
        if not isinstance(raw, Mapping) or set(raw) != _FUNCTION_RESULT_KEYS:
            return False
        if any(
            not isinstance(raw.get(key), str)
            for key in (
                "function",
                "entry_key",
                "entry_identity",
                "entry_file_path",
                "entry_signature",
                "verdict",
                "budget_exhaustion_policy",
                "error",
            )
        ):
            return False
        integer_fields = (
            "issue_count",
            "audit_observation_count",
            "context_tokens",
            "cumulative_prompt_tokens",
            "cumulative_completion_tokens",
            "cumulative_total_tokens",
        )
        if any(_strict_nonnegative_integer(raw.get(key)) is None for key in integer_fields):
            return False
        numeric_fields = (
            "duration_seconds",
            "entry_budget_seconds",
            "entry_budget_overrun_seconds",
        )
        if any(
            isinstance(raw.get(key), bool)
            or not isinstance(raw.get(key), (int, float))
            or cast(float, raw.get(key)) < 0
            for key in numeric_fields
        ):
            return False
        if (
            not isinstance(raw.get("entry_budget_exceeded"), bool)
            or not isinstance(raw.get("validation_performance"), Mapping)
            or raw.get("error") != ""
        ):
            return False
        matches = [value for value in expected if _entry_matches(raw.get("function"), value)]
        if len(matches) != 1 or matches[0] in matched:
            return False
        if raw.get("entry_identity") and not _entry_matches(raw.get("entry_identity"), matches[0]):
            return False
        matched.add(matches[0])
    return matched == expected


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
        or _strict_nonnegative_integer(summary.get("functions_failed")) != 0
        or _strict_nonnegative_integer(summary.get("functions_completed"))
        != len(workspace.scenarios) * 2
        or not _validated_function_result_set(workspace, functions)
    ):
        raise SyntheticReplayError("scan", "anonymous_qualification_failed")

    # Usage identity and all six conservation dimensions are prerequisites for
    # interpreting semantic success.  A protected-side finding must never hide
    # an unverifiable provider exchange or a broken accounting ledger.
    usage_path, events = _usage_events(workspace)
    usage = _validate_usage(report, events, workspace.provider_contract)
    conservation, trace_manifest_path, trace_manifest = _validate_report_conservation(
        workspace,
        report,
        events,
        usage,
        usage_path=usage_path,
    )
    for state in terminal_states:
        if not isinstance(state, Mapping):
            raise SyntheticReplayError("scan", "terminal_state_inconsistent")
        if state.get("candidate_disposition") == "confirmed" and not _complete_v4_confirmation(
            workspace,
            state,
            trace_manifest_path=trace_manifest_path,
            trace_manifest=trace_manifest,
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
            # The authority replay above is intentionally single-use: some
            # provider/checker implementations maintain audit state while
            # replaying a sealed proof.  Scenario attribution is a pure,
            # independently re-extracted binding check and must not invoke the
            # authority a second time.
            and _proof_binds_scenario(workspace, row, scenario)
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
                [
                    {
                        "model_input": scenario.model_input(),
                        "proof_contract": scenario.proof_contract(),
                    }
                    for scenario in workspace.scenarios
                ]
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
