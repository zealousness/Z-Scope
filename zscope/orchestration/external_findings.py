"""Passive, bounded JSON/SARIF observations for the shared candidate registrar.

This module never starts a scanner or resolves a URI. Caller-supplied identities
describe the approved import, not vendor access entitlement. External claims are
untrusted observations; neither an import nor its serialized copy grants proof.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Literal, Sequence

from ..reporting.attribution import FindingAttribution
from ..tools.source_access import ProjectSourceAccess, SourceAccessError
from ..tools.symbols import project_relative_path_error
from .candidate_envelope import CandidateEnvelope
from .candidates import CandidateRegistrar, CandidateRegistrationResult

IMPORT_SCHEMA = "zscope.external-findings.v1"
MAX_PAYLOAD_BYTES = 2 * 1024 * 1024
MAX_FINDINGS = 1000
MAX_FILES = 2000
MAX_RUNS = 16
MAX_SOURCE_BYTES = 32 * 1024 * 1024


class ExternalImportError(ValueError):
    """Stable diagnostic without echoing imported text or source contents."""


def _object(value: Any, required: set[str], optional: set[str] | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or not required <= value.keys():
        raise ExternalImportError("invalid_object")
    if value.keys() - required - (optional or set()):
        raise ExternalImportError("unsupported_field")
    return value


def _text(value: Any, *, limit: int = 256, empty: bool = False) -> str:
    if (
        not isinstance(value, str)
        or len(value) > limit
        or (not empty and not value.strip())
        or any(ord(ch) < 32 and ch not in "\n\t" for ch in value)
    ):
        raise ExternalImportError("invalid_text")
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise ExternalImportError("invalid_text_encoding") from None
    return value


def _array(value: Any, limit: int) -> list[Any]:
    if not isinstance(value, list) or len(value) > limit:
        raise ExternalImportError("array_budget_or_shape")
    return value


def _positive(value: Any) -> int:
    if type(value) is not int or not 1 <= value <= 10_000_000:
        raise ExternalImportError("invalid_position")
    return value


def _path(value: Any) -> str:
    path = _text(value, limit=512)
    if (
        project_relative_path_error(path)
        or any(ch in path for ch in "\\:%?#")
        or str(PurePosixPath(path)) != path
        or path == "."
    ):
        raise ExternalImportError("invalid_source_path")
    return path


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    ).hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ExternalImportError("duplicate_json_key")
        result[key] = value
    return result


@dataclass(frozen=True)
class ExternalContext:
    project_id: str
    revision: str
    build_identity: str
    rule_identity: str


@dataclass(frozen=True)
class ExternalSourceFile:
    path: str
    sha256: str


@dataclass(frozen=True)
class ExternalCoverage:
    status: str
    files: tuple[ExternalSourceFile, ...]


@dataclass(frozen=True)
class ExternalFinding:
    path: str
    line: int
    column: int
    defect_class: str
    function: str
    resource: str
    rule_id: str
    message: str
    evidence: tuple[str, ...]
    external_claims_sha256: str


@dataclass(frozen=True)
class ExternalRun:
    context: ExternalContext
    tool: str
    version: str
    coverage: ExternalCoverage
    findings: tuple[ExternalFinding, ...]


@dataclass(frozen=True)
class ExternalImportBatch:
    runs: tuple[ExternalRun, ...]
    payload_sha256: str
    format: str


@dataclass(frozen=True)
class ExternalImportStatistics:
    input_findings: int
    unique_candidate_sites: int
    same_source_duplicates: int
    cross_tool_overlap_groups: int
    needs_review: int


@dataclass(frozen=True)
class ExternalRegistration:
    registration: CandidateRegistrationResult
    statistics: ExternalImportStatistics
    issues: tuple[dict[str, Any], ...]
    batches: tuple[ExternalImportBatch, ...]


class ExternalFindingsImporter:
    """An explicit offline boundary; no CLI, config, network or proof authority.

    JSON uses IMPORT_SCHEMA and one run. SARIF 2.1.0 uses a deliberately small
    inline subset: tool.driver, results and run.properties.zscope. The latter
    contains context and coverage. Unsupported external artifacts are rejected.
    All coverage entries are source files, with current SHA-256 values; complete
    coverage remains a source assertion, never a program coverage guarantee.
    """

    def __init__(
        self,
        source_access: ProjectSourceAccess,
        *,
        project_id: str,
        revision: str,
        build_identity: str,
        rule_identity: str,
        allowed_tools: Sequence[tuple[str, str]],
    ) -> None:
        self.source_access = source_access
        self.context = ExternalContext(
            *(_text(v) for v in (project_id, revision, build_identity, rule_identity))
        )
        self.allowed_tools = frozenset(
            (_text(name), _text(version)) for name, version in allowed_tools
        )
        if not self.allowed_tools:
            raise ExternalImportError("approved_tool_version_required")

    def parse(
        self, payload: bytes, *, format: Literal["json", "sarif"] = "json"
    ) -> ExternalImportBatch:
        if not isinstance(payload, bytes) or len(payload) > MAX_PAYLOAD_BYTES:
            raise ExternalImportError("payload_budget_or_shape")
        try:
            value = json.loads(payload.decode("utf-8"), object_pairs_hook=_unique_object)
            pending = [(value, 0)]
            count = 0
            while pending:
                item, depth = pending.pop()
                count += 1
                if depth > 24 or count > 100_000:
                    raise ExternalImportError("json_structure_budget")
                if isinstance(item, dict):
                    pending.extend((v, depth + 1) for v in item.values())
                elif isinstance(item, list):
                    pending.extend((v, depth + 1) for v in item)
                elif isinstance(item, float):
                    raise ExternalImportError("unsupported_number")
            runs: tuple[ExternalRun, ...]
            if format == "json":
                root = _object(value, {"schema_version", "context", "tool", "coverage", "findings"})
                if root["schema_version"] != IMPORT_SCHEMA:
                    raise ExternalImportError("unsupported_schema")
                runs = (self._json_run(root),)
            elif format == "sarif":
                root = _object(value, {"version", "runs"}, {"$schema"})
                if root["version"] != "2.1.0":
                    raise ExternalImportError("unsupported_sarif_version")
                runs = tuple(self._sarif_run(run) for run in _array(root["runs"], MAX_RUNS))
            else:
                raise ExternalImportError("unsupported_format")
        except (UnicodeError, json.JSONDecodeError, RecursionError, OverflowError):
            raise ExternalImportError("invalid_json") from None
        batch = ExternalImportBatch(runs, hashlib.sha256(payload).hexdigest(), format)
        self._validate_runs(batch.runs)
        return batch

    def _binding(self, value: Any, tool: Any) -> tuple[ExternalContext, str, str]:
        context = _object(value, {"project_id", "revision", "build_identity", "rule_identity"})
        binding = ExternalContext(**{key: _text(val) for key, val in context.items()})
        if binding != self.context:
            raise ExternalImportError("context_mismatch")
        source = _object(tool, {"name", "version"})
        name, version = _text(source["name"]), _text(source["version"])
        if (name, version) not in self.allowed_tools:
            raise ExternalImportError("unapproved_tool_version")
        return binding, name, version

    @staticmethod
    def _coverage(value: Any) -> ExternalCoverage:
        coverage = _object(value, {"status", "files"})
        status = _text(coverage["status"])
        if status not in {"complete", "partial", "unknown"}:
            raise ExternalImportError("invalid_coverage")
        files = []
        for item in _array(coverage["files"], MAX_FILES):
            row = _object(item, {"path", "sha256"})
            digest = _text(row["sha256"])
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ExternalImportError("invalid_source_digest")
            files.append(ExternalSourceFile(_path(row["path"]), digest))
        if len({item.path for item in files}) != len(files):
            raise ExternalImportError("duplicate_coverage_path")
        return ExternalCoverage(status, tuple(sorted(files, key=lambda item: item.path)))

    @staticmethod
    def _finding(value: Any) -> ExternalFinding:
        item = _object(
            value,
            {
                "path",
                "line",
                "defect_class",
                "function",
                "resource",
                "rule_id",
                "message",
                "evidence",
            },
            {"column", "verdict", "proof", "validator_contract", "attribution"},
        )
        defect = _text(item["defect_class"])
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", defect):
            raise ExternalImportError("invalid_defect_class")
        claims = {
            key: item[key]
            for key in ("verdict", "proof", "validator_contract", "attribution")
            if key in item
        }
        return ExternalFinding(
            _path(item["path"]),
            _positive(item["line"]),
            _positive(item.get("column", 1)),
            defect,
            _text(item["function"]),
            _text(item["resource"]),
            _text(item["rule_id"]),
            _text(item["message"], limit=4096),
            tuple(_text(v, limit=4096) for v in _array(item["evidence"], 16)),
            _digest(claims),
        )

    def _json_run(self, value: dict[str, Any]) -> ExternalRun:
        context, name, version = self._binding(value["context"], value["tool"])
        return ExternalRun(
            context,
            name,
            version,
            self._coverage(value["coverage"]),
            tuple(self._finding(item) for item in _array(value["findings"], MAX_FINDINGS)),
        )

    def _sarif_run(self, value: Any) -> ExternalRun:
        run = _object(value, {"tool", "properties", "results"})
        tool = _object(run["tool"], {"driver"})
        if not isinstance(tool["driver"], dict):
            raise ExternalImportError("invalid_tool_driver")
        driver = tool["driver"]
        props = _object(run["properties"], {"zscope"})
        binding = _object(props["zscope"], {"context", "coverage"})
        context, name, version = self._binding(
            binding["context"],
            {
                "name": driver.get("name"),
                "version": driver.get("semanticVersion", driver.get("version")),
            },
        )
        findings = []
        for raw in _array(run["results"], MAX_FINDINGS):
            result = _object(
                raw, {"ruleId", "message", "locations", "properties"}, {"level", "kind"}
            )
            message = _object(result["message"], {"text"})
            locations = _array(result["locations"], 1)
            if len(locations) != 1:
                raise ExternalImportError("single_location_required")
            location = _object(locations[0], {"physicalLocation"})
            physical = _object(location["physicalLocation"], {"artifactLocation", "region"})
            artifact = _object(physical["artifactLocation"], {"uri"})
            region = _object(physical["region"], {"startLine"}, {"startColumn"})
            props = _object(
                result["properties"],
                {"zscope"},
                {"verdict", "proof", "validator_contract", "attribution"},
            )
            details = _object(props["zscope"], {"defect_class", "function", "resource", "evidence"})
            findings.append(
                self._finding(
                    {
                        **details,
                        "path": artifact["uri"],
                        "line": region["startLine"],
                        "column": region.get("startColumn", 1),
                        "rule_id": result["ruleId"],
                        "message": message["text"],
                        "verdict": {
                            "kind": result.get("kind"),
                            "level": result.get("level"),
                            "claims": {k: v for k, v in props.items() if k != "zscope"},
                        },
                    }
                )
            )
        return ExternalRun(
            context, name, version, self._coverage(binding["coverage"]), tuple(findings)
        )

    def _validate_runs(self, runs: Sequence[ExternalRun]) -> None:
        if not 1 <= len(runs) <= MAX_RUNS or sum(len(r.findings) for r in runs) > MAX_FINDINGS:
            raise ExternalImportError("run_or_finding_budget")
        if sum(len(r.coverage.files) for r in runs) > MAX_FILES:
            raise ExternalImportError("source_file_budget")
        known: dict[str, tuple[str, list[str], tuple[int, ...]]] = {}
        total = 0
        for run in runs:
            if run.context != self.context or (run.tool, run.version) not in self.allowed_tools:
                raise ExternalImportError("context_or_tool_mismatch")
            # Revalidate even directly constructed dataclasses. These are data,
            # not capabilities, and may be copied or decoded by another caller.
            coverage = self._coverage(
                {
                    "status": run.coverage.status,
                    "files": [asdict(item) for item in run.coverage.files],
                }
            )
            allowed = {item.path: item.sha256 for item in coverage.files}
            for item in coverage.files:
                if item.path not in known:
                    try:
                        text, digest, identity = self.source_access.read(item.path)
                    except SourceAccessError as exc:
                        raise ExternalImportError("source_" + exc.reason) from None
                    total += len(text.encode("utf-8"))
                    if total > MAX_SOURCE_BYTES:
                        raise ExternalImportError("source_byte_budget")
                    known[item.path] = digest, text.splitlines(), identity
                if known[item.path][0] != item.sha256:
                    raise ExternalImportError("stale_source")
            for finding in run.findings:
                row = asdict(finding)
                claims_digest = row.pop("external_claims_sha256")
                if not isinstance(claims_digest, str) or not re.fullmatch(
                    r"[0-9a-f]{64}", claims_digest
                ):
                    raise ExternalImportError("invalid_claim_digest")
                row["evidence"] = list(finding.evidence)
                self._finding(row)
                if _path(finding.path) not in allowed:
                    raise ExternalImportError("finding_outside_coverage")
                lines = known[finding.path][1]
                if (
                    _positive(finding.line) > len(lines)
                    or _positive(finding.column) > len(lines[finding.line - 1]) + 1
                ):
                    raise ExternalImportError("position_outside_source")
        # Detect replacement of an earlier file while later files were read.
        for path, (_, _, identity) in known.items():
            try:
                if self.source_access.identity(path) != identity:
                    raise ExternalImportError("source_changed")
            except SourceAccessError as exc:
                raise ExternalImportError("source_" + exc.reason) from None

    def register(
        self,
        batch: ExternalImportBatch | Sequence[ExternalImportBatch],
        registrar: CandidateRegistrar,
    ) -> ExternalRegistration:
        batches = (batch,) if isinstance(batch, ExternalImportBatch) else tuple(batch)
        if not batches or len(batches) > MAX_RUNS:
            raise ExternalImportError("batch_budget")
        if registrar.ledger.is_frozen:
            raise RuntimeError("candidate ledger is frozen")
        runs = tuple(run for item in batches for run in item.runs)
        if (
            registrar.project_id != self.context.project_id
            or registrar.revision != self.context.revision
            or Path(registrar.project_root).resolve() != self.source_access.root
            or registrar.ledger.project_id != registrar.project_id
            or registrar.ledger.revision != registrar.revision
            or Path(registrar.ledger.project_root).resolve() != self.source_access.root
        ):
            raise ExternalImportError("registrar_context_mismatch")
        self._validate_runs(runs)
        run_artifacts: list[tuple[ExternalRun, dict[str, str]]] = []
        for item in batches:
            if item.format not in {"json", "sarif"} or not re.fullmatch(
                r"[0-9a-f]{64}", item.payload_sha256
            ):
                raise ExternalImportError("invalid_artifact_identity")
            for run in item.runs:
                run_artifacts.append((run, {"format": item.format, "sha256": item.payload_sha256}))
        groups: dict[str, dict[str, Any]] = {}
        source_counts: Counter[tuple[str, str, str]] = Counter()
        group_tools: dict[str, set[str]] = defaultdict(set)
        for run, artifact in run_artifacts:
            coverage = {
                "status": run.coverage.status,
                "manifest_sha256": _digest(asdict(run.coverage)),
                "declared_file_count": len(run.coverage.files),
            }
            file_digests = {item.path: item.sha256 for item in run.coverage.files}
            for finding in run.findings:
                issue: dict[str, Any] = {
                    "location": f"{finding.path}:{finding.line}",
                    "file": finding.path,
                    "line": finding.line,
                    "column": finding.column,
                    "function": finding.function,
                    "defect_class": finding.defect_class,
                    "resource_signature": finding.resource,
                    "description": "Review an unconfirmed external observation.",
                    "candidate_source": "external_offline",
                    "evidence_completeness": "unknown",
                    "validator_contract": {
                        "external_import": IMPORT_SCHEMA,
                        "build_identity": self.context.build_identity,
                        "rule_identity": self.context.rule_identity,
                        "source_sha256": file_digests[finding.path],
                    },
                }
                uid = CandidateEnvelope.from_issue(
                    issue,
                    project_id=self.context.project_id,
                    project_root=str(self.source_access.root),
                    revision=self.context.revision,
                ).candidate_uid
                source_counts[(uid, run.tool, run.version)] += 1
                group_tools[uid].add(run.tool)
                observation = {
                    "kind": "external_offline",
                    "tool": run.tool,
                    "version": run.version,
                    "rule_id": finding.rule_id,
                    "message": finding.message,
                    "evidence": list(finding.evidence),
                    "external_claims_sha256": finding.external_claims_sha256,
                    "coverage": coverage,
                    "coverage_authority": "source_reported",
                    "source_path": finding.path,
                    "source_sha256": file_digests[finding.path],
                    "source_assurance": "source_only",
                    "proof_authority": "none",
                    "assurance_reason": (
                        "build_unverifiable"
                        if self.context.build_identity in {"unknown", "unavailable", "unverifiable"}
                        else "external_observation_unverified"
                    ),
                    "artifact": artifact,
                    "context": asdict(run.context),
                }
                if uid not in groups:
                    issue["evidence_pack"] = {
                        "external_observations": [],
                        "proof_status": "unproven",
                    }
                    groups[uid] = issue
                observations = groups[uid]["evidence_pack"]["external_observations"]
                if observation not in observations:
                    observations.append(observation)
        issues = tuple(groups[key] for key in sorted(groups))
        for issue in issues:
            observations = issue["evidence_pack"]["external_observations"]
            issue["attribution"] = FindingAttribution(
                discovered_by=("backend_signal",),
                discovery_details=tuple(
                    {
                        "kind": "backend_signal",
                        "source_id": "external_offline",
                        "tool": item["tool"],
                        "version": item["version"],
                    }
                    for item in observations
                ),
            ).to_dict()
        result = registrar.register_issues(
            issues, source="external_offline", force_unconfirmed=True
        )
        return ExternalRegistration(
            result,
            ExternalImportStatistics(
                sum(len(r.findings) for r in runs),
                len(groups),
                sum(n - 1 for n in source_counts.values()),
                sum(len(names) > 1 for names in group_tools.values()),
                len(groups),
            ),
            issues,
            batches,
        )
