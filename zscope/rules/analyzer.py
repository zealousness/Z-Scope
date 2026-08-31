"""
Rule-driven analyzer for Z-SCOPE.
Runs Joern rules, then validates findings with LLM ValidatorAgent.
"""

import datetime
import hashlib
import json
import logging
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..common.issue_identity import canonical_issue_key
from ..config.config import ZScopeConfig
from ..config.user_config_store import UserConfigStore
from ..core.validation.pipeline import ValidationPipeline
from ..core.validation.runner import ValidationRunner
from ..retrieval.code_index import CodeIndex
from ..snapshots.store import SnapshotStore
from .engine import RuleEngine, RuleMatch
from .catalog import EffectiveRuleSet, serialize_effective_rules
from .extensions import preflight_rules
from ..orchestration.agent_policy import attach_agent_contract, tool_policy_for_agent
from ..orchestration.candidates import CandidateLedger, CandidateRegistrar
from ..orchestration.decision_trace import ensure_decision_trace_store
from ..orchestration.specs import SpecRegistry
from ..reporting.attribution import FindingAttribution
from ..reporting.report import FinalReport, Issue, ReportGenerator
from ..reporting.schema import apply_report_schema_v2
from ..reporting.assembler import ReportAssembler
from ..reporting.views import build_report_views
from ..framework.llm_client import LLMClient
from ..framework.llm_usage import (
    ensure_scan_token_usage_ledger,
    scan_token_usage_snapshot,
)
from ..orchestration.rollout import rollout_runtime_policy
from .._version import __version__

logger = logging.getLogger(__name__)


class RuleDrivenAnalyzer:
    """Runs Joern rules then validates with LLM agent."""

    def __init__(
        self,
        config: ZScopeConfig,
        code_index: CodeIndex,
        user_config: Optional[UserConfigStore] = None,
    ):
        self.config = config
        # Third-party/direct construction must not bypass the same strict rule
        # preflight used by CLI, Web, MCP, and batch scans.
        self.spec_registry = SpecRegistry(project_root=config.project.project_root)
        self.effective_rules = preflight_rules(config, spec_registry=self.spec_registry)
        self.code_index = code_index
        db_dir = (
            Path(config.analysis.user_config_db)
            if config.analysis.user_config_db
            else Path(config.analysis.snapshot_dir)
        )
        self.user_config = user_config or UserConfigStore(db_dir)
        self.snapshot_store = SnapshotStore.from_config(config)
        self.validation_pipeline = ValidationPipeline(self.user_config)
        self.llm_clients: Dict[str, LLMClient] = {}
        token_usage_ledger = ensure_scan_token_usage_ledger(config)
        for name, llm_cfg in config.llms.items():
            self.llm_clients[name] = LLMClient(
                api_key=llm_cfg.api_key,
                base_url=getattr(llm_cfg, "base_urls", None) or llm_cfg.base_url,
                models=llm_cfg.models,
                timeout=llm_cfg.timeout,
                max_retries=llm_cfg.max_retries,
                retry_until_available=getattr(llm_cfg, "retry_until_available", False),
                max_tokens=llm_cfg.max_tokens,
                base_url_rate_limit_per_minute=getattr(
                    llm_cfg, "base_url_rate_limit_per_minute", 0
                ),
                base_url_max_concurrent_requests=getattr(
                    llm_cfg, "base_url_max_concurrent_requests", 0
                ),
                global_max_concurrent_requests=config.concurrency.llm_max_inflight,
                supports_structured_output=getattr(llm_cfg, "supports_structured_output", False),
                require_exact_response_model=getattr(
                    llm_cfg, "require_exact_response_model", False
                ),
                token_usage_ledger=token_usage_ledger,
                llm_ref=name,
            )
        self.report_generator = ReportGenerator(config.project.project_root)
        self._last_validation_state: Dict[str, Any] = {}

        from ..retrieval.joern_backend import JoernBackend

        if not isinstance(code_index.backend, JoernBackend):
            raise ValueError("Rule-driven mode requires Joern CPG backend")
        self.rule_engine = RuleEngine(code_index.backend.joern_client, self.user_config)
        self.validation_runner = self._make_validation_runner()

    def run(self, custom_script_dir: Optional[str] = None) -> Dict[str, Any]:
        """Execute rule-driven analysis pipeline."""
        logger.info("Starting rule-driven analysis")
        all_matches: List[RuleMatch] = []

        # 1. Joern built-in scan
        logger.info("Running Joern built-in scan...")
        all_matches.extend(self.rule_engine.run_builtin_scan())

        # 2. Paired function checks
        logger.info("Running paired function checks...")
        all_matches.extend(self.rule_engine.run_paired_function_checks())

        # 3. Custom scripts
        if custom_script_dir and Path(custom_script_dir).is_dir():
            logger.info("Running custom scripts from %s", custom_script_dir)
            all_matches.extend(self.rule_engine.run_custom_scripts(custom_script_dir))

        logger.info("Total rule matches: %d", len(all_matches))
        if not all_matches:
            return self._build_report([], [])

        # 4. Group only for audit notes. Validation itself is scan-wide so
        # V3 top-percent limits and validation-cluster deduplication are not
        # accidentally reset for every function.
        by_func: Dict[str, List[RuleMatch]] = {}
        for m in all_matches:
            by_func.setdefault(m.func_name, []).append(m)

        validated_issues = self._validate_matches(
            "[rule-driven]",
            [match.to_dict() for match in all_matches],
        )
        notes = [
            f"Checked {func_name}: {len(matches)} rule matches"
            for func_name, matches in by_func.items()
        ]
        for note in self._last_validation_state.get("notes") or []:
            text = str(note)
            if text and text not in notes:
                notes.append(text)

        # 5. Filter false positives
        validated_issues = self._filter_false_positives(validated_issues)

        return self._build_report(validated_issues, notes)

    def close(self) -> None:
        seen: set[int] = set()
        for client in getattr(self, "llm_clients", {}).values():
            client_id = id(client)
            if client_id in seen:
                continue
            seen.add(client_id)
            close_client = getattr(client, "close", None)
            if callable(close_client):
                close_client()

    def _make_validation_runner(self) -> ValidationRunner:
        runner = ValidationRunner(
            config=self.config,
            llm_clients=self.llm_clients,
            validation_pipeline=self.validation_pipeline,
            code_index=self.code_index,
            snapshot_store=self.snapshot_store,
            get_tools=self._get_tools,
            tool_policy_for_agent=self._tool_policy_for_agent,
            attach_agent_contract=self._attach_agent_contract,
            remember_validation_result=self._remember_validation_result,
        )
        factory = getattr(self, "_proof_engine_agent_factory", None)
        if callable(factory):
            runner.proof_engine_agent_factory = factory
        return runner

    def _get_tools(self, agent_name: Optional[str] = None) -> List[Any]:
        """Build the same bounded read-only Proof Engine tools as the main pipeline."""

        from ..tools.registry import build_tool_registry

        include_advanced = getattr(self.code_index, "backend_name", "") in {
            "joern",
            "svf",
            "unified",
        }
        tools = list(
            build_tool_registry(
                self.code_index,
                self.snapshot_store,
                self.user_config,
                include_advanced=include_advanced,
            ).values()
        )
        if not agent_name:
            return tools
        agent_spec = self.spec_registry.get_agent(agent_name)
        allowed = set(agent_spec.tools) if agent_spec and agent_spec.tools else set()
        if allowed:
            tools = [tool for tool in tools if tool.name in allowed]
        policy = self._tool_policy_for_agent(agent_name)
        return [tool for tool in tools if policy.is_tool_visible(tool.name)]

    def _tool_policy_for_agent(self, agent_name: Optional[str]) -> Any:
        return tool_policy_for_agent(self.spec_registry, self.config, agent_name)

    def _attach_agent_contract(self, context: Dict[str, Any], agent_name: str) -> None:
        visible_tools: List[str] = []
        scan = getattr(self.config, "scan", None)
        if str(getattr(scan, "depth", "fast") or "fast").lower() in {
            "balanced",
            "deep",
        }:
            visible_tools = [tool.name for tool in self._get_tools(agent_name)]
        attach_agent_contract(
            context,
            agent_name,
            self.spec_registry,
            visible_tool_names=visible_tools,
        )

    def _remember_validation_result(self, issue: Dict[str, Any], status: str) -> None:
        status_key = str(status or "").strip().lower()
        if status_key in {"", "rejected", "engine_failed"}:
            return
        dedup_key = str(issue.get("dedup_key") or canonical_issue_key(issue))
        if not dedup_key:
            return
        memory_status = {
            "validated": "verified",
            "needs_review": "uncertain",
            "uncertain": "uncertain",
        }.get(status_key, status_key)
        try:
            self.validation_pipeline.review_memory.record_validator_memory(
                dedup_key,
                memory_status,
                issue,
            )
        except Exception as exc:
            logger.debug(
                "Failed to persist rule-driven validation memory for %s: %s",
                issue.get("candidate_uid"),
                exc,
            )

    def _get_function_impl(self, func_name: str) -> Optional[Dict[str, Any]]:
        getter = getattr(self.code_index, "get_function_impl", None)
        if not callable(getter):
            return None
        try:
            result = getter(func_name, warn_missing=False)
        except TypeError:
            result = getter(func_name)
        except Exception:
            return None
        return result if isinstance(result, dict) else None

    def _validate_matches(
        self, func_name: str, issues: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Register, freeze, and validate each backend obligation exactly once.

        Joern rule IDs are detector provenance, not validation identity.  All
        raw signals therefore cross the same CandidateRegistrar/CandidateLedger
        boundary as the main scan before a validation group is constructed.
        This lets equivalent rules share one Validator future while retaining
        every detector alias in the canonical evidence payload.
        """

        canonical = [
            self._canonicalize_rule_issue(issue, validation_enabled=True) for issue in issues
        ]
        project_root = str(getattr(self.config.project, "project_root", "") or "")
        project_id = str(
            getattr(self.config.project, "project_id", "")
            or (Path(project_root).name if project_root else "rule-driven")
        )
        revision = str(
            getattr(self.config.project, "source_revision", "")
            or getattr(self.config.analysis, "source_revision", "")
            or ""
        )
        ledger = CandidateLedger(
            project_id=project_id,
            project_root=project_root,
            revision=revision,
            decision_trace_store=ensure_decision_trace_store(self.config),
        )
        registrar = CandidateRegistrar(
            ledger,
            project_id=project_id,
            project_root=project_root,
            revision=revision,
        )
        registration = registrar.register_issues(
            canonical,
            source="backend_signal:rule_driven",
            default_entry_identity=func_name or "__project__",
        )
        # Rule collection is complete at this point.  Validation must consume
        # a frozen snapshot so no late producer can evade the queue.
        ledger.freeze()
        self._last_candidate_ledger = ledger
        pending = self._validation_groups_from_ledger(ledger)
        merged_count = max(
            0,
            registration.registered_occurrence_count - len(pending),
        )
        context_code = ""
        if func_name and func_name != "[rule-driven]":
            impl = self._get_function_impl(func_name)
            context_code = str(impl.get("code") or "") if impl else ""
        state: Dict[str, Any] = {
            "pending_new_issues": pending,
            "agent_context": {
                "func_name": func_name,
                "code": context_code,
                "entry_custom_prompt": "",
            },
            "entry_func": func_name,
            "issues": [],
            "observations": [],
            "notes": (
                [
                    f"Merged {merged_count} equivalent backend signal(s) into "
                    f"{len(pending)} frozen validation group(s)."
                ]
                if merged_count
                else []
            ),
            "candidate_ledger": ledger,
            "candidate_discovery_frozen": True,
            "scan_level_raw_occurrence_count": registration.registered_occurrence_count,
            "candidate_registrar_submitted_count": registration.submitted_issue_count,
            "candidate_registrar_registered_occurrence_count": (
                registration.registered_occurrence_count
            ),
            "candidate_registrar_new_validation_group_count": (
                registration.new_validation_group_count
            ),
            "eligible_validation_group_count": len(pending),
            "eligible_duplicate_request_count": merged_count,
            "coalesced_duplicate_request_count": merged_count,
            "validation_group_merged_count": merged_count,
        }
        runner = getattr(self, "validation_runner", None)
        if runner is None:
            runner = self._make_validation_runner()
            self.validation_runner = runner
        runner.run(state)

        terminal = [
            issue
            for issue in pending
            if issue.get("candidate_disposition") or issue.get("validation_status")
        ]
        records_by_cluster = {record.validation_cluster_uid: record for record in ledger.records()}
        for issue in terminal:
            self._restore_backend_signal_attribution(issue)
            history = issue.get("validator_pass_history")
            if isinstance(history, list):
                issue["validator_invocation_count"] = len(history)
            elif issue.get("validator_evidence_slice_version"):
                issue["validator_invocation_count"] = 1
            record = records_by_cluster.get(str(issue.get("validation_cluster_uid") or ""))
            grouped_count = (record.duplicate_count + 1) if record is not None else 1
            issue["grouped_candidate_count"] = grouped_count
            issue["validation_group_alias_count"] = max(
                0,
                grouped_count - 1,
            )
            # ValidationRunner records the terminal issue before the
            # backend-only attribution cleanup above.  Re-project the cleaned
            # terminal payload into the Ledger without incrementing attempts.
            ledger.mark_issue_terminal(
                issue,
                disposition=str(issue.get("candidate_disposition") or "needs_review"),
                status=str(
                    issue.get("validation_status")
                    or issue.get("status")
                    or issue.get("candidate_disposition")
                    or "needs_review"
                ),
            )

        lifecycle = ledger.lifecycle_snapshot()
        ledger_summary = dict(lifecycle.get("summary") or {})

        self._last_validation_state = {
            key: value
            for key, value in state.items()
            if key
            not in {
                "agent_context",
                "issues",
                "observations",
                "pending_new_issues",
                "candidate_ledger",
            }
        }
        self._last_validation_state.update(
            {
                "candidate_discovery_frozen": True,
                "candidate_ledger_summary": ledger_summary,
                "candidate_lifecycle_records": list(lifecycle.get("records") or []),
                "candidate_terminal_states": list(lifecycle.get("outcomes") or []),
                "candidate_lifecycle_snapshot": lifecycle,
                "decision_trace_store": ensure_decision_trace_store(self.config),
            }
        )
        return terminal

    @staticmethod
    def _validation_groups_from_ledger(ledger: CandidateLedger) -> List[Dict[str, Any]]:
        """Project one open Validator input from every frozen Ledger group."""

        pending: List[Dict[str, Any]] = []
        for record in ledger.records():
            if record.record_role != "validation_obligation" or record.disposition:
                continue
            evidence = deepcopy(
                record.ticket.evidence if isinstance(record.ticket.evidence, dict) else {}
            )
            issue = deepcopy(evidence.pop("candidate_payload", {}) or {})
            if not issue:
                issue = {
                    "id": record.ticket.id,
                    "category": record.defect_class,
                    "defect_class": record.defect_class,
                    "description": record.ticket.task,
                    "source": record.ticket.origin,
                    "sink": record.ticket.sink,
                }
            issue["evidence_pack"] = evidence
            issue.setdefault("code_snippet", record.ticket.context_slice)
            issue.update(
                {
                    "candidate_schema_version": record.schema_version,
                    "candidate_uid": record.candidate_uid,
                    "history_key": record.history_key,
                    "obligation_uid": record.obligation_uid,
                    "decision_context_version": record.decision_context_version,
                    "evidence_hash": record.evidence_hash,
                    "decision_evidence_hash": record.decision_evidence_hash,
                    "validation_cluster_uid": record.validation_cluster_uid,
                    "context_signature": record.context_signature,
                    "occurrence_uid": (record.occurrence_uids[0] if record.occurrence_uids else ""),
                    "occurrence_uids": list(record.occurrence_uids),
                    "call_paths": [list(path) for path in record.call_paths],
                    "entry_paths": [list(path) for path in record.call_paths],
                    "entry_identity": (
                        record.occurrences[0].entry_identity
                        if record.occurrences
                        else str(issue.get("entry_identity") or "")
                    ),
                    "grouped_candidate_count": record.duplicate_count + 1,
                    "validation_group_alias_count": record.duplicate_count,
                }
            )
            evidence.update(
                {
                    "candidate_uid": record.candidate_uid,
                    "evidence_hash": record.evidence_hash,
                    "decision_evidence_hash": record.decision_evidence_hash,
                    "validation_cluster_uid": record.validation_cluster_uid,
                    "context_signature": record.context_signature,
                }
            )
            pending.append(issue)
        pending.sort(key=lambda item: str(item.get("validation_cluster_uid") or ""))
        return pending

    @staticmethod
    def _stable_rule_identity(issue: Dict[str, Any]) -> str:
        identity = {
            "signal_source": issue.get("signal_source") or "joern_rule_engine",
            "native_rule_id": issue.get("native_rule_id") or issue.get("rule_id"),
            "function": issue.get("function"),
            "file": issue.get("file_path") or issue.get("file"),
            "line": issue.get("line_number") or issue.get("line"),
            "category": issue.get("category"),
        }
        return hashlib.sha256(
            json.dumps(identity, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest()

    def _canonicalize_rule_issue(
        self,
        raw_issue: Dict[str, Any],
        *,
        validation_enabled: bool,
    ) -> Dict[str, Any]:
        issue = dict(raw_issue)
        digest = self._stable_rule_identity(issue)
        producer_occurrence_uid = str(issue.get("occurrence_uid") or f"OCC_JOERN_PRODUCER_{digest}")
        # Rule-engine payloads are observations, not lifecycle authorities.
        # Recompute every candidate/group identity at the shared Registrar
        # boundary so custom scripts cannot fragment the queue with a
        # detector-specific UID or smuggle in a terminal disposition.
        for field_name in (
            "candidate_schema_version",
            "candidate_uid",
            "candidate_id",
            "occurrence_uid",
            "history_key",
            "obligation_uid",
            "decision_context_version",
            "decision_fact_version",
            "evidence_hash",
            "decision_evidence_hash",
            "provenance_hash",
            "validation_cluster_uid",
            "context_signature",
            "run_issue_uid",
            "record_role",
            "candidate_disposition",
            "policy_disposition",
            "validation_status",
            "model_verdict",
            "status",
            "verdict",
            "confirmed",
            "is_confirmed",
            "terminal_disposition",
        ):
            issue.pop(field_name, None)
        file_path = str(issue.get("file_path") or issue.get("file") or "")
        line = int(issue.get("line_number") or issue.get("line") or 0)
        signal_source = str(issue.get("signal_source") or "joern_rule_engine")
        native_rule_id = str(issue.get("native_rule_id") or issue.get("rule_id") or "")
        semantic_identity = {
            "function": issue.get("function"),
            "file": file_path,
            "line": line,
            "category": issue.get("defect_class") or issue.get("category"),
            "source": issue.get("source"),
            "sink": issue.get("sink"),
            "resource": issue.get("resource_signature") or issue.get("resource"),
        }
        semantic_digest = hashlib.sha256(
            json.dumps(
                semantic_identity,
                ensure_ascii=False,
                sort_keys=True,
                default=str,
            ).encode("utf-8")
        ).hexdigest()
        fact_uid = f"fact:joern-obligation:{semantic_digest}"
        provenance_alias = {
            "signal_source": signal_source,
            "native_rule_id": native_rule_id,
            "rule_id": str(issue.get("rule_id") or native_rule_id),
            "rule_name": str(issue.get("rule_name") or ""),
            "producer_occurrence_uid": producer_occurrence_uid,
        }
        raw_positive = issue.get("positive_evidence")
        positive_evidence = list(raw_positive) if isinstance(raw_positive, list) else []
        raw_negative = issue.get("negative_evidence")
        negative_evidence = list(raw_negative) if isinstance(raw_negative, list) else []
        raw_fact_slice = issue.get("decision_fact_slice")
        decision_fact_slice = dict(raw_fact_slice) if isinstance(raw_fact_slice, dict) else {}
        raw_decision_facts = issue.get("decision_facts")
        decision_facts = list(raw_decision_facts) if isinstance(raw_decision_facts, list) else []
        issue.update(
            {
                "id": str(issue.get("id") or f"JOERN_{digest[:16]}"),
                "candidate_source": "backend_signal",
                "candidate_kind": "backend_signal",
                "signal_source": signal_source,
                "native_rule_id": native_rule_id,
                # The detector/rule label is provenance.  A same-category
                # signal at the same semantic site must not become a distinct
                # obligation merely because another native query found it.
                "defect_class": str(
                    issue.get("defect_class") or issue.get("category") or "backend_signal"
                ),
                "backend_signal_provenance_aliases": [provenance_alias],
                "file": file_path,
                "line": line,
                "location": str(issue.get("location") or f"{file_path}:{line}"),
                "subcategory": str(
                    issue.get("subcategory")
                    or issue.get("rule_name")
                    or issue.get("rule_id")
                    or "backend_signal"
                ),
                "description": str(
                    issue.get("description")
                    or issue.get("message")
                    or issue.get("rule_name")
                    or "Joern backend signal requires validation"
                ),
                "root_cause": str(issue.get("root_cause") or "Requires semantic validation"),
                "suggested_fix": str(issue.get("suggested_fix") or "Review the reported path"),
                "impact_level": str(issue.get("impact_level") or "medium"),
                "confidence": float(issue.get("confidence") or issue.get("score") or 0.5),
                "evidence_refs": [fact_uid],
                "positive_evidence": positive_evidence
                or [
                    str(
                        issue.get("description") or issue.get("rule_name") or "Joern backend signal"
                    )
                ],
                "negative_evidence": negative_evidence,
                "decision_fact_slice": decision_fact_slice
                or {
                    "coverage": "partial",
                    "fact_uids": [fact_uid],
                    "edge_uids": [],
                    "dependency_code_hashes": [],
                    "missing_fact_kinds": [],
                },
                "decision_facts": decision_facts
                or [
                    {
                        "fact_uid": fact_uid,
                        "kind": "backend_signal",
                        "payload": {
                            "signal_source": str(issue.get("signal_source") or "joern_rule_engine"),
                            "native_rule_id": str(
                                issue.get("native_rule_id") or issue.get("rule_id") or ""
                            ),
                            "message": str(
                                issue.get("description")
                                or issue.get("rule_name")
                                or "Joern backend signal"
                            ),
                            "location": str(issue.get("location") or f"{file_path}:{line}"),
                        },
                    }
                ],
                "validation_group_alias_count": 0,
                "validator_invocation_count": 0,
                "rejected_with_proof_count": 0,
                "cluster_fragmentation_count": 0,
                "attribution": FindingAttribution(
                    discovered_by=("backend_signal",),
                    discovery_details=(
                        {
                            "kind": "backend_signal",
                            "source_id": native_rule_id or signal_source,
                            "signal_source": signal_source,
                            "native_rule_id": native_rule_id,
                        },
                    ),
                ).to_dict(),
            }
        )
        if not validation_enabled:
            issue.update(
                {
                    "validation_status": "needs_review",
                    "candidate_disposition": "needs_review",
                    "policy_disposition": "needs_review",
                    "model_verdict": "uncertain",
                    "validation_reasoning": "Validator is disabled for this scan.",
                }
            )
        return issue

    @staticmethod
    def _restore_backend_signal_attribution(issue: Dict[str, Any]) -> None:
        """Keep Joern rule IDs as backend provenance, never deterministic discovery."""

        current = issue.get("attribution")
        current = current if isinstance(current, dict) else {}
        raw_decision_details = current.get("decision_details")
        decision_details = (
            dict(raw_decision_details) if isinstance(raw_decision_details, dict) else {}
        )
        aliases = issue.get("backend_signal_provenance_aliases")
        aliases = (
            [item for item in aliases if isinstance(item, dict)]
            if isinstance(aliases, list)
            else []
        )
        if not aliases:
            aliases = [
                {
                    "signal_source": str(issue.get("signal_source") or "joern_rule_engine"),
                    "native_rule_id": str(
                        issue.get("native_rule_id") or issue.get("rule_id") or ""
                    ),
                }
            ]
        details: List[Dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for alias in aliases:
            signal_source = str(alias.get("signal_source") or "joern_rule_engine")
            native_rule_id = str(alias.get("native_rule_id") or alias.get("rule_id") or "")
            key = (signal_source, native_rule_id)
            if key in seen:
                continue
            seen.add(key)
            details.append(
                {
                    "kind": "backend_signal",
                    "source_id": native_rule_id or signal_source,
                    "signal_source": signal_source,
                    "native_rule_id": native_rule_id,
                }
            )
        issue["attribution"] = FindingAttribution(
            discovered_by=("backend_signal",),
            discovery_details=tuple(details),
            decided_by=str(current.get("decided_by") or "unresolved"),
            decision_level=str(current.get("decision_level") or "none"),
            decision_details=decision_details,
        ).to_dict()

    def _filter_false_positives(self, issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        filtered = []
        for issue in issues:
            func = issue.get("function", "")
            loc = f"{issue.get('file_path', '')}:{issue.get('line_number', '')}"
            subcat = issue.get("category", "")
            if self.user_config.is_false_positive(func, loc, subcat):
                logger.info("Filtering false positive: %s in %s", issue.get("rule_id"), func)
                continue
            filtered.append(issue)
        return filtered

    def _build_report(self, issues: List[Dict[str, Any]], notes: List[str]) -> Dict[str, Any]:
        validation_state = dict(getattr(self, "_last_validation_state", {}) or {})
        validation_state.setdefault("finding_root_projection_enabled", True)
        config = getattr(self, "config", None)
        if config is not None:
            validation_state.setdefault("decision_trace_store", ensure_decision_trace_store(config))
        canonical = ReportAssembler._canonical_outcome_items(validation_state)
        if canonical is not None:
            issues = canonical
        confirmed = [
            issue
            for issue in issues
            if str(issue.get("candidate_disposition") or "") == "confirmed"
            or str(issue.get("validation_status") or "") in {"validated", "verified", "confirmed"}
        ]
        observations = [issue for issue in issues if issue not in confirmed]
        verdict = "issues_found" if confirmed else "no_issue_found"
        report = FinalReport(
            entry_function="[rule-driven]",
            overall_verdict=verdict,
            issues=[
                Issue.from_dict(i, context_function=i.get("function", ""), issue_index=idx + 1)
                for idx, i in enumerate(confirmed)
                if isinstance(i, dict)
            ],
            notes=notes,
        )
        effective = getattr(self, "effective_rules", None)
        rule_catalog = (
            serialize_effective_rules(effective) if isinstance(effective, EffectiveRuleSet) else {}
        )
        backend_signal_counts: Dict[str, int] = {}
        for issue in issues:
            if str(issue.get("candidate_kind") or "") != "backend_signal":
                continue
            aliases = issue.get("backend_signal_provenance_aliases")
            raw_aliases = (
                [item for item in aliases if isinstance(item, dict)]
                if isinstance(aliases, list)
                else []
            )
            native_ids = {
                str(item.get("native_rule_id") or item.get("rule_id") or "")
                for item in raw_aliases
                if str(item.get("native_rule_id") or item.get("rule_id") or "")
            }
            if not native_ids:
                native_id = str(issue.get("native_rule_id") or issue.get("rule_id") or "")
                if native_id:
                    native_ids.add(native_id)
            for native_id in native_ids:
                backend_signal_counts[native_id] = backend_signal_counts.get(native_id, 0) + 1
        scan = getattr(config, "scan", None)
        llm_usage = scan_token_usage_snapshot(config) if config is not None else {}
        report.metadata = {
            "timestamp": datetime.datetime.now().isoformat(),
            "version": __version__,
            "mode": "rule_driven",
            "effective_rules_sha256": str(
                getattr(getattr(effective, "provenance", None), "effective_sha256", "") or ""
            ),
            "rule_catalog": rule_catalog,
            # Rule-driven Joern findings are backend signals, not registered
            # deterministic rules.  Keep deterministic counts honest and
            # expose native signal aggregation separately.
            "rule_candidate_counts": {"total": 0, "by_engine": {}, "by_rule": {}},
            "backend_signal_counts": dict(sorted(backend_signal_counts.items())),
            "scan_depth": str(getattr(scan, "depth", "fast") or "fast"),
            "effective_scan": {
                "depth": str(getattr(scan, "depth", "fast") or "fast"),
                "depth_source": str(getattr(scan, "depth_source", "default") or "default"),
                "rollout": rollout_runtime_policy(config),
            },
            "rollout": rollout_runtime_policy(config),
            "llm_usage": llm_usage,
        }
        report.report_views = build_report_views(
            confirmed,
            observations,
            canonical_projection=True,
        )
        lifecycle_terminal_states = validation_state.get("candidate_terminal_states")
        if not isinstance(lifecycle_terminal_states, list):
            lifecycle_terminal_states = issues
        validation_state.update(
            {
                "candidate_terminal_states": lifecycle_terminal_states,
                "canonical_outcome_projection": True,
                "validation_queue_drained": bool(
                    validation_state.get("validation_queue_drained", True)
                )
                and not any(
                    str(item.get("candidate_disposition") or "")
                    in {"deferred_budget", "engine_failed"}
                    for item in issues
                ),
                "llm_usage": llm_usage,
                "budget_exhaustion_policy": "observe",
            }
        )
        report_dict = apply_report_schema_v2(
            report.to_dict(),
            state=validation_state,
            issues=confirmed,
            observations=observations,
            metadata=report.metadata,
            entry_function="[rule-driven]",
        )
        raw_occurrence_count = int(
            validation_state.get("scan_level_raw_occurrence_count") or len(issues)
        )
        report_dict["run_manifest"]["raw_occurrence_count"] = raw_occurrence_count
        report_dict["metadata"]["candidate_lifecycle"] = {
            "discovery_frozen": bool(validation_state.get("candidate_discovery_frozen")),
            "raw_occurrence_count": raw_occurrence_count,
            "canonical_validation_group_count": int(
                report_dict["run_manifest"].get("canonical_validation_group_count") or 0
            ),
            "provenance_alias_count": int(
                validation_state.get("validation_group_merged_count") or 0
            ),
            "ledger_summary": dict(validation_state.get("candidate_ledger_summary") or {}),
        }
        from ..reporting.funnel import candidate_funnel

        report_dict["metadata"]["candidate_funnel"] = candidate_funnel(report_dict)
        report.metadata = dict(report_dict["metadata"])
        for field_name in (
            "schema_version",
            "finding_status",
            "completeness",
            "scan_outcome",
            "run_manifest",
            "candidate_terminal_states",
            "needs_review_governance",
        ):
            setattr(report, field_name, report_dict[field_name])
        self.report_generator.save_json_report(report)
        self.report_generator.save_markdown_report(report)
        return report.to_dict()
