"""
Alert verification orchestrator.
Takes external alerts (SARIF etc.), enriches them with code context from CodeIndex,
then uses the Validator Agent to confirm or reject each alert.
"""

import hashlib
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config.config import ZScopeConfig
from ..config.user_config_store import UserConfigStore
from ..retrieval.code_index import CodeIndex
from .adapter import AlertAdapter, ExternalAlert, AlertSeverity
from ..snapshots.store import SnapshotStore
from ..tools.policy import ToolPolicy, deny_sensitive_paths_hook
from ..tools.runtime import ToolsRuntime
from ..framework.llm_client import LLMClient
from ..reporting.attribution import FindingAttribution
from ..reporting.report import FinalReport, Issue, ReportGenerator
from ..orchestration.scheduler import VALIDATOR_ROLE, ScanScheduler
from ..orchestration.specs import SpecRegistry
from ..orchestration.decision_trace import ensure_decision_trace_store
from ..core.validation.authority import TerminalAuthorityEvaluator

logger = logging.getLogger(__name__)


class AlertVerifier:
    """告警验证编排器。"""

    def __init__(
        self,
        config: ZScopeConfig,
        code_index: CodeIndex,
        llm_client: LLMClient,
        user_config: Optional[UserConfigStore] = None,
        scheduler: Optional[ScanScheduler] = None,
    ):
        self.config = config
        self.code_index = code_index
        self.llm_client = llm_client
        self.user_config = user_config
        self.scheduler = scheduler
        self.snapshot_store = SnapshotStore.from_config(config)
        self.spec_registry = SpecRegistry(project_root=config.project.project_root)
        self.decision_trace_store = ensure_decision_trace_store(config)
        self.terminal_authority = TerminalAuthorityEvaluator()
        self.tools_runtime = ToolsRuntime(
            code_index=code_index,
            snapshot_store=self.snapshot_store,
            user_config=user_config,
            tool_policy=ToolPolicy.allow_all(
                pre_hooks=[deny_sensitive_paths_hook],
                audit_log_path=self._tool_audit_log_path(),
            ),
        )

    def _tool_audit_log_path(self) -> Optional[Path]:
        configured = str(getattr(self.config.analysis, "tool_audit_log", "") or "").strip()
        if not configured:
            return None
        path = Path(configured)
        if path.is_absolute():
            return path
        return self.config.project.project_root / path

    def verify_alerts(
        self,
        alerts: List[ExternalAlert],
        max_workers: int = 1,
    ) -> List[Dict[str, Any]]:
        """验证一批外部告警，返回验证结果列表。"""
        total = len(alerts)
        logger.info("Starting verification of %d alerts", total)

        worker_count = self._worker_count(total, max_workers)
        if worker_count <= 1:
            results = [
                self._verify_alert_safely(alert, idx, total) for idx, alert in enumerate(alerts, 1)
            ]
        elif getattr(self, "scheduler", None) is not None:
            logger.info(
                "Verifying %d alert(s) through the scan-level scheduler.",
                total,
            )
            scheduler = self.scheduler
            assert scheduler is not None
            results_by_index: Dict[int, Dict[str, Any]] = {}
            future_to_index = {
                scheduler.submit(
                    VALIDATOR_ROLE,
                    self._verify_alert_safely,
                    alert,
                    idx,
                    total,
                ): idx
                for idx, alert in enumerate(alerts, 1)
            }
            for future in as_completed(future_to_index):
                idx = future_to_index[future]
                try:
                    results_by_index[idx] = future.result()
                except Exception as e:
                    alert = alerts[idx - 1]
                    logger.exception(
                        "Scheduled alert verification crashed for alert %d.",
                        idx,
                    )
                    results_by_index[idx] = self._make_error_result(
                        alert,
                        idx,
                        str(e),
                    )
            results = [results_by_index[idx] for idx in range(1, total + 1)]
        else:
            logger.info(
                "Verifying %d alert(s) with %d worker(s).",
                total,
                worker_count,
            )
            local_results_by_index: Dict[int, Dict[str, Any]] = {}
            with ThreadPoolExecutor(
                max_workers=worker_count,
                thread_name_prefix="zscope-alert-verifier",
            ) as executor:
                future_to_index = {
                    executor.submit(self._verify_alert_safely, alert, idx, total): idx
                    for idx, alert in enumerate(alerts, 1)
                }
                for future in as_completed(future_to_index):
                    idx = future_to_index[future]
                    try:
                        local_results_by_index[idx] = future.result()
                    except Exception as e:
                        alert = alerts[idx - 1]
                        logger.exception("Alert verification worker crashed for alert %d.", idx)
                        local_results_by_index[idx] = self._make_error_result(alert, idx, str(e))
            results = [local_results_by_index[idx] for idx in range(1, total + 1)]

        confirmed = sum(1 for r in results if r.get("verdict") == "confirmed")
        rejected = sum(1 for r in results if r.get("verdict") == "rejected")
        uncertain = sum(1 for r in results if r.get("verdict") == "uncertain")
        logger.info(
            "Verification complete: %d confirmed, %d rejected, %d uncertain",
            confirmed,
            rejected,
            uncertain,
        )
        trace_store = getattr(self, "decision_trace_store", None)
        for idx, (alert, result) in enumerate(zip(alerts, results), start=1):
            candidate_uid, cluster_uid = self._alert_identity(alert)
            result.setdefault("candidate_uid", candidate_uid)
            result.setdefault("validation_cluster_uid", cluster_uid)
            if trace_store is None:
                continue
            trace_store.bind_candidate(
                cluster_uid,
                candidate_uids=(candidate_uid,),
            )
            disposition = str(result.get("candidate_disposition") or "engine_failed")
            memberships = (
                ("default", "with_needs_review")
                if disposition == "confirmed"
                else ("with_needs_review",) if disposition == "needs_review" else ("excluded",)
            )
            trace_store.finalize_issue(
                result,
                view_memberships=memberships,
            )
        return results

    @staticmethod
    def _alert_identity(alert: ExternalAlert) -> tuple[str, str]:
        identity = {
            "tool": alert.tool,
            "rule_id": alert.rule_id,
            "file": alert.file_path,
            "line": alert.line,
            "function": alert.function,
        }
        digest = hashlib.sha256(
            json.dumps(identity, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        return f"CAND_ALERT_{digest}", f"VCL_ALERT_{digest}"

    def _worker_count(self, alert_count: int, max_workers: int) -> int:
        if alert_count <= 1:
            return 1
        try:
            requested = int(max_workers or 1)
        except (TypeError, ValueError):
            requested = 1
        return max(1, min(alert_count, requested))

    def _verify_alert_safely(
        self,
        alert: ExternalAlert,
        idx: int,
        total: int,
    ) -> Dict[str, Any]:
        logger.info(
            "[%d/%d] Verifying %s:%d (%s)",
            idx,
            total,
            alert.file_path,
            alert.line,
            alert.rule_id,
        )
        try:
            return self._verify_single(alert, idx)
        except Exception as e:
            logger.error("Failed to verify alert %d: %s", idx, e)
            return self._make_error_result(alert, idx, str(e))
        finally:
            self._close_thread_llm_session()

    def _close_thread_llm_session(self) -> None:
        llm_client = getattr(self, "llm_client", None)
        close_thread_session = getattr(llm_client, "close_thread_session", None)
        if callable(close_thread_session):
            close_thread_session()

    def close(self) -> None:
        llm_client = getattr(self, "llm_client", None)
        close_client = getattr(llm_client, "close", None)
        if callable(close_client):
            close_client()

    def _verify_single(self, alert: ExternalAlert, idx: int) -> Dict[str, Any]:
        """Validate one external signal with the bounded Validator v3 V1 pass."""
        from ..agents.validator_agent.agent import ValidatorAgent
        from ..core.validation.evidence import build_validator_evidence_slice_v3

        alert_id = f"ALERT_{idx}"

        # 1. 收集代码上下文
        context = self._build_context(alert)

        identity = {
            "tool": alert.tool,
            "rule_id": alert.rule_id,
            "file": alert.file_path,
            "line": alert.line,
            "function": alert.function,
        }
        candidate_uid, cluster_uid = self._alert_identity(alert)
        digest = candidate_uid.removeprefix("CAND_ALERT_")
        fact_uid = f"fact:external-alert:{digest}"
        issue = {
            "candidate_uid": candidate_uid,
            "validation_cluster_uid": cluster_uid,
            "occurrence_uid": f"OCC_ALERT_{digest}",
            "candidate_kind": "backend_signal",
            "candidate_source": "backend_signal",
            "function": alert.function,
            "location": f"{alert.file_path}:{alert.line}",
            "category": alert.category or "external_alert",
            "subcategory": alert.rule_id,
            "decision_fact_slice": {
                "coverage": "partial",
                "fact_uids": [fact_uid],
                "edge_uids": [],
                "dependency_code_hashes": [],
                "missing_fact_kinds": [],
            },
            "decision_facts": [
                {
                    "fact_uid": fact_uid,
                    "kind": "backend_signal",
                    "payload": {
                        **identity,
                        "message": alert.message,
                        "severity": alert.severity.value,
                    },
                }
            ],
            "positive_evidence": [alert.message],
        }
        code = str(context.get("function_code") or context.get("code_snippet") or "")
        evidence_pack = {
            "finding_summary": {
                "function": alert.function,
                "location": f"{alert.file_path}:{alert.line}",
                "category": alert.category or "external_alert",
                "subcategory": alert.rule_id,
            },
            "function_context": {
                "code": code,
                "callers": context.get("callers") or [],
                "callees": context.get("callees") or [],
            },
            "positive_evidence": [alert.message],
            "negative_evidence": [],
            "validation_requirements": [
                "Treat the external alert as a signal, not as proof of a vulnerability."
            ],
        }
        evidence_slice = build_validator_evidence_slice_v3(
            issue,
            evidence_pack,
            code,
            validation_pass="initial",
        )
        validator_input = {
            "finding_uid": candidate_uid,
            "validation_cluster_uid": cluster_uid,
            "validation_pass": "initial",
            "evidence_slice": evidence_slice,
        }
        usage_ledger = getattr(self.config, "scan_token_usage_ledger", None)
        usage_getter = getattr(usage_ledger, "events_for_cluster", None)
        usage_start = len(usage_getter(cluster_uid)) if callable(usage_getter) else 0
        response = ValidatorAgent(self.llm_client, []).run(validator_input)
        usage_events = (
            list(usage_getter(cluster_uid))[usage_start:] if callable(usage_getter) else []
        )
        call_ids = tuple(
            str(value.get("call_id") or "") for value in usage_events if value.get("call_id")
        )
        model_ref = self.decision_trace_store.put_model_event(
            call_identity=f"{cluster_uid}:V1:{usage_start}",
            stage="V1",
            validation_cluster_uid=cluster_uid,
            structured_input=validator_input,
            structured_output=(
                response.data
                if response.success and isinstance(response.data, dict)
                else {"protocol_failure": True}
            ),
            call_ids=call_ids,
            prompt_revision="zscope.validator-protocol.v3",
        )
        self.decision_trace_store.append_event(
            cluster_uid,
            stage="V1",
            actor="validator_agent",
            reason_code="V1_COMPLETED",
            output_refs=(model_ref,),
            call_ids=call_ids,
            token_delta=sum(int(value.get("total_tokens") or 0) for value in usage_events),
            details={"external_alert": True, "success": bool(response.success)},
        )
        if not response.success:
            return self._make_error_result(
                alert,
                idx,
                response.error or "validator_v3_failed",
            )
        return self._validator_v3_result(
            response.data,
            alert=alert,
            alert_id=alert_id,
            candidate_uid=candidate_uid,
            cluster_uid=cluster_uid,
        )

    def _validator_v3_result(
        self,
        data: Dict[str, Any],
        *,
        alert: ExternalAlert,
        alert_id: str,
        candidate_uid: str,
        cluster_uid: str,
    ) -> Dict[str, Any]:
        model_verdict = str(data.get("verdict") or "uncertain")
        proposed_disposition = "confirmed" if model_verdict == "verified" else "needs_review"
        terminal_authority = (
            getattr(self, "terminal_authority", None) or TerminalAuthorityEvaluator()
        )
        authority = terminal_authority.evaluate(
            {
                "candidate_uid": candidate_uid,
                "validation_cluster_uid": cluster_uid,
                "candidate_disposition": proposed_disposition,
                "model_verdict": model_verdict,
                "evidence_closure_state": {
                    "complete": False,
                    "missing_fact_kinds": ["external_alert_program_evidence"],
                },
            },
            model_result=data,
        )
        confirmed = authority.disposition == "confirmed"
        policy_disposition = authority.disposition
        return {
            "alert_id": alert_id,
            "candidate_uid": candidate_uid,
            "validation_cluster_uid": cluster_uid,
            "tool": alert.tool,
            "rule_id": alert.rule_id,
            "file": alert.file_path,
            "line": alert.line,
            "original_message": alert.message,
            "original_severity": alert.severity.value,
            "verdict": "confirmed" if confirmed else "uncertain",
            "model_verdict": model_verdict,
            "policy_disposition": policy_disposition,
            "validation_status": "validated" if confirmed else "needs_review",
            "candidate_disposition": policy_disposition,
            "engine_status": "complete",
            "reasoning": str(data.get("reasoning") or ""),
            "validation_reasoning": str(data.get("reasoning") or ""),
            "positive_evidence": list(data.get("positive_evidence") or []),
            "negative_evidence": list(data.get("negative_evidence") or []),
            "evidence_refs": list(data.get("evidence_refs") or []),
            "blocking_negative_evidence": bool(data.get("blocking_negative_evidence")),
            "validator_result_pass": str(data.get("pass") or "initial"),
            "validator_pass_history": [dict(data)],
            "validator_policy_outcome": {
                "model_verdict": model_verdict,
                "policy_disposition": policy_disposition,
                "stop_reason": str(data.get("stop_reason") or ""),
            },
            "terminal_authority": authority.authority,
            "terminal_authority_decision": authority.to_dict(),
            "terminal_reason_codes": [authority.reason_code],
            "open_clause_ids": ([] if confirmed else ["external_alert_program_evidence"]),
            "attribution": FindingAttribution(
                discovered_by=("backend_signal",),
                discovery_details=({"tool": alert.tool, "native_rule_id": alert.rule_id},),
                decided_by="validator_llm" if confirmed else "unresolved",
                decision_level="V1",
                decision_details={"model_verdict": model_verdict},
            ).to_dict(),
        }

    def _system_prompt(self) -> str:
        agent_spec = self.spec_registry.get_agent("alert_verifier")
        if not agent_spec:
            return "alert_verifier"
        return agent_spec.to_prompt_block()

    def _build_context(self, alert: ExternalAlert) -> Dict[str, Any]:
        """为告警收集代码上下文。"""
        context: Dict[str, Any] = {"code_snippet": "", "callers": [], "callees": []}

        # 获取告警所在位置的代码片段
        snippet = self.code_index.get_file_snippet(
            alert.file_path,
            max(1, alert.line - 10),
            (alert.end_line or alert.line) + 10,
        )
        if snippet:
            context["code_snippet"] = snippet.get("code", "")

        # 如果知道函数名，获取完整实现和调用关系
        if alert.function:
            impl = self.code_index.get_function_impl(alert.function)
            if impl:
                context["function_code"] = impl.get("code", "")
                context["callees"] = impl.get("callees", [])
            context["callers"] = self.code_index.get_callers(alert.function)

        return context

    def _build_prompt(self, alert: ExternalAlert, alert_id: str, context: Dict[str, Any]) -> str:
        """构建发送给 LLM 的验证 prompt。"""
        parts = [
            f"## 待验证告警 [{alert_id}]",
            f"- 工具: {alert.tool}",
            f"- 规则: {alert.rule_id}",
            f"- 严重级别: {alert.severity.value}",
            f"- 文件: {alert.file_path}:{alert.line}",
            f"- 描述: {alert.message}",
        ]
        if alert.function:
            parts.append(f"- 函数: {alert.function}")
        if alert.category:
            parts.append(f"- 类别: {alert.category}")

        # 代码上下文
        code = context.get("function_code") or context.get("code_snippet", "")
        if code:
            parts.append(f"\n## 相关代码\n```c\n{code}\n```")

        # codeFlows（SARIF 数据流路径）
        if alert.code_flows:
            parts.append("\n## 数据流路径")
            for i, flow in enumerate(alert.code_flows):
                parts.append(f"### Flow {i + 1}")
                for step in flow.get("steps", []):
                    parts.append(
                        f"  - {step.get('file', '?')}:{step.get('line', '?')} "
                        f"— {step.get('message', '')}"
                    )

        parts.append("\n请使用工具获取更多上下文后，输出验证结果 JSON。")
        return "\n".join(parts)

    def _parse_verification(
        self, response: str, alert: ExternalAlert, alert_id: str
    ) -> Dict[str, Any]:
        """从 LLM 响应中解析验证结果 JSON。"""
        base = {
            "alert_id": alert_id,
            "tool": alert.tool,
            "rule_id": alert.rule_id,
            "file": alert.file_path,
            "line": alert.line,
            "original_message": alert.message,
            "original_severity": alert.severity.value,
        }

        from ..common.utils import extract_json_blocks

        candidates = extract_json_blocks(response or "")
        parsed = next(
            (
                item
                for item in candidates
                if isinstance(item, dict)
                and (item.get("type") == "alert_verification" or "verdict" in item)
            ),
            None,
        )

        if not parsed:
            logger.warning("No JSON block found in verification response for %s", alert_id)
            base.update(
                {"verdict": "uncertain", "confidence": 0.0, "reasoning": "无法解析验证结果"}
            )
            base.update(
                {
                    "validation_status": "pending",
                    "candidate_disposition": "engine_failed",
                    "engine_status": "failed",
                    "verification_error": "validator_response_parse_failed",
                }
            )
            return base

        base.update(
            {
                "verdict": parsed.get("verdict", "uncertain"),
                "confidence": parsed.get("confidence", 0.0),
                "reasoning": parsed.get("reasoning", ""),
                "severity_adjustment": parsed.get("severity_adjustment", ""),
                "missing_context": parsed.get("missing_context", []),
            }
        )
        verdict = str(base.get("verdict") or "uncertain").strip().lower()
        confirmed = verdict in {"confirmed", "verified"}
        base.update(
            {
                "verdict": verdict,
                # This is an LLM boundary. A model-proposed rejection is not
                # deterministic proof that the external alert is false.
                "validation_status": "validated" if confirmed else "needs_review",
                "candidate_disposition": "confirmed" if confirmed else "needs_review",
                "engine_status": "complete",
            }
        )
        return base

    def _make_error_result(self, alert: ExternalAlert, idx: int, error: str) -> Dict[str, Any]:
        candidate_uid, cluster_uid = self._alert_identity(alert)
        return {
            "alert_id": f"ALERT_{idx}",
            "candidate_uid": candidate_uid,
            "validation_cluster_uid": cluster_uid,
            "tool": alert.tool,
            "rule_id": alert.rule_id,
            "file": alert.file_path,
            "line": alert.line,
            "original_message": alert.message,
            "original_severity": alert.severity.value,
            "validation_status": "pending",
            "candidate_disposition": "engine_failed",
            "engine_status": "failed",
            "verification_error": error,
            "verdict": "uncertain",
            "confidence": 0.0,
            "reasoning": f"验证过程出错: {error}",
        }
