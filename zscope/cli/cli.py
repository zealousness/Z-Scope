"""
Command Line Interface for Z-SCOPE.
"""

import click
import logging
import sys
import os
from pathlib import Path # Keep this import as it's used for 'config: Path'
from typing import Optional
from .._version import __version__
from ..retrieval.code_index import CodeIndex
from ..common.utils import setup_logging
from ..config.config import ConfigLoader
from ..framework.conversation_recorder import enable_conversation_recording
from ..orchestration.scan_session import ScanSessionResult, ScanSessionRunner

@click.command()
@click.version_option(version=__version__, prog_name="Z-SCOPE")
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to config file (zscope.yaml).",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging.")
@click.option("--dashboard", "-d", is_flag=True, help="Launch the web dashboard to view results.")
@click.option("--dashboard-host", default="0.0.0.0", show_default=True, help="Host/IP to bind for --dashboard.")
@click.option("--dashboard-port", default=8000, show_default=True, type=int, help="Port to bind for --dashboard.")
@click.option("--build-cpg", is_flag=True, help="Only build CPG and index, then exit.")
@click.option("--mode", type=click.Choice(["default", "ruledriven", "alert-verify"]), default="default", help="Analysis mode.")
@click.option("--sarif", type=click.Path(exists=True, dir_okay=False, path_type=Path), default=None, help="SARIF file for alert-verify mode.")
@click.option("--resume", is_flag=True, default=False, help="Resume interrupted batch scan from last checkpoint.")
@click.option("--maintain", is_flag=True, default=False, help="Incremental maintenance scan: skip unchanged functions, verify historical issues.")
@click.option("--discover-entries", is_flag=True, default=False, help="Discover public API, communication, thread, and other input entries before scanning.")
@click.option("--diff-base", default=None, help="Base git ref for diff impact mode.")
@click.option("--diff-head", default="HEAD", show_default=True, help="Head git ref for diff impact mode.")
@click.option(
    "--diff-repo-root",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
    default=None,
    help="Optional git worktree root for diff impact mode. Defaults to project.source_root auto-detection.",
)
@click.option(
    "--diff-path",
    multiple=True,
    help="Limit diff impact mode to changed files under this path. Repeat for multiple paths.",
)
@click.option("--infer-user-config", is_flag=True, default=False, help="Infer/update the human-editable user_config.xlsx and exit.")
@click.option("--mcp-stdio", is_flag=True, default=False, help="Run Z-SCOPE local MCP server over stdio.")
@click.option("--mcp-http", is_flag=True, default=False, help="Run experimental remote MCP server over Streamable HTTP.")
@click.option("--mcp-host", default="127.0.0.1", show_default=True, help="Host/IP to bind for --mcp-http.")
@click.option("--mcp-port", default=8765, show_default=True, type=int, help="Port to bind for --mcp-http.")
@click.option("--mcp-endpoint", default="/mcp", show_default=True, help="HTTP path for --mcp-http.")
@click.option("--mcp-auth-token-env", default="", help="Environment variable containing the bearer token for --mcp-http.")
@click.option("--mcp-client-allowlist", multiple=True, help="Client IP allowed to call --mcp-http. Repeat for multiple IPs.")
@click.option("--export-sarif", type=click.Path(dir_okay=False, path_type=Path), default=None, help="Export the completed Z-SCOPE report to SARIF v2.1.0.")
def main(
    config: Path,
    verbose: bool,
    dashboard: bool,
    dashboard_host: str,
    dashboard_port: int,
    build_cpg: bool,
    mode: str,
    sarif: Path,
    resume: bool,
    maintain: bool,
    discover_entries: bool,
    diff_base: Optional[str],
    diff_head: str,
    diff_repo_root: Optional[Path],
    diff_path: tuple[str, ...],
    infer_user_config: bool,
    mcp_stdio: bool,
    mcp_http: bool,
    mcp_host: str,
    mcp_port: int,
    mcp_endpoint: str,
    mcp_auth_token_env: str,
    mcp_client_allowlist: tuple[str, ...],
    export_sarif: Optional[Path],
):
    """
    Z-SCOPE: AI-powered defect detection for C projects.
    """
    setup_logging(verbose)
    logger = logging.getLogger("zscope.cli")

    if dashboard:
        logger.info("Launching dashboard...")
        from ..web.server import run_server
        from ..config.user_config_store import UserConfigStore
        from ..snapshots.store import SnapshotStore

        if not config:
            config = Path("zscope.yaml")
        if config.exists():
            zscope_config = ConfigLoader.load(str(config))
            cfg = zscope_config.indexing
            # 通过 CodeIndex 创建后端，保持统一入口
            dashboard_code_index = CodeIndex(
                zscope_config.project.project_root,
                zscope_config.project.compile_commands_path,
                source_root=zscope_config.project.source_root,
                indexing_config=cfg,
                include_paths=zscope_config.project.include_paths,
                exclude_paths=zscope_config.project.exclude_paths,
                wait_for_cpg=False,
                svf_parallel_workers=zscope_config.analysis.parallel_workers,
            )
            db_dir = Path(zscope_config.analysis.user_config_db) if zscope_config.analysis.user_config_db else Path(zscope_config.analysis.snapshot_dir)
            ucs = UserConfigStore(db_dir)
            snapshot_store = SnapshotStore(Path(zscope_config.analysis.snapshot_dir))
            
            run_server(
                code_index=dashboard_code_index,
                user_config_store=ucs,
                project_config=zscope_config.project,
                snapshot_store=snapshot_store,
                config_path=config,
                host=dashboard_host,
                port=dashboard_port,
            )
        else:
            click.echo("Warning: No config file found, dashboard running without backend/config support")
            run_server(config_path=config, host=dashboard_host, port=dashboard_port)
        sys.exit(0)

    if not config:
        config = Path("zscope.yaml")
        if not config.exists():
            click.echo("Error: Please provide a config file using --config or create zscope.yaml")
            sys.exit(1)

    code_index: Optional[CodeIndex] = None
    try:
        zscope_config = ConfigLoader.load(str(config))
        logger.info(f"Loaded configuration from: {config}")
        if verbose:
            recorder = enable_conversation_recording(
                zscope_config.project.project_root / ".zscope_conversations"
            )
            logger.info("LLM conversation recording enabled: %s", recorder.run_dir)

        if resume and maintain:
            click.echo("Error: --resume and --maintain cannot be used together.")
            sys.exit(1)
        if diff_base and (resume or maintain):
            click.echo("Error: --diff-base cannot be combined with --resume or --maintain.")
            sys.exit(1)
        if diff_path and not diff_base:
            click.echo("Error: --diff-path requires --diff-base.")
            sys.exit(1)
        if mcp_stdio and mcp_http:
            click.echo("Error: --mcp-stdio and --mcp-http cannot be used together.")
            sys.exit(1)

        if maintain:
            zscope_config.analysis.workflow_name = "maintain"
        elif resume:
            zscope_config.analysis.workflow_name = "resume"

        if mcp_stdio:
            from ..mcp.server import run_stdio_server

            run_stdio_server(str(config))
            sys.exit(0)

        if mcp_http:
            from ..mcp.http_server import run_http_server

            click.echo(
                "Warning: remote MCP Streamable HTTP support is experimental and has no "
                "TLS termination. Bind only to trusted IPs/networks."
            )
            try:
                run_http_server(
                    str(config),
                    host=mcp_host,
                    port=mcp_port,
                    endpoint=mcp_endpoint,
                    auth_token_env=mcp_auth_token_env,
                    client_allowlist=mcp_client_allowlist,
                )
            except ValueError as exc:
                click.echo(f"Error: {exc}")
                sys.exit(1)
            sys.exit(0)

        if infer_user_config:
            from ..config.user_config_workbook import UserConfigWorkbook
            from ..framework.llm_client import LLMClient
            from ..orchestration.user_config_inference import (
                filter_user_config_rows_with_llm,
                infer_user_config_rows,
            )

            click.echo("Inferring user configuration candidates...")
            code_index = CodeIndex(
                zscope_config.project.project_root,
                zscope_config.project.compile_commands_path,
                source_root=zscope_config.project.source_root,
                indexing_config=zscope_config.indexing,
                include_paths=zscope_config.project.include_paths,
                exclude_paths=zscope_config.project.exclude_paths,
                wait_for_cpg=True,
                defer_svf=True,
                svf_parallel_workers=zscope_config.analysis.parallel_workers,
            )
            workbook_path = _resolve_user_config_workbook_path(zscope_config)
            generated = infer_user_config_rows(
                code_index,
                snapshot_dir=Path(zscope_config.analysis.snapshot_dir),
            )
            llm_workers = max(1, int(getattr(zscope_config.analysis, "parallel_workers", 1) or 1))
            click.echo(f"Screening user configuration candidates with LLM ({llm_workers} worker(s))...")
            llm_cfg = zscope_config.llms.get("default") or next(iter(zscope_config.llms.values()))
            llm_client = LLMClient(
                api_key=llm_cfg.api_key,
                base_url=getattr(llm_cfg, "base_urls", None) or llm_cfg.base_url,
                models=llm_cfg.models,
                timeout=llm_cfg.timeout,
                max_retries=llm_cfg.max_retries,
                max_tokens=llm_cfg.max_tokens,
                base_url_rate_limit_per_minute=getattr(
                    llm_cfg, "base_url_rate_limit_per_minute", 0
                ),
                base_url_max_concurrent_requests=getattr(
                    llm_cfg, "base_url_max_concurrent_requests", 0
                ),
                supports_structured_output=getattr(
                    llm_cfg, "supports_structured_output", False
                ),
            )
            try:
                generated, llm_stats = filter_user_config_rows_with_llm(
                    generated,
                    code_index,
                    llm_client,
                    max_workers=llm_workers,
                )
            finally:
                llm_client.close()
            stats = UserConfigWorkbook(workbook_path).merge_generated(generated)
            total_symbols = sum(len(items) for items in generated.values())
            click.echo(f"User config workbook: {workbook_path}")
            click.echo(
                "LLM screening: "
                f"{llm_stats['reviewed']} reviewed, "
                f"{llm_stats['kept']} kept, {llm_stats['revised']} revised, "
                f"{llm_stats['dropped']} dropped, {llm_stats['unreviewed']} unreviewed, "
                f"{llm_stats['errors']} batch error(s)."
            )
            click.echo(
                "Inference complete: "
                f"{total_symbols} generated row(s), "
                f"{stats['added']} added, {stats['refreshed']} refreshed, {stats['removed']} removed."
            )
            click.echo("Review the workbook, then run Z-SCOPE normally.")
            sys.exit(0)

        if build_cpg:
            click.echo("Building CPG and index...")
            code_index = CodeIndex(
                zscope_config.project.project_root,
                zscope_config.project.compile_commands_path,
                source_root=zscope_config.project.source_root,
                indexing_config=zscope_config.indexing,
                include_paths=zscope_config.project.include_paths,
                exclude_paths=zscope_config.project.exclude_paths,
                wait_for_cpg=True,
                svf_parallel_workers=zscope_config.analysis.parallel_workers,
            )
            func_count = len(code_index.list_functions())
            click.echo(f"CPG build complete. Indexed {func_count} functions.")
            sys.exit(0)

        # ── Mode-specific analysis ──

        if mode == "ruledriven":
            logger.info("Rule-driven mode: running Joern rules + validation")
            from ..rules.analyzer import RuleDrivenAnalyzer
            code_index = CodeIndex(
                zscope_config.project.project_root,
                zscope_config.project.compile_commands_path,
                source_root=zscope_config.project.source_root,
                indexing_config=zscope_config.indexing,
                include_paths=zscope_config.project.include_paths,
                exclude_paths=zscope_config.project.exclude_paths,
                svf_parallel_workers=zscope_config.analysis.parallel_workers,
            )
            rda = RuleDrivenAnalyzer(zscope_config, code_index=code_index)
            try:
                result = rda.run()
            finally:
                rda.close()
            issues_count = len(result.get("issues", []))
            click.echo(f"\nRule-driven analysis complete. Issues: {issues_count}")
            sys.exit(1 if issues_count > 0 else 0)

        if mode == "alert-verify":
            if not sarif:
                click.echo("Error: --sarif is required for alert-verify mode")
                sys.exit(1)
            logger.info("Alert verification mode: validating SARIF alerts")
            from ..alerts.sarif_adapter import SarifAdapter
            from ..alerts.verifier import AlertVerifier
            from ..framework.llm_client import LLMClient
            from ..config.user_config_store import UserConfigStore

            code_index = CodeIndex(
                zscope_config.project.project_root,
                zscope_config.project.compile_commands_path,
                source_root=zscope_config.project.source_root,
                indexing_config=zscope_config.indexing,
                include_paths=zscope_config.project.include_paths,
                exclude_paths=zscope_config.project.exclude_paths,
                svf_parallel_workers=zscope_config.analysis.parallel_workers,
            )
            adapter = SarifAdapter(
                source_root=str(zscope_config.project.source_root),
            )
            alerts = adapter.parse(str(sarif))
            click.echo(f"Parsed {len(alerts)} alerts from SARIF")
            
            if resume:
                # For alert-verify mode, --resume is not supported yet
                click.echo("Warning: --resume is not supported for alert-verify mode. Starting from beginning.")

            if not alerts:
                click.echo("No alerts to verify.")
                sys.exit(0)

            val_agent_cfg = next((a for a in zscope_config.project.agents if a.name == "validator_agent"), None)
            val_llm_ref = val_agent_cfg.llm_ref if val_agent_cfg and val_agent_cfg.llm_ref else "default"
            llm_cfg = zscope_config.llms.get(val_llm_ref, zscope_config.llms["default"])
            
            llm_client = LLMClient(
                api_key=llm_cfg.api_key,
                base_url=getattr(llm_cfg, "base_urls", None) or llm_cfg.base_url,
                models=llm_cfg.models,
                timeout=llm_cfg.timeout,
                max_retries=llm_cfg.max_retries,
                max_tokens=llm_cfg.max_tokens,
                base_url_rate_limit_per_minute=getattr(
                    llm_cfg, "base_url_rate_limit_per_minute", 0
                ),
                base_url_max_concurrent_requests=getattr(
                    llm_cfg, "base_url_max_concurrent_requests", 0
                ),
                supports_structured_output=getattr(
                    llm_cfg, "supports_structured_output", False
                ),
            )
            db_dir = (
                Path(zscope_config.analysis.user_config_db)
                if zscope_config.analysis.user_config_db
                else Path(zscope_config.analysis.snapshot_dir)
            )
            ucs = UserConfigStore(db_dir)

            verifier = AlertVerifier(
                config=zscope_config,
                code_index=code_index,
                llm_client=llm_client,
                user_config=ucs,
            )
            configured_alert_workers = getattr(
                zscope_config.analysis,
                "validation_parallel_workers",
                0,
            )
            try:
                alert_workers = int(configured_alert_workers or 0)
            except (TypeError, ValueError):
                alert_workers = 0
            if alert_workers <= 0:
                try:
                    alert_workers = int(
                        getattr(zscope_config.analysis, "parallel_workers", 1) or 1
                    )
                except (TypeError, ValueError):
                    alert_workers = 1
            alert_workers = max(1, min(len(alerts), alert_workers))
            click.echo(f"Verifying alerts with {alert_workers} worker(s)")
            try:
                verification_results = verifier.verify_alerts(
                    alerts,
                    max_workers=alert_workers,
                )
            finally:
                verifier.close()

            # 输出报告
            import json
            report_path = zscope_config.project.project_root / "zscope_alert_verify_report.json"
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump({"results": verification_results}, f, ensure_ascii=False, indent=2)

            confirmed = sum(1 for r in verification_results if r.get("verdict") == "confirmed")
            rejected = sum(1 for r in verification_results if r.get("verdict") == "rejected")
            click.echo(f"\nVerification complete: {confirmed} confirmed, {rejected} rejected")
            click.echo(f"Report: {report_path}")
            sys.exit(1 if confirmed > 0 else 0)

        session_runner = ScanSessionRunner(
            zscope_config,
            resume=resume,
            maintain=maintain,
            discover_entries=discover_entries,
            diff_base=diff_base,
            diff_head=diff_head,
            diff_repo_root=diff_repo_root,
            diff_paths=diff_path,
            emit=click.echo,
        )
        session_result = session_runner.run()
        if export_sarif:
            from ..reporting.sarif_exporter import save_sarif_report

            json_reports = [
                path for path in session_result.reports
                if isinstance(path, Path) and path.suffix.lower() == ".json"
            ]
            report_path = json_reports[0] if json_reports else session_result.project_root / "report.json"
            if not report_path.exists():
                raise FileNotFoundError(f"Unable to export SARIF; report not found: {report_path}")
            save_sarif_report(
                report_path,
                export_sarif,
                source_root=zscope_config.project.source_root,
            )

        if session_result.is_batch:
            reports = ", ".join(str(path) for path in session_result.reports)
            click.echo("\nBatch Analysis Complete.")
            click.echo(f"Functions analyzed: {session_result.functions_analyzed}")
            click.echo(f"Total issues found: {session_result.issues_count}")
            click.echo(f"needs_review issues: {session_result.needs_review_count}")
            click.echo(f"Reports saved: {reports}")
            for line in _batch_interruption_lines(session_result):
                click.echo(line)
            if export_sarif:
                click.echo(f"SARIF saved: {export_sarif}")
            if session_result.interrupted:
                click.echo("[!] Exiting immediately due to prior interrupt.")
                os._exit(1)
        else:
            click.echo(
                f"\nAnalysis Complete. Verdict: {session_result.verdict}. "
                f"Issues found: {session_result.issues_count}"
            )
            click.echo(f"needs_review issues: {session_result.needs_review_count}")
            click.echo(f"Reports saved in: {session_result.project_root}")
            if export_sarif:
                click.echo(f"SARIF saved: {export_sarif}")

        sys.exit(session_result.exit_code)

    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=True)
        sys.exit(1)
    finally:
        if code_index:
            code_index.close()


def _resolve_user_config_workbook_path(zscope_config) -> Path:
    configured = zscope_config.analysis.user_config_db
    raw_path = Path(configured) if configured else Path(zscope_config.analysis.snapshot_dir)
    if raw_path.suffix.lower() == ".xlsx":
        if raw_path.exists() and raw_path.is_dir():
            raise ValueError("analysis.user_config_db must point to an .xlsx workbook or a directory.")
        return raw_path
    if raw_path.suffix and not raw_path.exists():
        raise ValueError("analysis.user_config_db must point to an .xlsx workbook or a directory.")
    if raw_path.exists() and raw_path.is_file():
        raise ValueError("analysis.user_config_db must point to an .xlsx workbook or a directory.")
    return raw_path / "user_config.xlsx"


def _batch_interruption_lines(session_result: ScanSessionResult) -> list[str]:
    interrupted_entries = list(getattr(session_result, "interrupted_entries", []) or [])
    if interrupted_entries:
        preview_limit = 10
        preview = ", ".join(interrupted_entries[:preview_limit])
        if len(interrupted_entries) > preview_limit:
            preview = f"{preview}, ... (+{len(interrupted_entries) - preview_limit} more)"
        return [
            f"Interrupted entries: {len(interrupted_entries)} ({preview})",
            "Use --resume to continue from the last checkpoint.",
        ]
    if getattr(session_result, "interrupted", False):
        return [
            "Interrupted entries: unknown (scan stopped before all workers reported status).",
            "Use --resume to continue from the last checkpoint.",
        ]
    return ["Interrupted entries: none."]


if __name__ == "__main__":
    main()

