"""
Command Line Interface for Z-SCOPE.
"""

import click
import logging
import sys
import os
from pathlib import Path # Keep this import as it's used for 'config: Path'
from ..retrieval.code_index import CodeIndex
from ..common.utils import setup_logging
from ..config.config import ZScopeConfig, LLMConfig, AnalysisConfig, ProjectConfig, IndexingConfig, ConfigLoader
from ..config.function_entry import FunctionListLoader
from ..core.analyzer import Analyzer
from ..core.parallel_analyzer import ParallelAnalyzer

@click.command()
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to config file (zscope.yaml).",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging.")
@click.option("--dashboard", "-d", is_flag=True, help="Launch the web dashboard to view results.")
@click.option("--build-cpg", is_flag=True, help="Only build CPG and index, then exit.")
@click.option("--mode", type=click.Choice(["default", "topdown", "ruledriven", "alert-verify"]), default="default", help="Analysis mode.")
@click.option("--sarif", type=click.Path(exists=True, dir_okay=False, path_type=Path), default=None, help="SARIF file for alert-verify mode.")
@click.option("--resume-from", type=str, default=None, help="Resume batch or alert-verify scan from a specific function name or alert ID.")
def main(
    config: Path,
    verbose: bool,
    dashboard: bool,
    build_cpg: bool,
    mode: str,
    sarif: Path,
    resume_from: str,
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
        from ..core.snapshot_store import SnapshotStore

        if not config:
            config = Path("zscope.yaml")
        if config.exists():
            zscope_config = ConfigLoader.load(str(config))
            cfg = zscope_config.indexing
            # 通过 CodeIndex 创建后端，保持统一入口
            code_index = CodeIndex(
                zscope_config.project.project_root,
                zscope_config.project.compile_commands_path,
                source_root=zscope_config.project.source_root,
                indexing_config=cfg,
                wait_for_cpg=False,
            )
            db_dir = Path(zscope_config.analysis.user_config_db) if zscope_config.analysis.user_config_db else Path(zscope_config.analysis.snapshot_dir)
            ucs = UserConfigStore(db_dir)
            snapshot_store = SnapshotStore(Path(zscope_config.analysis.snapshot_dir))
            
            run_server(
                code_index=code_index,
                user_config_store=ucs,
                project_config=zscope_config.project,
                snapshot_store=snapshot_store,
            )
        else:
            click.echo("Warning: No config file found, dashboard running without backend/config support")
            run_server()
        sys.exit(0)

    if not config:
        config = Path("zscope.yaml")
        if not config.exists():
            click.echo("Error: Please provide a config file using --config or create zscope.yaml")
            sys.exit(1)

    code_index = None
    try:
        zscope_config = ConfigLoader.load(str(config))
        logger.info(f"Loaded configuration from: {config}")

        if build_cpg:
            click.echo("Building CPG and index...")
            code_index = CodeIndex(
                zscope_config.project.project_root,
                zscope_config.project.compile_commands_path,
                source_root=zscope_config.project.source_root,
                indexing_config=zscope_config.indexing,
                wait_for_cpg=True,
            )
            func_count = len(code_index.list_functions())
            click.echo(f"CPG build complete. Indexed {func_count} functions.")
            sys.exit(0)

        # ── Mode-specific analysis ──
        if mode == "topdown":
            logger.info("Top-down mode: analyzing public API functions from headers")
            code_index = CodeIndex(
                zscope_config.project.project_root,
                zscope_config.project.compile_commands_path,
                source_root=zscope_config.project.source_root,
                indexing_config=zscope_config.indexing,
            )
            pa = ParallelAnalyzer(zscope_config, code_index=code_index)
            results = pa.run_topdown_mode()
            json_path = zscope_config.project.project_root / "zscope_batch_report.json"
            md_path = zscope_config.project.project_root / "zscope_batch_report.md"
            combined = pa.generate_combined_report(results, json_path)
            pa.generate_combined_markdown_report(results, md_path)
            total = combined["summary"]["total_issues"]
            click.echo(f"\nTop-down analysis complete. Functions: {len(results)}, Issues: {total}")
            sys.exit(1 if total > 0 else 0)

        if mode == "ruledriven":
            logger.info("Rule-driven mode: running Joern rules + validation")
            from ..core.rule_driven_analyzer import RuleDrivenAnalyzer
            code_index = CodeIndex(
                zscope_config.project.project_root,
                zscope_config.project.compile_commands_path,
                source_root=zscope_config.project.source_root,
                indexing_config=zscope_config.indexing,
            )
            rda = RuleDrivenAnalyzer(zscope_config, code_index=code_index)
            result = rda.run()
            issues_count = len(result.get("issues", []))
            click.echo(f"\nRule-driven analysis complete. Issues: {issues_count}")
            sys.exit(1 if issues_count > 0 else 0)

        if mode == "alert-verify":
            if not sarif:
                click.echo("Error: --sarif is required for alert-verify mode")
                sys.exit(1)
            logger.info("Alert verification mode: validating SARIF alerts")
            from ..core.sarif_adapter import SarifAdapter
            from ..core.alert_verifier import AlertVerifier
            from ..framework.llm_client import LLMClient
            from ..config.user_config_store import UserConfigStore

            code_index = CodeIndex(
                zscope_config.project.project_root,
                zscope_config.project.compile_commands_path,
                source_root=zscope_config.project.source_root,
                indexing_config=zscope_config.indexing,
            )
            adapter = SarifAdapter(
                source_root=str(zscope_config.project.source_root),
            )
            alerts = adapter.parse(str(sarif))
            click.echo(f"Parsed {len(alerts)} alerts from SARIF")
            
            if resume_from:
                idx = next((i for i, a in enumerate(alerts) if a.id == resume_from or a.function == resume_from), -1)
                if idx >= 0:
                    click.echo(f"Resuming scan from alert/function '{resume_from}' (skipping {idx} alerts)")
                    alerts = alerts[idx:]
                else:
                    click.echo(f"Warning: '--resume-from {resume_from}' not found in SARIF. Starting from beginning.")

            if not alerts:
                click.echo("No alerts to verify.")
                sys.exit(0)

            val_agent_cfg = next((a for a in zscope_config.project.agents if a.name == "validator_agent"), None)
            val_llm_ref = val_agent_cfg.llm_ref if val_agent_cfg and val_agent_cfg.llm_ref else "default"
            llm_cfg = zscope_config.llms.get(val_llm_ref, zscope_config.llms["default"])
            
            llm_client = LLMClient(
                api_key=llm_cfg.api_key,
                base_url=llm_cfg.base_url,
                models=llm_cfg.models,
                timeout=llm_cfg.timeout,
                max_retries=llm_cfg.max_retries,
                max_tokens=llm_cfg.max_tokens,
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
            results = verifier.verify_alerts(alerts)

            # 输出报告
            import json
            report_path = zscope_config.project.project_root / "zscope_alert_verify_report.json"
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump({"results": results}, f, ensure_ascii=False, indent=2)

            confirmed = sum(1 for r in results if r.get("verdict") == "confirmed")
            rejected = sum(1 for r in results if r.get("verdict") == "rejected")
            click.echo(f"\nVerification complete: {confirmed} confirmed, {rejected} rejected")
            click.echo(f"Report: {report_path}")
            sys.exit(1 if confirmed > 0 else 0)

        # Detect batch mode vs single mode
        if zscope_config.project.entry_functions_list:
            # Batch mode
            logger.info(f"Batch mode activated: {zscope_config.project.entry_functions_list}")
            entries = FunctionListLoader.load(zscope_config.project.entry_functions_list)
            logger.info(f"Loaded {len(entries)} function entries")
            
            # Save the full entries list before slicing for resume
            all_entries = list(entries)
            skipped_entries = []
            
            if resume_from:
                idx = next((i for i, e in enumerate(entries) if e.function_name == resume_from), -1)
                if idx >= 0:
                    click.echo(f"Resuming scan from function '{resume_from}' (skipping {idx} functions)")
                    skipped_entries = entries[:idx]
                    entries = entries[idx:]
                else:
                    click.echo(f"Warning: '--resume-from {resume_from}' not found in entries. Starting from beginning.")

            # Build code index once (shared across all analyses)
            logger.info("Building shared code index...")
            code_index = CodeIndex(
                zscope_config.project.project_root,
                zscope_config.project.compile_commands_path,
                source_root=zscope_config.project.source_root,
                indexing_config=zscope_config.indexing,
                priority_functions=[e.function_name for e in entries]
            )

            # Create parallel analyzer with shared code index
            parallel_analyzer = ParallelAnalyzer(zscope_config, code_index=code_index)

            # Run batch analysis
            results = parallel_analyzer.analyze_function_entries(entries)

            # Generate reports
            json_report_path = zscope_config.project.project_root / "zscope_batch_report.json"
            md_report_path = zscope_config.project.project_root / "zscope_batch_report.md"

            # For --resume-from: load skipped functions' issues from SQLite snapshot store
            # (each function's final report is persisted to SQLite immediately after analysis,
            #  so this is the reliable source of truth even if the previous run was Ctrl+C'd)
            if skipped_entries:
                from ..core.parallel_analyzer import ParallelAnalysisResult
                from ..core.snapshot_store import SnapshotStore

                snapshot_store = SnapshotStore(Path(zscope_config.analysis.snapshot_dir))
                merged_count = 0

                for entry in skipped_entries:
                    fname = entry.function_name
                    if fname in results:
                        continue  # Already analyzed in this run (shouldn't happen, but be safe)

                    saved_report = snapshot_store.load_final_report(fname)
                    if saved_report:
                        saved_issues = saved_report.get("issues", [])
                        saved_verdict = saved_report.get("overall_verdict", "unknown")
                        mock_result = ParallelAnalysisResult(
                            function_name=fname,
                            verdict=saved_verdict,
                            issues=saved_issues,
                            duration_seconds=0.0
                        )
                        results[fname] = mock_result
                        merged_count += 1
                    else:
                        logger.warning(f"No saved report found in SQLite for skipped function '{fname}'")

                if merged_count > 0:
                    logger.info(f"Loaded {merged_count} skipped function reports from snapshot database.")

            # Create a failsafe backup before overwriting existing report
            if json_report_path.exists():
                try:
                    import shutil
                    import time
                    backup_dir = zscope_config.project.project_root / ".zscope_knowledge" / "backups"
                    backup_dir.mkdir(parents=True, exist_ok=True)
                    timestamp = time.strftime("%Y%m%d_%H%M%S")
                    backup_path = backup_dir / f"zscope_batch_report_{timestamp}.json"
                    shutil.copy2(json_report_path, backup_path)
                    logger.info(f"Created failsafe backup of previous batch report at {backup_path}")
                except Exception as e:
                    logger.warning(f"Failed to create backup of batch report: {e}")

            combined_report = parallel_analyzer.generate_combined_report(results, json_report_path)
            parallel_analyzer.generate_combined_markdown_report(results, md_report_path)

            total_issues = combined_report["summary"]["total_issues"]
            functions_analyzed = combined_report["summary"]["functions_analyzed"]

            click.echo(f"\nBatch Analysis Complete.")
            click.echo(f"Functions analyzed: {functions_analyzed}")
            click.echo(f"Total issues found: {total_issues}")
            click.echo(f"Reports saved: {json_report_path}, {md_report_path}")

            # Force exit if interrupted to avoid hanging on thread pool cleanup
            if getattr(parallel_analyzer, '_interrupted', False):
                click.echo("[!] Exiting immediately due to prior interrupt.")
                os._exit(1)

            if total_issues > 0:
                sys.exit(1)
            else:
                sys.exit(0)
        else:
            # Single function mode
            entry_function = zscope_config.project.entry_function
            if not entry_function:
                 click.echo("Error: No entry function or entry functions list provided.")
                 sys.exit(1)

            logger.info(f"Single mode: entry function = {entry_function}")

            analyzer = Analyzer(zscope_config)
            result = analyzer.run()

            overall_verdict = result.get("overall_verdict", "unknown")
            issues_count = len(result.get("issues", []))

            click.echo(f"\nAnalysis Complete. Verdict: {overall_verdict}. Issues found: {issues_count}")
            click.echo(f"Reports saved in: {zscope_config.project.project_root}")

            if issues_count > 0:
                sys.exit(1)
            else:
                sys.exit(0)

    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=True)
        sys.exit(1)
    finally:
        if code_index:
            code_index.close()


if __name__ == "__main__":
    main()

