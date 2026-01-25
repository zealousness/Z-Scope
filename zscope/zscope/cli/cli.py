"""
Command Line Interface for Z-SCOPE.
"""

import click
import logging
import sys
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
def main(
    config: Path,
    verbose: bool,
    dashboard: bool,
):
    """
    Z-SCOPE: AI-powered defect detection for C projects.
    """
    setup_logging(verbose)
    logger = logging.getLogger("zscope.cli")

    if dashboard:
        logger.info("Launching dashboard...")
        from ..web.server import run_server
        run_server()
        sys.exit(0)

    if not config:
        config = Path("zscope.yaml")
        if not config.exists():
            click.echo("Error: Please provide a config file using --config or create zscope.yaml")
            sys.exit(1)

    try:
        zscope_config = ConfigLoader.load(str(config))
        logger.info(f"Loaded configuration from: {config}")
        
        # Detect batch mode vs single mode
        if zscope_config.project.entry_functions_list:
            # Batch mode
            logger.info(f"Batch mode activated: {zscope_config.project.entry_functions_list}")
            entries = FunctionListLoader.load(zscope_config.project.entry_functions_list)
            logger.info(f"Loaded {len(entries)} function entries")
            
            # Build code index once (shared across all analyses)
            logger.info("Building shared code index...")
            code_index = CodeIndex(
                zscope_config.project.project_root,
                zscope_config.project.compile_commands_path
            )
            
            # Create parallel analyzer with shared code index
            parallel_analyzer = ParallelAnalyzer(zscope_config, code_index=code_index)
            
            # Run batch analysis
            results = parallel_analyzer.analyze_function_entries(entries)
            
            # Generate reports
            json_report_path = zscope_config.project.project_root / "zscope_batch_report.json"
            md_report_path = zscope_config.project.project_root / "zscope_batch_report.md"
            
            combined_report = parallel_analyzer.generate_combined_report(results, json_report_path)
            parallel_analyzer.generate_combined_markdown_report(results, md_report_path)
            
            total_issues = combined_report["summary"]["total_issues"]
            functions_analyzed = combined_report["summary"]["functions_analyzed"]
            
            click.echo(f"\nBatch Analysis Complete.")
            click.echo(f"Functions analyzed: {functions_analyzed}")
            click.echo(f"Total issues found: {total_issues}")
            click.echo(f"Reports saved: {json_report_path}, {md_report_path}")
            
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


if __name__ == "__main__":
    main()

