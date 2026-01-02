"""
Command Line Interface for Z-SCOPE.
"""

import click
import logging
import sys
from pathlib import Path

from .config import ZScopeConfig, LLMConfig, AnalysisConfig, ProjectConfig
from .analyzer import Analyzer
from .utils import setup_logging

@click.command()
@click.option(
    "--project",
    "-p",
    required=True,
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
    help="Path to the C project root directory.",
)
@click.option(
    "--entry",
    "-e",
    required=True,
    help="Name of the entry function to start analysis from.",
)
@click.option(
    "--task",
    "-t",
    required=True,
    help="Natural language description of the analysis task.",
)
@click.option(
    "--base-url",
    envvar="ZSCOPE_BASE_URL",
    required=True,
    help="Base URL for OpenAI-compatible LLM API.",
)
@click.option(
    "--api-key",
    envvar="ZSCOPE_API_KEY",
    required=True,
    help="API Key for LLM.",
)
@click.option(
    "--model",
    default=None,
    help="Model name to use (optional, defaults to server preference).",
)
@click.option(
    "--compile-db",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to compile_commands.json (optional).",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging.")
def main(
    project: Path,
    entry: str,
    task: str,
    base_url: str,
    api_key: str,
    model: str,
    compile_db: Path,
    verbose: bool,
):
    """
    Z-SCOPE: AI-powered defect detection for C projects.
    """
    setup_logging(verbose)
    logger = logging.getLogger("zscope.cli")

    logger.info(f"Initializing Z-SCOPE for project: {project}")
    logger.info(f"Entry function: {entry}")

    # Build config
    llm_config = LLMConfig(
        api_key=api_key,
        base_url=base_url,
        model=model,
    )

    project_config = ProjectConfig(
        project_root=project,
        entry_function=entry,
        task_description=task,
        compile_commands_path=compile_db,
    )

    analysis_config = AnalysisConfig(
        snapshot_dir=str(project / ".zscope_snapshots")
    )

    config = ZScopeConfig(
        llm=llm_config,
        project=project_config,
        analysis=analysis_config
    )

    # Initialize and run analyzer
    try:
        analyzer = Analyzer(config)
        result = analyzer.run()
        
        overall_verdict = result.get("overall_verdict", "unknown")
        issues_count = len(result.get("issues", []))
        
        click.echo(f"\nAnalysis Complete. Verdict: {overall_verdict}. Issues found: {issues_count}")
        click.echo(f"Reports saved in: {project}")
        
        if issues_count > 0:
            sys.exit(1)
        else:
            sys.exit(0)

    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
