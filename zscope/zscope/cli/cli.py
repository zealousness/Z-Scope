"""
Command Line Interface for Z-SCOPE.
"""

import click
import logging
import sys
from pathlib import Path

from ..config.config import ZScopeConfig, LLMConfig, AnalysisConfig, ProjectConfig, IndexingConfig, ConfigLoader
from ..core.analyzer import Analyzer
from ..common.utils import setup_logging

@click.command()
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to config file (zscope.yaml).",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging.")
def main(
    config: Path,
    verbose: bool,
):
    """
    Z-SCOPE: AI-powered defect detection for C projects.
    """
    setup_logging(verbose)
    logger = logging.getLogger("zscope.cli")

    if not config:
        config = Path("zscope.yaml")
        if not config.exists():
            click.echo("Error: Please provide a config file using --config or create zscope.yaml")
            sys.exit(1)

    try:
        zscope_config = ConfigLoader.load(str(config))
        logger.info(f"Loaded configuration from: {config}")
        logger.info(f"Entry function: {zscope_config.project.entry_function}")

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
