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
    help="Path to config file (zscope.yaml). If not specified, searches default locations.",
)
# Legacy CLI args (optional if config file is used)
@click.option(
    "--project",
    "-p",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
    help="Path to the C project root directory.",
)
@click.option(
    "--entry",
    "-e",
    help="Name of the entry function to start analysis from.",
)
@click.option(
    "--task",
    "-t",
    help="Natural language description of the analysis task.",
)
@click.option(
    "--base-url",
    envvar="ZSCOPE_BASE_URL",
    help="Base URL for OpenAI-compatible LLM API.",
)
@click.option(
    "--api-key",
    envvar="ZSCOPE_API_KEY",
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
    config: Path,
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

    # Try to load from config file first
    zscope_config = None
    if config:
        try:
            zscope_config = ConfigLoader.load(str(config))
            logger.info(f"Loaded configuration from: {config}")
        except Exception as e:
            logger.error(f"Failed to load config file: {e}")
            sys.exit(1)
    else:
        # Try default locations
        try:
            zscope_config = ConfigLoader.load()
            logger.info("Loaded configuration from default location")
        except FileNotFoundError:
            # No config file found, use CLI args
            logger.info("No config file found, using command-line arguments")
        except Exception as e:
            logger.warning(f"Failed to load default config: {e}. Using CLI args.")

    # If config file loaded, use it
    if zscope_config:
        logger.info(f"Initializing Z-SCOPE for project: {zscope_config.project.project_root}")
        logger.info(f"Entry function: {zscope_config.project.entry_function}")
    else:
        # Validate CLI args if no config file
        if not project or not entry or not task or not base_url or not api_key:
            click.echo("Error: Either provide --config or all required arguments (--project, --entry, --task, --base-url, --api-key)")
            sys.exit(1)

        logger.info(f"Initializing Z-SCOPE for project: {project}")
        logger.info(f"Entry function: {entry}")

        # Build config from CLI args
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
        
        indexing_config = IndexingConfig()

        zscope_config = ZScopeConfig(
            llm=llm_config,
            project=project_config,
            analysis=analysis_config,
            indexing=indexing_config,
        )

    # Initialize and run analyzer
    try:
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
