from ._version import __version__

__author__ = "Z-SCOPE Team"
__all__ = [
    "__version__",
    "Analyzer",
    "ParallelAnalyzer",
    "ZScopeConfig",
    "ConfigLoader",
    "CodeIndex",
]


def __getattr__(name):
    """Lazy-load heavy runtime classes so importing zscope does not require all deps."""
    if name == "Analyzer":
        from .core.analyzer import Analyzer

        return Analyzer
    if name == "ParallelAnalyzer":
        from .core.parallel_analyzer import ParallelAnalyzer

        return ParallelAnalyzer
    if name in {"ZScopeConfig", "ConfigLoader"}:
        from .config.config import ConfigLoader, ZScopeConfig

        return {"ZScopeConfig": ZScopeConfig, "ConfigLoader": ConfigLoader}[name]
    if name == "CodeIndex":
        from .retrieval.code_index import CodeIndex

        return CodeIndex
    raise AttributeError(f"module 'zscope' has no attribute {name!r}")
