"""
Z-SCOPE: Zeal + Scope
AI-powered defect detection for C projects.
"""

from .analyzer import Analyzer
from .parallel_analyzer import ParallelAnalyzer
from .config import ZScopeConfig, ConfigLoader
from .code_index import CodeIndex

__version__ = "0.1.0"
__author__ = "Z-SCOPE Team"
__all__ = ["Analyzer", "ParallelAnalyzer", "ZScopeConfig", "ConfigLoader", "CodeIndex"]
