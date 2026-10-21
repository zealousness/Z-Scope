"""Deterministic project-document ingestion for the LLM Wiki."""

from .classification import DocumentClassifier, classify_document, classify_file
from .discovery import DiscoveryResult, MarkdownDiscovery, discover_markdown
from .markdown_parser import MarkdownDocument, parse_markdown, parse_sections
from .source_manifest import build_source_manifest
from .source_index import SourceIndex, SourceIndexBuild, build_source_index

__all__ = [
    "build_source_manifest",
    "DiscoveryResult",
    "MarkdownDiscovery",
    "discover_markdown",
    "DocumentClassifier",
    "classify_document",
    "classify_file",
    "MarkdownDocument",
    "parse_markdown",
    "parse_sections",
    "SourceIndex",
    "SourceIndexBuild",
    "build_source_index",
]
