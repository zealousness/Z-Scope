"""No-LLM source-document fallback for project knowledge queries."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..models import DirectResolution, SourceExcerpt
from .obligation import ConstraintObligation


@dataclass
class DirectDocumentResolver:
    """Resolve bounded source excerpts from the deterministic SQLite index."""

    source_index: object

    def resolve(
        self,
        obligation: ConstraintObligation,
        *,
        max_results: int = 4,
        max_tokens: Optional[int] = None,
        fallback_reason: str = "compiler_unavailable",
    ) -> DirectResolution:
        rows = self.source_index.search(obligation, max_results=max_results, max_tokens=max_tokens)
        excerpts = tuple(
            SourceExcerpt(
                ref_id=row["ref_id"],
                relative_path=row["relative_path"],
                heading_path=tuple(row["heading_path"]),
                start_line=int(row["start_line"]),
                end_line=int(row["end_line"]),
                text=row["text"],
                match_reasons=tuple(row["match_reasons"]),
                score=float(row["score"]),
            )
            for row in rows
        )
        if excerpts:
            return DirectResolution(source_excerpts=excerpts, fallback_reason=fallback_reason)
        return DirectResolution(source_excerpts=(), fallback_reason="no_relevant_project_constraint")
