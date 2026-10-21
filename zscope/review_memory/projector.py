from __future__ import annotations

import json
from typing import Any, Dict, List


def project_hints(hints: List[Dict[str, Any]], *, token_budget: int = 1200) -> Dict[str, Any]:
    selected: List[Dict[str, Any]] = []
    used_tokens = 0
    if token_budget > 0:
        for hint in hints[:3]:
            estimate = max(1, (len(json.dumps(hint, ensure_ascii=False, sort_keys=True)) + 3) // 4)
            if used_tokens + estimate > token_budget:
                break
            selected.append(hint)
            used_tokens += estimate
    return {"schema_version": "zscope.validator-review-memory.v1", "authority": "advisory", "hints": selected, "selection": {"candidate_count": len(hints), "selected_count": len(selected), "omitted_count": max(0, len(hints) - len(selected)), "token_budget": token_budget}}
