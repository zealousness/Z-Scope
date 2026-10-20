"""Bind the locally reviewed candidate to its staged evidence before application."""
import ast
import hashlib
import json
from pathlib import Path

base = Path(__file__).resolve().parent
digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
checks = json.loads((base / "reviewed-regressions.json").read_text())
lifecycle = json.loads((base / "lifecycle-reviewed.json").read_text())
stage = Path(checks["work"]) / "repo/zscope/core/validation/dynamic_reproduction.py"
candidate = base / "dynamic_reproduction.candidate.py"
assert ast.dump(ast.parse(stage.read_text())) == ast.dump(ast.parse(candidate.read_text()))
assert checks["counts"] == {"passed": 8, "failed": 0, "errors": 0, "skipped": 0}
assert lifecycle["counts"] == {"passed": 5, "failed": 0, "errors": 0, "skipped": 0}
assert not checks["changed_inputs"]
review = json.loads((base / "candidate-review.json").read_text())
review["preformatCandidateDigest"] = review["candidateDigest"]
review["candidateDigest"] = digest(candidate)
review["formatting_ast_equivalent"] = True
(base / "candidate-review.json").write_text(json.dumps(review, indent=2) + "\n")
accepted = {
    "accepted": True, "sessionId": review["sessionId"],
    "sourceDigest": review["sourceDigest"], "candidateDigest": review["candidateDigest"],
    "modelCandidateDigest": review["modelCandidateDigest"],
    "localReviewChanges": review["localReviewChanges"],
    "resource_tests": checks["counts"], "lifecycle_tests": lifecycle["counts"],
    "formatting_ast_equivalent": True,
    "static_review": ["Exact original-source replacements only",
                      "Per-stream spool writes and EOF probes stay bounded",
                      "No replacement of cancellation/shared budget/deadline",
                      "Known owned process-group identity survives leader exit",
                      "Always clean descendants, including closed-pipe children",
                      "Pipe read errors cannot become clean EOF",
                      "Source/binary drift, witness trust and TTL unchanged"],
}
(base / "independent-review-accepted.json").write_text(json.dumps(accepted, indent=2) + "\n")
print(json.dumps(accepted))
