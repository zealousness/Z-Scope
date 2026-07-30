from pathlib import Path

import pytest

from zscope.orchestration.specs import WorkflowSpec


def test_workflow_rejects_fields_that_are_not_executed(tmp_path: Path) -> None:
    workflow = tmp_path / "bad.yaml"
    workflow.write_text(
        """
name: bad
steps:
  - id: analyze
    scope: entry
    skills: [bounds]
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="non-executable field"):
        WorkflowSpec.from_yaml(workflow)
