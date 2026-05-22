from types import SimpleNamespace

from zscope.core.validation.pipeline import ValidationPipeline
from zscope.core.validation.runner import ValidationRunner
from zscope.framework.base import AgentResponse


class FakeUserConfig:
    def __init__(self):
        self.baseline = None

    def is_false_positive(self, func_name, location, category):
        return False

    def get_finding_baseline_for_issue(self, issue, dedup_key):
        return self.baseline

    def get_finding_baseline(self, dedup_key):
        return self.baseline


class FakeCodeIndex:
    def get_file_snippet(self, file_path, start, end):
        return "snippet"

    def get_callers(self, func_name, limit=8):
        return []

    def get_callees(self, func_name, limit=12):
        return []

    def get_function_impl(self, func_name):
        return {"code": "void sink_func(void) {}"}


class FakeSnapshotStore:
    def load_snapshot(self, func_name):
        return None


class FakeValidatorAgent:
    def __init__(self, responses):
        self.responses = list(responses)
        self.inputs = []

    def run(self, input_data):
        self.inputs.append(input_data)
        return self.responses.pop(0)


def _runner(agent, *, enabled=True, memory=None):
    memory = memory if memory is not None else []
    config = SimpleNamespace(
        project=SimpleNamespace(
            agents=[SimpleNamespace(name="validator_agent", enabled=enabled, llm_ref="default")]
        )
    )
    return ValidationRunner(
        config=config,
        llm_clients={"default": object()},
        validation_pipeline=ValidationPipeline(FakeUserConfig()),
        code_index=FakeCodeIndex(),
        snapshot_store=FakeSnapshotStore(),
        get_tools=lambda agent_name: [],
        tool_policy_for_agent=lambda agent_name: None,
        attach_agent_contract=lambda context, agent_name: context.update({"agent_contract": agent_name}),
        remember_validation_result=lambda issue, status: memory.append((issue["id"], status)),
        validator_agent_factory=lambda *args, **kwargs: agent,
    )


def _state(issue):
    return {
        "pending_new_issues": [issue],
        "agent_context": {
            "func_name": "api_entry",
            "code": "void api_entry(void) { sink_func(); }",
            "entry_custom_prompt": "Public API declared in header file",
        },
        "entry_func": "api_entry",
        "issues": [],
        "observations": [],
        "notes": [],
    }


def _issue(**overrides):
    issue = {
        "id": "ISSUE_1",
        "function": "sink_func",
        "entry_function": "api_entry",
        "location": "src/demo.c:10",
        "category": "memory_leak",
        "confidence": 1.0,
        "rule_confidence": 1.0,
        "source": "arg",
        "sink": "free",
        "evidence_pack": {"path": {"complete": True, "complete_to_entry": True}},
    }
    issue.update(overrides)
    return issue


def test_validation_runner_validates_issue_and_remembers_outcome() -> None:
    memory = []
    agent = FakeValidatorAgent(
        [
            AgentResponse(
                success=True,
                data={
                    "verdict": "verified",
                    "reasoning": "reachable public API path",
                    "confidence_score": 1.0,
                    "source": "arg",
                    "sink": "free",
                },
            )
        ]
    )
    state = _state(_issue())

    _runner(agent, memory=memory).run(state)

    assert state["pending_new_issues"] == []
    assert len(state["issues"]) == 1
    assert state["issues"][0]["validation_status"] == "validated"
    assert state["issues"][0]["validator_verdict"] == "verified"
    assert memory == [("ISSUE_1", "validated")]
    assert agent.inputs[0]["agent_contract"] == "validator_agent"


def test_validation_runner_retries_entry_root_dead_code_rejection_as_observation() -> None:
    memory = []
    agent = FakeValidatorAgent(
        [
            AgentResponse(
                success=True,
                data={"verdict": "rejected", "reasoning": "No callers, dead code."},
            ),
            AgentResponse(
                success=True,
                data={"verdict": "rejected", "reasoning": "Still no callers above main."},
            ),
        ]
    )
    state = _state(_issue(id="ISSUE_2"))

    _runner(agent, memory=memory).run(state)

    assert len(agent.inputs) == 2
    assert agent.inputs[1]["evidence_pack"]["mode"] == "tri_state_exploitability_validation_entry_root_retry"
    assert state["issues"] == []
    assert len(state["observations"]) == 1
    assert state["observations"][0]["validation_status"] == "needs_review"
    assert state["observations"][0]["finding_kind"] == "needs_review"
    assert memory == [("ISSUE_2", "needs_review")]


def test_validation_runner_rewrites_contract_scope_rejection_as_observation() -> None:
    memory = []
    agent = FakeValidatorAgent(
        [
            AgentResponse(
                success=True,
                data={
                    "verdict": "rejected",
                    "reasoning": "The current callback is empty and only local.",
                },
            )
        ]
    )
    state = _state(
        _issue(
            id="ISSUE_3",
            defect_class="held_lock_callback",
            evidence_refs=["src/demo.c:10: callback invoked under lock"],
        )
    )

    _runner(agent, memory=memory).run(state)

    assert state["issues"] == []
    assert len(state["observations"]) == 1
    observation = state["observations"][0]
    assert observation["validation_status"] == "needs_review"
    assert observation["finding_kind"] == "needs_review"
    assert "external entry contract" in observation["validation_reasoning"]
    assert memory == [("ISSUE_3", "needs_review")]


def test_validation_runner_keeps_structured_reachable_caller_control_rejection() -> None:
    memory = []
    agent = FakeValidatorAgent(
        [
            AgentResponse(
                success=True,
                data={
                    "verdict": "rejected",
                    "reasoning": (
                        "The current direct caller uses a local buffer, so the input is not "
                        "caller controllable and this is only by design."
                    ),
                },
            )
        ]
    )
    state = _state(
        _issue(
            id="ISSUE_5",
            category="alignment",
            defect_class="alignment",
            evidence_checker="clang_ast_cfg",
            positive_evidence=["packet + 1 is cast to uint32_t *"],
            source="public packet bytes",
            sink="unaligned uint32_t load",
        )
    )

    _runner(agent, memory=memory).run(state)

    assert state["issues"] == []
    assert len(state["observations"]) == 1
    observation = state["observations"][0]
    assert observation["validation_status"] == "needs_review"
    assert observation["finding_kind"] == "needs_review"
    assert observation["validator_verdict"] == "uncertain"
    assert memory == [("ISSUE_5", "needs_review")]


def test_validation_runner_recovers_uncertain_observation_location_from_evidence_pack() -> None:
    agent = FakeValidatorAgent(
        [
            AgentResponse(
                success=True,
                data={"verdict": "uncertain", "reasoning": "Plausible, needs source review."},
            )
        ]
    )
    issue = _issue(
        id="ISSUE_4",
        location="",
        file="",
        line=None,
        start_line=None,
        evidence_pack={
            "path": {"complete": True, "complete_to_entry": True},
            "finding_summary": {
                "function": "sink_func",
                "location": "src/recovered.c:77-79",
            },
            "source_loc": "src/recovered.c:70",
        },
    )
    state = _state(issue)

    _runner(agent).run(state)

    assert state["issues"] == []
    assert len(state["observations"]) == 1
    observation = state["observations"][0]
    assert observation["validation_status"] == "uncertain"
    assert observation["location"] == "src/recovered.c:77-79"
    assert observation["file"] == "src/recovered.c"
    assert observation["line"] == 77
    assert observation["start_line"] == 77
    assert observation["end_line"] == 79
    assert observation["source_loc"] == "src/recovered.c:70"
