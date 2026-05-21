from zscope.orchestration.workflow_runner import WorkflowRunner


class FakeExecutor:
    def __init__(self, final_report_dict=None):
        self.current_step = None
        self.final_report_dict = final_report_dict
        self.steps_seen = None

    def execute(self, state, steps):
        self.steps_seen = list(steps)
        self.current_step = self.steps_seen[-1] if self.steps_seen else None
        if self.final_report_dict is not None:
            state["final_report_dict"] = self.final_report_dict


def test_workflow_runner_builds_and_persists_when_no_report_exists() -> None:
    executor = FakeExecutor()
    built = []
    persisted = []
    current_steps = []
    state = {"entry_func": "entry", "final_report": None}

    runner = WorkflowRunner(
        workflow_name="default",
        state_factory=lambda: state,
        step_selector=lambda: ["model", "validate"],
        executor=executor,
        build_final_report=lambda workflow_state: built.append(workflow_state),
        persist_final_report=lambda workflow_state: persisted.append(workflow_state) or {"ok": True},
        finalize_returned_report=lambda workflow_state: {"unexpected": True},
        current_step_sink=current_steps.append,
    )

    assert runner.run() == {"ok": True}
    assert built == [state]
    assert persisted == [state]
    assert executor.steps_seen == ["model", "validate"]
    assert current_steps == ["validate"]


def test_workflow_runner_finalizes_existing_returned_report() -> None:
    state = {"entry_func": "entry", "final_report": None}
    executor = FakeExecutor(final_report_dict={"metadata": {"old": True}})

    runner = WorkflowRunner(
        workflow_name="resume",
        state_factory=lambda: state,
        step_selector=lambda: ["resume"],
        executor=executor,
        build_final_report=lambda workflow_state: (_ for _ in ()).throw(AssertionError()),
        persist_final_report=lambda workflow_state: (_ for _ in ()).throw(AssertionError()),
        finalize_returned_report=lambda workflow_state: {"metadata": {"new": True}},
    )

    assert runner.run() == {"metadata": {"new": True}}


def test_workflow_runner_returns_state_error_without_executing() -> None:
    executor = FakeExecutor()
    runner = WorkflowRunner(
        workflow_name="default",
        state_factory=lambda: {"error": "missing entry"},
        step_selector=lambda: ["never"],
        executor=executor,
        build_final_report=lambda workflow_state: None,
        persist_final_report=lambda workflow_state: {},
        finalize_returned_report=lambda workflow_state: {},
    )

    assert runner.run() == {"error": "missing entry"}
    assert executor.steps_seen is None
