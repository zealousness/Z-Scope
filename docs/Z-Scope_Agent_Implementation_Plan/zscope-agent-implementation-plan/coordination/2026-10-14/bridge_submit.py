"""Submit only a checked request to the existing standard-MCP client's queue."""

from __future__ import annotations

import json
from pathlib import Path
import sys

from dispatch_safety import DispatchJournal, DispatchStopped, validate_route

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]


def main():
    source = Path(sys.argv[1]).resolve()
    if not source.is_relative_to(ROOT):
        raise DispatchStopped("request_file_must_be_in_project")
    request = json.loads(source.read_text(encoding="utf-8"))
    arguments = request.get("arguments", {})
    if request.get("tool") != "dispatch_task" or Path(arguments.get("cwd", "")).resolve() != ROOT:
        raise DispatchStopped("public_dispatch_and_current_project_required")
    if not request.get("branch") or not arguments.get("request_id"):
        raise DispatchStopped("branch_and_request_id_required")
    agent = arguments.get("agent")
    if agent == "kimi":
        if arguments.get("model") != "volceapi/kimi-k3":
            raise DispatchStopped("requested_kimi_model_mismatch")
    elif agent in {"dsh", "zcode"}:
        binding = json.loads((HERE / "ENTRY_BINDINGS.json").read_text(encoding="utf-8"))[agent]
        if not binding.get("dispatch_ready"):
            raise DispatchStopped("agent_route_or_prior_execution_unverified_no_send")
        evidence = json.loads(
            (HERE / f"{agent}-current-route-evidence.json").read_text(encoding="utf-8")
        )
        validate_route(dict(binding, agent=agent), evidence, connection_state="ready")
        if arguments.get("model") != binding["model"]:
            raise DispatchStopped("requested_model_does_not_match_binding")
    else:
        raise DispatchStopped("agent_not_authorized_for_this_round")
    journal = DispatchJournal(HERE / "dispatch-journal.sqlite")
    try:
        claimed = journal.claim(
            arguments["request_id"], request["branch"], arguments, connection_state="ready"
        )
        if claimed["send"]:
            journal.queued(arguments["request_id"])
            name = request["id"]
            if not name or any(
                c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
                for c in name
            ):
                journal.uncertain(arguments["request_id"])
                raise DispatchStopped("unsafe_request_id")
            queue = HERE / "bridge-queue"
            queue.mkdir(exist_ok=True)
            target = queue / ("100-" + arguments["request_id"] + "-" + name + ".request.json")
            temporary = target.with_suffix(".tmp")
            with temporary.open("x", encoding="utf-8", newline="\n") as output:
                output.write(json.dumps(request, ensure_ascii=False) + "\n")
            if target.exists():
                journal.uncertain(arguments["request_id"])
                raise DispatchStopped("queue_entry_already_exists_inspect_before_retry")
            temporary.rename(target)
        print(
            json.dumps(
                {"agent": agent, "branch": request["branch"], "submission": claimed},
                ensure_ascii=False,
            )
        )
    finally:
        journal.close()


if __name__ == "__main__":
    try:
        main()
    except DispatchStopped as error:
        print(json.dumps({"stopped": True, "reason": str(error)}))
        raise SystemExit(2)
