"""Paired live Validator prompt comparison; labels are read only by score.py.

Both arms use the current execution/admission code and the same source inputs.
The baseline restores the immediately preceding model-facing prompts and schema.
This is a small development experiment, not a full-pipeline benchmark.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import importlib.util
import json
import logging
import os
from pathlib import Path
import re
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from zscope.agents.base import JsonOutputSpec
from zscope.agents.validator_agent.agent import ValidatorAgent
from zscope.common.validator_protocol import parse_validator_result_v3
from zscope.core.validation.evidence import VALIDATOR_EVIDENCE_SLICE_V3
from zscope.framework.base import BaseTool
from zscope.framework.llm_client import LLMClient
from zscope.framework.llm_usage import ScanTokenUsageLedger
from zscope.orchestration.specs import AgentSpec

HERE = Path(__file__).resolve().parent


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def connection(env_file):
    values = {}
    for line in env_file.read_text(encoding="utf-8-sig").splitlines():
        match = re.fullmatch(r"(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)", line.strip())
        if match:
            key, value = match.groups()
            values[key] = value.strip().strip('"').strip("'")
    return {
        "api_key": os.environ.get("Z_SCOPE_API_KEY") or values["Z_SCOPE_API_KEY"],
        "base_url": os.environ.get("Z_SCOPE_LLM_BASE_URL") or values["Z_SCOPE_LLM_BASE_URL"],
    }


class SourceReader(BaseTool):
    """Read only the case's supplied source; no workspace or answer-file access."""

    def __init__(self, files):
        super().__init__("read_code", "Read current source from the supplied file catalog.")
        self.files = files
        self.calls = []

    def get_schema(self):
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "file_path": {"type": "string", "enum": list(self.files)},
                        "start_line": {"type": "integer", "minimum": 1},
                        "end_line": {"type": "integer", "minimum": 1},
                    },
                    "required": ["file_path"],
                    "additionalProperties": False,
                },
            },
        }

    def execute(self, arguments):
        path = arguments["file_path"]
        lines = self.files[path].splitlines()
        start, end = arguments.get("start_line", 1), arguments.get("end_line", len(lines))
        if end < start or start > len(lines):
            return {"success": False, "error": "Line range is outside this source file."}
        result = {
            "success": True,
            "status": "ok",
            "data": {
                "file": path,
                "start_line": start,
                "end_line": min(end, len(lines)),
                "code": "\n".join(lines[start - 1 : end]),
                "total_lines": len(lines),
            },
        }
        self.calls.append({"arguments": deepcopy(arguments), "result": deepcopy(result)})
        return result


class RecordedClient(LLMClient):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.exchanges = []

    def chat_completion(self, messages, **kwargs):
        started = time.monotonic()
        request = {
            "messages": deepcopy(messages),
            "options": {k: deepcopy(v) for k, v in kwargs.items() if not k.startswith("trace_")},
        }
        # Provider reasoning remains in the live session when required by the
        # client, but the experiment stores public responses and usage only.
        for message in request["messages"]:
            message.pop("reasoning_content", None)
        self.exchanges.append(request)
        try:
            response = super().chat_completion(messages, **kwargs)
        except Exception as exc:
            request["error_type"] = type(exc).__name__
            raise
        finally:
            request["seconds"] = round(time.monotonic() - started, 3)
        public = {key: deepcopy(response.get(key)) for key in ("model", "choices", "usage")}
        for choice in public.get("choices", []):
            choice.get("message", {}).pop("reasoning_content", None)
        request["response"] = public
        return response


def evidence_input(case):
    review = case.get("review", {})
    excerpts = [
        {"file": name, "code": case["source_files"][name], "start_line": 1}
        for name in case["visible_files"]
    ] + case.get("initial_code", [])
    catalog = {
        f"SRC_{index + 1}": {
            "kind": "decision_fact",
            "file": excerpt["file"],
            "code": excerpt["code"],
            "basis": "current_source",
            **(
                {"start_line": excerpt["start_line"]}
                if "start_line" in excerpt
                else {"coverage": "selected source fragments; not a contiguous line range"}
            ),
        }
        for index, excerpt in enumerate(excerpts)
    }
    obligation = {
        **case["finding"],
        "candidate_uid": "CAND_" + case["id"],
        "validation_cluster_uid": "VAL_" + case["id"],
        "subject_uid": "OBJ_" + case["id"],
    }
    evidence = {
        "schema_version": VALIDATOR_EVIDENCE_SLICE_V3,
        "protocol_version": "zscope.validator-protocol.v3",
        "validation_pass": case["stage"],
        "obligation": obligation,
        "evidence_ref_catalog": catalog,
        "available_source_files": list(case["source_files"]),
        "decision_facts": {"facts": list(catalog.values())},
        "allowed_missing_fact_kinds": case.get("allowed_missing_fact_kinds", []),
        "entry_conditions": case.get("conditions", []),
    }
    if case.get("unresolved_condition"):
        evidence["unresolved_condition"] = case["unresolved_condition"]
    if review.get("prior_rejection"):
        evidence["prior_rejection"] = review["prior_rejection"]
    return {
        "evidence_slice": evidence,
        "validation_pass": case["stage"],
        "candidate_build_context_id": "BUILD_" + case["id"],
        "candidate_subject_uid": obligation["subject_uid"],
        "autonomous_validation": True,
        "review_protocol_enabled": review.get("enabled", False),
        "review_rejection_expected": bool(review.get("prior_rejection")),
    }


def baseline_agent_class():
    prompts = load_module("comparison_baseline_prompts", HERE / "baseline/prompts.py")
    protocol = load_module("comparison_baseline_protocol", HERE / "baseline/schema.py")
    terminal = json.loads((HERE / "baseline/terminal_spec.json").read_text(encoding="utf-8"))

    class BaselineAgent(ValidatorAgent):
        _validator_v3_prompt = staticmethod(prompts.direct_prompt)

        @classmethod
        def _validation_json_output_spec_v3(cls, **kwargs):
            return JsonOutputSpec(
                type_name=terminal["type_name"],
                schema=protocol.validator_result_provider_schema_v3(**kwargs),
                final_tool_name=terminal["final_tool_name"],
                final_tool_description=terminal["final_tool_description"],
                validator=lambda value: parse_validator_result_v3(value) is not None,
                metadata_prefix="validator",
            )

        def _run_tool_conversation(self, messages, **kwargs):
            session = kwargs.get("tool_executor")
            if session is not None and hasattr(session, "pass_kind"):
                messages = deepcopy(messages)
                messages[1]["content"] = prompts.investigation_prompt(
                    session, kwargs["max_iterations"]
                )
                schemas = deepcopy(kwargs["additional_tools_schema"])
                # The live comparison found an ambiguous reference boundary.
                # Its new argument guidance belongs only to the optimized arm.
                fields = schemas[0]["function"]["parameters"]["properties"]
                fields["evidence_refs"].pop("description", None)
                if "claim_scope" in fields:
                    fields["claim_scope"]["description"] = (
                        "For counterexample facts: whether a concrete premise is refuted "
                        "or a universal absence/cleanup claim is made."
                    )
                    fields["subject_uid"]["description"] = (
                        "For counterexample facts, copy the exact candidate subject UID; "
                        "evidence must concern this object."
                    )
                if session.review_enabled:
                    schemas[-1]["function"]["parameters"] = protocol.review_schema()
                kwargs["additional_tools_schema"] = schemas
            return super()._run_tool_conversation(messages, **kwargs)

    return BaselineAgent


def run_one(case, arm, args, credentials, agent_class):
    directory = args.output / case["id"] / arm
    directory.mkdir(parents=True, exist_ok=False)
    ledger = ScanTokenUsageLedger(depth="balanced")
    client = RecordedClient(
        **credentials,
        models=[args.model],
        max_tokens=8192,
        timeout=120,
        max_retries=0,
        retry_until_available=False,
        supports_structured_output=False,
        token_usage_ledger=ledger,
        global_max_concurrent_requests=args.workers,
    )
    reader = SourceReader(case["source_files"])
    agent = agent_class(client, [reader])
    input_data = evidence_input(case)
    prompt_path = (
        HERE / "baseline/AGENT.md"
        if arm == "before"
        else ROOT / "zscope/agents/validator_agent/AGENT.md"
    )
    input_data["agent_contract"] = AgentSpec.from_markdown(prompt_path).to_prompt_block()
    write_json(directory / "input.json", input_data)
    started = time.monotonic()
    try:
        response = (
            agent.run(input_data)
            if case["stage"] in {"initial", "evidence_recheck"}
            else agent.investigate(input_data, max_iterations=8, pass_kind=case["stage"])
        )
        result = {
            "case_id": case["id"],
            "stage": case["stage"],
            "arm": arm,
            "success": response.success,
            "data": response.data,
            "metadata": response.metadata,
            "seconds": round(time.monotonic() - started, 3),
            "usage": ledger.snapshot(include_events=True),
        }
        write_json(directory / "result.json", result)
        print(
            json.dumps(
                {
                    "case": case["id"],
                    "arm": arm,
                    "verdict": response.data.get("verdict"),
                    "protocol": response.metadata.get("validator_protocol_audit", {}).get(
                        "parsed", False
                    ),
                    "tokens": result["usage"]["consumed_tokens"],
                }
            ),
            flush=True,
        )
        return result
    finally:
        write_json(directory / "exchanges.json", client.exchanges)
        write_json(directory / "tool_reads.json", reader.calls)
        client.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, default=ROOT / "test/range/zscope.local.env")
    parser.add_argument("--model", default="deepseek-v4.1-flash")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--case", action="append")
    parser.add_argument("--arm", choices=("before", "after", "both"), default="both")
    parser.add_argument("--workers", type=int, default=2)
    args = parser.parse_args()
    # Error bodies may include private routes; artifacts contain only public
    # responses and ledger data, and failed calls retain the exception category.
    logging.disable(logging.CRITICAL)
    cases = json.loads((HERE / "cases.json").read_text(encoding="utf-8"))
    if isinstance(cases, dict):
        cases = cases["cases"]
    if args.case:
        cases = [case for case in cases if case["id"] in args.case]
    if not cases or not 1 <= args.workers <= 4:
        raise ValueError("Select at least one case and one to four workers")
    args.output.mkdir(parents=True, exist_ok=False)
    credentials = connection(args.env_file)
    baseline = baseline_agent_class()
    write_json(
        args.output / "run.json",
        {
            "model": args.model,
            "case_ids": [case["id"] for case in cases],
            "max_tokens": 8192,
            "max_iterations": 8,
            "workers": args.workers,
            "arm": args.arm,
            "comparison": "immediately preceding prompts/schema versus current; shared runtime",
            "formal": False,
        },
    )

    def pair(index_case):
        index, case = index_case
        arms = ("before", "after") if index % 2 == 0 else ("after", "before")
        if args.arm != "both":
            arms = (args.arm,)
        return [
            run_one(case, arm, args, credentials, baseline if arm == "before" else ValidatorAgent)
            for arm in arms
        ]

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = list(pool.map(pair, enumerate(cases)))
    write_json(
        args.output / "results.json", [item for pair_results in results for item in pair_results]
    )


if __name__ == "__main__":
    main()
