"""CLI for project-local Validator Review Memory."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

import click

from ..config.config import ConfigLoader
from ..review_memory.extractor import extract_with_llm, proposal_from_record
from ..review_memory.lifecycle import qualify_and_activate
from ..review_memory.identity import review_subject_id, utc_now
from ..review_memory.store import ReviewMemoryStore
from ..framework.llm_client import LLMClient
from ..framework.llm_usage import ensure_scan_token_usage_ledger
from ..framework.conversation_recorder import enable_conversation_recording


def _store(config_path: Path) -> ReviewMemoryStore:
    config = ConfigLoader.load(str(config_path))
    settings = config.project.review_memory
    return ReviewMemoryStore(config.project.project_root, settings.state_dir)


def _config_and_store(config_path: Path):
    config = ConfigLoader.load(str(config_path))
    return config, ReviewMemoryStore(config.project.project_root, config.project.review_memory.state_dir)


def _filter_extraction_records(records: list[Dict[str, Any]], *, retry_failed: bool, retry_all: bool) -> list[Dict[str, Any]]:
    records = [record for record in records if record.get("status") != "superseded"]
    if retry_failed:
        return [record for record in records if record.get("status") == "proposal_failed"]
    if retry_all:
        return records
    return [record for record in records if record.get("status") not in {"proposal_failed", "extracted"}]


def _llm_client(config: Any) -> LLMClient:
    llm_cfg = config.llms.get("default")
    if llm_cfg is None:
        raise click.ClickException("default LLM profile is required for extraction")
    return LLMClient(
        api_key=llm_cfg.api_key,
        base_url=getattr(llm_cfg, "base_urls", None) or llm_cfg.base_url,
        models=llm_cfg.models,
        timeout=llm_cfg.timeout,
        max_retries=llm_cfg.max_retries,
        retry_until_available=getattr(llm_cfg, "retry_until_available", False),
        max_tokens=llm_cfg.max_tokens,
        global_max_concurrent_requests=config.concurrency.llm_max_inflight,
        supports_structured_output=getattr(llm_cfg, "supports_structured_output", False),
        token_usage_ledger=ensure_scan_token_usage_ledger(config),
        llm_ref="default",
    )


@click.group()
@click.option("--config", "config_path", "-c", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True)
@click.pass_context
def main(ctx: click.Context, config_path: Path) -> None:
    config, store = _config_and_store(config_path)
    enable_conversation_recording(
        config.project.project_root / ".zscope_conversations",
        metadata={
            "config_path": str(config_path),
            "zscope_version": "review_memory",
            "mode": "review_memory_extract",
        },
    )
    ctx.ensure_object(dict).update({"store": store, "config": config})


@main.command("list")
@click.pass_context
def list_records(ctx: click.Context) -> None:
    store = ctx.obj["store"]
    click.echo(json.dumps({"records": store.list_records(), "proposals": store.list_proposals(), "jobs": store.list_extraction_jobs()}, ensure_ascii=False, indent=2))


@main.command("extract")
@click.option("--review-id", default=None)
@click.option("--retry-failed", is_flag=True, default=False)
@click.option("--retry-all", is_flag=True, default=False)
@click.option("--job-id", default=None)
@click.option("--enqueue", is_flag=True, default=False)
@click.pass_context
def extract(ctx: click.Context, review_id: Optional[str], retry_failed: bool, retry_all: bool, job_id: Optional[str], enqueue: bool) -> None:
    if retry_failed and retry_all:
        raise click.UsageError("--retry-failed and --retry-all are mutually exclusive")
    store = ctx.obj["store"]
    config = ctx.obj["config"]
    records = [record for record in store.list_records() if not review_id or record.get("review_id") == review_id]
    # ReviewRecord is an immutable event log; proposal extraction is subject-level.
    latest_by_subject = {}
    for record in records:
        subject = str(record.get("review_subject_id") or review_subject_id(record))
        previous = latest_by_subject.get(subject)
        if previous is None or str(record.get("created_at", "")) > str(previous.get("created_at", "")):
            latest_by_subject[subject] = record
    records = list(latest_by_subject.values())
    records = _filter_extraction_records(records, retry_failed=retry_failed, retry_all=retry_all)
    if enqueue:
        job = store.create_extraction_job([str(record["review_id"]) for record in records])
        click.echo(json.dumps({"job": job}, ensure_ascii=False, indent=2))
        return
    selected_job = None
    if job_id:
        selected_job = next((job for job in store.list_extraction_jobs() if job["job_id"] == job_id), None)
        if selected_job is None:
            raise click.ClickException("extraction job not found")
        records = [record for record in store.list_records() if str(record.get("review_id")) in set(selected_job["review_ids"])]
        store.update_extraction_job(selected_job, status="running")
    proposals = []
    extraction_errors = []
    client = None
    try:
        if getattr(config.project.review_memory, "llm_enabled", True):
            client = _llm_client(config)
        for record in records:
            try:
                proposal = extract_with_llm(record, client) if client is not None and record.get("user_rebuttal") else proposal_from_record(record)
                if proposal.get("status") == "proposed":
                    try:
                        proposal = qualify_and_activate(proposal)
                    except ValueError:
                        pass
                proposal["review_subject_id"] = str(record.get("review_subject_id") or review_subject_id(record))
                proposals.append(store.save_proposal(proposal))
                store.update_record(dict(record, status="extracted", extraction_error=""))
            except Exception as exc:
                failed = dict(record, status="proposal_failed", extraction_error=str(exc), extraction_attempted_at=utc_now())
                store.update_record(failed)
                store.append_audit("extraction_failed", {"review_id": record.get("review_id"), "error": str(exc)})
                extraction_errors.append({"review_id": record.get("review_id"), "error": str(exc)})
    finally:
        if client is not None:
            client.close()
    if selected_job is not None:
        store.update_extraction_job(
            selected_job,
            status="failed" if extraction_errors else "completed",
            error=json.dumps(extraction_errors, ensure_ascii=False) if extraction_errors else "",
        )
    click.echo(json.dumps({"extracted": len(proposals), "proposals": proposals, "errors": extraction_errors}, ensure_ascii=False, indent=2))


@main.command("jobs")
@click.pass_context
def jobs(ctx: click.Context) -> None:
    click.echo(json.dumps({"jobs": ctx.obj["store"].list_extraction_jobs()}, ensure_ascii=False, indent=2))


@main.command("proposals")
@click.pass_context
def proposals(ctx: click.Context) -> None:
    click.echo(json.dumps({"proposals": ctx.obj["store"].list_proposals()}, ensure_ascii=False, indent=2))


@main.command("show")
@click.argument("review_id")
@click.pass_context
def show(ctx: click.Context, review_id: str) -> None:
    """Show one immutable ReviewRecord and its derived proposals."""
    store = ctx.obj["store"]
    record = store.get_record(review_id)
    if record is None:
        raise click.ClickException("review record not found")
    proposals_for_record = [
        item for item in store.list_proposals()
        if review_id in {str(value) for value in item.get("origin_review_ids", [])}
    ]
    click.echo(json.dumps({"record": record, "proposals": proposals_for_record}, ensure_ascii=False, indent=2))


@main.command("enable")
@click.argument("pattern_id")
@click.pass_context
def enable(ctx: click.Context, pattern_id: str) -> None:
    store = ctx.obj["store"]
    matches = [item for item in store.list_proposals() if item.get("pattern_id") == pattern_id]
    if not matches:
        raise click.ClickException("pattern not found")
    try:
        pattern = qualify_and_activate(matches[0])
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    pattern["updated_at"] = utc_now()
    store.save_proposal(pattern)
    click.echo(json.dumps(pattern, ensure_ascii=False, indent=2))


@main.command("disable")
@click.argument("pattern_id")
@click.pass_context
def disable(ctx: click.Context, pattern_id: str) -> None:
    store = ctx.obj["store"]
    matches = [item for item in store.list_proposals() if item.get("pattern_id") == pattern_id]
    if not matches:
        raise click.ClickException("pattern not found")
    pattern = dict(matches[0], status="disabled", updated_at=utc_now())
    store.save_proposal(pattern)
    click.echo(json.dumps(pattern, ensure_ascii=False, indent=2))


@main.command("stale")
@click.argument("pattern_id")
@click.pass_context
def stale(ctx: click.Context, pattern_id: str) -> None:
    try:
        pattern = ctx.obj["store"].set_proposal_status(pattern_id, "stale")
    except KeyError as exc:
        raise click.ClickException("pattern not found") from exc
    click.echo(json.dumps(pattern, ensure_ascii=False, indent=2))


@main.command("refresh-stale")
@click.option("--fingerprint", "fingerprints", multiple=True, required=True)
@click.pass_context
def refresh_stale(ctx: click.Context, fingerprints: tuple[str, ...]) -> None:
    stale_ids = ctx.obj["store"].mark_source_drift(set(fingerprints))
    click.echo(json.dumps({"schema_version": "zscope.review-memory-operation.v1", "operation": "refresh-stale", "staled": stale_ids}, ensure_ascii=False, indent=2))


@main.command("export")
@click.option("--output", type=click.Path(dir_okay=False, path_type=Path), required=True)
@click.pass_context
def export_memory(ctx: click.Context, output: Path) -> None:
    output.write_text(json.dumps(ctx.obj["store"].export_json(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    click.echo(json.dumps({"output": str(output), "status": "exported"}, ensure_ascii=False))


@main.command("replay")
@click.argument("pattern_id")
@click.option("--input", "input_path", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True)
@click.option("--output", "output_path", type=click.Path(dir_okay=False, path_type=Path), default=None)
@click.pass_context
def replay(ctx: click.Context, pattern_id: str, input_path: Path, output_path: Optional[Path]) -> None:
    pattern = ctx.obj["store"].get_proposal(pattern_id)
    if pattern is None:
        raise click.ClickException("pattern not found")
    payload = json.loads(input_path.read_text(encoding="utf-8"))
    issues = payload.get("issues", []) if isinstance(payload, dict) else []
    from ..review_memory.replay import paired_replay
    result = paired_replay(payload, pattern, scan_id=f"replay-{input_path.stem}")
    result["input"] = str(input_path)
    for row in result.get("rows", []):
        hints = row.get("advisory", {}).get("hints", [])
        if not hints:
            continue
        ctx.obj["store"].save_match({
            "schema_version": "zscope.review-pattern-match.v1",
            "pattern_id": pattern_id,
            "scan_id": result["scan_id"],
            "project_id": pattern.get("project_id", ""),
            "issue_identity": {"issue_id": row.get("issue_id")},
            "match_basis": hints[0].get("match_basis", []),
            "source_compatible": True,
            "injected": bool(row.get("advisory", {}).get("would_inject")),
            "validator_status": row.get("baseline", {}).get("validation_status", ""),
            "overturned": bool(row.get("baseline", {}).get("validation_status") in {"rejected", "false_positive"}),
        })
    ctx.obj["store"].append_audit("pattern_replayed", result)
    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = output_path.with_suffix(output_path.suffix + ".tmp")
        temporary.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        temporary.replace(output_path)
    click.echo(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
