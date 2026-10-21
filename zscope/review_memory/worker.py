"""Background extraction worker for Web Review Memory feedback."""

from __future__ import annotations

import threading
from typing import Any

from .extractor import extract_with_llm, proposal_from_record
from .identity import review_subject_id, utc_now
from .lifecycle import qualify_and_activate


class ReviewMemoryWorker:
    def __init__(self, store: Any, *, llm_client_factory: Any = None, llm_enabled: bool = True):
        self.store = store
        self.llm_client_factory = llm_client_factory
        self.llm_enabled = llm_enabled
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="zscope-review-memory", daemon=True)

    def start(self) -> None:
        self.store.recover_extraction_jobs()
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        self._thread.join(timeout)

    def _run(self) -> None:
        while not self._stop.is_set():
            job = self.store.claim_extraction_job()
            if job is None:
                self._stop.wait(0.25)
                continue
            errors = []
            client = self.llm_client_factory() if self.llm_enabled and self.llm_client_factory else None
            for review_id in job["review_ids"]:
                record = self.store.get_record(str(review_id))
                if record is None:
                    errors.append({"review_id": review_id, "error": "review record not found"})
                    continue
                try:
                    proposal = extract_with_llm(record, client) if client is not None and record.get("user_rebuttal") else proposal_from_record(record)
                    if proposal.get("status") == "proposed":
                        proposal = qualify_and_activate(proposal)
                    proposal["review_subject_id"] = str(record.get("review_subject_id") or review_subject_id(record))
                    self.store.save_proposal(proposal)
                    self.store.update_record(dict(record, status="extracted", extraction_error=""))
                except Exception as exc:
                    self.store.update_record(dict(record, status="proposal_failed", extraction_error=str(exc), extraction_attempted_at=utc_now()))
                    self.store.append_audit("extraction_failed", {"review_id": review_id, "error": str(exc)})
                    errors.append({"review_id": review_id, "error": str(exc)})
            if client is not None:
                client.close()
            self.store.update_extraction_job(job, status="failed" if errors else "completed", error=str(errors) if errors else "")
