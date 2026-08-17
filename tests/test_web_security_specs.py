from __future__ import annotations

from io import BytesIO
import json
from pathlib import Path

from zscope.semantics.security_specs.models import build_security_spec
from zscope.semantics.security_specs.canonical import canonical_json, content_sha256
from zscope.web import server
from zscope.web.services import SecuritySpecReviewService


def _spec() -> dict:
    return build_security_spec(
        subject={
            "language": "c_cpp",
            "function_uid": "src/api.c::entry",
            "signature": "int entry(char *data)",
            "slot_uids": ["parameter:0"],
        },
        scope={"kind": "function", "target": "src/api.c::entry"},
        predicate="source",
        parameters={"source_slot": "parameter:0", "label": "untrusted"},
        evidence_refs=["evidence:src/api.c:4"],
        dependency_hashes=["a" * 64],
        origin="program",
        confidence=1.0,
        status="verified_scoped",
        explanation="Exact external entry parameter.",
        impact_preview=["src/api.c::entry"],
    )


def test_security_spec_review_service_lists_details_and_exports(tmp_path: Path) -> None:
    service = SecuritySpecReviewService(tmp_path / "security-specs")
    spec = _spec()
    assert service.store is not None
    service.store.put_spec(spec)

    payload = service.list_payload("status=verified_scoped")
    assert payload["read_only"] is True
    assert payload["security_spec_mode"] == "shadow"
    assert payload["reviewer_identity_mode"] == "unavailable_read_only"
    assert payload["specs"] == [spec]

    status, detail = service.detail_payload(spec["spec_uid"])
    assert status == 200
    assert detail["spec"] == spec
    assert detail["compilation_preview"]["compiled_specs"] == []

    json_data, json_type, _ = service.export_bytes("json")
    xlsx_data, xlsx_type, _ = service.export_bytes("xlsx")
    assert json_type == "application/json"
    assert "spreadsheet" in xlsx_type
    assert json_data and xlsx_data
    assert service.dry_run_import(json_data, "json")["applied"] is False

    archive = json.loads(json_data)
    second = build_security_spec(
        subject=spec["subject"],
        scope={"kind": "callsite", "target": "src/api.c::entry:call:1"},
        predicate=spec["predicate"],
        parameters=spec["parameters"],
        evidence_refs=spec["evidence_refs"],
        dependency_hashes=spec["dependency_hashes"],
        origin="program",
        confidence=1.0,
        status="verified_scoped",
        spec_uid=spec["spec_uid"],
        revision=2,
        explanation="Narrow exact callsite.",
        impact_preview=["src/api.c::entry"],
    )
    archive["specs"].append(second)
    body = {key: value for key, value in archive.items() if key != "bundle_sha256"}
    archive["bundle_sha256"] = content_sha256(body)
    preview = service.dry_run_import((canonical_json(archive) + "\n").encode(), "json")
    assert preview["impact_preview"]["added_spec_revisions"] == [f"{spec['spec_uid']}@2"]
    assert service.store.list_specs(latest_only=False) == [spec]


def test_security_spec_apply_and_review_routes_fail_closed(monkeypatch) -> None:
    service = SecuritySpecReviewService()
    monkeypatch.setattr(server, "_security_spec_service", service)
    sent = []
    handler = object.__new__(server.ZScopeHandler)
    handler.headers = {"Content-Length": "0"}
    handler.rfile = BytesIO()
    handler._send_json = lambda payload, status=200: sent.append((status, payload))

    handler.path = "/api/security-specs/SPEC_" + "a" * 32 + "/reviews"
    handler.do_POST()
    handler.path = "/api/security-specs/import?format=json&apply=true"
    handler.do_POST()

    assert [status for status, _ in sent] == [403, 403]
    assert all(payload["error"] == "reviewer_identity_unavailable" for _, payload in sent)


def test_security_spec_get_routes_are_read_only(monkeypatch) -> None:
    class FakeService:
        def list_payload(self, query):
            return {"query": query, "read_only": True}

        def detail_payload(self, uid):
            return 200, {"uid": uid, "read_only": True}

    monkeypatch.setattr(server, "_security_spec_service", FakeService())
    handler = object.__new__(server.ZScopeHandler)
    sent = []
    handler._send_json = lambda payload, status=200: sent.append((status, payload))

    handler.path = "/api/security-specs?status=stable"
    handler.do_GET()
    handler.path = "/api/security-specs/SPEC_" + "b" * 32
    handler.do_GET()

    assert sent[0] == (200, {"query": "status=stable", "read_only": True})
    assert sent[1][1]["read_only"] is True


def test_dashboard_exposes_read_only_security_spec_center() -> None:
    html = server.WEB_DIR.joinpath("index.html").read_text(encoding="utf-8")
    assert "Security Spec Review Center" in html
    assert "reviewer identity" in html
    assert "fetch('/api/security-specs'" in html
    assert "/api/security-specs/import?format=" in html
    assert "method: 'POST'" in html
