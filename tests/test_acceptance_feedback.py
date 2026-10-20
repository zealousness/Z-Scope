"""Acceptance dispositions: persistence, identity isolation, and concurrency."""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from uuid import uuid4

import pytest

from zscope.config.acceptance_feedback import (
    SCHEMA,
    AcceptanceDispositionService,
    AcceptanceFeedbackStore,
    resolver_from_report,
)
from zscope.config.user_config_store import UserConfigStore
from zscope.reporting.issue_markdown import issue_identity
from zscope.web.review_reports import report_identity

UTC = timezone.utc
T0 = datetime(2026, 10, 14, 12, 0, 0, tzinfo=UTC)


class Clock:
    def __init__(self) -> None:
        self.moment = T0

    def __call__(self) -> datetime:
        return self.moment

    def advance(self, **kwargs) -> None:
        self.moment += timedelta(**kwargs)


def make_issue(number, *, build="build-a", resource="g_pool"):
    issue = {
        "id": f"ISSUE_{number}",
        "function": f"entry_{number}",
        "location": f"src/demo.c:{number + 6}",
        "subcategory": "double_free",
        "defect_class": "double_free",
        "impact_level": "high",
        "confidence": 0.8,
        "description": f"第 {number} 个问题的证据描述",
        "root_cause": "生命周期提前结束",
        "validation_status": "needs_review",
        "dedup_key": f"double_free|entry_{number}|src/demo.c:{number + 6}",
        "evidence_refs": [f"ir_path_slices:{number}"],
    }
    if build is not None:
        issue["build_context_id"] = build
    if resource is not None:
        issue["resource"] = resource
    return issue


def make_report(*issues, run_id="run-1"):
    return {
        "run_manifest": {"project_id": "demo", "run_id": run_id},
        "metadata": {"project_id": "demo", "run_id": run_id},
        "issues": list(issues),
        "report_views": {
            "default": {"issues": copy.deepcopy(list(issues))},
            "with_needs_review": {"issues": copy.deepcopy(list(issues))},
        },
    }


def iso(moment):
    return moment.isoformat()


@pytest.fixture
def env(tmp_path):
    issues = [
        make_issue(1, build="build-a", resource="g_pool"),
        make_issue(2, build="build-a", resource="g_queue"),
        make_issue(3, build="build-b", resource="g_pool"),
        make_issue(4, build=None, resource=None),
    ]
    report = make_report(*issues)
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False), encoding="utf-8")
    clock = Clock()
    store = AcceptanceFeedbackStore(tmp_path / "state" / "acceptance.db", clock=clock)
    return SimpleNamespace(
        tmp_path=tmp_path,
        issues=issues,
        report=report,
        report_path=report_path,
        rid=report_identity(report, str(report_path)),
        ids=[issue_identity(issue) for issue in issues],
        builds=[issue.get("build_context_id") for issue in issues],
        clock=clock,
        store=store,
        service=AcceptanceDispositionService(store),
        resolver=resolver_from_report(
            report, report_id=report_identity(report, str(report_path))
        ),
    )


def scope(env, index):
    resolution = env.resolver(env.rid, env.ids[index])
    assert resolution is not None
    return resolution.scope


def post(env, index=0, resolver=None, **overrides):
    payload = {
        "report_id": env.rid,
        "issue_id": env.ids[index],
        "build_context_id": env.builds[index],
        "base_revision": 0,
        "request_id": f"req-{uuid4().hex}",
        "type": "risk_accept",
        "reason": "已经评估，暂时接受该风险",
    }
    payload.update(overrides)
    return env.service.post_disposition(payload, resolver or env.resolver)


def get(env, index=0, resolver=None, **overrides):
    query = {"report_id": env.rid, "issue_id": env.ids[index]}
    query.update(overrides)
    return env.service.get_dispositions(query, resolver or env.resolver)


def tree(root):
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            result[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def user_store_dump(store):
    conn = store._connect()
    try:
        tables = {}
        for table in (
            "config_warnings",
            "finding_suppressions",
            "finding_baselines",
            "protocol_assumption_answers",
        ):
            tables[table] = [dict(row) for row in conn.execute(f"SELECT * FROM {table}")]
        return tables
    finally:
        conn.close()


# ── Contract envelope shape ──


def test_get_empty_envelope_matches_contract(env):
    status, payload = get(env, 0)
    assert status == 200
    assert set(payload) == {
        "schema",
        "report_id",
        "issue_id",
        "build_context_id",
        "revision",
        "disposition",
        "writable",
    }
    assert payload["schema"] == SCHEMA == "zscope.acceptance-dispositions.v1"
    assert payload["report_id"] == env.rid and payload["issue_id"] == env.ids[0]
    assert payload["build_context_id"] == "build-a"
    assert payload["revision"] == 0 and payload["disposition"] is None
    assert payload["writable"] is True


def test_unknown_build_is_reported_as_null(env):
    status, payload = get(env, 3)
    assert status == 200 and payload["build_context_id"] is None


def test_success_post_envelope_matches_contract(env):
    expires = iso(T0 + timedelta(hours=1))
    status, payload = post(env, 0, expires_at=expires)
    assert status == 200
    assert set(payload) == {
        "schema",
        "success",
        "report_id",
        "issue_id",
        "build_context_id",
        "revision",
        "disposition",
        "writable",
    }
    assert payload["success"] is True and payload["revision"] == 1
    disposition = payload["disposition"]
    assert set(disposition) == {"type", "reason", "expires_at", "updated_at", "request_id"}
    assert disposition["type"] == "risk_accept"
    assert disposition["expires_at"] == iso(T0 + timedelta(hours=1))
    assert datetime.fromisoformat(disposition["updated_at"]).tzinfo is not None


def test_writable_flag_is_coordinator_controlled(env):
    service = AcceptanceDispositionService(env.store, writable=False)
    status, payload = service.get_dispositions(
        {"report_id": env.rid, "issue_id": env.ids[0]}, env.resolver
    )
    assert status == 200 and payload["writable"] is False


# ── Persistence ──


def test_real_persistence_across_reopen(env):
    status, _ = post(env, 0, request_id="persist-1")
    assert status == 200
    db_path = env.store.db_path
    assert db_path.exists() and db_path.stat().st_size > 0
    reopened = AcceptanceFeedbackStore(db_path, clock=env.clock)
    state = reopened.current(scope(env, 0))
    assert state["revision"] == 1
    assert state["disposition"]["type"] == "risk_accept"
    assert state["disposition"]["request_id"] == "persist-1"
    assert reopened.history(env.rid, env.ids[0])[0]["reason"] == "已经评估，暂时接受该风险"


def test_revision_grows_monotonically_and_clear_keeps_history(env):
    assert post(env, 0, type="risk_accept", request_id="r1")[0] == 200
    assert post(env, 0, type="followup", base_revision=1, request_id="r2", title="跟进")[0] == 200
    assert post(env, 0, type="clear", base_revision=2, request_id="r3", reason="撤销")[0] == 200
    status, payload = get(env, 0)
    assert status == 200 and payload["revision"] == 3 and payload["disposition"] is None
    history = env.store.history(env.rid, env.ids[0])
    assert [row["type"] for row in history] == ["risk_accept", "followup", "clear"]
    assert [row["revision"] for row in history] == [1, 2, 3]
    assert history[0]["reason"] == "已经评估，暂时接受该风险"
    assert history[2]["reason"] == "撤销"


# ── Optimistic concurrency, idempotency, rollback ──


def test_stale_base_revision_conflicts_and_preserves_record(env):
    assert post(env, 0, request_id="first")[0] == 200
    status, payload = post(env, 0, base_revision=0, request_id="second")
    assert status == 409 and payload["code"] == "revision_conflict"
    assert payload["error"] and "/" not in payload["error"]
    status, payload = post(env, 0, base_revision=5, request_id="third")
    assert status == 409
    state = env.store.current(scope(env, 0))
    assert state["revision"] == 1 and state["disposition"]["request_id"] == "first"


def test_idempotent_replay_and_request_id_reuse_rejected(env):
    first_status, first = post(env, 0, request_id="same-req")
    assert first_status == 200
    replay_status, replay = post(env, 0, request_id="same-req")
    assert replay_status == 200 and replay == first
    assert env.store.current(scope(env, 0))["revision"] == 1
    status, payload = post(env, 0, request_id="same-req", reason="不同请求")
    assert status == 409 and payload["code"] == "request_id_conflict"
    assert env.store.current(scope(env, 0))["revision"] == 1
    status, _ = post(env, 0, base_revision=1, request_id="same-req-2")
    assert status == 200
    assert env.store.current(scope(env, 0))["revision"] == 2


def test_concurrent_writers_have_single_winner(env):
    def attempt(index):
        return post(env, 0, request_id=f"race-{index}", reason=f"第 {index} 次并发")

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(attempt, range(6)))
    codes = sorted(status for status, _ in results)
    assert codes == [200, 409, 409, 409, 409, 409]
    assert env.store.current(scope(env, 0))["revision"] == 1
    assert len(env.store.history(env.rid, env.ids[0])) == 1


def test_concurrent_idempotent_replay_shares_one_outcome(env):
    def attempt(_):
        return post(env, 1, type="followup", request_id="shared-req", title="跟进")

    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(attempt, range(5)))
    assert [status for status, _ in results] == [200] * 5
    assert {payload["revision"] for _, payload in results} == {1}
    assert len(env.store.history(env.rid, env.ids[1])) == 1


class _FailingConn:
    """Fails the ledger insert with a secret-looking, path-bearing error."""

    def __init__(self, real):
        self._real = real

    def execute(self, sql, parameters=()):
        if str(sql).startswith("INSERT INTO acceptance_disposition_requests"):
            raise sqlite3.OperationalError("injected failure at /secret/db?token=sk-123")
        return self._real.execute(sql, parameters)

    def commit(self):
        return self._real.commit()

    def rollback(self):
        return self._real.rollback()

    def close(self):
        return self._real.close()


def test_failed_write_rolls_back_and_preserves_old_record(env, monkeypatch):
    assert post(env, 0, request_id="ok-1")[0] == 200
    real_connect = env.store._connect
    monkeypatch.setattr(env.store, "_connect", lambda: _FailingConn(real_connect()))
    status, payload = post(env, 0, base_revision=1, request_id="broken-1")
    assert status == 503
    assert payload == {"error": "处置存储暂不可用，请稍后重试", "code": "unavailable"}
    blob = json.dumps(payload, ensure_ascii=False)
    assert "/secret" not in blob and "sk-123" not in blob
    state = env.store.current(scope(env, 0))
    assert state["revision"] == 1 and state["disposition"]["request_id"] == "ok-1"
    assert len(env.store.history(env.rid, env.ids[0])) == 1


def test_unavailable_store_never_leaks_internals(env, monkeypatch):
    def broken():
        raise sqlite3.OperationalError("cannot open /secret/db?token=sk-123")

    monkeypatch.setattr(env.store, "_connect", broken)
    status, payload = get(env, 0)
    assert status == 503
    assert payload == {"error": "处置存储暂不可用，请稍后重试", "code": "unavailable"}
    blob = json.dumps(payload, ensure_ascii=False)
    assert "/secret" not in blob and "sk-123" not in blob


# ── Identity binding and invalidation ──


def test_issue_content_change_invalidates_disposition(env):
    assert post(env, 0, request_id="before-change")[0] == 200
    changed = copy.deepcopy(env.issues)
    changed[0]["description"] = "重新扫描后的不同证据"
    changed_report = make_report(*changed)
    resolver = resolver_from_report(changed_report, report_id=env.rid)
    before = scope(env, 0)
    after = resolver(env.rid, env.ids[0]).scope
    assert after.issue_digest != before.issue_digest
    status, payload = get(env, 0, resolver=resolver)
    assert status == 200 and payload["revision"] == 0 and payload["disposition"] is None
    status, payload = post(env, 0, resolver=resolver, base_revision=1, request_id="stale-draft")
    assert status == 409
    status, payload = post(env, 0, resolver=resolver, base_revision=0, request_id="rebased")
    assert status == 200 and payload["revision"] == 1
    assert len(env.store.history(env.rid, env.ids[0])) == 2


def test_build_context_is_exact_and_never_a_wildcard(env):
    assert post(env, 0, request_id="build-a-1")[0] == 200
    # 同报告不同构建的问题互不复用，也不能互为 duplicate 目标。
    status, payload = post(
        env, 2, type="duplicate", duplicate_of=env.ids[0], request_id="cross-build"
    )
    assert status == 400
    # 未知构建只匹配未知构建：客户端不能凭 null 或其他构建通过绑定。
    status, _ = post(env, 3, build_context_id="build-a", request_id="null-as-wildcard")
    assert status == 409
    status, _ = post(env, 0, build_context_id=None, request_id="null-for-known")
    assert status == 409
    status, _ = post(env, 0, build_context_id="build-b", request_id="wrong-build")
    assert status == 409
    # 未知构建的问题没有同构建 duplicate 目标。
    status, _ = post(env, 3, type="duplicate", duplicate_of=env.ids[2], request_id="no-target")
    assert status == 400
    assert post(env, 3, type="followup", request_id="followup-null-build")[0] == 200
    state = env.store.current(scope(env, 0))
    assert state["revision"] == 1 and state["disposition"]["request_id"] == "build-a-1"


def test_object_digest_change_invalidates_without_touching_issue_digest(env):
    before = scope(env, 0)
    assert post(env, 0, request_id="object-1")[0] == 200
    changed = copy.deepcopy(env.issues)
    changed[0]["resource"] = "g_other_pool"
    resolver = resolver_from_report(make_report(*changed), report_id=env.rid)
    after = resolver(env.rid, env.ids[0]).scope
    assert after.issue_digest == before.issue_digest
    assert after.object_digest != before.object_digest
    status, payload = get(env, 0, resolver=resolver)
    assert status == 200 and payload["revision"] == 0 and payload["disposition"] is None


def test_new_report_run_does_not_reuse_dispositions(env):
    assert post(env, 0, request_id="run-1-write")[0] == 200
    rerun = make_report(*env.issues, run_id="run-2")
    rid2 = report_identity(rerun, str(env.report_path))
    assert rid2 != env.rid
    resolver2 = resolver_from_report(rerun, report_id=rid2)
    status, payload = get(env, 0, resolver=resolver2, report_id=rid2)
    assert status == 200 and payload["revision"] == 0 and payload["disposition"] is None
    # 旧报告身份已失效：GET 404，POST 409 并保留草稿语义。
    status, payload = get(env, 0, resolver=resolver2, report_id=env.rid)
    assert status == 404 and payload["code"] == "not_found"
    status, payload = post(env, 0, resolver=resolver2, request_id="stale-report")
    assert status == 409 and payload["code"] == "stale_scope"


def test_ambiguous_issue_identity_cannot_be_bound(env):
    twin = copy.deepcopy(env.issues[0])
    twin["description"] = "同一身份键下的不同证据版本"
    report = make_report(env.issues[0], twin)
    resolver = resolver_from_report(report, report_id=env.rid)
    status, payload = get(env, 0, resolver=resolver)
    assert status == 404
    status, payload = post(env, 0, resolver=resolver, request_id="ambiguous")
    assert status == 409


# ── duplicate/risk_accept/followup/clear semantics ──


def test_duplicate_requires_real_distinct_same_build_target(env):
    status, _ = post(env, 0, type="duplicate", duplicate_of=env.ids[0], request_id="self")
    assert status == 400
    status, _ = post(env, 0, type="duplicate", duplicate_of="0" * 64, request_id="unknown")
    assert status == 400
    status, _ = post(env, 0, type="duplicate", duplicate_of=env.ids[2], request_id="other-build")
    assert status == 400
    status, payload = post(
        env, 0, type="duplicate", duplicate_of=env.ids[1], request_id="valid-duplicate"
    )
    assert status == 200
    assert payload["disposition"]["duplicate_of"] == env.ids[1]
    # 标记 duplicate 不合并、不改写任何一侧问题；目标问题保持独立。
    assert json.loads(env.report_path.read_text(encoding="utf-8")) == env.report
    status, payload = get(env, 1)
    assert status == 200 and payload["disposition"] is None
    status, payload = get(env, 0)
    assert status == 200 and payload["disposition"]["type"] == "duplicate"


def test_followup_is_a_local_record_without_side_effects(env, tmp_path):
    user_store = UserConfigStore(tmp_path / "config")
    user_store.add_false_positive_suppression(
        func_name="entry_1", location="src/demo.c:7", category="double_free", reason="人工误报"
    )
    user_store.upsert_finding_baseline(
        "dk-1", "accepted", {"id": "I1", "location": "src/demo.c:7", "category": "double_free"}
    )
    user_store.add_config_warning("backend", "ctx", "警告")
    assumption = {
        "id": "a1",
        "fact_kind": "event:business_release_requirement",
        "statement": "接口约定允许延迟释放",
        "scope": {"build_context_id": "build-a", "entry_usr": "c:@F@entry_1", "object_ref": "o1"},
        "basis": {"dependency_hash": "h1", "observation_kind": "source"},
    }
    user_store.save_protocol_answers(
        [{"assumption": assumption, "answer": "yes", "source_note": "约定", "expected_revision": 0}]
    )
    business_before = user_store_dump(user_store)
    report_bytes = env.report_path.read_bytes()
    before = tree(tmp_path)

    assert post(env, 0, type="followup", title="跟进剩余释放路径", request_id="followup-1")[0] == 200
    assert post(env, 1, type="duplicate", duplicate_of=env.ids[0], base_revision=0, request_id="dup-1")[0] == 200
    assert post(env, 2, request_id="risk-1")[0] == 200
    assert post(env, 0, type="clear", base_revision=1, request_id="clear-1", reason="撤销跟进")[0] == 200

    # 只新增本模块自己的数据库文件；报告、业务回答、suppression、baseline 全部不变。
    changed = {key for key, value in tree(tmp_path).items() if before.get(key) != value}
    assert changed and all(key.startswith("state/acceptance.db") for key in changed)
    assert env.report_path.read_bytes() == report_bytes
    assert user_store_dump(user_store) == business_before
    assert user_store.is_false_positive("entry_1", "src/demo.c:7", "double_free") is True
    followup = env.store.history(env.rid, env.ids[0])
    assert [row["type"] for row in followup] == ["followup", "clear"]
    assert followup[0]["title"] == "跟进剩余释放路径"


def test_clear_requires_an_active_disposition(env):
    status, payload = post(env, 0, type="clear", request_id="clear-empty")
    assert status == 400
    assert post(env, 0, request_id="risk-1")[0] == 200
    assert post(env, 0, type="clear", base_revision=1, request_id="clear-1")[0] == 200
    status, payload = post(env, 0, type="clear", base_revision=2, request_id="clear-again")
    assert status == 400
    status, payload = post(env, 0, type="clear", base_revision=1, request_id="clear-stale")
    assert status == 409


# ── risk_accept expiry ──


def test_risk_accept_expires_and_history_is_kept(env):
    expires = T0 + timedelta(hours=1)
    status, payload = post(env, 0, expires_at=iso(expires), request_id="expiring")
    assert status == 200 and payload["disposition"]["expires_at"] == iso(expires)
    env.clock.advance(hours=2)
    status, payload = get(env, 0)
    assert status == 200 and payload["disposition"] is None and payload["revision"] == 1
    history = env.store.history(env.rid, env.ids[0])
    assert len(history) == 1 and history[0]["type"] == "risk_accept"
    status, _ = post(env, 0, type="clear", base_revision=1, request_id="clear-expired")
    assert status == 400
    status, payload = post(env, 0, base_revision=1, request_id="accept-again")
    assert status == 200 and payload["revision"] == 2


def test_expires_at_requires_timezone_and_future(env):
    status, _ = post(env, 0, expires_at="2026-10-14 13:00:00", request_id="naive")
    assert status == 400
    status, _ = post(env, 0, expires_at="not-a-time", request_id="garbage")
    assert status == 400
    status, _ = post(env, 0, expires_at=iso(T0 - timedelta(seconds=1)), request_id="past")
    assert status == 400
    status, payload = post(env, 0, expires_at="2026-10-14T13:00:00Z", request_id="zulu")
    assert status == 200
    assert payload["disposition"]["expires_at"] == "2026-10-14T13:00:00+00:00"


# ── Input validation ──


def test_post_input_validation_matrix(env):
    good = {
        "report_id": env.rid,
        "issue_id": env.ids[0],
        "build_context_id": "build-a",
        "base_revision": 0,
        "request_id": "matrix",
        "type": "risk_accept",
        "reason": "理由",
    }

    def mod(**updates):
        payload = dict(good)
        payload.update(updates)
        return payload

    cases = [
        ("not-a-dict", 400),
        (["list"], 400),
        ({}, 400),
        ({k: v for k, v in good.items() if k != "request_id"}, 400),
        (mod(unknown=1), 400),
        (mod(report_id=""), 400),
        (mod(report_id="x" * 513), 400),
        (mod(issue_id=""), 400),
        (mod(build_context_id=123), 400),
        (mod(base_revision=-1), 400),
        (mod(base_revision=True), 400),
        (mod(base_revision="0"), 400),
        (mod(request_id=""), 400),
        (mod(request_id="  padded  "), 400),
        (mod(request_id="x" * 129), 400),
        (mod(request_id="bad\x01id"), 400),
        (mod(type="confirmed"), 400),
        (mod(type="DUPLICATE"), 400),
        (mod(reason=""), 400),
        (mod(reason="   \n\t "), 400),
        (mod(reason="x" * 2001), 400),
        (mod(reason=123), 400),
        (mod(title="x" * 201), 400),
        (mod(title="有标题"), 400),
        (mod(duplicate_of=env.ids[1]), 400),
        (mod(type="duplicate"), 400),
        (mod(type="duplicate", duplicate_of=""), 400),
        (mod(type="duplicate", title="t", duplicate_of=env.ids[1]), 400),
        (mod(type="followup", expires_at="2027-01-01T00:00:00Z"), 400),
        (mod(type="followup", duplicate_of=env.ids[1]), 400),
        (mod(type="clear", expires_at="2027-01-01T00:00:00Z"), 400),
    ]
    for payload, expected in cases:
        status, envelope = env.service.post_disposition(payload, env.resolver)
        assert status == expected, payload
        assert set(envelope) == {"error", "code"} and envelope["code"] == "invalid_request"
    assert env.store.history(env.rid, env.ids[0]) == []


def test_get_query_validation(env):
    for query, expected in [
        ({}, 400),
        ({"report_id": env.rid}, 400),
        ({"issue_id": env.ids[0]}, 400),
        ({"report_id": "", "issue_id": env.ids[0]}, 400),
        ({"report_id": env.rid, "issue_id": "0" * 64}, 404),
    ]:
        status, envelope = env.service.get_dispositions(query, env.resolver)
        assert status == expected
        assert set(envelope) == {"error", "code"}
