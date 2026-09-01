import argparse
import hashlib
import json
import os
from pathlib import Path

import pytest

from scripts import p6_pilot_protocol as p6_cli
from zscope.benchmarking import p6_protocol
from zscope.benchmarking.p6_protocol import (
    P6ProtocolError,
    P6_CHECKPOINT_STAGE_ORDER,
    P6_WORKFLOW_PATH,
    canonical_sha256,
    validate_expected_proxy_attestation,
    validate_proxy_provision,
    seal_toolchain_evidence,
    validate_final_evidence_manifest,
    validate_toolchain_provenance_files,
)


def _encoded(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _write_final_payload(tmp_path: Path) -> tuple[Path, Path, dict[str, object]]:
    root = tmp_path / "payload"
    nested = root / "nested"
    nested.mkdir(parents=True)
    first = b'{"schema_version":"zscope.synthetic-one.v1"}\n'
    second = b'{"schema_version":"zscope.synthetic-two.v1"}\n'
    (root / "one.json").write_bytes(first)
    (nested / "two.json").write_bytes(second)
    value: dict[str, object] = {
        "schema_version": "zscope.p6-final-evidence-manifest.v1",
        "control_plane_commit": "c" * 40,
        "candidate_git_sha": "1" * 40,
        "workflow_run_id": "33260000001",
        "workflow_run_attempt": 2,
        "attempt_id": "p6-33260000001-2",
        "artifacts": [
            {"path": "nested/two.json", "sha256": hashlib.sha256(second).hexdigest()},
            {"path": "one.json", "sha256": hashlib.sha256(first).hexdigest()},
        ],
        "phase_status": {stage: "completed" for stage in P6_CHECKPOINT_STAGE_ORDER},
        "formal_benchmark": False,
        "release_eligible": False,
    }
    value["evidence_sha256"] = canonical_sha256(value)
    manifest = root / "final-evidence-manifest.json"
    manifest.write_bytes(_encoded(value))
    return root, manifest, value


def _final_expected() -> dict[str, object]:
    return {
        "expected_run_id": "33260000001",
        "expected_run_attempt": 2,
        "expected_attempt_id": "p6-33260000001-2",
        "expected_control_plane_commit": "c" * 40,
        "expected_candidate_git_sha": "1" * 40,
        "expected_candidate_sha256": hashlib.sha256(("1" * 40).encode()).hexdigest(),
    }


def test_final_evidence_manifest_validates_exact_tree_and_cli(tmp_path: Path) -> None:
    root, manifest, _ = _write_final_payload(tmp_path)
    validated = validate_final_evidence_manifest(manifest, payload_root=root, **_final_expected())
    assert validated == manifest.read_bytes()
    args = argparse.Namespace(
        manifest=manifest,
        payload_root=root,
        workflow_run_id="33260000001",
        workflow_run_attempt=2,
        attempt_id="p6-33260000001-2",
        control_plane_commit="c" * 40,
        candidate_commit="1" * 40,
        candidate_sha256=hashlib.sha256(("1" * 40).encode()).hexdigest(),
    )
    assert p6_cli._validate_final_manifest(args) == 0


@pytest.mark.parametrize("mutation", ("mutate", "delete", "add"))
def test_final_evidence_manifest_rejects_payload_tree_mutation(
    tmp_path: Path, mutation: str
) -> None:
    root, manifest, _ = _write_final_payload(tmp_path)
    target = root / "nested/two.json"
    if mutation == "mutate":
        target.write_bytes(target.read_bytes() + b" ")
    elif mutation == "delete":
        target.unlink()
    else:
        (root / "extra.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(P6ProtocolError, match="payload (hash|member set)"):
        validate_final_evidence_manifest(manifest, payload_root=root, **_final_expected())


def test_final_evidence_manifest_rejects_self_resealed_wrong_identity(tmp_path: Path) -> None:
    root, manifest, value = _write_final_payload(tmp_path)
    value["workflow_run_attempt"] = 3
    value.pop("evidence_sha256")
    value["evidence_sha256"] = canonical_sha256(value)
    manifest.write_bytes(_encoded(value))
    with pytest.raises(P6ProtocolError, match="workflow run attempt"):
        validate_final_evidence_manifest(manifest, payload_root=root, **_final_expected())


def test_final_evidence_manifest_rejects_symlink_and_special_member(tmp_path: Path) -> None:
    root, manifest, _ = _write_final_payload(tmp_path)
    target = root / "one.json"
    original = target.with_suffix(".target")
    original.write_bytes(target.read_bytes())
    target.unlink()
    try:
        target.symlink_to(original)
    except OSError:
        pytest.skip("symbolic links are unavailable")
    with pytest.raises(P6ProtocolError, match="link or special"):
        validate_final_evidence_manifest(manifest, payload_root=root, **_final_expected())


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO is unavailable")
def test_final_evidence_manifest_rejects_fifo(tmp_path: Path) -> None:
    root, manifest, _ = _write_final_payload(tmp_path)
    os.mkfifo(root / "unexpected.fifo")
    with pytest.raises(P6ProtocolError, match="link or special"):
        validate_final_evidence_manifest(manifest, payload_root=root, **_final_expected())


def _toolchain_probe() -> dict[str, object]:
    tools = [
        "python3",
        "cmake",
        "gcc",
        "clang",
        "clangd",
        "gclang",
        "get-bc",
        "llvm-link",
        "llvm-nm",
        "wpa",
        "saber",
        "cc",
    ]
    return {
        "schema_version": "zscope.p6-toolchain-probe.v1",
        "required_tools": tools,
        "paths": {name: f"/usr/bin/{name}" for name in tools},
        "versions": {
            name: "synthetic-version" for name in ("python3", "cmake", "gcc", "clang", "clangd")
        },
        "missing_shared_libraries": {"wpa": [], "saber": []},
        "passed": True,
    }


def _image_provenance(candidate: str = "1" * 40) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "zscope.p6-local-image-provenance.v1",
        "git_revision": candidate,
        "platform": "linux/amd64",
        "base_image_ref": p6_protocol.P6_PYTHON_BASE_IMAGE_REF,
        "base_image_digest": p6_protocol.P6_PYTHON_BASE_IMAGE_DIGEST,
        "runtime_lock_sha256": "2" * 64,
        "containerfile_sha256": "3" * 64,
        "python_requirements_sha256": "4" * 64,
        "image_ref": "registry.invalid/zscope@sha256:" + "5" * 64,
        "image_digest": "sha256:" + "5" * 64,
        "image_id": "sha256:" + "6" * 64,
        "toolchain_probe": _toolchain_probe(),
        "credential_material_present": False,
        "formal_evidence": False,
        "release_eligible": False,
    }
    value["content_sha256"] = canonical_sha256(value)
    return value


def _proxy_provision() -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "zscope.p6-local-proxy-provision.v2",
        "created": True,
        "image_ref": "registry.invalid/zscope@sha256:" + "5" * 64,
        "image_id": "sha256:" + "6" * 64,
        "provider_identity_sha256": "7" * 64,
        "network_name": "zscope-p6-internal",
        "egress_network_name": "zscope-p6-egress",
        "network_names": ["zscope-p6-egress", "zscope-p6-internal"],
        "network_aliases_sha256": "c" * 64,
        "proxy_container": "zscope-p6-proxy",
        "proxy_container_id": "8" * 64,
        "endpoint_origin": "https://models.example.test",
        "endpoint_host": "models.example.test",
        "network_policy_sha256": "9" * 64,
        "relay_sha256": "a" * 64,
        "relay_projection_sha256": "d" * 64,
        "upstreams_sha256": "b" * 64,
        "upstream_count": 2,
        "command_projection_sha256": "e" * 64,
        "expected_environment_sha256": "f" * 64,
        "credential_environment_keys": [],
        "security_projection_sha256": "1" * 64,
        "log_driver_projection_sha256": "2" * 64,
        "image_inspect_projection_sha256": "3" * 64,
        "proxy_inspect_projection_sha256": "4" * 64,
        "formal_evidence": False,
        "release_eligible": False,
    }
    value["content_sha256"] = canonical_sha256(value)
    return value


def _lineage(candidate: str = "1" * 40) -> dict[str, object]:
    return {
        "workflow_run_id": "33260000001",
        "workflow_run_attempt": 2,
        "attempt_id": "p6-33260000001-2",
        "control_plane_commit": "c" * 40,
        "candidate_sha256": hashlib.sha256(candidate.encode()).hexdigest(),
        "candidate_git_sha": candidate,
        "candidate_git_tree": "d" * 40,
        "provider_identity_sha256": "7" * 64,
        "image_ref": "registry.invalid/zscope@sha256:" + "5" * 64,
        "image_id": "sha256:" + "6" * 64,
        "proxy_container": "zscope-p6-proxy",
        "proxy_container_id": "8" * 64,
        "network_name": "zscope-p6-internal",
        "egress_network_name": "zscope-p6-egress",
        "network_policy_sha256": "9" * 64,
        "endpoint_origin": "https://models.example.test",
    }


def _expected_proxy_attestation() -> dict[str, object]:
    lineage = _lineage()
    proxy = _proxy_provision()
    value: dict[str, object] = {
        "schema_version": "zscope.p6-expected-proxy-attestation.v2",
        "workflow_run_id": lineage["workflow_run_id"],
        "workflow_run_attempt": lineage["workflow_run_attempt"],
        "attempt_id": lineage["attempt_id"],
        "control_plane_commit": lineage["control_plane_commit"],
        "candidate_sha256": lineage["candidate_sha256"],
        "candidate_git_sha": lineage["candidate_git_sha"],
        "candidate_git_tree": lineage["candidate_git_tree"],
        "toolchain_evidence_sha256": "5" * 64,
        "toolchain_evidence_content_sha256": "6" * 64,
        "image_provenance_sha256": "7" * 64,
        "image_provenance_content_sha256": "8" * 64,
        "proxy_provision_sha256": "9" * 64,
        "proxy_provision_content_sha256": proxy["content_sha256"],
        **{
            field: proxy[field]
            for field in (
                "image_ref",
                "image_id",
                "provider_identity_sha256",
                "network_name",
                "egress_network_name",
                "network_names",
                "network_aliases_sha256",
                "proxy_container",
                "proxy_container_id",
                "endpoint_origin",
                "endpoint_host",
                "network_policy_sha256",
                "relay_sha256",
                "relay_projection_sha256",
                "upstreams_sha256",
                "upstream_count",
                "command_projection_sha256",
                "expected_environment_sha256",
                "credential_environment_keys",
                "security_projection_sha256",
                "log_driver_projection_sha256",
                "image_inspect_projection_sha256",
                "proxy_inspect_projection_sha256",
                "formal_evidence",
                "release_eligible",
            )
        },
    }
    value["content_sha256"] = canonical_sha256(value)
    return value


def _write_toolchain_bundle(
    tmp_path: Path,
    *,
    candidate: str = "1" * 40,
    provenance: dict[str, object] | None = None,
    proxy: dict[str, object] | None = None,
) -> tuple[dict[str, object], Path, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    provenance = provenance or _image_provenance(candidate)
    proxy = proxy or _proxy_provision()
    provenance_path = tmp_path / "image-provenance.json"
    proxy_path = tmp_path / "proxy-provision.json"
    provenance_path.write_bytes(_encoded(provenance))
    proxy_path.write_bytes(_encoded(proxy))
    draft = {
        "schema_version": "zscope.p6-toolchain-oci-evidence.v1",
        "workflow_path": P6_WORKFLOW_PATH,
        "workflow_run_id": "33260000001",
        "workflow_run_attempt": 2,
        "attempt_id": "p6-33260000001-2",
        "control_plane_commit": "c" * 40,
        "candidate_sha256": hashlib.sha256(candidate.encode()).hexdigest(),
        "candidate_git_sha": candidate,
        "candidate_git_tree": "d" * 40,
        "image_ref": provenance["image_ref"],
        "image_digest": provenance["image_digest"],
        "image_id": provenance["image_id"],
        "image_provenance_sha256": hashlib.sha256(provenance_path.read_bytes()).hexdigest(),
        "image_provenance_content_sha256": provenance["content_sha256"],
        "proxy_provision_sha256": hashlib.sha256(proxy_path.read_bytes()).hexdigest(),
        "proxy_provision_content_sha256": proxy["content_sha256"],
        "runtime_source_sha256": "e" * 64,
        "oci_execution_sha256": "f" * 64,
        "rootless_verified": True,
        "image_digest_verified": True,
        "mounts_verified": True,
        "network_restriction_verified": True,
        "runtime_source_mounted": True,
        "formal_evidence": False,
        "release_eligible": False,
    }
    return dict(seal_toolchain_evidence(draft)), provenance_path, proxy_path


def test_toolchain_provenance_files_bind_raw_objects_and_cli(tmp_path: Path) -> None:
    evidence, provenance, proxy = _write_toolchain_bundle(tmp_path)
    result = validate_toolchain_provenance_files(
        evidence, provenance, proxy, expected_lineage=_lineage()
    )
    assert result["proxy_provision"]["proxy_container_id"] == "8" * 64
    evidence_path = tmp_path / "toolchain-evidence.json"
    evidence_path.write_bytes(_encoded(evidence))
    lineage = _lineage()
    args = argparse.Namespace(
        toolchain_evidence=evidence_path,
        image_provenance=provenance,
        proxy_provision=proxy,
        workflow_run_id=lineage["workflow_run_id"],
        workflow_run_attempt=lineage["workflow_run_attempt"],
        attempt_id=lineage["attempt_id"],
        control_plane_commit=lineage["control_plane_commit"],
        candidate_sha256=lineage["candidate_sha256"],
        candidate_commit=lineage["candidate_git_sha"],
        candidate_tree=lineage["candidate_git_tree"],
        provider_identity_sha256=lineage["provider_identity_sha256"],
        image_ref=lineage["image_ref"],
        image_id=lineage["image_id"],
        proxy_container=lineage["proxy_container"],
        proxy_container_id=lineage["proxy_container_id"],
        network_name=lineage["network_name"],
        egress_network_name=lineage["egress_network_name"],
        network_policy_sha256=lineage["network_policy_sha256"],
        endpoint_origin=lineage["endpoint_origin"],
    )
    assert p6_cli._validate_toolchain_provenance(args) == 0


def test_toolchain_provenance_rejects_tamper_swap_and_self_reseal(tmp_path: Path) -> None:
    evidence, provenance, proxy = _write_toolchain_bundle(tmp_path / "tamper")
    provenance.write_bytes(provenance.read_bytes() + b" ")
    with pytest.raises(P6ProtocolError, match="file hash binding"):
        validate_toolchain_provenance_files(
            evidence, provenance, proxy, expected_lineage=_lineage()
        )

    other_candidate = "2" * 40
    other, other_provenance, other_proxy = _write_toolchain_bundle(
        tmp_path / "swap", candidate=other_candidate
    )
    with pytest.raises(P6ProtocolError, match="candidate"):
        validate_toolchain_provenance_files(
            other, other_provenance, other_proxy, expected_lineage=_lineage()
        )

    forged_proxy = _proxy_provision()
    forged_proxy["provider_identity_sha256"] = "0" * 64
    forged_proxy.pop("content_sha256")
    forged_proxy["content_sha256"] = canonical_sha256(forged_proxy)
    forged, forged_provenance, forged_proxy_path = _write_toolchain_bundle(
        tmp_path / "reseal", proxy=forged_proxy
    )
    with pytest.raises(P6ProtocolError, match="lineage"):
        validate_toolchain_provenance_files(
            forged, forged_provenance, forged_proxy_path, expected_lineage=_lineage()
        )


def test_toolchain_provenance_rejects_symlink(tmp_path: Path) -> None:
    evidence, provenance, proxy = _write_toolchain_bundle(tmp_path / "link")
    target = provenance.with_suffix(".target")
    target.write_bytes(provenance.read_bytes())
    provenance.unlink()
    try:
        provenance.symlink_to(target)
    except OSError:
        pytest.skip("symbolic links are unavailable")
    with pytest.raises(P6ProtocolError, match="regular file"):
        validate_toolchain_provenance_files(
            evidence, provenance, proxy, expected_lineage=_lineage()
        )


def test_toolchain_provenance_rejects_extra_schema_field(tmp_path: Path) -> None:
    schema_root = tmp_path / "schema"
    proxy_value = _proxy_provision()
    proxy_value["unexpected"] = True
    proxy_value.pop("content_sha256")
    proxy_value["content_sha256"] = canonical_sha256(proxy_value)
    forged, image_path, proxy_path = _write_toolchain_bundle(schema_root, proxy=proxy_value)
    with pytest.raises(P6ProtocolError, match="fields are invalid"):
        validate_toolchain_provenance_files(
            forged, image_path, proxy_path, expected_lineage=_lineage()
        )


@pytest.mark.parametrize("mutation", ("missing", "extra", "old-schema", "same-name-id"))
def test_expected_proxy_attestation_closed_schema_fails_old_or_ambiguous_identity(
    mutation: str,
) -> None:
    value = _expected_proxy_attestation()
    if mutation == "missing":
        value.pop("command_projection_sha256")
    elif mutation == "extra":
        value["unexpected"] = True
    elif mutation == "old-schema":
        value["schema_version"] = "zscope.p6-expected-proxy-attestation.v1"
    elif mutation == "same-name-id":
        value["proxy_container_id"] = "different-id"
    else:
        raise AssertionError(mutation)
    value["content_sha256"] = canonical_sha256(
        {key: item for key, item in value.items() if key != "content_sha256"}
    )
    with pytest.raises(P6ProtocolError):
        validate_expected_proxy_attestation(value)


def test_proxy_provision_v1_cannot_be_resealed_as_complete_v2() -> None:
    value = _proxy_provision()
    value["schema_version"] = "zscope.p6-local-proxy-provision.v1"
    value["content_sha256"] = canonical_sha256(
        {key: item for key, item in value.items() if key != "content_sha256"}
    )
    with pytest.raises(P6ProtocolError, match="schema"):
        validate_proxy_provision(value)
