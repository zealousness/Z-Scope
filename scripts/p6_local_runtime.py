#!/usr/bin/env python3
"""Build the P6 toolchain image or provision its credential-free TCP relay."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Sequence

from zscope.benchmarking.isolation import (
    RootlessOciExecutor,
    validate_oci_execution_evidence,
)
from zscope.benchmarking.p6_local_runtime import (
    ProxyProvisionRequest,
    build_bootstrap_proxy_attestation,
    build_expected_proxy_attestation,
    build_toolchain_image,
    load_image_provenance,
    provision_transparent_proxy,
    validate_image_provenance,
)
from zscope.benchmarking.p6_protocol import (
    canonical_sha256,
    load_json_bytes_strict,
    load_json_strict,
    read_regular_file_once,
    seal_toolchain_evidence,
    validate_proxy_provision,
    validate_toolchain_evidence,
)
from zscope.benchmarking.provider_runtime import require_p6_provider_contract
from zscope.benchmarking.runner import prepare_p6_runtime_source


def _build(args: argparse.Namespace) -> int:
    result = build_toolchain_image(
        runtime=args.runtime,
        repository=args.repository,
        git_revision=args.git_revision,
        lock_path=args.lock,
        containerfile=args.containerfile,
        context=args.context,
        output=args.output,
    )
    print(f"p6 image ready: {result['image_ref']}")
    return 0


def _proxy(args: argparse.Namespace) -> int:
    contract = require_p6_provider_contract(args.config)
    result = provision_transparent_proxy(
        request=ProxyProvisionRequest(
            runtime=args.runtime,
            image_ref=args.image,
            internal_network=args.network,
            egress_network=args.egress_network,
            proxy_container=args.proxy_container,
            relay_path=args.relay,
            image_provenance_path=args.image_provenance,
        ),
        provider_contract=contract,
        output=args.output,
    )
    print(
        "p6 proxy ready: "
        f"network={result['network_name']}; policy={result['network_policy_sha256']}"
    )
    return 0


def _write_private_json(path: Path, value: object) -> None:
    path = path.absolute()
    if path.exists() or path.is_symlink():
        raise RuntimeError(f"refusing to replace {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _git_value(root: Path, revision: str) -> str:
    return subprocess.run(
        ["git", "rev-parse", revision],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env={"PATH": os.environ.get("PATH", "")},
    ).stdout.strip()


_TOOLCHAIN_PROBE = r"""
import pathlib, shutil, subprocess, tempfile
tools = ('python3','cmake','gcc','clang','clangd','gclang','get-bc','llvm-link','llvm-nm','wpa','saber','cc')
paths = {name: shutil.which(name) for name in tools}
assert all(paths.values())
for name in ('wpa','saber'):
    result = subprocess.run(('ldd', paths[name]), check=True, capture_output=True, text=True)
    assert 'not found' not in result.stdout and 'not found' not in result.stderr
with tempfile.TemporaryDirectory() as raw:
    root = pathlib.Path(raw)
    source = root / 'probe.c'
    source.write_text('int probe(void){return 0;}\n', encoding='utf-8')
    subprocess.run((paths['cc'], '-std=c11', '-Werror', '-Wall', '-Wextra', '-c', str(source), '-o', str(root / 'probe.o')), check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
"""


def _preflight(args: argparse.Namespace) -> int:
    if (
        re.fullmatch(r"[0-9a-f]{40}", args.control_plane_commit) is None
        or re.fullmatch(r"[0-9a-f]{40}", args.candidate_commit) is None
        or re.fullmatch(r"[1-9][0-9]*", args.workflow_run_id) is None
        or args.workflow_run_attempt < 1
        or args.attempt_id != f"p6-{args.workflow_run_id}-{args.workflow_run_attempt}"
        or re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository) is None
        or re.fullmatch(r"[^@]+@sha256:[0-9a-f]{64}", args.image) is None
        or not args.toolchain_evidence.is_absolute()
        or not args.expected_proxy_attestation.is_absolute()
    ):
        raise RuntimeError("local P6 preflight identity is invalid")
    candidate_root = args.candidate_root.resolve(strict=True)
    candidate_commit = _git_value(candidate_root, f"{args.candidate_commit}^{{commit}}")
    if (
        candidate_commit != args.candidate_commit
        or _git_value(candidate_root, "HEAD") != candidate_commit
    ):
        raise RuntimeError("candidate checkout is not the exact candidate commit")
    candidate_tree = _git_value(candidate_root, "HEAD^{tree}")
    image_provenance = load_image_provenance(args.image_provenance.absolute())
    proxy_value = load_json_strict(args.proxy_provision.absolute())
    if not isinstance(proxy_value, dict):
        raise RuntimeError("proxy provenance is not an object")
    proxy_provision = dict(validate_proxy_provision(proxy_value))
    if image_provenance["git_revision"] != candidate_commit:
        raise RuntimeError("image provenance candidate mismatch")
    if image_provenance["image_ref"] != args.image:
        raise RuntimeError("image provenance reference mismatch")
    contract = require_p6_provider_contract(args.config)
    request = ProxyProvisionRequest(
        runtime=args.runtime,
        image_ref=args.image,
        internal_network=args.network,
        egress_network=args.egress_network,
        proxy_container=args.proxy_container,
        relay_path=args.relay,
        image_provenance_path=args.image_provenance,
    )
    if (
        proxy_provision["image_ref"] != args.image
        or proxy_provision["network_name"] != args.network
        or proxy_provision["egress_network_name"] != args.egress_network
        or proxy_provision["proxy_container"] != args.proxy_container
        or proxy_provision["provider_identity_sha256"] != contract.identity_sha256
    ):
        raise RuntimeError("proxy provenance mismatch")
    bootstrap_attestation = build_bootstrap_proxy_attestation(
        request=request,
        provider_contract=contract,
        image_provenance_path=args.image_provenance,
        proxy_provision_path=args.proxy_provision,
        expected_lineage={
            "workflow_run_id": args.workflow_run_id,
            "workflow_run_attempt": args.workflow_run_attempt,
            "attempt_id": args.attempt_id,
            "repository": args.repository,
        },
    )
    image_provenance_bytes = read_regular_file_once(args.image_provenance.absolute())
    proxy_provision_bytes = read_regular_file_once(args.proxy_provision.absolute())
    if (
        hashlib.sha256(image_provenance_bytes).hexdigest()
        != bootstrap_attestation["image_provenance_sha256"]
        or hashlib.sha256(proxy_provision_bytes).hexdigest()
        != bootstrap_attestation["proxy_provision_sha256"]
    ):
        raise RuntimeError("P6 bootstrap receipt changed after binding")
    image_value = load_json_bytes_strict(image_provenance_bytes, name="P6 image provenance")
    proxy_value = load_json_bytes_strict(proxy_provision_bytes, name="P6 proxy provision")
    if not isinstance(image_value, dict) or not isinstance(proxy_value, dict):
        raise RuntimeError("P6 bootstrap receipt is not an object")
    image_provenance = validate_image_provenance(image_value)
    proxy_provision = dict(validate_proxy_provision(proxy_value))
    with tempfile.TemporaryDirectory(prefix="zscope-p6-local-preflight-") as raw:
        root = Path(raw)
        scan_input, artifact_output, cache_output = root / "input", root / "output", root / "cache"
        runtime_source = root / "runtime-source" / "zscope"
        for target in (scan_input, artifact_output, cache_output):
            target.mkdir()
        runtime_source_sha256 = prepare_p6_runtime_source(
            runtime_source, git_revision=candidate_commit
        )
        executor = RootlessOciExecutor(
            runtime=args.runtime,
            image=args.image,
            scan_input=scan_input,
            artifact_output=artifact_output,
            cache_output=cache_output,
            runtime_source=runtime_source,
            environment={
                "Z_SCOPE_API_KEY": "p6-preflight-credential-not-forwarded",
                "Z_SCOPE_BENCHMARK_OCI_NETWORK": args.network,
                "Z_SCOPE_BENCHMARK_OCI_MODEL_PROXY_CONTAINER": args.proxy_container,
                "GITHUB_REPOSITORY": args.repository,
                "GITHUB_RUN_ID": args.workflow_run_id,
                "GITHUB_RUN_ATTEMPT": str(args.workflow_run_attempt),
                "P6_ATTEMPT_ID": args.attempt_id,
            },
            provider_contract=contract,
            bootstrap_expected_proxy_attestation=bootstrap_attestation,
        )
        executor.preflight()
        phase_log = root / "toolchain-phase.json"
        executor.execute_phase(
            "preflight",
            ("python3", "-c", _TOOLCHAIN_PROBE),
            log_path=phase_log,
            accepted_returncodes=(0,),
            provider_credentials=False,
        )
        execution = executor.execution_evidence(required_phases=("preflight",))
        if validate_oci_execution_evidence(execution, require_release_capable=False):
            raise RuntimeError("OCI execution evidence is invalid")
        if (
            execution.get("runtime_source_sha256") != runtime_source_sha256
            or execution.get("image_id") != image_provenance["image_id"]
            or execution.get("proxy_container_id") != proxy_provision["proxy_container_id"]
            or execution.get("network_policy_sha256") != proxy_provision["network_policy_sha256"]
            or execution.get("provider_identity_sha256") != contract.identity_sha256
        ):
            raise RuntimeError("OCI execution lineage mismatch")
    draft = {
        "schema_version": "zscope.p6-toolchain-oci-evidence.v1",
        "workflow_path": ".github/workflows/p6-pilot-validation.yml",
        "control_plane_commit": args.control_plane_commit,
        "workflow_run_id": args.workflow_run_id,
        "workflow_run_attempt": args.workflow_run_attempt,
        "attempt_id": args.attempt_id,
        "candidate_sha256": hashlib.sha256(candidate_commit.encode()).hexdigest(),
        "candidate_git_sha": candidate_commit,
        "candidate_git_tree": candidate_tree,
        "image_ref": args.image,
        "image_digest": args.image.rsplit("@", 1)[1],
        "image_id": execution["image_id"],
        "image_provenance_sha256": hashlib.sha256(image_provenance_bytes).hexdigest(),
        "image_provenance_content_sha256": image_provenance["content_sha256"],
        "proxy_provision_sha256": hashlib.sha256(proxy_provision_bytes).hexdigest(),
        "proxy_provision_content_sha256": proxy_provision["content_sha256"],
        "runtime_source_sha256": runtime_source_sha256,
        "oci_execution_sha256": canonical_sha256(execution),
        "rootless_verified": execution["rootless_verified"] is True,
        "image_digest_verified": execution["image_digest_verified"] is True,
        "mounts_verified": execution["mounts_verified"] is True,
        "network_restriction_verified": execution["network_restriction_verified"] is True,
        "runtime_source_mounted": execution["runtime_source_mounted"] is True,
        "formal_evidence": False,
        "release_eligible": False,
    }
    evidence = seal_toolchain_evidence(draft)
    validate_toolchain_evidence(
        evidence,
        expected_run_id=args.workflow_run_id,
        expected_run_attempt=args.workflow_run_attempt,
        expected_attempt_id=args.attempt_id,
        expected_control_plane_commit=args.control_plane_commit,
        expected_git_sha=candidate_commit,
        expected_git_tree=candidate_tree,
    )
    _write_private_json(args.toolchain_evidence, evidence)
    lineage = {
        "workflow_run_id": args.workflow_run_id,
        "workflow_run_attempt": args.workflow_run_attempt,
        "attempt_id": args.attempt_id,
        "control_plane_commit": args.control_plane_commit,
        "candidate_sha256": hashlib.sha256(candidate_commit.encode()).hexdigest(),
        "candidate_git_sha": candidate_commit,
        "candidate_git_tree": candidate_tree,
        "provider_identity_sha256": contract.identity_sha256,
        "image_ref": args.image,
        "image_id": image_provenance["image_id"],
        "proxy_container": args.proxy_container,
        "proxy_container_id": proxy_provision["proxy_container_id"],
        "network_name": args.network,
        "egress_network_name": args.egress_network,
        "network_policy_sha256": proxy_provision["network_policy_sha256"],
        "endpoint_origin": proxy_provision["endpoint_origin"],
    }
    attestation = build_expected_proxy_attestation(
        request=request,
        provider_contract=contract,
        toolchain_evidence_path=args.toolchain_evidence,
        proxy_provision_path=args.proxy_provision,
        expected_lineage=lineage,
        output=args.expected_proxy_attestation,
    )
    attestation_file_sha256 = hashlib.sha256(
        args.expected_proxy_attestation.read_bytes()
    ).hexdigest()
    with tempfile.TemporaryDirectory(prefix="zscope-p6-final-attestation-preflight-") as raw:
        root = Path(raw)
        scan_input, artifact_output, cache_output = root / "input", root / "output", root / "cache"
        runtime_source = root / "runtime-source" / "zscope"
        for target in (scan_input, artifact_output, cache_output):
            target.mkdir()
        final_runtime_source_sha256 = prepare_p6_runtime_source(
            runtime_source, git_revision=candidate_commit
        )
        final_executor = RootlessOciExecutor(
            runtime=args.runtime,
            image=args.image,
            scan_input=scan_input,
            artifact_output=artifact_output,
            cache_output=cache_output,
            runtime_source=runtime_source,
            environment={
                "Z_SCOPE_API_KEY": "p6-final-attestation-credential-not-forwarded",
                "Z_SCOPE_BENCHMARK_OCI_NETWORK": args.network,
                "Z_SCOPE_BENCHMARK_OCI_MODEL_PROXY_CONTAINER": args.proxy_container,
                "Z_SCOPE_BENCHMARK_EXPECTED_PROXY_ATTESTATION_FILE": str(
                    args.expected_proxy_attestation
                ),
                "Z_SCOPE_BENCHMARK_EXPECTED_PROXY_ATTESTATION_SHA256": (attestation_file_sha256),
                "GITHUB_REPOSITORY": args.repository,
                "GITHUB_RUN_ID": args.workflow_run_id,
                "GITHUB_RUN_ATTEMPT": str(args.workflow_run_attempt),
                "P6_ATTEMPT_ID": args.attempt_id,
            },
            provider_contract=contract,
        )
        final_preflight = final_executor.preflight()
        if (
            final_runtime_source_sha256 != runtime_source_sha256
            or final_preflight.get("proxy_attestation_file_sha256") != attestation_file_sha256
            or final_preflight.get("proxy_attestation_content_sha256")
            != attestation["content_sha256"]
            or final_preflight.get("proxy_container_id") != proxy_provision["proxy_container_id"]
        ):
            raise RuntimeError("final proxy attestation preflight binding is invalid")
    print(
        "p6 preflight ready: "
        f"toolchain={evidence['evidence_sha256']}; proxy={attestation['content_sha256']}"
    )
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build-image")
    build.add_argument("--runtime", choices=("podman",), default="podman")
    build.add_argument("--repository", default="zscope-p6-toolchain")
    build.add_argument("--git-revision", required=True)
    build.add_argument("--lock", type=Path, default=Path("containers/p6/runtime-lock.json"))
    build.add_argument("--containerfile", type=Path, default=Path("containers/p6/Containerfile"))
    build.add_argument("--context", type=Path, default=Path("."))
    build.add_argument("--output", type=Path, required=True)
    build.set_defaults(handler=_build)

    proxy = commands.add_parser("provision-proxy")
    proxy.add_argument("--runtime", choices=("podman",), default="podman")
    proxy.add_argument("--image", required=True)
    proxy.add_argument("--image-provenance", type=Path, required=True)
    proxy.add_argument("--network", required=True)
    proxy.add_argument("--egress-network", required=True)
    proxy.add_argument("--proxy-container", required=True)
    proxy.add_argument("--config", type=Path, default=Path("test/range/zscope.benchmark.yaml"))
    proxy.add_argument("--relay", type=Path, default=Path("scripts/p6_tcp_relay.py"))
    proxy.add_argument("--output", type=Path, required=True)
    proxy.set_defaults(handler=_proxy)

    preflight = commands.add_parser("preflight")
    preflight.add_argument("--runtime", choices=("podman",), default="podman")
    preflight.add_argument("--image", required=True)
    preflight.add_argument("--image-provenance", type=Path, required=True)
    preflight.add_argument("--proxy-provision", type=Path, required=True)
    preflight.add_argument("--network", required=True)
    preflight.add_argument("--egress-network", required=True)
    preflight.add_argument("--proxy-container", required=True)
    preflight.add_argument("--repository", required=True)
    preflight.add_argument("--workflow-run-id", required=True)
    preflight.add_argument("--workflow-run-attempt", type=int, required=True)
    preflight.add_argument("--attempt-id", required=True)
    preflight.add_argument("--control-plane-commit", required=True)
    preflight.add_argument("--candidate-commit", required=True)
    preflight.add_argument("--candidate-root", type=Path, required=True)
    preflight.add_argument("--config", type=Path, default=Path("test/range/zscope.benchmark.yaml"))
    preflight.add_argument("--relay", type=Path, default=Path("scripts/p6_tcp_relay.py"))
    preflight.add_argument("--toolchain-evidence", type=Path, required=True)
    preflight.add_argument("--expected-proxy-attestation", type=Path, required=True)
    preflight.set_defaults(handler=_preflight)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
