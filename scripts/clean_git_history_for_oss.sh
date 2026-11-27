#!/usr/bin/env bash
# Safely rewrite Git history in an isolated mirror clone to remove historical
# oversized third-party binaries, internal coordination/handoff archives,
# temporary experiment dumps, and early placeholder credentials before public
# open-sourcing.
#
# This script NEVER modifies your active working directory and NEVER pushes to
# any remote automatically.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/clean_git_history_for_oss.sh \
    --source <repo-path-or-url> \
    --workdir <output-directory-outside-repo> \
    [--mailmap <mailmap-file>]

Options:
  --source   Source Git repository path (clean committed repo) or URL.
  --workdir  Empty/new directory where the backup bundle and cleaned mirro
             clone will be written. Must be outside the source repository.
  --mailmap  Optional git-filter-repo mailmap file to remap author/committe
             emails (e.g. personal emails -> GitHub noreply addresses):
               Your Name <id+username@users.noreply.github.com> <old@email>

Prerequisites:
  - git
  - git-filter-repo (install via: pip install git-filter-repo)
  - python3 (for post-clean secret scan)

Workflow after running this script:
  1. Commit or stash all working-tree changes in your normal checkout first.
  2. Run this script against your repository.
  3. Inspect the printed size comparison, commit log, and secret scan output.
  4. Verify a fresh clone from <workdir>/cleaned.git passes your test suite.
  5. During an agreed maintenance window, force-push cleaned refs to origin and
     have collaborators re-clone. Keep <workdir>/backup.bundle offline/private
     until the transition completes, then destroy it.
EOF
}

source_repo=""
workdir=""
mailmap=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source) source_repo="${2:-}"; shift 2 ;;
    --workdir) workdir="${2:-}"; shift 2 ;;
    --mailmap) mailmap="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ -n "${source_repo}" && -n "${workdir}" ]] || { usage >&2; exit 2; }
command -v git >/dev/null || { echo "git is required" >&2; exit 1; }
command -v git-filter-repo >/dev/null || {
  echo "git-filter-repo is not installed. Install it with: python3 -m pip install git-filter-repo" >&2
  exit 1
}

if [[ -n "${mailmap}" && ! -f "${mailmap}" ]]; then
  echo "Mailmap file does not exist: ${mailmap}" >&2
  exit 1
fi

mkdir -p "${workdir}"
workdir="$(cd "${workdir}" && pwd -P)"
if [[ -d "${source_repo}" ]]; then
  source_repo="$(cd "${source_repo}" && pwd -P)"
  case "${workdir}" in
    "${source_repo}"|"${source_repo}"/*)
      echo "Refusing --workdir inside --source repository: ${workdir}" >&2
      exit 2
      ;;
  esac
  if [[ -n "$(git -C "${source_repo}" status --porcelain)" ]]; then
    echo "Warning: ${source_repo} has uncommitted working-tree changes." >&2
    echo "         Mirror cloning commits only; commit/stash first if you want them included." >&2
  fi
fi

mirror_dir="${workdir}/cleaned.git"
backup_bundle="${workdir}/backup.bundle"
if [[ -e "${mirror_dir}" || -e "${backup_bundle}" ]]; then
  echo "Target files already exist under ${workdir}; use a fresh --workdir." >&2
  exit 2
fi

echo "==> Step 1: Creating mirror clone at ${mirror_dir}"
git clone --mirror "${source_repo}" "${mirror_dir}"

echo "==> Step 2: Recording pre-clean size and creating verified backup bundle"
git -C "${mirror_dir}" count-objects -vH
git -C "${mirror_dir}" bundle create "${backup_bundle}" --all
git -C "${mirror_dir}" bundle verify "${backup_bundle}" >/dev/null
echo "Backup bundle saved and verified: ${backup_bundle}"

# Paths removed from history:
# - Historical vendored Maven JARs (tens of MiB of third-party binaries)
# - Internal multi-agent coordination logs, handoff bundles, and scratch experiments
# - Oversized raw benchmark JSONL/CSV/backup reports and .webm screen recordings
# - Early test/junior directory (contained placeholder sk-11111... config and CMake binaries)
# - Root-level Clang .plist outputs and hotpath scratch script
filter_args=(
  --force
  --invert-paths
  --path third_party/maven/offline-repo/
  --path docs/Z-Scope_Agent_Implementation_Plan/
  --path docs/archive/coordination/
  --path docs/handoffs/
  --path benchmarks/experiments/
  --path docs/reports/benchmarks/20261106-three-depth-review/candidate-evidence.jsonl
  --path docs/reports/benchmarks/20261106-three-depth-review/case-evidence.md
  --path docs/reports/benchmarks/20261106-three-depth-review/candidate-costs.csv
  --path docs/reports/benchmarks/20261106-three-depth-review/truth-evidence.csv
  --path docs/reports/benchmarks/20261106-three-depth-review/unmatched-findings.csv
  --path docs/reports/benchmarks/20261106-three-depth-review/truth-reference.json
  --path docs/reports/benchmarks/20261106-three-depth-review/artifact-index.json
  --path docs/reports/benchmarks/20261106-three-depth-review/candidate-cost-summary.json
  --path docs/design/webui/assets/before-flow.webm
  --path docs/design/webui/assets/after-flow.webm
  --path docs/design/webui/assets/primitives/primitives-flow.webm
  --path test/junior/
  --path cpg.bin
  --path conversation_export.md
  --path 'docs/Z-SCOPE 面向 C 语言 AI 代码检视工具深度评估报告.pdf'
  --path docs/range_reports/v33_shadow_evaluation.json
  --path tests/fixtures/p2_proof_kernel/corpus.json
  --path test/range/test/range/
  --path test/range/current_eval.json
  --path test/range/benchmark/v16/
  --path test/range/zscope_batch_report.json.pre_llm_reasoning.bak
  --path test/range/metrics.json
  --path test/llm_wiki_demo/output/
  --path-glob 'test/llm_wiki_demo/zscope_batch_report*.json'
  --path callback_registry.plist
  --path caller.plist
  --path command_runner.plist
  --path frame_decoder.plist
  --path label_store.plist
  --path port_parser.plist
  --path _bench_hotpath.py
)

if [[ -n "${mailmap}" ]]; then
  filter_args+=(--mailmap "${mailmap}")
fi

echo "==> Step 3: Running git-filter-repo"
(cd "${mirror_dir}" && git-filter-repo "${filter_args[@]}")

echo "==> Step 4: Expiring reflogs and compacting packfiles"
git -C "${mirror_dir}" reflog expire --expire=now --all || true
git -C "${mirror_dir}" gc --prune=now --aggressive

echo "==> Step 5: Post-clean size and largest remaining blobs"
git -C "${mirror_dir}" count-objects -vH
git -C "${mirror_dir}" rev-list --objects --all \
  | git -C "${mirror_dir}" cat-file --batch-check='%(objecttype) %(objectname) %(objectsize) %(rest)' \
  | awk '$1 == "blob" {print $3, $4}' \
  | sort -nr \
  | head -n 15

echo "==> Step 6: Verifying cleaned history secret scan on main"
verify_dir="${workdir}/verify-checkout"
git clone --branch main "${mirror_dir}" "${verify_dir}"
if [[ -f "${verify_dir}/scripts/scan_git_history_secrets.py" ]]; then
  (cd "${verify_dir}" && python3 scripts/scan_git_history_secrets.py --ref main)
fi

cat <<EOF

Cleanup complete in isolated mirror: ${mirror_dir}
Verification checkout:               ${verify_dir}
Offline backup bundle (DO NOT PUSH): ${backup_bundle}

Next steps (manual review required):
  1. Run your test suite in ${verify_dir}.
  2. Confirm 'git -C ${mirror_dir} shortlog -sne --all' and refs look right.
  3. When ready to publish, push cleaned refs manually, for example:
       git -C "${mirror_dir}" remote add target <your-public-repo-url>
       git -C "${mirror_dir}" push --force target main
EOF
