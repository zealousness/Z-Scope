# v1.3.1 repository security audit

## Current tree

The high-confidence local scanner found no private key block, AWS/GitHub/OpenAI-style credential, or private IPv4 HTTP endpoint in the current tree. Generated reports, local `.env` files, caches, Java `target/` directories and benchmark run directories are ignored. CI additionally runs Gitleaks and dependency review.

## Full Git history blocker

The 2026-08-10 full-ref audit scanned 262 unique Git trees and found one high-entropy OpenAI-style credential value (redacted fingerprint `sha256:3b3f96e686dbe942`) repeated in historical configuration/conversation-export paths across 135 tree revisions. The current tree no longer contains the value. A second `sk-...` value was classified as a low-entropy placeholder and is not treated as a credential.

Release is blocked until an administrator confirms that fingerprint `3b3f96e686dbe942` has been revoked or rotated. The value is intentionally not reproduced in this document or scanner output.

No history rewrite was performed. Rewriting shared history requires, in this order:

1. Revoke/rotate and record the credential fingerprint and revocation time outside the repository.
2. Back up all refs and Release tags and agree on a maintenance window with every clone owner.
3. Rewrite every affected branch/tag with an approved tool, re-run Gitleaks plus `scripts/scan_git_history_secrets.py`, and compare protected tags/assets.
4. Force-update only under the agreed migration plan, then require every collaborator and runner cache to re-clone.

Until that process completes, the full-history secret-scan required check is expected to fail. Do not add an allowlist merely to make the gate green unless the owning security administrator has documented revocation.
