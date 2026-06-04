# No-Key Test Quarantine

## Status

Signet project tests are quarantined from CI execution until the no-key gate
passes. This is an execution hold, not proof that current test sources meet
the custody policy.

## Incident

On 2026-06-04, draft PR #2 triggered GitHub Actions run `26984879471`.
Both workspace test jobs began executing `cargo test --workspace` before the
run was cancelled. That command is prohibited while any test path constructs,
carries, or uses signing or private-key material.

## Gate

`scripts/no_key_material_scan.py` inspects Rust test regions, integration test
files, generated test artifacts, CI workflow commands, and local `make`
execution entrypoints. Any finding fails CI before build, lint, audit, or test
execution can proceed.

Until all findings are removed or replaced with approved non-secret evidence
seams:

- Do not run `cargo test`, `cargo nextest`, or generated test suites.
- Do not publish a Signet release as MEA custody evidence.
- Build-only checks do not establish cryptographic conformance.

## Remediation Inventory

The detector reported 157 findings across 22 paths on 2026-06-04. Findings
must be remediated in source; they are not allowlisted here.

| Findings | Path |
|---:|---|
| 20 | `crates/signet-cred/src/authority.rs` |
| 4 | `crates/signet-cred/src/issuance.rs` |
| 1 | `crates/signet-mcp/src/error.rs` |
| 9 | `crates/signet-mcp/src/session.rs` |
| 6 | `crates/signet-notify/src/dispatcher.rs` |
| 8 | `crates/signet-notify/src/types.rs` |
| 18 | `crates/signet-notify/src/webhook.rs` |
| 1 | `crates/signet-sdk/src/verify.rs` |
| 9 | `crates/signet-vault/src/key_hierarchy.rs` |
| 10 | `crates/signet-vault/src/mnemonic.rs` |
| 3 | `crates/signet-vault/src/passkey.rs` |
| 3 | `crates/signet-vault/src/session.rs` |
| 9 | `crates/signet-vault/src/signer.rs` |
| 2 | `crates/signet-vault/tests/attack_surface.rs` |
| 6 | `crates/signet/src/multi_tenant.rs` |
| 12 | `crates/signet/tests/integration_e2e.rs` |
| 4 | `crates/signet/tests/journey_e2e.rs` |
| 3 | `tests/root/contract_test_suite.json` |
| 2 | `tests/signet_cred/contract_test_suite.json` |
| 18 | `tests/signet_notify/contract_test_suite.json` |
| 1 | `tests/signet_policy/contract_test_suite.json` |
| 8 | `tests/signet_vault/contract_test_suite.json` |

| Findings | Detector rule |
|---:|---|
| 42 | `key-derivation-or-generation` |
| 60 | `key-material-identifier` |
| 29 | `signing-operation` |
| 26 | `signing-or-secret-key-type` |
