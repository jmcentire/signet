# REVIEW.md — Signet automated review checklist

Tailored for this repo (Rust workspace, cryptographic vault/policy engine). Keep
concise — this drives automated code review, not documentation. See
`~/Code/tools/CODE-REVIEW-STANDARD.md` and `~/Code/tools/DIFF-INTENT-GATE.md` for
the governing standard this checklist implements.

## Always check

- **No production credentials.** Preserve generated test keys and documented
  test-only vectors. The credential scanner must block committed credentials,
  including in test directories; never exempt all tests or delete cryptographic
  coverage. `scripts/test_credential_gate.py` exercises denial through `make`.
- **`cargo clippy --workspace -- -D warnings` and `cargo fmt --all -- --check` are
  green, and `cargo test --workspace --locked` passes.** CI runs these after
  the credential scan; build-only success is not cryptographic test evidence.
- **Constant-time comparison for secrets.** Any new comparison touching a MAC,
  hash, signature, or ciphertext uses `subtle::ConstantTimeEq`, never `==`.
- **`OsRng` only for cryptographic randomness** (key/nonce/salt generation).
  `thread_rng()` in a security-sensitive path is a finding.
- **Secret material is `Zeroizing<>`-wrapped.** New key/token/passphrase fields
  that hold raw `String`/`Vec<u8>` instead of `Zeroizing<>` get flagged.
- **No `.unwrap()`/`.expect()` in library code** (crates other than `signet` CLI
  binary, and outside `#[cfg(test)]`). Propagate `Result`.
- **BlindDB invariant**: storage-backend-visible data is SHA-256 record IDs and
  AES-256-GCM ciphertext only — never plaintext labels, semantic fields, or
  relationship/ownership metadata. Any new storage path is checked against this
  before merge.
- **Capability/authority verification changes are HIGH risk by default** (auth,
  tenant/actor isolation). `crates/signet-cred/src/capability.rs`,
  `crates/signet-cred/src/delegated_provider.rs`,
  `crates/signet-sdk/src/capability.rs`, and `crates/signet-sdk/src/authority.rs`
  govern whether a request is authorized at all — see
  `docs/capability-verification-boundary-2026-06-04.md` and
  `docs/delegated-provider-authorization-boundary-2026-06-04.md` for the ratified
  boundary. A diff touching these needs `HUMAN_REVIEW_REQUIRED`, never an
  agent-issued approval, per the Code Review Standard.
- **Fail-closed on issuance/verification.** Signature verification, capability
  parsing, and credential issuance must reject on missing/invalid/ambiguous input
  — no silent default-grant path. Trace any relaxed check back to the invariant it
  claims to satisfy (Diff-Intent Gate: quote the before/after, find the human
  antecedent).
- **`.kin/` stays a regenerated projection.** Don't hand-edit `.kin/code-map.json`
  or `.kin/index.json`; regenerate with `kin index` and commit the output.

## Style

- Follow `CONTRIBUTING.md`'s Security Guidelines section — it's the canonical
  source for the constant-time/OsRng/Zeroizing/no-unwrap rules above.
- Crate boundaries follow the build order in `CLAUDE.md` (`signet-vault` is root
  of trust; `signet-cred`/`signet-proof`/`signet-policy`/`signet-notify` depend on
  it; `signet-mcp` bridges to `signet-sdk`/`signet-notify`). A dependency edge
  pointing the wrong direction is a design smell, not just a lint.
- Prefer `Result`-returning functions with the crate's own error enum
  (`CredError`, `RootError`, etc.) over `anyhow`/stringly-typed errors in library
  code.
- Doc comments on public APIs should state the invariant, not just repeat the
  signature (see existing `capability.rs` for the pattern).

## Skip

- `.kin/code-map.json`, `.kin/index.json` — generated, reviewed only for "does it
  regenerate cleanly," never diffed line-by-line.
- `Cargo.lock` — reviewed only for unexpected new dependencies, not line noise.
- `docs/index.html`, `docs/privacy.html`, `docs/style.css` — marketing site, not
  part of the security surface.
- Historical incident records (`docs/no-key-test-quarantine.md`'s remediation
  inventory table) — append/update status, don't rewrite the incident record.
