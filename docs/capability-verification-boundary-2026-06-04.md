# Capability Verification Boundary

## Status

This change is a draft safety correction, not a Signet release claim and not
MEA custody approval. The no-key project-test quarantine remains in force.

## Corrected Defects

- The previous `v4.public` token was not a PASETO v4.public implementation
  and its parser did not verify its signature.
- The corrected format is explicitly Signet-specific: `signet.cap.v1`.
- `verify_capability_for_context` is the exact-context acceptance entrypoint:
  it verifies the Ed25519 envelope, internally consistent time window, expected
  issuer, domain, purpose, and any requested amount/currency before returning
  claims.
- Signature-only parsing is crate-internal so consumers cannot mistake decoded
  claims for complete authorization.
- One-time capability issuance and acceptance fail closed until a consumption
  ledger can enforce replay prevention with auditable state transitions.
- MCP and SDK capability issuance fail closed until verified issuer wiring
  exists.
- CLI and legacy SPL issuance fail closed; they no longer export or use raw
  signer material to mint a token.

## Dependency And License Evidence

`agent-safe-spl` is already present in the workspace dependency graph. Its
issuance API remains disabled in this draft, but its upstream repository
publishes the MIT license:

- https://github.com/jmcentire/agent-safe/blob/main/LICENSE

That license permits commercial use. This evidence does not establish
cryptographic suitability, compliance certification, maintenance posture, or
approval as the custody backend.

## Withheld Evidence

- Project test execution remains prohibited while the detector reports
  signing or private-key operations in test paths.
- The key-free verifier seam exercises accepted and rejected authenticator
  outcomes, expiry, not-before, and domain rejection; it does not constitute
  executed proof of Ed25519 forgery resistance.
- A trusted-issuer key configuration, key rotation model, audit event model,
  consumption ledger, and custody-controlled signing transport remain to be
  agreed with Exemplar/Baton before MEA consumes capabilities.
- This generic envelope does not carry Baton's exact connector, channel,
  request-fingerprint, and attempt-budget scope. It must never be adapted into
  Baton's delegated provider runtime.
- The separate acceptance-only `signet.delegated-provider.v1` draft defines
  that exact scope, but remains blocked on a concrete trusted issuer/rotation
  verifier and key-free executable cross-stack evidence.
