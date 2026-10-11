# Open work and answered decisions

October 11, 2026. This is a preserved research backlog, not a delivery commitment.
No implementation should resume merely because an item appears here.

## Answered decisions

- One user-chosen agent across services; platform-neutral authority.
- Rings bind separate, versioned rules and assets; account starts at zero only.
- Task/worker scope, aggregate reservations, optional shared budgets, bounded
  swaps and explicit expiry; completion ends authority and swaps cannot renew it.
- Private R2, native JSON, content-addressed history and conditional head CAS.
  Policy restoration creates a new version without rolling back execution state.
- Retention needs both age and newer-version count with protected references;
  values and cleanup implementation remain undecided.
- Owner-provided asset key, no escrow/recovery; client-only decryption direction.
  Current key plus fresh owner authentication required for rotation.
- Designated participants per handshake step, not arbitrary two-of-three quorum.
- Controlled browser pauses actions; Jev classifies, Signet evaluates rules and
  returns allow/deny/ask-owner; only the exact granted action may execute.
- Agent may request an exception and explain its case; explanation is not authority.
- Preserve the prototype, document the concept, pause additional unfunded build.

## Questions and acceptance work before any product claim

1. **Native owner review:** complete readable requirements binding, real-device and
   full HTTP tests, credential-revocation races, uncertain enrollment/login recovery,
   signer failure cases and independent review. Keep auth and ring changes atomic.
2. **Custody:** specify exact messages, contribution material, final plaintext
   recipient, isolated execution boundary, client availability and crash recovery.
   Demonstrate that agent tools cannot read secrets or reuse protected sessions.
3. **Browser:** choose wrapper/extension/managed-session design and an enforceable
   reference monitor. Cover every action route, not only visible clicks. Test dynamic
   pages, network effects, redirects, background scripts and malicious content.
4. **Jev evaluation:** use minimized structured context, no asset secrets. Measure
   false negatives, option-order and injection sensitivity, thresholds and abstention
   against representative tasks. Numeric/time checks remain deterministic. No API
   account, key, paid use or user-data transmission has been authorized.
5. **Exception contract:** distinguish one purchase from an extra allowance for one
   named period and from a standing-rule edit. Bind exact delta/total/currency,
   remaining budget, task, evidence and expiry. Prevent stacking and replay; require
   provider-confirmed results before adjusting reservations or future baselines.
6. **Provider routes:** verify actual payment/token/virtual-card constraints and
   credential-broker isolation. Provider-required confirmation cannot be waived by
   Signet. No universal merchant compatibility or named integration exists.
7. **Durability:** live R2/KMS contract checks, protected monotonic checkpoint,
   backup/recovery, retention fence, quota/size handling and separate cleanup access.
8. **Operations:** validate Docker, finish infrastructure plan, choose region and
   cost envelope, configure narrowly scoped runtime grants only after approval.
   CI and the manifest now target Rust 1.88 minimum. Do not deploy the legacy custody path.
9. **Publication:** public prototype source and docs in `jmcentire/signet`, website
   source in `jmcentire/Signet-Tools`, and the existing `signet.tools` Fly website
   are approved destinations. This does not authorize deployment of the authority
   app, new cloud resources, billing or IAM. Source attribution and dated history
   record contribution; they do not prove exclusivity or endorsement.

## Smallest coherent demonstration

The existing fictional website and owner preview explain the value. The tested
one-time approval contract shows an exception without changing a standing rule.
Synthetic native rings tests demonstrate bindings, budgets, version restoration
and revocation. This can explain the concept without a live merchant, new cloud
resources or an unfinished browser security claim.

## Native revocation finding

Scoped pre-publication review found that revoking a native owner passkey leaves
previously authorized ring delegations active. They can reserve new work until
separately revoked or expired. Repair this and force cross-instance races in tests
before any live native deployment; the SQLite invalidation guarantee must not be
applied to the native prototype.
