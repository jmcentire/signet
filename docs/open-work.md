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

## Resumed: remote passkey approval

On November 26, 2026 Jeremy resumed build for one subsystem: approving a passkey
request from a phone when the computer that asked is somewhere else. The design,
what is built and tested, and the decisions still open are in
[remote passkey approval](remote-passkey.md). Nothing else on this page resumed.

Still to do there, in order:

1. TLS in the relay client, so the computer can reach a relay that is not on
   the same machine.
2. Mount the relay's routes in Herald. Decided November 26, 2026; needs this
   work merged first, and Jeremy's approval to deploy.
3. Keep the machine key in the operating system's key store.
4. A cancel message, so dismissing a request on the computer clears it on the
   phone.
5. The phone app, and with it the push the relay must send to wake it.

## Proposed: rules for dealing with other parties' agents

Proposed by Jeremy on November 26, 2026. Not designed, not built.

Signet's rules so far govern what the owner's agent may spend, disclose and use.
These would govern what it accepts from the agent on the other side of a
conversation, for example an airline's:

- **Require disclosure** of certain things before continuing, such as who else
  pays the other agent.
- **Decline every up-sell and cross-sell.**
- **Opt out of everything** optional: marketing, data sharing, enrollment.
- **Invoke the right to be forgotten** when the task ends.

Three of these are actions the owner's agent takes and can be enforced on the
owner's side alone. Required disclosure is different: the agent can refuse to
continue without a signed statement, but cannot verify that the statement is
true. The signed statement is then evidence. Erasure is a request whose force
depends on the law that applies. These fit the agent-to-agent protocol and the
small shared vocabulary of defaults, with signed tokens carrying only the
bounds that differ.

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
