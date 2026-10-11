# Passkey owner approval app

This revision includes an everyday owner app and a real WebAuthn verifier connected
to the persistent authority core. It is implemented and tested locally; no real
owner key, passkey, vendor account, merchant connection or deployment was provisioned.
Created by Jeremy McEntire as part of Signet's platform-neutral personal authority layer.

## Two preserved implementations

This document primarily describes the tested SQLite exact-approval flow. The later
`owner-native-init` / `owner-native-serve` path connects WebAuthn owner management
to rings and native R2-compatible JSON persistence. It commits credentials and ring
changes atomically; synthetic service-level lifecycle tests pass. Its management
forms and shared HTTP interface still need dedicated browser, concurrency and
independent review. Native purchase requirements currently appear as hashes;
readable binding must be completed before owner-facing use. No existing data was
migrated. See [prototype status](prototype-status.md). Further build is paused.

## See the experience without credentials

From this checkout (Rust 1.88+):

```sh
cargo build --locked -p signet
./target/debug/signet owner-preview --port 4322
```

Open `http://localhost:4322`. This static-only mode has fictional requests, a visible
preview banner and no authentication, authority or purchase endpoints. It shows an
exact $75 lamp exception, adding electronics confirmation, changing a $50 limit to
$80, and backup-passkey management. Preview clicks cannot create real credentials.
The live owner app uses the same assets with real authenticated endpoints instead.

## What the person approves

The inbox separates a one-time purchase from a rule addition, edit or removal.
Purchase review shows the executor-signed merchant, item, quantity, currency, total,
requirements, terms and fulfillment. Rule review shows exact before/after values
and current version. Every action requests fresh passkey user verification; signing
in merely opens the private inbox. Requests expire and never turn an exception into
a standing rule or raise a reorder baseline.

An authenticated agent submits `propose_approval` with an `ApprovedAction` and a
`documents` map from SHA-256 digest to its exact plain UTF-8 text. Missing or
mismatched readable terms are rejected. The agent's labels and text remain claims
from that agent or the trusted quote executor; a hash does not establish that a
merchant is honest or that its fulfillment promise will be met. The trusted
executor must verify those facts. No model-supplied `approved` flag is accepted.

The service creates an immutable proposal, records its client and policy revision,
and exposes its ID through `approval_status` only to that authenticated client.
The owner UI shows the registered agent's operator-configured label and fingerprint.
Approval binds a server-held WebAuthn challenge to that proposal's complete action
and review, owner session, credential epoch, revision and expiry. After verification:

- A rule mutation is signed and committed atomically, once.
- A purchase gets one short-lived exact grant. No merchant purchase happens here.
  The separate authenticated executor must reserve and perform it under the core's
  idempotency and reconciliation contract.
- A decline marks only that proposal rejected, after fresh verification.

## Authentication and isolated signing

[`webauthn-rs` 0.5.5](https://docs.rs/webauthn-rs/0.5.5/webauthn_rs/) handles registration
and assertion cryptography, RP-ID binding, exact origin, challenge, signature and
required user verification. Signet additionally checks session/CSRF, short expiry,
one-shot ceremony IDs, current credential revocation, counters, proposal binding
and policy revisions in the transaction that changes authority. The dependency is
pinned; no custom WebAuthn cryptography or fake production authenticator is used.

WebAuthn assertions are **not** arbitrary Ed25519 signatures. The server verifies
the passkey assertion, then its injected owner signer signs the exact core approval.
Neither browser nor agent receives the signer key or a generic signing endpoint.
The authenticator verifies the relying party and user; the trusted Signet page
presents the transaction. This is not a claim that an authenticator displays or
independently understands the purchase itself. Synced passkeys may have zero
signature counters; challenge one-use and database state still prevent replay.

The software-file signer requires an externally provisioned 32-byte binary seed,
mode 0600, a mode-0700 parent, and no symbolic/hard links. Buffers are zeroized.
It pins the public key to the authority configuration. This is software custody,
not a hardware-key claim. Deploy the process, executable, signer, configuration and
SQLite/WAL files under an account or boundary the agent cannot read or modify.
Same-user macOS file permissions are **not** process isolation. An injected `Signer`
backend permits later reviewed hardware/remote custody without exposing key material.

## Enrollment, backup and recovery

An operator privately delivers a high-entropy one-time invitation. Only its SHA-256
hash is stored in `OwnerConfig`; it expires within 15 minutes of first setup. The
first registration needs that invitation and WebAuthn user verification. The
initialized flag is durable, so removing every credential cannot reopen bootstrap.

Add a backup by first verifying an existing passkey, then completing a separate,
bound registration ceremony. Up to eight active passkeys are supported. Revoking
a key requires a different enrolled passkey; the last key cannot be removed.
In the SQLite implementation, adding or revoking a key advances the credential
epoch and policy revision, invalidating other sessions, ceremonies and unspent
grants. Already reserved merchant work cannot be undone by revoking a key.

**Native prototype limitation:** passkey revocation advances the owner credential
epoch, but does not invalidate existing ring delegations. Those assignments can
still reserve new actions until separately revoked or expired. Do not treat a
native passkey revocation as revoking all authority it previously approved. This
is a blocker for live use and must be repaired with cross-instance forcing tests
before a native owner service is deployed.

Use a separately enrolled backup if a passkey is lost. If every key is lost,
approvals stay locked. There is no email reset, agent override or automatic ledger
restore. A reviewed operator recovery into a new authority plus reconciliation of
outstanding work remains an operational gate. Agent/executor key rotation and
owner-signing-key rotation are not exposed by this app. Do not reset the database
to recover access: doing so can resurrect old authority or lose execution records.

## Operator configuration (not automatic provisioning)

After choosing and protecting the service boundary, an operator supplies the
existing authority database/trust configuration and an `OwnerConfig` JSON file:

```json
{
  "rp_id": "owner.example.com",
  "origin": "https://owner.example.com",
  "user_id": "<stable operator-generated UUID>",
  "display_name": "Your name",
  "agent_labels": {"<provisioned agent public key>": "My personal agent"},
  "enrollment_token_hash": "<SHA-256 of privately delivered random invitation>",
  "enrollment_expires_at": 0
}
```

Placeholders are deliberately unusable. Supply a future Unix expiry within 15
minutes when initializing owner metadata; the pinned config must stay identical
on restarts, including the original expiry. Existing enrollments continue after
that invitation expires. The RP and exact origin are pinned in the database.
HTTPS is required except an explicit `http://localhost:PORT` origin with RP
`localhost` for development. Never broaden an origin to make a failing test pass.

```sh
signet owner-serve \
  --database /private/service/authority.sqlite \
  --trust-config /private/service/trust.json \
  --owner-config /private/service/owner.json \
  --owner-key-file /private/signer/owner.seed \
  --port 4322
```

The CLI binds **127.0.0.1 only**. Production HTTPS termination, exact Host forwarding,
trusted service placement, rate limiting, monitoring and rollback-safe backups need
separate review. Do not expose it publicly by forwarding a port as an integration
shortcut. Configuration currently supports one owner per authority, not multitenancy.
Passkey records and readable review terms are stored in the protected authority
SQLite database, not encrypted by the separate vault runtime.

## HTTP and MCP adapters

- `/api/session` issues an opaque HttpOnly, SameSite=Strict cookie and CSRF token.
  HTTPS uses a Secure `__Host-` cookie. Enrollment/login rotate session IDs.
- Browser POSTs require exact Origin, Host, cookie and CSRF. Cross-site requests
  fail closed. CSP prevents framing and third-party scripts; responses are no-store.
- `/api/agent` accepts the same authenticated signed envelope as the stdio core.
- `/mcp` supports stateless Streamable HTTP JSON responses: POST initialize, ping,
  tools/list and tools/call; accepted notifications return 202, GET returns 405.
  Accept must include JSON and event-stream, supported protocol headers are
  validated, and invalid supplied origins return 403. There is no SSE push stream.

The agent adapter owns its provisioned agent signature; browser owner cookies do
not authorize agent calls. Signed client authentication is implemented, but vendor
OAuth/discovery, remote session binding, host validation and public deployment are
**not** supplied. Host approval policies still apply. Only Signet-routed actions
are governed; this cannot veto unrelated platform tools.

## Verification and remaining gates

Run `make check`. Owner tests use `webauthn-authenticator-rs` software passkeys with
synthetic user-verification flags and ephemeral random keys, never a real device
or ambient vault. They cover UV, RP/origin/port rejection, challenge expiry,
session/action/revision binding, replay and counter regression, concurrent proposal
completion, grant invalidation, enrollment/backup/revocation, restart behavior,
signer failure rollback, HTTP cookies/CSRF and MCP boundary behavior.

Chrome desktop/mobile review covers the fictional UI, keyboard interaction, overflow,
accessible names and browser errors. Real-device passkey interoperability, an
independent security review, deployment isolation, reviewed recovery/key rotation,
merchant execution/reconciliation, vendor access and per-host testing remain before
live use. Local tests do not certify production custody.
