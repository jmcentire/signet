# Client asset custody and staged handshake proposal

Status: local cryptographic primitive and proposal, not an integrated custody product. No real asset or encryption key was enrolled. The exact handshake and final plaintext recipient remain decisions for the owner.

## Accepted boundaries

The user supplies the asset key. Signet does not escrow or recover it. Account/passkey recovery does not recover assets; losing the key means re-uploading the asset. Creation, replacement and key rotation require strong fresh owner authentication; rotation additionally requires the existing asset key. Authentication is not a key-reset substitute.

`signet-vault::asset_cipher` implements AES-256-GCM with a random 96-bit nonce, associated asset identifier and monotonic key epoch. It accepts a caller-held 32-byte key and returns authenticated ciphertext. Decryption validates the expected asset and epoch. Rotation decrypts with the current key, encrypts with the replacement key, and increments the epoch. Plaintext/key buffers use zeroization. This primitive supplies no password derivation, enrollment, MFA wiring or distributed handshake. Keep the old key locally until the newly encrypted version is durably committed. Rotation cannot invalidate old ciphertext/key copies already held elsewhere.

The established direction is client-only decryption: the server stores and returns ciphertext, not the asset key, reusable unlock token or plaintext. A raw copied key does not self-expire. Enforceable TTL applies to a redemption ledger or an isolated broker lease with non-exportable material; it is not a cryptographic promise that a copied secret disappears.

## Proposed designated-pair exchange — not implemented

This is a specific pair at each step, not an arbitrary two-of-three quorum or secret-sharing scheme.

| Step | Required parties | Proposed material and check |
|---|---|---|
| Authorize | Owner/client and agent | After fresh owner authentication, client signs a ticket for one request, asset version, ring version, agent key, task, operation, audience, expiry and random nonce. Agent receives the ticket, not an asset key. |
| Register | Client and authority server | Server receives the matching signed authorization and records its approval and redemption state in the current native JSON aggregate. |
| Redeem | Agent and authority server | Agent signs a fresh request proving possession of its registered key. Server verifies both signatures, exact bindings, current ring/task state and deadline, then atomically consumes the ticket nonce and reserves the operation through CAS. It releases only the corresponding encrypted asset or opaque provider capability. |
| Unlock/use | Agent and client | Agent presents the committed redemption receipt. A separate authenticated client contribution is required. **Decision pending:** whether the client performs the approved operation in an isolated broker and returns only its result, or releases some other cryptographic material. No raw asset-key release is implemented. |
| Settle | Executor and authority server | Store an authenticated result or an unknown outcome under the original execution ID. Retries recover that result; they cannot create a second redemption or refund an uncertain action. |

Use established signatures, authenticated encryption and authenticated channels. No bespoke threshold cryptography is proposed. Tickets are authorization statements; ciphertext is encrypted data; keys unlock it; a result describes the approved operation. They are not interchangeable “things.” Exact encoding, audience, channel binding, client availability, crash recovery and pair-by-pair proofs require protocol review before implementation.

## Payment and credential threat model

If the agent sees a reusable PAN, API key or password, it can retain it. An expiring ring cannot make it forget. Direct browser checkout that exposes an unrestricted card number to the agent fails the no-secret-exposure criterion.

Candidate routes are an isolated executor that uses the credential and returns a bounded receipt, or a provider-issued credential with enforceable restrictions. A virtual card is useful only to the extent its issuer actually enforces the required merchant, amount, expiry and/or single-use controls. An ordinary unrestricted virtual PAN is still reusable. The adapter must reject a requested scope when the issuer cannot enforce it; underlying card details must remain hidden. No card issuance, provider account or universal merchant coverage is implied.

The isolation boundary must prevent agent access to executor memory, environment, logs, filesystem, shell and administrative credentials. Merely renaming a tool or starting another process under the same powerful user does not provide that separation. Provider-held custody is preferred where supported; a future first-party local credential broker remains a separate option. Unattended cloud operation needs an available trusted client or a valid provider-delegated route.

## Prior art and deployment gates

`~/Code/BlindDB` is Jeremy's browser demonstration of opaque storage addressing, with SHA-256 and demonstration XOR encryption. Its encryption is not reused here. Signet's older `BlindStorage` uses authenticated encryption; its compare-and-swap was repaired to compare exact stored ciphertext atomically. The new ring manifest does not yet hide metadata relationships from the server.

The legacy `signet serve` initialization in `crates/signet/src/lib.rs` persists a mnemonic in `vault.json`. Do not deploy it as evidence of this client-only custody model. The legacy mock passkey code is also distinct from the new owner app's real WebAuthn implementation. Existing local vaults were not opened or migrated. A production custody deployment must eliminate that legacy server-side key path, integrate fresh MFA, finish the reviewed protocol and validate the actual execution isolation.

No compliance certification, legal ownership conclusion or provider endorsement is claimed. Jeremy's prior CJIS work is background experience, not an audit of Signet.

## Protected browser session — unresolved candidate

A general-purpose agent could prepare a cart while a protected component supplies login into a constrained browser session. That could reduce per-merchant integrations, but password hiding alone is insufficient: cookies and the authenticated session confer authority, and existing stored cards may permit purchases without exposing a PAN. Arbitrary JavaScript, developer tools, network interception, cookie export, agent-controlled extensions or a shared debugging endpoint can bypass a superficial boundary. Spending limits require a trustworthy transaction/action boundary that can inspect and constrain the actual checkout. Cross-merchant portability and reliable semantic enforcement are unproven; this is not a universal-checkout implementation or accepted replacement for the client protocol.

Jeremy identifies the proposed classifier as TypeSafe.ai's non-LLM probabilistic context classifier (behavior is/is not), with its exact architecture still under investigation. Evaluate calibration, false negatives and evidence rather than assuming an LLM. Classification confidence is separate from enforcement: every state-changing operation, including saved-card and one-click purchases in an existing protected session, must pass the action-bound Signet check. Fresh website login is not inherently required for each action. The gate may automatically authorize within a current ring; a fresh Signet permission check does not always mean another human prompt. Unknown or unsupported behavior must stop, and alternate session/network routes must be excluded. This candidate remains research, not an implemented guarantee.

## Final design checkpoint

Further implementation is paused. The agreed browser direction is controlled
execution, Jev classification, then deterministic Signet permission evaluation;
only an exact allowed action may execute. Jev is TypeSafe's non-text-generating
System One model, not an LLM. Its known adversarial and numeric weaknesses require
independent enforcement and testing. Current state, source references and open
questions are consolidated in [architecture](architecture.md). No Jev call or
controlled-browser prototype was implemented.
