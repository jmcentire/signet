# Signet

**Your AI. Your rules.**

Signet is a proposal for personal authority across services: choose your agent,
define what it may do, and keep exceptions specific. Created by
[Jeremy McEntire](https://perardua.dev), it includes open-source foundations and a
preserved research prototype. It is not a launched purchasing or custody service.

**October 11, 2026: further implementation is paused.** The architecture and code
are retained for evaluation and possible future collaboration, without a promise
of continued development. The intended conversational experience is not connected.

[Read the complete architecture](docs/architecture.md) ·
[Implemented and tested status](docs/prototype-status.md) ·
[Answered decisions and open work](docs/open-work.md)

The native owner prototype has a known revocation gap: removing a passkey does
not revoke its existing ring assignments. See the status document before use;
this source publication is not approval to deploy it.

## What that should feel like

- “Don't spend more than $50 on Amazon without asking.” A suitable $18 USB-C
  cable can fit the standing rule; choose final confirmation or let it act within
  the rule where the host permits that.
- “For dog food, find a better deal; otherwise pay the usual amount.” The same
  approved order can use a cheaper or equal established total. An increase or
  changed requirement needs review; an exception never raises the baseline.
- “Approve this $75 desk lamp once.” That exact item, merchant and total receive
  an exception. Your $50 standing rule stays $50.
- “Always ask before electronics purchases.” The agent proposes a readable rule.
  You separately authorize the exact addition once. Editing or removing an
  identified rule needs its own temporary authority too.

A purchase approval cannot rewrite rules, and the agent cannot expand its own
permissions. One agent, chosen by you, should carry your intent across services.
These are intended product behaviors, not a claim of live merchant integrations.

[Try the website preview](https://signet.tools/) ·
[Run the agent preview](docs/agent-preview.md) ·
[Product contract](docs/everyday-authority.md) ·
[Platform readiness](docs/platform-readiness.md)

## The intended architecture

Rules and assets are separate versioned records; a ring binds them. A worker gets
explicit task authority with an aggregate budget and an end: completion or expiry.
New accounts start at zero permissions. R2 stores native JSON snapshots with an
atomic current-head update. Restoring policy never restores spent authority.

Sensitive assets follow a client-only decryption direction with user-held keys
and no escrow. The designated-pair unlock protocol remains unresolved. The
proposed controlled browser uses Jev to classify behavior and Signet to evaluate
rules; classification is not the enforcement boundary. An agent can ask for an
exception, but its explanation cannot authorize one. See the [architecture](docs/architecture.md).

## The foundations

A model supplies intelligence. A connector reaches a service. Signet addresses
what an agent may know, disclose, and request on a person's behalf.

- **A private source of context.** Vault storage and a key hierarchy separate
  provable facts, agent-internal context, and sensitive credentials.
- **A boundary for requests.** Policy components evaluate actor, predicate,
  and context; return permit, deny, or anomaly decisions; and support audit.
- **A smaller disclosure.** Proof and credential components support selective
  disclosure. Exact-context capability verification checks issuer, domain,
  purpose, validity, and requested financial constraints.
- **An integration surface.** A local CLI, MCP server, and Rust SDK give
  personal-agent builders components to evaluate and connect.

For example, an agent could recommend a stay using private preferences, prove an
age threshold without sharing a birth date, or stop before using a payment
credential. These are integration scenarios, not shipped travel, identity, or
payment services. No named platform integration or endorsement is claimed.

## What works, and what remains

This repository contains nine Rust crates covering vault, policy, credential,
proof, notification, MCP, SDK, shared types, and CLI components. It is a preserved research prototype, not a production custody service.

The distinction between components and connected product behavior matters:

| Surface | Current boundary |
|---|---|
| Authenticated authority core | Versioned rule mutations, owner-signed exact approvals, atomic single-use grants, executor reservations, and receipt-backed baselines. Raw signed protocol and MCP relay; passkey owner app and signed HTTP adapter. Isolated deployment and merchant adapters still required. See [authority service](docs/authority-service.md). |
| Native rings/owner | Versioned rule/asset bindings, bounded task scopes and native JSON CAS with passkey state. Service-level synthetic tests pass; native UI/HTTP/concurrency review and readable requirement binding remain. [Status](docs/prototype-status.md). |
| Controlled browser/Jev | Agreed design only: pause actions, classify, evaluate permission, execute exact grants. No browser gate, classifier integration or universal checkout claim. |
| Read-only agent preview | `preview-serve` supports local MCP discovery and hypothetical purchase/rule-change evaluation, with no authority or persistence. |
| Local CLI storage | Initialize a development vault, store/list synthetic data, inspect status and audit entrypoints. |
| MCP `get_proof` | Returns deterministic placeholder bytes; **not a cryptographic proof**. |
| MCP `query` | Tier 1 and Tier 2 responses are scaffolding, not real vault reasoning. |
| Policy enforcement | An authenticated pipeline exists; direct JSON-RPC dispatch has separate paths. Review transport wiring. |
| Capability requests | MCP/SDK/CLI issuance fails closed; verified issuer wiring remains to be implemented. |
| One-time generic capabilities | Issuance and acceptance disabled pending a consumption ledger. |
| Personal-agent platforms | Signed authority MCP relay and read-only preview tested locally. Local passkey owner authentication and HTTP/MCP transport are implemented. Protected deployment, vendor OAuth/session binding, host review, merchant adapters and connection tests remain. |

See the [source-linked integration status](docs/integration.md#implementation-status)
and [security policy](SECURITY.md) before using sensitive workloads.

## Start here

Requires Rust 1.88+ and Git. Install the vault CLI from this repository:

```sh
cargo install --locked --git https://github.com/jmcentire/signet.git signet
signet --help
```

The new read-only MCP preview is available from this source checkout:

```sh
cargo build --locked -p signet
./target/debug/signet preview-serve
```

It evaluates hypothetical purchase/rule-change inputs, never loads a vault, and
never authorizes execution. See [agent preview](docs/agent-preview.md). It is not
available from the remote install until this revision is published.

For the persistent authority core, run `cargo run --locked -p signet --example authority_walkthrough`. It exercises synthetic signed identities, durable rule state and replay rejection without buying anything. Read the [authority contract and deployment gates](docs/authority-service.md) before wiring a real signer. Preview the credential-free owner experience with `./target/debug/signet owner-preview --port 4322`, then open `http://localhost:4322`. The [passkey owner app](docs/owner-approval.md) has real WebAuthn verification and isolated signing interfaces, tested with synthetic authenticators. No live credentials were provisioned.

Follow the [isolated local walkthrough](docs/getting-started.md) to create a
separate development vault and connect an MCP client with synthetic data.
`cargo install signet` is not the installation command for this project.

## Find your way

- **Evaluating the idea:** [signet.tools](https://signet.tools/)
- **Using the CLI or connecting an agent:** [Getting started](docs/getting-started.md)
- **Building a personal-agent platform:** [Integration guide](docs/integration.md)
- **Navigating as a human or agent:** [Documentation index](docs/README.md)
- **Contributing:** [CONTRIBUTING.md](CONTRIBUTING.md), [CHANGELOG.md](CHANGELOG.md)

The canonical website lives in
[jmcentire/Signet-Tools](https://github.com/jmcentire/Signet-Tools). This repository
owns the Rust stack and technical documentation; its HTML files retain redirects
for old GitHub Pages links.

[Signet Eval](https://github.com/wandercom/signet-eval) is the separate tool-call
policy engine maintained by Wander. It has its own installation and runtime;
it is not the Signet vault.

## Development and license

```sh
make check
```

This runs the credential scan, build, lint, formatting check, and tests. Generated
test keys and documented test vectors are permitted; production credentials and
real vaults are forbidden in tests. See the [test policy](docs/no-key-test-quarantine.md).

Created by Jeremy McEntire. Licensed under [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE), at your option. The source and history provide a
concrete record of the project; no exclusivity, certification, or outside
endorsement is implied.
