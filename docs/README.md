# Signet documentation

Signet is Jeremy McEntire's proposal for personal authority beneath a user-chosen
agent. The prototype is preserved and further implementation is paused. The
[architecture](architecture.md), [status](prototype-status.md) and
[open work](open-work.md) are the October 11, 2026 checkpoint. They distinguish
settled direction from tested code and unresolved integration.

## Choose a path

| Goal | Start here |
|---|---|
| See tested vs proposed work | [Prototype status](prototype-status.md), [open questions](open-work.md) |
| Understand the value | [Project overview](../README.md), [website](https://signet.tools/) |
| Understand the intended everyday behavior | [Product contract](everyday-authority.md) |
| Explore exact approvals and passkey recovery | [Owner app and safe preview](owner-approval.md) |
| Integrate persistent signed authority | [Authority core, protocol and deployment gates](authority-service.md) |
| Evaluate rules through a local agent | [Read-only MCP preview](agent-preview.md) |
| Understand rings and asset bindings | [Rings, rules and assets](rings-and-assets.md) |
| Review native persistence | [R2 and recovery](r2-persistence.md) |
| Review custody and proposed handshake | [Client asset custody](client-asset-custody.md) |
| Inspect personal cloud checkpoint | [GCP deployment gates](gcp-deployment.md) |
| Check vendor integration routes | [Platform readiness](platform-readiness.md) |
| Evaluate with synthetic data | [Getting started](getting-started.md) |
| Connect Claude Desktop | [MCP client setup](claude-desktop-setup.md) |
| Build an agent or service integration | [Integration guide and implementation status](integration.md) |
| Understand trust and component boundaries | [Architecture](architecture.md) |
| Review capability acceptance | [Generic capability boundary](capability-verification-boundary-2026-06-04.md) |
| Review delegated provider work | [Acceptance-only draft](delegated-provider-authorization-boundary-2026-06-04.md) |
| Contribute and run checks | [Contributing](../CONTRIBUTING.md), [test policy](no-key-test-quarantine.md) |
| Report a vulnerability | [Security policy](../SECURITY.md) |

## For agents reading these docs

Read the integration status before executing examples. Use a separate development
config and only synthetic data. Discover actual tool input schemas with MCP
`tools/list`; do not infer parameter names from the marketing scenarios.
Never treat MCP placeholder proof bytes as cryptographic evidence, a pending
challenge as consent, or a denied capability request as permission to bypass the
boundary. Report unmet integration requirements explicitly.

The README is the high-level orientation; these docs are the usage and integration
reference. `DESIGN.md` and `CLAUDE.md` include broader design intent and historical
proposals. They are not evidence that a feature is connected or production ready.
When they differ, inspect the current source and the implementation-status guide.
