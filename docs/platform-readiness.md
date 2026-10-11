# Platform readiness

Research snapshot; no integration commitment. Further implementation is paused.
See [architecture](architecture.md) and [prototype status](prototype-status.md) for
the current local design and code boundary. Platform rules below were checked on
the stated date and must be reverified before any future integration.

Verified against current official documentation on 2026-10-11. **No vendor
integration is installed, registered, submitted, or certified by this change.**
The local `preview-serve` tools remain read-only. A separate [authority core](authority-service.md)
now implements persistent signed approvals, versioned rules, single-use grants
and receipt baselines, with both raw and MCP stdio adapters tested locally.
A [passkey owner app](owner-approval.md) and signed HTTP/Streamable HTTP adapter
are implemented and tested locally with synthetic credentials. Protected deployment,
real-device validation and merchant purchasing remain; no vendor connection is claimed.

| Target | Official route | Current Signet status | Coverage and remaining gate |
|---|---|---|---|
| Generic local MCP host | Stdio tools protocol | Read-only preview and authenticated authority relay tested, including actual subprocess calls | The authority relay requires isolated service custody, provisioned caller keys and a trusted merchant executor; the owner app is implemented locally. It reserves exact work but makes no merchant calls. |
| Google Gemini Spark | Custom connected app with remote MCP URL | Documented adapter route; not connected | Needs protected remote service deployment and host authentication. Google currently requires manual confirmation for writes. Cannot veto unrelated native tools. |
| Consumer Muse | API/MCP connector, platform review | Documented adapter route; not submitted | Sensitive writes require Allow once each use. Purchases/rule authority must retain proper classification. Only Signet-routed tools are covered. |
| Muse Code | Stdio or Streamable HTTP MCP; lifecycle hooks | Stdio config prepared; installed CLI observed as 1.4.4 (1.4.4-R5419.1), not connected | Read-only preview can be evaluated through MCP. Harness enforcement needs a separate hook adapter, version-specific contract tests and failure checks. |
| dot / ChatGPT | Private MCP plugin over public HTTPS or Secure MCP Tunnel | Documented adapter route; not connected | A tunnel can target stdio for testing; no tunnel created. Host policy and approval still apply. Only mediated tools/resources can be protected. |
| Alexa+ | US MCP add-on over Streamable HTTP, MCP 2025-11-25 | Documented adapter route; not registered | Protected remote deployment, vendor authentication and add-on review required. No global Alexa enforcement hook established. |
| Siri | Native App Intents/App Shortcuts integration | Native adapter remains to be built | App-owned actions only; no general interception of Siri actions. |
| Meta AI Connectors | API/MCP onboarding and OAuth, limited early access | Separate possible route; no access application | Do not conflate with consumer Muse or Muse Code. Requires access and integration testing. |

## Host-specific constraints

**Google:** Gemini Spark is the intended Google product. Custom apps are connected
in Gemini web using an MCP URL, then usable on web/mobile. The documented rollout
requires a US adult with a personal Google account, English, and Keep Activity on.
Mandatory write confirmation limits the “act within my rules” experience on this
surface. [Google documentation](https://support.google.com/gemini/answer/17209137).

**Muse:** the connector guidelines distinguish read, write and sensitive write.
Purchases need per-use approval; scope changes require a fresh approval. A future
rule-management operation changes authority and must not masquerade as a read.
Review and complete task support are prerequisites; approval is not guaranteed.
[Muse guidelines](https://muse.ai/platform/docs).

**Muse Code:** MCP configuration supports stdio and Streamable HTTP. Hooks can
block tool use, but malformed project/managed hook files may contribute no
handlers, and unsupported entries can be skipped with warnings. `mode: required`
protects MCP startup availability, not universal action enforcement. No live
hook or settings changes were made. [Official extending guide](https://dev.meta.ai/docs/muse-code/extending).

**dot / ChatGPT:** a private MCP plugin can use HTTPS or a Secure MCP Tunnel; a
public endpoint uses Streamable HTTP. The tunnel is a testing path, not public
submission readiness. Tool annotations describe behavior but do not replace
server-side authorization. [Connection guide](https://developers.openai.com/plugins/deploy/connect-chatgpt).

**Alexa+:** the add-on route uses Streamable HTTP and MCP 2025-11-25. Service
client credentials and user authorization-code/PKCE have separate roles. A
service token is not owner consent. Amazon's Local Inspector setup goes through
Developer Console; no registration or simulator deployment was attempted.
[Overview](https://www.developer.amazon.com/docs/alexaplus/add-ons/mcp-toolkit-overview.html),
[authentication](https://www.developer.amazon.com/docs/alexaplus/add-ons/mcp-toolkit-authentication.html),
[inspector](https://www.developer.amazon.com/docs/alexaplus/add-ons/mcp-toolkit-local-inspector.html).

**Siri:** App Intents exposes an app's own actions. A native app, authenticated
owner flow, exact-change confirmation and device tests remain work; this is not
a global Siri rule engine. [Apple App Intents](https://developer.apple.com/documentation/AppIntents).

**Meta AI:** API/MCP onboarding with OAuth is an early-access path distinct from
Muse's reviewed connector platform. [Meta AI Connectors](https://dev.meta.ai/products/connectors).

## Implemented shared core and remaining gates

The [authority core](authority-service.md) now provides verified exact owner
approvals, versioned add/edit/remove rules, atomic single-use grants and replay
protection, revision invalidation/revocation, executor-only purchase reservations,
and completed-receipt baselines requiring separate owner approval. Both raw signed
stdio and an MCP relay are implemented. The synthetic walkthrough and adversarial
tests cover these locally; this is not a live vendor integration.

The selected owner experience is now a passkey-backed approval app with server-side
WebAuthn verification, exact-action review, isolated signer injection, backup
passkeys and revocation. Local signed HTTP and stateless Streamable HTTP MCP share
the core. The browser preview is fictional; synthetic authenticator tests exercise
the real verification/approval path. No real passkey or signing key was provisioned.

The next gates are independent security review, real-device passkey tests, protected
service deployment, operational recovery/rotation and rollback-safe storage. Integrate
a merchant executor with authoritative quotes, durable intent identity, provider
idempotency, verified receipts and reconciliation for uncertain outcomes. Vendor
OAuth/session binding and per-platform tests/review remain separate work.

The existing `signet serve` HTTP endpoint remains separate. It is not evidence
of Streamable HTTP compatibility or production authority. Its placeholders and
separate dispatch/enforcement paths are not enabled or repaired by this work.
The new service's stateful grants do not enable legacy `signet.cap.v1` one-time
issuance or bypass Tier 3 live-auth requirements.
