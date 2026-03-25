# Privacy Policy

**Last updated:** March 24, 2026

## The short version

Signet is a local cryptographic vault. Your keys, credentials, and identity proofs never leave your machine. We have no access to them.

## What Signet Is

Signet is an open-source, local-first cryptographic authorization framework. It runs entirely on your computer as a CLI tool and MCP server. There is no cloud service, no account system, no central authority, and no server infrastructure.

Signet's entire purpose is to keep your data sovereign — it would be contradictory for the tool itself to collect it.

## Data We Collect

None. Signet does not collect, transmit, store, or process any user data on external servers.

## Data You Create

When you use Signet, you create local cryptographic material:

- Key pairs and identity vaults stored in `~/.signet/`
- Capability tokens and authorization policies
- Signed attestations and zero-knowledge proofs

All of this is stored locally on your filesystem. Nothing is transmitted unless you explicitly present a proof to a verifier you choose.

## Proof Presentation

When you use Signet to prove something (e.g., "I am over 18" or "I hold credential X"), Signet constructs a cryptographic proof and presents it to the verifier you specify. This is an intentional, user-initiated action. Signet never presents proofs autonomously or transmits data without your explicit command.

The proofs are designed to be zero-knowledge where possible — the verifier learns the fact you're proving, nothing more.

## Third-Party Services

Signet does not communicate with any third-party services for its core operation. It does not phone home, check for updates, or transmit telemetry.

## Claude Code Plugin Context

When Signet is used as a Claude Code plugin, MCP tool responses are returned to the Claude session. This content is processed by Anthropic according to the [Anthropic Privacy Policy](https://www.anthropic.com/privacy). Signet does not transmit cryptographic private keys or vault contents through MCP tool responses — only public attestations and policy evaluation results.

## Analytics and Tracking

The website (signet.tools) does not use cookies, analytics, tracking pixels, or third-party scripts.

## Data Retention and Deletion

All data is local. Delete `~/.signet/` and everything is gone. There is nothing to request from us because we have nothing.

## Children's Privacy

Signet does not collect personal information from anyone, including children under 13.

## Changes to This Policy

If Signet ever adds cloud features or data collection, this policy will be updated before those features ship. Local-first is an architectural principle, not an accident.

## Contact

- Email: jmc@cageandmirror.com
- Source: [github.com/jmcentire/signet](https://github.com/jmcentire/signet)
- Web: [signet.tools/privacy](https://signet.tools/privacy)
