# Personal cloud deployment checkpoint

Verified October 11, 2026. Nothing in this document is an instruction to apply resources without action-time approval.

## Created and verified

A new personal GCP project was created, is ACTIVE, has no organization parent and
remains unbilled. The open personal billing account was identified but not linked;
a second personal billing account is closed. Existing gcloud defaults were left
unchanged. Exact account, billing and project identifiers are retained in the
local operational checkpoint, not this public-facing design document.

No hosted service, additional runtime IAM grant, signing key, secret, R2 bucket,
load balancer or DNS record was created. Local OpenTofu initialization downloaded
the official Google provider 6.50.0; provider validation and formatting passed.
No cloud plan or apply ran. Docker image build remains unvalidated.

## Intended topology and hard gates

`app.signet.tools` is the owner app origin; private native JSON state lives in R2. Keep the present DNS provider (`ns-cloud-c*.googledomains.com`). The user will update DNS after an approved deployment yields exact records. There is no load-balancer IP or requested DNS change yet.

Proposed GCP ingress: external HTTPS Application Load Balancer, serverless NEG, Cloud Run and Google-managed certificate. Direct Cloud Run domain mapping is a preview feature, so it is not the proposed production ingress. Region, resource sizing and spend envelope still need final approval.

The original owner HTTP surface remains SQLite-based. A separate native owner path now shares the HTTP contract and commits passkey state with rings in R2-compatible JSON; CLI wiring includes an explicit bind address. Synthetic service-level tests pass, but native HTTP/browser/concurrency review remains. The client custody protocol is still unimplemented. Do not deploy the current legacy Docker command or claim this topology works end-to-end. Cloud Run needs a reviewed all-interface listener and persistent authority backend; its writable filesystem is ephemeral. The local KMS signer validates fixed key version, CRC32C and Ed25519 response signatures. Its workload-identity transport is implemented and mock-tested, with fixed metadata/API destinations, bounded responses, timeouts and redirects disabled. No live KMS call was made.

The foundation Terraform in `deployment/gcp-foundation/` describes APIs, a runtime identity, Artifact Registry and a software Ed25519 key for review. It is **not applied** and deliberately contains no runnable service, public ingress or billing-link action. A later runtime/ingress plan must be generated against a reviewed image and native R2 owner integration.

## Next action-time approval

Further setup is paused. If resumed with explicit approval, a reviewable first cloud step is to link the personal billing account, enable the specified APIs, and apply the foundation plan only after inspecting its exact resource/IAM diff and estimate. Do not grant broad project Editor/Owner roles or create downloadable service-account keys. Key signing must be isolated from the agent runtime; merely placing both in one service account defeats the boundary.

R2 setup needs a selected Cloudflare account, private bucket and narrowly scoped credentials. No Cloudflare account ownership or token was verified. Keep cleanup privileges separate. Required secret references must be provided through protected runtime configuration; never commit values or expose them to the agent.

Published list-price references: [Cloud Run](https://cloud.google.com/run/pricing), [load balancing](https://cloud.google.com/load-balancing/pricing), [KMS](https://cloud.google.com/kms/pricing), [R2](https://developers.cloudflare.com/r2/pricing/). The load-balancer forwarding-rule base alone is about $18.25 per 730-hour month at $0.025/hour; IP, data processing, compute, storage and requests are additional. Software KMS is $0.06 per active key version/month plus $0.03 per 10,000 operations. A complete regional estimate and budget alerts are still required; alerts do not cap spending.

## Existing Fly deployment

Read-only inspection found `signet-tools` serving the website and `signet-vault` serving `vault.signet.tools`; the latter has a persistent volume and runs the legacy server entrypoint. The new owner/rings service was not deployed. Another process or Machine in the same Fly app is not secret isolation: app secrets are available to Machines and deployers can change code. Protected signing requires a separate administrative and runtime boundary.
