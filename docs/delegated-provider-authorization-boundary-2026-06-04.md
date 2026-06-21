# Delegated Provider Authorization Boundary

## Status

This is an acceptance-only draft contract for a trusted Signet verifier and
Baton's delegated provider runtime. It is separate from Signet's generic
financial capability envelope and is not MEA production approval.

The Signet no-key project-test quarantine remains active. Source-level tests
are authored but must not execute until the no-key gate passes.

## Envelope

The envelope header is:

```text
signet.delegated-provider.v1.
```

The authenticated JSON claims are:

```json
{
  "authorization_id": "authorization-1",
  "issuer": "signet://issuer/mea",
  "audience": "baton://delegated-provider-executor",
  "workload_id": "mea-comms",
  "issued_at": "2026-06-04T22:00:00+00:00",
  "not_before": "2026-06-04T22:00:00+00:00",
  "not_after": "2026-06-04T22:10:00+00:00",
  "channel": "sms",
  "allowed_connector_ids": ["sms-primary", "sms-backup"],
  "allowed_purposes": ["case_notification"],
  "request_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "max_uses": 1,
  "max_provider_attempts": 2
}
```

The claims contain no provider credential, credential handle, recipient value,
payload value, provider response, or dispatch claim ID.

## Exact Acceptance Context

`DelegatedProviderAcceptanceContext` supplies the trusted verifier with:

- expected issuer;
- Baton delegated-executor audience;
- workload ID;
- exactly one channel;
- the available runtime connector-ID ceiling;
- exact runtime purpose;
- exact canonical Baton request fingerprint; and
- a provider-attempt ceiling of at most `3` attempts;
- an authorization-lifetime ceiling of at most `15` minutes, measured from
  `issued_at` through `not_after`; and
- issuer-policy and rotation-policy references.

The issuer and rotation policy references are active verifier inputs, not
authenticated envelope claims. A production trust verifier must resolve and
enforce them and must treat the claimed issuer as untrusted input. The verified
outcome carries the applied policy references as verification metadata so
Baton can require an exact match to its configured policy bundle.

Acceptance rejects:

- a failed authenticator;
- an issuer, audience, workload, channel, purpose, connector, or request
  fingerprint mismatch;
- any authorized connector outside the available runtime connector ceiling;
- a purpose set that does not contain exactly the runtime purpose;
- empty, duplicate, oversized, or unbounded scope;
- an inconsistent, future, not-yet-valid, expired, or overlong time window;
- `max_uses` other than `1`; or
- a zero or over-ceiling provider-attempt budget.

The public verifier returns `VerifiedDelegatedProviderAuthorization`, not raw
parsed claims. Signature-only parsing is not exposed.

## Baton Mapping

The verified Signet outcome maps into Baton's one shared
`VerifiedDelegatedAuthorization`:

| Signet verified field | Baton field |
|---|---|
| `authorization_id` | `authorization_id` and sanitized audit correlation |
| `issuer` | `issuer` |
| `audience` | `audience` |
| `workload_id` | `principal`, then custody `workload_id` |
| `channel` | exact dispatch channel and custody channel |
| `allowed_connector_ids` | dispatch `allowed_connectors`, then custody `allowed_connector_ids` |
| `allowed_purposes` | custody `allowed_purposes` |
| `request_fingerprint` | dispatch and custody `request_fingerprint` |
| `not_before`, `not_after` | shared validity window |
| `max_uses` | custody `max_uses`, required to equal `1` |
| `max_provider_attempts` | dispatch `max_attempts`, then custody `max_provider_attempts` |
| verified `issuer_policy_ref`, `rotation_policy_ref` metadata | exact `ConfiguredVerifierBundle` policy references |

Baton must derive dispatch and custody views from the same immutable verified
outcome. It must not invoke independent verifiers for those views.
The runtime's enabled connectors are a ceiling: a verified authorization may
narrow to a non-empty subset, but it cannot authorize any connector outside
that runtime set.

The canonical Baton request fingerprint binds dispatch ID, workflow/operation
ID, channel, opaque recipient reference, opaque payload reference, and
idempotency key. The later-acquired dispatch claim ID remains outside the
envelope and is enforced by Baton's durable active-claim journal and
authorization ledger.

## Runtime Consumption

This verifier only accepts a signed authorization. It does not consume it,
track provider attempts, or grant a grace interval beyond the strict UTC
validity window. Baton must revalidate the immutable verified authorization at
every provider attempt and use its durable authorization ledger to atomically
reject a consumed authorization, an exhausted attempt budget, an expired
authorization, or a revoked issuer/rotation policy. An outage or unknown
ledger/policy state must fail closed. The 15-minute hard lifetime bounds the
window in which a non-renewed authorization can remain eligible.

## Remaining Production Blockers

1. A concrete trusted Signet verifier implementation that enforces approved
   issuer and rotation policy.
2. Key-free executable proof of the Signet envelope verifier and Baton mapping.
3. Baton's shared highly available journal, consumption ledger, audit,
   notification, provider-attempt state, and per-attempt revalidation.
4. Approved custody-internal provider executor and provider idempotency.

The generic `signet.cap.v1` financial envelope must not be adapted into this
contract.
