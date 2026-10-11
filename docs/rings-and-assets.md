# Rings, rules and assets

Local implementation: `crates/signet/src/authority/rings/`. The native owner service now commits passkeys and ring management in one JSON CAS aggregate and has synthetic service-level tests. The static owner preview remains fictional; the later native forms/HTTP path still need browser, concurrency and independent review. Provider adapters and isolated execution are absent. See [prototype status](prototype-status.md).

A new account has exactly the zero-permissions ring, no rules, no assets and no active assignments. Vacation, replenishment and work-API examples load only on explicit request in the preview. They are not account defaults.

- A **rule** is a versioned record containing structured conditions: spend, share selected fields, or invoke approved credential operations.
- An **asset** is a separate versioned record with kind, provider, account label, opaque capability reference, supported operations and interaction mode. It contains no PAN, password, API key or identity document.
- A **ring** binds exact asset and rule versions. Editing a referenced record invalidates the old binding. Creating a ring never activates it.
- A **delegation** binds a worker's signing key and task to approved ring versions, currency, aggregate budget, operation count, expiry and bounded swaps. An activation has its own explicit deadline. Swapping cannot extend the first activation deadline. Completion or expiry ends new authority; no automatic renewal.

Owner management, worker requests and executor quotes have separate signing domains and pinned roles. Mandatory global restrictions still apply. A worker cannot authorize a new ring, enlarge its own scope, undo completion or renew itself. Revocation stops new actions; it cannot erase an operation already dispatched.

Reservations count against task and optional shared budgets atomically in the same aggregate. Card/ring swaps cannot reset counters. Success and unknown outcomes retain the reservation; only a definitive failure before execution releases the amount. Operation counts do not reset. Quote IDs cannot be reused. Reports are idempotent for identical outcomes; a provider receipt cannot be attached to two reservations.

A reservation response includes `dispatch_before`: the earliest quote, task or activation expiry. A trusted executor must enforce that deadline, use the original execution/idempotency key and reconcile an uncertain outcome. It must never reinterpret a historical receipt as current permission. `CommittedNow` alone can initiate fresh dispatch. `Recovered` means lookup/reconciliation only—even when its historical output says `reserved`.

Rules can authorize credential **use** without reveal/export/rotation. Safe operation names and enforcement belong to the adapter; a name is not security. Interactive provider mode requires an executor-signed confirmation attestation, which is not independent verification of an Apple, Google or other provider authorization. No provider is live in this slice.

Restoring earlier policy content means a newly approved, monotonically newer record. It does not restore the entire historical authority aggregate, spent grants, task budgets, nonces or receipts. Storage history is available for inspection, not execution.
