# Everyday authority: intended product behavior

**Signet lets you tell your AI what it can do for you—and makes sure it listens.**
That is the product goal, not a claim that today's code already delivers the full
experience. Signet is for everyday people: set rules by talking, let an agent
handle ordinary tasks, approve exceptions, and change rules when wanted.

The website's interactive preview and the local `preview-serve` interface are
simulations. The Rust stack now also includes a separate [authenticated authority core](authority-service.md)
with durable rules, exact owner-signed grants, atomic replay protection and
receipt-backed baselines. The conversational approval app, isolated production
deployment and merchant execution adapters remain implementation work.

## Three kinds of permission

| Kind | Example | Intended meaning |
|---|---|---|
| Standing | “Don't spend more than $50 on Amazon without asking.” | Routine qualifying Amazon purchases at or below $50 total may proceed, subject to other rules and host confirmations. |
| Conditional | “Reorder the usual dog food. Find a better deal; otherwise pay the usual amount.” | Same approved item, pack, merchant and requirements; a cheaper or equal approved total is allowed. |
| Temporary action | “Approve this $75 desk lamp on Amazon once.” | One exact transaction exception. The standing $50 limit stays unchanged. |
| Temporary rule management | “Add this electronics-confirmation rule once.” | One exact add/edit/remove operation, separately authorized. No purchase authority is granted. |

The person may choose final confirmation for every purchase or allow actions
within rules where the host permits it. More restrictive requirements still
apply. Signet cannot suppress mandatory confirmations imposed by a host platform.

## Everyday examples

**Cable:** the agent finds a suitable $18 USB-C cable on Amazon. With a $50
standing ceiling, requirements met, and no stricter rule, it could proceed.
If the user selects final confirmation—or has an electronics-always-confirm
rule—it must ask first.

**Dog food:** an approved prior order establishes a fictional $46 total baseline.
The agent searches for a better deal. A $42 offer can qualify; if no better deal
exists, $46 can qualify too. A $49 offer requires review despite being below the
general $50 ceiling. A different pack, merchant, currency, or delivery condition
must not be treated as the established reorder.

**One-time exception:** approval identifies the desk lamp, Amazon, $75 total,
quantity, terms and exact action. It does not cover any transaction costing $75.
A subsequent change in item, price, merchant or terms needs fresh approval.

**Rule change:** the agent displays “Electronics purchases always require
confirmation” as proposed, not active. The authenticated owner confirms that exact
addition and grants temporary authority to add it once. Editing the Amazon limit
from $50 to $80 requires a separate exact edit of the identified rule and current
revision; purchase approval cannot perform that edit. Removal identifies the
existing rule and revision and also needs separate authority.

## Keep the usual price defensible

Use verified historical purchases, normalized currency, quantity/pack and total
price including required charges. Present the candidate baseline and require
explicit owner approval when establishing or changing it. Keep the history
reference and approved revision. Do not ratchet upward after an expensive
exception or silently replace it after a purchase. Missing or conflicting history
requires review. A better current price is an offer, not permission to change the
baseline. These provenance controls are not implemented by the preview. The authority core
requires a completed executor-authenticated receipt plus an exact owner-approved
rule mutation; real merchant provenance still depends on a trusted provider adapter.

## Enforcement architecture and current boundary

Separate **proposal**, **owner approval**, and **commit**. Agent-provided text,
`approved: true`, model inference, or an OAuth connection cannot confer authority.
Owner authentication and exact-change confirmation are both required.

A real grant must bind canonical action, owner, agent/client, merchant/resource,
exact arguments and financial total where relevant, expiry, policy revision and
a single-use nonce. Rule-management grants additionally bind operation type,
rule identifier, expected version, and exact proposed content. Add, edit and
remove are distinct scopes; none grants general future rule-management authority.

The trusted service must atomically consume grants and recheck policy at execution,
rejecting changed arguments, stale revisions, expired or revoked grants, replay,
unknown state, or service failure. Transactions need idempotency and reconciliation
for uncertain provider outcomes; a failed response must not trigger a duplicate
purchase. Protect rule storage and approval surfaces from agent mutation.

The system must define whether a recurring allowance is an explicit scoped
exception to a general spending limit. The preview treats an established reorder
as that separate allowance, while merchant/currency, other requirements and
confirmation rules still apply. Production rule composition requires explicit
owner-visible semantics, not implicit precedence chosen by a model.

The local core implements the signed-envelope and transactional portions of this
contract. Its [deployment gates](authority-service.md#remaining-production-gates)
remain material: the [passkey owner app](owner-approval.md) is implemented locally,
but protected deployment, real-device validation, trusted merchant execution and
provider reconciliation are not supplied by the website or a same-user CLI.

## Acceptance criteria for the full product

- Under-limit cable qualifies; wrong merchant, unmet requirements or required
  confirmation cannot qualify silently.
- Cheaper and usual-price reorders qualify; higher total or changed requirements ask.
- Purchase exceptions leave standing limits and recurring baselines unchanged.
- An agent cannot create, broaden or delete its own rule authority.
- Exact add/edit/remove grants are single-use and revision-bound; replay,
  cross-owner/client use, stale state and altered content fail closed.
- Users see readable active rules, pending proposals, approvals and outcomes.
- Every adapter states its coverage. Unmediated native tools remain outside Signet.

See [agent preview protocol](agent-preview.md), [implementation status](integration.md#implementation-status),
and [platform readiness](platform-readiness.md).

## Settled architecture and pending exception workflow

The complete intended design is recorded in [architecture](architecture.md): separate
rules/assets bound by rings, explicit worker/task scopes, zero initial permissions,
aggregate budgets, completion-or-expiry and current-state execution.

An agent may propose an exact exception and explain why, such as $5 more for dog
food this month. Rationale is not authority. One purchase, a bounded extra allowance
for a named month and a standing-rule edit require distinct approvals; no automatic
baseline increase or repeated allowance stacking. The monthly escalation workflow
is planned only. Existing one-time approvals do not implement that whole flow.
Further build is paused; see [status](prototype-status.md) and [open work](open-work.md).
