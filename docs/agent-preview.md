# Read-only agent preview

A usable local MCP surface for exploring everyday permission rules, without
opening a vault, loading a config, issuing credentials, or making purchases.
It is deliberately separate from the legacy `signet serve` runtime.

## Run from this source checkout

```sh
cargo build --locked -p signet
./target/debug/signet preview-serve
```

`preview-serve` is added in this change. It is not available from the remote
installation command until this source revision is published. It uses
newline-delimited JSON-RPC over stdio; stdout contains protocol messages only.
Each process is a session. Messages are limited to 64 KiB. No HTTP listener,
account connection, persistent rule state, or authorization endpoint is created.

Example local MCP client entry (replace the binary path):

```json
{
  "mcpServers": {
    "signet-preview": {
      "command": "/absolute/path/to/signet/target/debug/signet",
      "args": ["preview-serve"]
    }
  }
}
```

An example using Muse Code's configuration shape is in
[examples/agents/muse-code-preview.json](../examples/agents/muse-code-preview.json).
It is prepared, not installed. Vendor-client connection tests are still required.

## Protocol

Initialize with a supported version (`2024-11-05`, `2025-03-26`, `2025-06-18`, or
`2025-11-25`), send `notifications/initialized`, then use `tools/list` and
`tools/call`. An unknown version receives the server's `2025-11-25` version;
the client must decide whether it supports that version. This is the small
stdio tools subset, not a claim to every optional MCP capability.

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"example-agent","version":"1"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
```

Tools return both a text content block and structured data. Tool validation errors
set `isError: true`; protocol errors use JSON-RPC errors. Notifications receive no
response. No tokens, signed grants or consent records are returned.

## `preview_purchase` — read-only

Use integer minor currency units for the **full** total (USD 1800 = $18). Exact
merchant identifiers and currency must match. `requirements_met`, categories,
rules and history are hypothetical caller inputs, never trusted evidence.

```json
{
  "jsonrpc": "2.0", "id": 3, "method": "tools/call",
  "params": {
    "name": "preview_purchase",
    "arguments": {
      "merchant": "amazon.com", "currency": "USD",
      "item_id": "cable-1", "category": "electronics",
      "total_minor": 1800, "requirements_met": true,
      "rules": {
        "merchant": "amazon.com", "currency": "USD", "limit_minor": 5000,
        "confirm_all": false, "confirm_categories": []
      }
    }
  }
}
```

Expected structured result includes `mode: "preview"`,
`outcome: "would_fit_rules"`, and **`authorizes_execution: false`**.
A $75 total yields `would_ask`. `confirm_all: true` or an `electronics`
confirmation category also yields `would_ask`. Unknown fields, including an
agent-supplied `approved` flag, are rejected.

For a reorder, supply `rules.recurring_baseline` with `item_id`, `total_minor`,
`history_ref`, `requirements_fingerprint`, and a `reorder` object with the matching
history reference and requirements fingerprint. Equal or lower totals can fit;
higher totals or missing/mismatched provenance ask. The preview neither verifies
historical provenance nor updates the supplied baseline. Discovery returns the
complete input schema.

## `preview_rule_change` — read-only

```json
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"preview_rule_change","arguments":{"operation":"add","rule_id":"electronics-confirm","proposed_rule":"Electronics purchases always require confirmation."}}}
```

For `edit`, add `expected_version` and the full `proposed_rule`. For `remove`,
identify `rule_id` and `expected_version` only. Every valid proposal returns
`requires_rule_management_grant` and `authorizes_execution: false`. No mutation
or owner authentication occurs. The request fingerprint helps compare preview
inputs; it is not a signature, nonce, canonical production grant or replay ledger.

## Trust boundary

This interface is useful for adapter development and deterministic product
examples. It must never gate live actions: the caller controls the hypothetical
rules. A production executor must load protected owner rules itself and verify
exact, single-use authority through a separate authenticated approval/commit
path. See the [required product contract](everyday-authority.md).
