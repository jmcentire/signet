# Evaluate Signet locally

Signet provides an authority-layer foundation for personal agents. This walkthrough
uses a separate development vault so a human or agent can inspect the CLI and MCP
surface with synthetic data. It does not enable real proofs or payments through MCP.

For everyday rule evaluation, start with the [read-only agent preview](agent-preview.md).
The walkthrough below explores the separate legacy vault runtime. Its direct
JSON-RPC methods are not a claim of complete standard MCP client interoperability.

## Install

Use Rust 1.88+ and Git:

```sh
cargo install --locked --git https://github.com/jmcentire/signet.git signet
signet --help
```

The locked source install is for this project; `cargo install signet` is not.

## Create an isolated development vault

In a POSIX shell, keep the variable in the same terminal for these commands:

```sh
signet_demo_dir="$(mktemp -d "${TMPDIR:-/tmp}/signet-demo.XXXXXX")"
signet --config "$signet_demo_dir/config.toml" init \
  --vault-path "$signet_demo_dir/vault" \
  --data-dir "$signet_demo_dir/state"
signet --config "$signet_demo_dir/config.toml" vault-status
signet --config "$signet_demo_dir/config.toml" store \
  --tier 1 --label demo_age --value 29
signet --config "$signet_demo_dir/config.toml" list --tier 1
signet --config "$signet_demo_dir/config.toml" audit
```

Expected: initialization reports the explicit paths; the list includes `demo_age`
with value `29`. Status and audit inspect their corresponding runtime surfaces.
An empty audit output is not proof that every operation has been logged. Do not
store real secrets in this evaluation or infer production key custody from it.

The temporary directory is disposable development state. Keep it while the MCP
client is running; a later OS cleanup may remove it. For a longer evaluation, use
a dedicated persistent development directory with the same explicit arguments.

## Connect an MCP client

Run `command -v signet` to find the executable and use the actual absolute paths
from your local setup. A client supporting local stdio servers can use this shape:

```json
{
  "mcpServers": {
    "signet": {
      "command": "/absolute/path/to/signet",
      "args": ["--config", "/absolute/path/to/config.toml", "serve"]
    }
  }
}
```

The paths above are placeholders to replace, not runnable defaults. MCP clients
may use different configuration wrappers; preserve their existing entries. See
[Claude Desktop setup](claude-desktop-setup.md) for one concrete host.

After connecting, inspect `tools/list`. Try `store_data` using only this synthetic
payload, then `list_data` with a Tier 1 filter:

```json
{ "label": "demo_age", "value": "29", "tier": 1 }
```

```json
{ "tier": 1 }
```

A tool being discoverable does not mean all its behavior is fully implemented.
[Read the implementation status](integration.md#implementation-status) before
trying proof, query, capability, or authorization flows.

## Troubleshoot

- **Executable not found:** use an absolute path in the client's config.
- **Wrong or empty vault:** check that the client and terminal use the same
  `--config` path, and that its vault/data directories still exist.
- **No tools:** restart the client after editing its configuration. Run
  `signet --config /absolute/path/to/config.toml serve` manually to check startup.
- **Capability denied or pending:** this is not a usable grant. Issuer wiring and
  the authorization lifecycle remain integration work; do not disable checks.

For implementation work, start with [the integration guide](integration.md).
