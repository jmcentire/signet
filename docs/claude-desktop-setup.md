# Connect a local MCP client

Signet's MCP interface is the connection surface beneath a personal agent. This
example uses Claude Desktop as a local stdio host; it is not an endorsement or
proof of complete platform integration. Read [current tool behavior](integration.md#implementation-status)
first: proof and query executors include placeholders and capability issuance
is not enabled.

For a standard MCP tools evaluation that does not open a vault, use
[preview-serve](agent-preview.md) instead. The legacy vault server has incomplete
MCP interoperability and enforcement wiring; the configuration below is a
candidate for development inspection, not a tested end-to-end host integration.

## Initialize a development vault

Follow [getting started](getting-started.md) to install the CLI and create a
separate config with synthetic data. Use `command -v signet` to locate the binary.
Keep the absolute config path printed by initialization.

## Configure the client

On macOS, Claude Desktop's configuration is normally at
`~/Library/Application Support/Claude/claude_desktop_config.json`; on Windows,
`%APPDATA%\Claude\claude_desktop_config.json`. Use the client's configuration UI
if your installation differs. Preserve all existing server entries.

Add an entry using your actual paths:

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

Restart the client, inspect its connected tools, and discover schemas with
`tools/list`. First try storing `demo_age` with string value `29` at Tier 1,
then listing Tier 1 data. The [walkthrough](getting-started.md) provides payloads.

## Interpret tool results correctly

| Tool | Meaning |
|---|---|
| `store_data`, `list_data` | Storage operations through the vault adapter. Use synthetic data. |
| `get_proof` | Current executor returns placeholder bytes, not a cryptographic proof. |
| `query` | Current Tier 1/Tier 2 responses are scaffolded. |
| `request_capability` | A denied or pending request is not a usable credential. |
| `negotiate_context` | Inspect the source and schema before relying on negotiation behavior. |
| `check_status` | Inspect pending request state; status alone does not constitute consent. |

## Local transport and troubleshooting

Use stdio for this evaluation. If testing HTTP, bind explicitly to loopback:

```sh
signet --config /absolute/path/to/config.toml serve --transport http --bind 127.0.0.1 --port 3000
```

Do not expose this development listener publicly. The authenticated middleware
and direct dispatch paths require integration review; HTTP availability is not
proof of complete authentication or policy enforcement.

If tools do not appear, confirm the executable/config paths and restart the
client. For CLI diagnostics use `signet --verbose --config /absolute/path/to/config.toml serve`.
Keep logs free of real personal data and credentials. For deeper work, read the
[integration guide](integration.md).
