# Claude Desktop Integration

Signet works as an MCP (Model Context Protocol) server that Claude Desktop can connect to directly. Once configured, Claude can store data in your vault, query it, generate proofs, and issue scoped capability tokens on your behalf.

## Prerequisites

Build and install Signet:

```bash
cargo install --git https://github.com/jmcentire/signet.git signet
```

Initialize your vault (creates keypair, config, and storage):

```bash
signet init
```

## Configure Claude Desktop

Edit your Claude Desktop configuration file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Linux**: `~/.config/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

Add the Signet MCP server:

```json
{
  "mcpServers": {
    "signet": {
      "command": "signet",
      "args": ["serve"]
    }
  }
}
```

Restart Claude Desktop. Signet will appear in the MCP tools list.

## Available MCP Tools

| Tool | Description |
|------|-------------|
| `store_data` | Store a labeled value in your vault at a specified tier |
| `list_data` | List stored data with optional tier filter (Tier 3 values masked) |
| `query` | Query vault data with context-aware responses |
| `get_proof` | Generate a cryptographic proof for an attribute |
| `request_capability` | Issue a scoped capability token (SPL format) |
| `negotiate_context` | Negotiate disclosure scope with external agents |
| `check_status` | Check vault and agent status |

## Example Interactions

**Storing data**:
> "Store my age as 29 in tier 1"

Claude calls `store_data` with `{ "label": "age", "value": "29", "tier": 1 }`.

**Querying**:
> "What do you know about me?"

Claude calls `list_data` to enumerate stored facts.

**Generating proofs**:
> "Prove I'm over 21 to shop.example.com"

Claude calls `get_proof` with `{ "attribute": "age_over_21", "domain": "shop.example.com" }`.

**Issuing capabilities**:
> "Give me a one-time payment token for up to $150 on amazon.com"

Claude calls `request_capability` with `{ "domain": "amazon.com", "max_amount": 150, "purpose": "purchase", "one_time": true }`.

## HTTP Mode

For remote access or service verification, run in HTTP mode:

```bash
signet serve --transport http --bind 0.0.0.0 --port 3000
```

Endpoints:
- `POST /mcp` -- JSON-RPC proxy (same protocol as stdio)
- `POST /verify` -- Verify a proof: `{ "proof": "...", "claim": { "attribute": "age_over_21", "value": true } }`
- `GET /health` -- Server info and signet ID

## Data Tiers

| Tier | Access | Examples |
|------|--------|----------|
| 1 | Agent answers freely with proofs | Age, preferences, public profile |
| 2 | Agent reasons internally, exports conclusions only | Purchase history, context |
| 3 | Requires explicit user authorization | Payment cards, identity docs, medical |

## CLI Equivalents

Everything Claude does via MCP can also be done from the command line:

```bash
signet store --tier 1 --label "age" --value "29"
signet store --tier 1 --label "name" --value "Alice Nakamoto"
signet store --tier 3 --label "credit_card" --value "4111-1111-1111-1111"
signet list
signet list --tier 1
signet capability --domain amazon.com --max-amount 150 --purpose purchase --one-time
signet vault-status
signet audit
```

## Troubleshooting

**"vault not initialized"**: Run `signet init` first.

**Claude doesn't show Signet tools**: Verify the config path is correct and restart Claude Desktop. Check that `signet serve` works from your terminal.

**"SPL mint failed"**: The vault signing key may be corrupted. Re-initialize with `signet init`.

**Verbose logging**: Run `signet serve -v` to see debug output on stderr.
