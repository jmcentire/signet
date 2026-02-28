use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::{error, info};

use signet::{
    handle_request, initialize_root, shutdown_root, JsonRpcRequest, RootConfig, RootError,
};

/// Signet: Personal Sovereign Agent Stack
///
/// Your vault is the crown, your agent is the steward,
/// external agents are petitioners.
#[derive(Parser, Debug)]
#[command(name = "signet", version, about, long_about = None)]
struct Cli {
    /// Path to config file
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialize the vault and create default configuration
    Init {
        /// Directory for the vault data store
        #[arg(long)]
        vault_path: Option<PathBuf>,

        /// Data directory for Signet state
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },

    /// Start the MCP server
    Serve {
        /// Transport type: stdio or http
        #[arg(long, default_value = "stdio")]
        transport: String,

        /// Bind address for HTTP transport
        #[arg(long, default_value = "127.0.0.1")]
        bind: String,

        /// Port for HTTP transport
        #[arg(long, default_value = "3000")]
        port: u16,
    },

    /// Show vault status
    VaultStatus,

    /// Show recent audit log entries
    Audit {
        /// Maximum number of entries to display
        #[arg(short, long, default_value = "20")]
        limit: usize,
    },
}

fn init_tracing(verbose: bool) {
    use tracing_subscriber::EnvFilter;

    let filter = if verbose {
        EnvFilter::new("signet=debug,signet_vault=debug,signet_policy=debug")
    } else {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("signet=info"))
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

fn load_config(path: Option<&PathBuf>) -> Result<RootConfig, RootError> {
    match path {
        Some(p) => RootConfig::load(p),
        None => {
            let default_path = RootConfig::default_config_path();
            RootConfig::load(&default_path)
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    let result = run(cli).await;
    if let Err(e) = result {
        error!("{}", e);
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), RootError> {
    match cli.command {
        Commands::Init {
            vault_path,
            data_dir,
        } => cmd_init(cli.config.as_ref(), vault_path, data_dir).await,
        Commands::Serve {
            transport,
            bind,
            port,
        } => cmd_serve(cli.config.as_ref(), &transport, &bind, port).await,
        Commands::VaultStatus => cmd_vault_status(cli.config.as_ref()).await,
        Commands::Audit { limit } => cmd_audit(cli.config.as_ref(), limit).await,
    }
}

async fn cmd_init(
    config_path: Option<&PathBuf>,
    vault_path: Option<PathBuf>,
    data_dir: Option<PathBuf>,
) -> Result<(), RootError> {
    let mut config = load_config(config_path)?;

    if let Some(vp) = vault_path {
        config.vault_path = vp;
    }
    if let Some(dd) = data_dir {
        config.data_dir = dd;
    }

    info!("initializing signet");

    let state = initialize_root(config.clone())?;

    // Save configuration for future use
    let save_path = config_path
        .cloned()
        .unwrap_or_else(RootConfig::default_config_path);
    config.save(&save_path)?;

    println!("Signet initialized successfully.");
    println!("  Vault path: {}", state.config.vault_path.display());
    println!("  Data dir:   {}", state.config.data_dir.display());
    println!("  Config:     {}", save_path.display());

    Ok(())
}

async fn cmd_serve(
    config_path: Option<&PathBuf>,
    transport: &str,
    bind: &str,
    port: u16,
) -> Result<(), RootError> {
    let mut config = load_config(config_path)?;

    // Override transport from CLI flags
    config.mcp.transport = match transport {
        "http" => signet::Transport::Http {
            bind: bind.to_string(),
            port,
        },
        _ => signet::Transport::Stdio,
    };

    let mut state = initialize_root(config)?;

    match &state.config.mcp.transport {
        signet::Transport::Stdio => {
            info!("starting MCP server on stdio");
            println!("Signet MCP server running on stdio. Send JSON-RPC requests via stdin.");

            // Read JSON-RPC requests from stdin line by line
            let stdin = tokio::io::stdin();
            let reader = tokio::io::BufReader::new(stdin);

            use tokio::io::AsyncBufReadExt;
            let mut lines = reader.lines();

            while let Ok(Some(line)) = lines.next_line().await {
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }

                match serde_json::from_str::<JsonRpcRequest>(&line) {
                    Ok(request) => {
                        let response = handle_request(&state, &request);
                        let response_json = serde_json::to_string(&response)
                            .unwrap_or_else(|_| {
                                r#"{"jsonrpc":"2.0","error":{"code":-32603,"message":"serialization failed"},"id":null}"#.to_string()
                            });
                        println!("{}", response_json);
                    }
                    Err(e) => {
                        let error_resp = serde_json::json!({
                            "jsonrpc": "2.0",
                            "error": {
                                "code": -32700,
                                "message": format!("parse error: {}", e)
                            },
                            "id": null
                        });
                        println!("{}", error_resp);
                    }
                }
            }
        }
        signet::Transport::Http { bind, port } => {
            info!(bind = %bind, port = %port, "HTTP transport selected");
            println!(
                "Signet MCP server would start on http://{}:{} (not yet implemented)",
                bind, port
            );
            println!("Use stdio transport for now: signet serve --transport stdio");
        }
    }

    shutdown_root(&mut state)?;
    Ok(())
}

async fn cmd_vault_status(config_path: Option<&PathBuf>) -> Result<(), RootError> {
    let config = load_config(config_path)?;
    let state = initialize_root(config)?;

    let request = JsonRpcRequest {
        jsonrpc: "2.0".into(),
        method: "vault/status".into(),
        params: None,
        id: serde_json::json!(1),
    };

    let response = handle_request(&state, &request);

    if let Some(result) = &response.result {
        println!("Vault Status:");
        println!(
            "  Path:        {}",
            result["vault_path"].as_str().unwrap_or("unknown")
        );
        println!(
            "  Initialized: {}",
            result["initialized"].as_bool().unwrap_or(false)
        );

        if let Some(tiers) = result.get("tiers") {
            println!("  Tiers:");
            if let Some(t1) = tiers.get("tier1") {
                println!(
                    "    Tier 1 ({}): {} items",
                    t1["description"].as_str().unwrap_or(""),
                    t1["count"].as_u64().unwrap_or(0)
                );
            }
            if let Some(t2) = tiers.get("tier2") {
                println!(
                    "    Tier 2 ({}): {} items",
                    t2["description"].as_str().unwrap_or(""),
                    t2["count"].as_u64().unwrap_or(0)
                );
            }
            if let Some(t3) = tiers.get("tier3") {
                println!(
                    "    Tier 3 ({}): {} items",
                    t3["description"].as_str().unwrap_or(""),
                    t3["count"].as_u64().unwrap_or(0)
                );
            }
        }
    } else if let Some(err) = &response.error {
        eprintln!("Error: {} (code {})", err.message, err.code);
    }

    let _ = std::fs::remove_dir_all(&state.config.data_dir);
    Ok(())
}

async fn cmd_audit(config_path: Option<&PathBuf>, limit: usize) -> Result<(), RootError> {
    let config = load_config(config_path)?;
    let state = initialize_root(config)?;

    let request = JsonRpcRequest {
        jsonrpc: "2.0".into(),
        method: "audit/list".into(),
        params: Some(serde_json::json!({ "limit": limit })),
        id: serde_json::json!(1),
    };

    let response = handle_request(&state, &request);

    if let Some(result) = &response.result {
        let total = result["total"].as_u64().unwrap_or(0);
        println!("Audit Log ({} entries):", total);

        if let Some(entries) = result["entries"].as_array() {
            if entries.is_empty() {
                println!("  (no entries)");
            }
            for entry in entries {
                println!("  {}", entry);
            }
        }
    } else if let Some(err) = &response.error {
        eprintln!("Error: {} (code {})", err.message, err.code);
    }

    let _ = std::fs::remove_dir_all(&state.config.data_dir);
    Ok(())
}
