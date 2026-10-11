use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::{error, info};

use signet::{
    handle_request, initialize_root, shutdown_root, JsonRpcRequest, RootConfig, RootError,
};
use signet_mcp::VaultAccess;

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
    /// Read-only MCP product preview; no vault, credentials, rule mutations, or purchases
    PreviewServe,
    /// Static fictional owner-app preview; no credentials, signer, or authority endpoints
    OwnerPreview {
        #[arg(long, default_value_t = 4322)]
        port: u16,
    },
    /// Isolated owner approval app plus signed HTTP/MCP adapters; binds loopback only
    OwnerServe {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        trust_config: PathBuf,
        #[arg(long)]
        owner_config: PathBuf,
        /// Existing private 32-byte binary seed; never passed to the model or browser
        #[arg(long)]
        owner_key_file: PathBuf,
        #[arg(long, default_value_t = 4322)]
        port: u16,
    },
    /// Native JSON owner service backed by private R2; never initializes missing state
    OwnerNativeServe {
        #[arg(long)]
        owner_config: PathBuf,
        #[arg(long)]
        user_hash: String,
        #[arg(long)]
        node: PathBuf,
        #[arg(long)]
        r2_bridge: PathBuf,
        #[arg(
            long,
            conflicts_with = "kms_version",
            required_unless_present = "kms_version"
        )]
        owner_key_file: Option<PathBuf>,
        #[arg(long, requires_all=["kms_public_key", "kms_bridge"])]
        kms_version: Option<String>,
        #[arg(long)]
        kms_public_key: Option<String>,
        #[arg(long)]
        kms_bridge: Option<PathBuf>,
        #[arg(long, default_value = "127.0.0.1")]
        bind: std::net::IpAddr,
        #[arg(long, default_value_t = 4322)]
        port: u16,
    },
    /// Explicit operator-only R2 bootstrap; no asset secrets or signing keys created
    OwnerNativeInit {
        #[arg(long)]
        owner_config: PathBuf,
        #[arg(long)]
        trust_config: PathBuf,
        #[arg(long)]
        restrictions: PathBuf,
        #[arg(long)]
        user_hash: String,
        #[arg(long)]
        node: PathBuf,
        #[arg(long)]
        r2_bridge: PathBuf,
    },
    /// Operator-only bootstrap using externally provisioned public keys (no private keys)
    AuthorityInit {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        trust_config: PathBuf,
    },
    /// Signed agent-neutral authority protocol; requires an isolated trusted service account
    AuthorityServe {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        trust_config: PathBuf,
        /// Wrap the signed authority contract in MCP tools protocol
        #[arg(long)]
        mcp: bool,
    },
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

    /// Store data in the vault
    Store {
        /// Data tier: 1=freely provable, 2=agent-internal, 3=capability-gated
        #[arg(long)]
        tier: u8,

        /// Label for the data
        #[arg(long)]
        label: String,

        /// Value to store
        #[arg(long)]
        value: String,
    },

    /// List stored data
    List {
        /// Optional tier filter (1, 2, or 3)
        #[arg(long)]
        tier: Option<u8>,
    },

    /// Request capability issuance (disabled until a custody-controlled issuer is configured)
    Capability {
        /// Domain the capability is scoped to
        #[arg(long)]
        domain: String,

        /// Maximum amount allowed
        #[arg(long)]
        max_amount: Option<u64>,

        /// Purpose of the capability
        #[arg(long)]
        purpose: String,

        /// One-time use (requires a consumption ledger before issuance is enabled)
        #[arg(long)]
        one_time: bool,
    },

    /// Show vault status
    VaultStatus,

    /// Show recent audit log entries
    Audit {
        /// Maximum number of entries to display
        #[arg(short, long, default_value = "20")]
        limit: usize,
    },

    /// Manage authority-issued credentials
    Credential {
        #[command(subcommand)]
        action: CredentialAction,
    },
}

#[derive(Subcommand, Debug)]
enum CredentialAction {
    /// List credentials (pending offers, accepted, revoked)
    List {
        /// Filter by authority public key (hex)
        #[arg(long)]
        authority: Option<String>,
        /// Filter by status (pending, accepted, rejected, expired, revoked)
        #[arg(long)]
        status: Option<String>,
    },

    /// Accept a pending authority offer
    Accept {
        /// Offer ID to accept
        offer_id: String,
        /// Review offer details before accepting
        #[arg(long)]
        review: bool,
    },

    /// Reject a pending authority offer
    Reject {
        /// Offer ID to reject
        offer_id: String,
        /// Reason for rejection
        #[arg(long)]
        reason: Option<String>,
    },

    /// Show credential details
    Show {
        /// Credential or offer ID
        id: String,
    },

    /// Revoke a credential
    Revoke {
        /// Credential ID to revoke
        credential_id: String,
        /// Reason for revocation
        #[arg(long)]
        reason: Option<String>,
    },

    /// Request a credential refresh from the authority
    Refresh {
        /// Credential ID to refresh
        credential_id: String,
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
        .with_writer(std::io::stderr)
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
        Commands::PreviewServe => cmd_preview_serve().await,
        Commands::OwnerPreview { port } => {
            serve_owner_router(signet::authority::owner::http::preview_router(), port).await
        }
        Commands::OwnerServe {
            database,
            trust_config,
            owner_config,
            owner_key_file,
            port,
        } => {
            use signet::authority::{
                owner::{file_signer, http, OwnerConfig, OwnerService},
                Authority,
            };
            let run = || -> signet::authority::Result<_> {
                let bytes = std::fs::read(&owner_config)?;
                if bytes.len() > signet::authority::MAX_MESSAGE {
                    return Err(signet::authority::AuthorityError::Rejected(
                        "owner config exceeds 64 KiB",
                    ));
                }
                let config: OwnerConfig = serde_json::from_slice(&bytes)?;
                let trust = authority_config(&trust_config).map_err(|_| {
                    signet::authority::AuthorityError::Rejected("invalid trust config")
                })?;
                let authority = Authority::open(&database, trust)?;
                OwnerService::open(authority, file_signer::load(&owner_key_file)?, config)
            };
            let owner = run().map_err(|e| RootError::Internal(e.to_string()))?;
            eprintln!("Owner service: {}. Keep this process, signer, configuration and database isolated from agents.",owner.origin());
            serve_owner_router(http::router(owner), port).await
        }
        Commands::OwnerNativeInit {
            owner_config,
            trust_config,
            restrictions,
            user_hash,
            node,
            r2_bridge,
        } => {
            use signet::authority::{
                object_store::r2::{NodeBridge, R2},
                owner::{native::NativeOwnerService, OwnerConfig},
                rings::Restrictions,
            };
            let config: OwnerConfig = serde_json::from_slice(&std::fs::read(owner_config)?)
                .map_err(|e| RootError::Internal(e.to_string()))?;
            let limits: Restrictions = serde_json::from_slice(&std::fs::read(restrictions)?)
                .map_err(|e| RootError::Internal(e.to_string()))?;
            let store =
                R2(NodeBridge::new(node, r2_bridge)
                    .map_err(|e| RootError::Internal(e.to_string()))?);
            NativeOwnerService::initialize(
                Box::new(store),
                user_hash,
                config,
                authority_config(&trust_config)?,
                limits,
            )
            .map_err(|e| RootError::Internal(e.to_string()))?;
            println!(
                "Native owner state initialized. No assets, permissions or signing keys created."
            );
            Ok(())
        }
        Commands::OwnerNativeServe {
            owner_config,
            user_hash,
            node,
            r2_bridge,
            owner_key_file,
            kms_version,
            kms_public_key,
            kms_bridge,
            bind,
            port,
        } => {
            use signet::authority::{
                object_store::r2::{NodeBridge, R2},
                owner::{
                    cloud_kms::{KmsSigner, NodeKmsTransport},
                    file_signer, http,
                    native::NativeOwnerService,
                    OwnerConfig,
                },
            };
            let config: OwnerConfig = serde_json::from_slice(&std::fs::read(owner_config)?)
                .map_err(|e| RootError::Internal(e.to_string()))?;
            let signer: Box<dyn signet_core::Signer> = if let Some(path) = owner_key_file {
                file_signer::load(&path).map_err(|e| RootError::Internal(e.to_string()))?
            } else {
                let key: [u8; 32] = hex::decode(kms_public_key.unwrap_or_default())
                    .map_err(|_| RootError::Internal("invalid pinned KMS public key".into()))?
                    .try_into()
                    .map_err(|_| {
                        RootError::Internal("invalid pinned KMS public key length".into())
                    })?;
                Box::new(
                    KmsSigner::new(
                        NodeKmsTransport {
                            node: node.clone(),
                            script: kms_bridge
                                .ok_or_else(|| RootError::Internal("KMS helper required".into()))?,
                        },
                        kms_version.unwrap_or_default(),
                        key,
                    )
                    .map_err(|e| RootError::Internal(e.to_string()))?,
                )
            };
            let store =
                R2(NodeBridge::new(node, r2_bridge)
                    .map_err(|e| RootError::Internal(e.to_string()))?);
            let owner = NativeOwnerService::open(Box::new(store), user_hash, signer, config)
                .map_err(|e| RootError::Internal(e.to_string()))?;
            eprintln!("Native owner service: {}. Isolate signing identity and R2 credentials from agents.",owner.origin());
            let listener = tokio::net::TcpListener::bind((bind, port)).await?;
            axum::serve(listener, http::router(owner))
                .await
                .map_err(|e| RootError::Internal(e.to_string()))?;
            Ok(())
        }
        Commands::AuthorityInit {
            database,
            trust_config,
        } => {
            signet::authority::Authority::create(&database, authority_config(&trust_config)?)
                .map_err(|e| RootError::Internal(e.to_string()))?;
            println!("Authority database initialized; protect the service account and external owner signer.");
            Ok(())
        }
        Commands::AuthorityServe {
            database,
            trust_config,
            mcp,
        } => cmd_authority_serve(&database, &trust_config, mcp).await,
        Commands::Init {
            vault_path,
            data_dir,
        } => cmd_init(cli.config.as_ref(), vault_path, data_dir).await,
        Commands::Serve {
            transport,
            bind,
            port,
        } => cmd_serve(cli.config.as_ref(), &transport, &bind, port).await,
        Commands::Store { tier, label, value } => {
            cmd_store(cli.config.as_ref(), tier, &label, &value).await
        }
        Commands::List { tier } => cmd_list(cli.config.as_ref(), tier).await,
        Commands::Capability {
            domain,
            max_amount,
            purpose,
            one_time,
        } => cmd_capability(cli.config.as_ref(), &domain, max_amount, &purpose, one_time).await,
        Commands::VaultStatus => cmd_vault_status(cli.config.as_ref()).await,
        Commands::Audit { limit } => cmd_audit(cli.config.as_ref(), limit).await,
        Commands::Credential { action } => cmd_credential(cli.config.as_ref(), action).await,
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
    let transport = state.config.mcp.transport.clone();

    match transport {
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
            info!(bind = %bind, port = %port, "starting HTTP server");
            println!("Signet server starting on http://{}:{}", bind, port);

            let tenant_manager = if state.config.hosting_mode == signet::HostingMode::MultiTenant {
                Some(signet::multi_tenant::TenantManager::new())
            } else {
                None
            };
            let app_state = std::sync::Arc::new(signet::http::AppState {
                root: state,
                tenant_manager,
            });
            let app = signet::http::build_router(app_state);

            let addr = format!("{}:{}", bind, port);
            let listener = tokio::net::TcpListener::bind(&addr)
                .await
                .map_err(|e| RootError::Internal(format!("failed to bind {}: {}", addr, e)))?;

            axum::serve(listener, app)
                .await
                .map_err(|e| RootError::Internal(format!("HTTP server error: {}", e)))?;

            return Ok(());
        }
    }

    shutdown_root(&mut state)?;
    Ok(())
}

async fn cmd_store(
    config_path: Option<&PathBuf>,
    tier: u8,
    label: &str,
    value: &str,
) -> Result<(), RootError> {
    if !(1..=3).contains(&tier) {
        return Err(RootError::Config("tier must be 1, 2, or 3".into()));
    }

    let config = load_config(config_path)?;
    let state = initialize_root(config)?;

    let vault = state
        .vault_access
        .as_ref()
        .ok_or_else(|| RootError::Internal("vault not initialized".into()))?;

    let tier_enum = match tier {
        1 => signet_core::Tier::Tier1,
        2 => signet_core::Tier::Tier2,
        3 => signet_core::Tier::Tier3,
        _ => unreachable!(),
    };

    vault
        .put(label, tier_enum, value.as_bytes())
        .map_err(|e| RootError::Internal(format!("store failed: {}", e)))?;

    println!("Stored: {} = {} (tier {})", label, value, tier);
    Ok(())
}

async fn cmd_list(config_path: Option<&PathBuf>, tier_filter: Option<u8>) -> Result<(), RootError> {
    if let Some(t) = tier_filter {
        if !(1..=3).contains(&t) {
            return Err(RootError::Config("tier must be 1, 2, or 3".into()));
        }
    }

    let config = load_config(config_path)?;
    let state = initialize_root(config)?;

    let vault = state
        .vault_access
        .as_ref()
        .ok_or_else(|| RootError::Internal("vault not initialized".into()))?;

    let tier_enum = tier_filter.map(|t| match t {
        1 => signet_core::Tier::Tier1,
        2 => signet_core::Tier::Tier2,
        3 => signet_core::Tier::Tier3,
        _ => unreachable!(),
    });

    let entries = vault
        .list(tier_enum)
        .map_err(|e| RootError::Internal(format!("list failed: {}", e)))?;

    if entries.is_empty() {
        println!("No stored data.");
        return Ok(());
    }

    println!("{:<20} {:<6} {:<30}", "LABEL", "TIER", "STORED AT");
    println!("{}", "-".repeat(56));
    for entry in &entries {
        let tier_n = match entry.tier {
            signet_core::Tier::Tier1 => 1,
            signet_core::Tier::Tier2 => 2,
            signet_core::Tier::Tier3 => 3,
        };
        let value_display = if entry.tier == signet_core::Tier::Tier3 {
            "[REQUIRES GRANT]".to_string()
        } else {
            match vault.get(&entry.label, entry.tier) {
                Ok(Some(data)) => String::from_utf8_lossy(&data).to_string(),
                _ => "[error]".to_string(),
            }
        };
        println!("{:<20} {:<6} {}", entry.label, tier_n, value_display);
    }
    println!("\n{} entries total", entries.len());

    Ok(())
}

async fn cmd_capability(
    _config_path: Option<&PathBuf>,
    _domain: &str,
    _max_amount: Option<u64>,
    _purpose: &str,
    _one_time: bool,
) -> Result<(), RootError> {
    Err(RootError::Internal(
        "capability issuance requires a configured custody-controlled issuer".into(),
    ))
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

    Ok(())
}

// ---------------------------------------------------------------------------
// Credential subcommands
// ---------------------------------------------------------------------------

/// Storage label prefix for credential offers stored in the vault
const CRED_OFFER_PREFIX: &str = "cred:offer:";
/// Storage label prefix for accepted credentials
const CRED_ACCEPTED_PREFIX: &str = "cred:accepted:";
/// Storage label prefix for credential status
const CRED_STATUS_PREFIX: &str = "cred:status:";

async fn cmd_credential(
    config_path: Option<&PathBuf>,
    action: CredentialAction,
) -> Result<(), RootError> {
    match action {
        CredentialAction::List { authority, status } => {
            cmd_cred_list(config_path, authority, status).await
        }
        CredentialAction::Accept { offer_id, review } => {
            cmd_cred_accept(config_path, &offer_id, review).await
        }
        CredentialAction::Reject { offer_id, reason } => {
            cmd_cred_reject(config_path, &offer_id, reason).await
        }
        CredentialAction::Show { id } => cmd_cred_show(config_path, &id).await,
        CredentialAction::Revoke {
            credential_id,
            reason,
        } => cmd_cred_revoke(config_path, &credential_id, reason).await,
        CredentialAction::Refresh { credential_id } => {
            cmd_cred_refresh(config_path, &credential_id).await
        }
    }
}

async fn cmd_cred_list(
    config_path: Option<&PathBuf>,
    authority_filter: Option<String>,
    status_filter: Option<String>,
) -> Result<(), RootError> {
    let config = load_config(config_path)?;
    let state = initialize_root(config)?;

    let vault = state
        .vault_access
        .as_ref()
        .ok_or_else(|| RootError::Internal("vault not initialized".into()))?;

    let entries = vault
        .list(None)
        .map_err(|e| RootError::Internal(format!("list failed: {}", e)))?;

    let cred_entries: Vec<_> = entries
        .iter()
        .filter(|e| {
            e.label.starts_with(CRED_OFFER_PREFIX) || e.label.starts_with(CRED_ACCEPTED_PREFIX)
        })
        .collect();

    if cred_entries.is_empty() {
        println!("No credentials found.");
        return Ok(());
    }

    println!(
        "{:<36} {:<12} {:<20} {:<20}",
        "ID", "STATUS", "TYPE", "AUTHORITY"
    );
    println!("{}", "-".repeat(88));

    for entry in &cred_entries {
        let data = vault
            .get(&entry.label, entry.tier)
            .map_err(|e| RootError::Internal(format!("get failed: {}", e)))?;

        if let Some(data) = data {
            let is_offer = entry.label.starts_with(CRED_OFFER_PREFIX);
            let id = if is_offer {
                entry
                    .label
                    .strip_prefix(CRED_OFFER_PREFIX)
                    .unwrap_or(&entry.label)
            } else {
                entry
                    .label
                    .strip_prefix(CRED_ACCEPTED_PREFIX)
                    .unwrap_or(&entry.label)
            };

            let (status_str, cred_type, authority_pk) = if is_offer {
                if let Ok(offer) =
                    serde_json::from_slice::<signet_cred::authority::AuthorityOffer>(&data)
                {
                    let auth_short = if offer.key.authority_pubkey.len() > 16 {
                        format!("{}...", &offer.key.authority_pubkey[..16])
                    } else {
                        offer.key.authority_pubkey.clone()
                    };
                    ("pending".to_string(), offer.credential_type, auth_short)
                } else {
                    continue;
                }
            } else if let Ok(accepted) =
                serde_json::from_slice::<signet_cred::authority::AcceptedCredential>(&data)
            {
                let auth_short = if accepted.offer.key.authority_pubkey.len() > 16 {
                    format!("{}...", &accepted.offer.key.authority_pubkey[..16])
                } else {
                    accepted.offer.key.authority_pubkey.clone()
                };
                (
                    "accepted".to_string(),
                    accepted.offer.credential_type,
                    auth_short,
                )
            } else {
                continue;
            };

            if let Some(ref auth) = authority_filter {
                if !authority_pk.contains(auth) {
                    continue;
                }
            }
            if let Some(ref status) = status_filter {
                if status_str != *status {
                    continue;
                }
            }

            println!(
                "{:<36} {:<12} {:<20} {:<20}",
                id, status_str, cred_type, authority_pk
            );
        }
    }

    Ok(())
}

async fn cmd_cred_accept(
    config_path: Option<&PathBuf>,
    offer_id: &str,
    review: bool,
) -> Result<(), RootError> {
    let config = load_config(config_path)?;
    let state = initialize_root(config)?;

    let vault = state
        .vault_access
        .as_ref()
        .ok_or_else(|| RootError::Internal("vault not initialized".into()))?;

    let signer = state
        .signer
        .as_ref()
        .ok_or_else(|| RootError::Internal("vault signer not initialized".into()))?;

    let offer_label = format!("{}{}", CRED_OFFER_PREFIX, offer_id);
    let offer_data = vault
        .get(&offer_label, signet_core::Tier::Tier2)
        .map_err(|e| RootError::Internal(format!("get failed: {}", e)))?
        .ok_or_else(|| RootError::Internal(format!("offer {} not found", offer_id)))?;

    let offer: signet_cred::authority::AuthorityOffer = serde_json::from_slice(&offer_data)
        .map_err(|e| RootError::Serialization(format!("failed to decode offer: {}", e)))?;

    if review {
        println!("Authority Offer: {}", offer_id);
        println!("  Authority: {}", offer.key.authority_pubkey);
        println!("  Type:      {}", offer.credential_type);
        println!("  Offered:   {}", offer.offered_at);
        println!("  Expires:   {}", offer.offer_expires_at);
        println!("  Claims:");
        for (k, v) in &offer.claims {
            println!("    {}: {:?}", k, v);
        }
        if let Some(ref decay) = offer.decay {
            println!("  Decay:");
            if let Some(ref ttl) = decay.ttl {
                println!("    TTL: {} seconds", ttl.expires_after_seconds);
            }
            if let Some(ref uc) = decay.use_count {
                println!("    Max uses: {}", uc.max_uses);
            }
            if let Some(ref rl) = decay.rate_limit {
                println!(
                    "    Rate limit: {}/{}s (grace: {})",
                    rl.max_per_window, rl.window_seconds, rl.grace
                );
            }
            if !decay.phases.is_empty() {
                println!("    Phases: {}", decay.phases.len());
            }
        }
        if !offer.authority_chain.is_empty() {
            println!("  Authority chain:");
            for link in &offer.authority_chain {
                let pk_display = if link.signer_pubkey.len() > 16 {
                    &link.signer_pubkey[..16]
                } else {
                    &link.signer_pubkey
                };
                println!("    {} ({}...)", link.signer_role, pk_display);
            }
        }
        println!();
    }

    let accepted = signet_cred::authority::accept_offer(&offer, signer)
        .map_err(|e| RootError::Internal(format!("accept failed: {}", e)))?;

    let accepted_label = format!(
        "{}{}",
        CRED_ACCEPTED_PREFIX,
        signet_cred::authority::generate_offer_id(&offer)
    );
    let accepted_data = serde_json::to_vec(&accepted).map_err(|e| {
        RootError::Serialization(format!("failed to encode accepted credential: {}", e))
    })?;
    vault
        .put(&accepted_label, signet_core::Tier::Tier2, &accepted_data)
        .map_err(|e| RootError::Internal(format!("store failed: {}", e)))?;

    println!("Credential accepted: {}", offer_id);
    println!("  Type: {}", offer.credential_type);
    println!("  Authority: {}", offer.key.authority_pubkey);

    Ok(())
}

async fn cmd_cred_reject(
    config_path: Option<&PathBuf>,
    offer_id: &str,
    reason: Option<String>,
) -> Result<(), RootError> {
    let config = load_config(config_path)?;
    let state = initialize_root(config)?;

    let vault = state
        .vault_access
        .as_ref()
        .ok_or_else(|| RootError::Internal("vault not initialized".into()))?;

    let status = signet_cred::authority::OfferStatus::Rejected {
        reason: reason.clone(),
    };
    let status_label = format!("{}{}", CRED_STATUS_PREFIX, offer_id);
    let status_data = serde_json::to_vec(&status)
        .map_err(|e| RootError::Serialization(format!("failed to encode status: {}", e)))?;
    vault
        .put(&status_label, signet_core::Tier::Tier2, &status_data)
        .map_err(|e| RootError::Internal(format!("store failed: {}", e)))?;

    println!("Offer rejected: {}", offer_id);
    if let Some(reason) = reason {
        println!("  Reason: {}", reason);
    }

    Ok(())
}

async fn cmd_cred_show(config_path: Option<&PathBuf>, id: &str) -> Result<(), RootError> {
    let config = load_config(config_path)?;
    let state = initialize_root(config)?;

    let vault = state
        .vault_access
        .as_ref()
        .ok_or_else(|| RootError::Internal("vault not initialized".into()))?;

    // Try offer first
    let offer_label = format!("{}{}", CRED_OFFER_PREFIX, id);
    if let Ok(Some(data)) = vault.get(&offer_label, signet_core::Tier::Tier2) {
        if let Ok(offer) = serde_json::from_slice::<signet_cred::authority::AuthorityOffer>(&data) {
            println!("Pending Offer: {}", id);
            println!("  Authority:   {}", offer.key.authority_pubkey);
            println!("  User:        {}", offer.key.user_signet_id);
            println!("  Type:        {}", offer.credential_type);
            println!("  Offered at:  {}", offer.offered_at);
            println!("  Expires at:  {}", offer.offer_expires_at);
            println!("  Claims:");
            for (k, v) in &offer.claims {
                println!("    {}: {:?}", k, v);
            }
            if let Some(ref decay) = offer.decay {
                println!("  Decay config: {:?}", decay);
            }
            if !offer.authority_chain.is_empty() {
                println!("  Chain: {} signers", offer.authority_chain.len());
            }
            return Ok(());
        }
    }

    // Try accepted
    let accepted_label = format!("{}{}", CRED_ACCEPTED_PREFIX, id);
    if let Ok(Some(data)) = vault.get(&accepted_label, signet_core::Tier::Tier2) {
        if let Ok(accepted) =
            serde_json::from_slice::<signet_cred::authority::AcceptedCredential>(&data)
        {
            println!("Accepted Credential: {}", id);
            println!("  Authority:   {}", accepted.offer.key.authority_pubkey);
            println!("  User:        {}", accepted.user_pubkey);
            println!("  Type:        {}", accepted.offer.credential_type);
            println!("  Accepted at: {}", accepted.accepted_at);
            println!("  Claims:");
            for (k, v) in &accepted.offer.claims {
                println!("    {}: {:?}", k, v);
            }
            if let Some(ref decay) = accepted.offer.decay {
                println!("  Decay config: {:?}", decay);
            }
            return Ok(());
        }
    }

    println!("Credential {} not found", id);
    Ok(())
}

async fn cmd_cred_revoke(
    config_path: Option<&PathBuf>,
    credential_id: &str,
    reason: Option<String>,
) -> Result<(), RootError> {
    let config = load_config(config_path)?;
    let state = initialize_root(config)?;

    let vault = state
        .vault_access
        .as_ref()
        .ok_or_else(|| RootError::Internal("vault not initialized".into()))?;

    let revocation = signet_cred::RevocationInfo {
        revoked_by: signet_cred::RevokedBy::User,
        revoked_at: chrono::Utc::now().to_rfc3339(),
        reason: reason.clone(),
    };
    let status_label = format!("{}{}", CRED_STATUS_PREFIX, credential_id);
    let status_data = serde_json::to_vec(&revocation)
        .map_err(|e| RootError::Serialization(format!("failed to encode revocation: {}", e)))?;
    vault
        .put(&status_label, signet_core::Tier::Tier2, &status_data)
        .map_err(|e| RootError::Internal(format!("store failed: {}", e)))?;

    println!("Credential revoked: {}", credential_id);
    if let Some(reason) = reason {
        println!("  Reason: {}", reason);
    }

    Ok(())
}

async fn cmd_cred_refresh(
    config_path: Option<&PathBuf>,
    credential_id: &str,
) -> Result<(), RootError> {
    let _config = load_config(config_path)?;

    println!("Refresh requested for credential: {}", credential_id);
    println!(
        "  The authority will be notified. Check back with 'signet credential show {}'.",
        credential_id
    );

    Ok(())
}

/// Separate preview transport: never initializes RootState or reads a config/vault.
async fn cmd_preview_serve() -> Result<(), RootError> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    let mut reader = tokio::io::BufReader::new(tokio::io::stdin());
    let mut output = tokio::io::stdout();
    let mut session = signet::preview::PreviewSession::default();
    loop {
        // A bounded line avoids accepting unbounded input from an MCP host.
        let mut line = Vec::new();
        loop {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                break;
            }
            let count = available
                .iter()
                .position(|b| *b == b'\n')
                .map_or(available.len(), |i| i + 1);
            if line.len() + count > 65536 {
                return Err(RootError::Internal("preview message exceeds 64 KiB".into()));
            }
            let ended = available[count - 1] == b'\n';
            line.extend_from_slice(&available[..count]);
            reader.consume(count);
            if ended {
                break;
            }
        }
        if line.is_empty() {
            break;
        }
        let text = String::from_utf8(line)
            .map_err(|_| RootError::Internal("preview message must be UTF-8".into()))?;
        if text.trim().is_empty() {
            continue;
        }
        if let Some(response) = session.handle(&text) {
            output.write_all(response.to_string().as_bytes()).await?;
            output.write_all(b"\n").await?;
            output.flush().await?;
        }
    }
    Ok(())
}

fn authority_config(
    path: &std::path::Path,
) -> Result<signet::authority::AuthorityConfig, RootError> {
    let bytes = std::fs::read(path)?;
    if bytes.len() > signet::authority::MAX_MESSAGE {
        return Err(RootError::Internal(
            "authority trust configuration exceeds 64 KiB".into(),
        ));
    }
    serde_json::from_slice(&bytes).map_err(|e| RootError::Internal(e.to_string()))
}

async fn cmd_authority_serve(
    database: &std::path::Path,
    trust_config: &std::path::Path,
    mcp: bool,
) -> Result<(), RootError> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    let authority = signet::authority::Authority::open(database, authority_config(trust_config)?)
        .map_err(|e| RootError::Internal(e.to_string()))?;
    let (mut authority, mut mcp_session) = if mcp {
        (
            None,
            Some(signet::authority::AuthorityMcpSession::new(authority)),
        )
    } else {
        (Some(authority), None)
    };
    let mut reader = tokio::io::BufReader::new(tokio::io::stdin());
    let mut output = tokio::io::stdout();
    loop {
        let mut line = Vec::new();
        loop {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                break;
            }
            let count = available
                .iter()
                .position(|b| *b == b'\n')
                .map_or(available.len(), |i| i + 1);
            if line.len() + count > signet::authority::MAX_MESSAGE {
                return Err(RootError::Internal(
                    "authority message exceeds 64 KiB".into(),
                ));
            }
            let ended = available[count - 1] == b'\n';
            line.extend_from_slice(&available[..count]);
            reader.consume(count);
            if ended {
                break;
            }
        }
        if line.is_empty() {
            break;
        }
        let response = if let Some(session) = &mut mcp_session {
            let text = std::str::from_utf8(&line)
                .map_err(|_| RootError::Internal("authority message must be UTF-8".into()))?;
            let Some(response) = session.handle(text) else {
                continue;
            };
            response
        } else {
            let result = serde_json::from_slice::<signet::authority::SignedMessage>(&line)
                .map_err(signet::authority::AuthorityError::from)
                .and_then(|message| {
                    authority
                        .as_mut()
                        .expect("raw transport authority")
                        .handle(&message)
                });
            match result {
                Ok(value) => serde_json::json!({"ok":true,"result":value}),
                Err(error) => serde_json::json!({"ok":false,"error":error.to_string()}),
            }
        };
        output.write_all(response.to_string().as_bytes()).await?;
        output.write_all(b"\n").await?;
        output.flush().await?;
    }
    Ok(())
}

async fn serve_owner_router(router: axum::Router, port: u16) -> Result<(), RootError> {
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await?;
    eprintln!(
        "Signet owner listener: http://localhost:{} (loopback only)",
        listener.local_addr()?.port()
    );
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
