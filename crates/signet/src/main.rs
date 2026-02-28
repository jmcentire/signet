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

    /// Issue a scoped capability token
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

        /// One-time use (sealed token)
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
            let listener = tokio::net::TcpListener::bind(&addr).await.map_err(|e| {
                RootError::Internal(format!("failed to bind {}: {}", addr, e))
            })?;

            axum::serve(listener, app).await.map_err(|e| {
                RootError::Internal(format!("HTTP server error: {}", e))
            })?;

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

    let vault = state.vault_access.as_ref().ok_or_else(|| {
        RootError::Internal("vault not initialized".into())
    })?;

    let tier_enum = match tier {
        1 => signet_core::Tier::Tier1,
        2 => signet_core::Tier::Tier2,
        3 => signet_core::Tier::Tier3,
        _ => unreachable!(),
    };

    vault.put(label, tier_enum, value.as_bytes()).map_err(|e| {
        RootError::Internal(format!("store failed: {}", e))
    })?;

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

    let vault = state.vault_access.as_ref().ok_or_else(|| {
        RootError::Internal("vault not initialized".into())
    })?;

    let tier_enum = tier_filter.map(|t| match t {
        1 => signet_core::Tier::Tier1,
        2 => signet_core::Tier::Tier2,
        3 => signet_core::Tier::Tier3,
        _ => unreachable!(),
    });

    let entries = vault.list(tier_enum).map_err(|e| {
        RootError::Internal(format!("list failed: {}", e))
    })?;

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
    config_path: Option<&PathBuf>,
    domain: &str,
    max_amount: Option<u64>,
    purpose: &str,
    one_time: bool,
) -> Result<(), RootError> {
    let config = load_config(config_path)?;
    let state = initialize_root(config)?;

    let signer = state.signer.as_ref().ok_or_else(|| {
        RootError::Internal("vault signer not initialized".into())
    })?;

    let constraints = signet_cred::spl_capability::SplCapabilityConstraints {
        domain: domain.to_string(),
        max_amount,
        purpose: purpose.to_string(),
        one_time,
        expires_seconds: Some(300),
    };

    let signing_key_hex = hex::encode(signer.signing_key_bytes());
    let token = signet_cred::spl_capability::generate_spl_capability(&constraints, &signing_key_hex)
        .map_err(|e| RootError::Credential(e.kind))?;

    let token_json = serde_json::to_string_pretty(&token).map_err(|e| {
        RootError::Serialization(e.to_string())
    })?;

    println!("{}", token_json);
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

    let vault = state.vault_access.as_ref().ok_or_else(|| {
        RootError::Internal("vault not initialized".into())
    })?;

    let entries = vault.list(None).map_err(|e| {
        RootError::Internal(format!("list failed: {}", e))
    })?;

    let cred_entries: Vec<_> = entries
        .iter()
        .filter(|e| {
            e.label.starts_with(CRED_OFFER_PREFIX)
                || e.label.starts_with(CRED_ACCEPTED_PREFIX)
        })
        .collect();

    if cred_entries.is_empty() {
        println!("No credentials found.");
        return Ok(());
    }

    println!("{:<36} {:<12} {:<20} {:<20}", "ID", "STATUS", "TYPE", "AUTHORITY");
    println!("{}", "-".repeat(88));

    for entry in &cred_entries {
        let data = vault.get(&entry.label, entry.tier).map_err(|e| {
            RootError::Internal(format!("get failed: {}", e))
        })?;

        if let Some(data) = data {
            let is_offer = entry.label.starts_with(CRED_OFFER_PREFIX);
            let id = if is_offer {
                entry.label.strip_prefix(CRED_OFFER_PREFIX).unwrap_or(&entry.label)
            } else {
                entry.label.strip_prefix(CRED_ACCEPTED_PREFIX).unwrap_or(&entry.label)
            };

            let (status_str, cred_type, authority_pk) = if is_offer {
                if let Ok(offer) = serde_json::from_slice::<signet_cred::authority::AuthorityOffer>(&data) {
                    let auth_short = if offer.key.authority_pubkey.len() > 16 {
                        format!("{}...", &offer.key.authority_pubkey[..16])
                    } else {
                        offer.key.authority_pubkey.clone()
                    };
                    ("pending".to_string(), offer.credential_type, auth_short)
                } else {
                    continue;
                }
            } else if let Ok(accepted) = serde_json::from_slice::<signet_cred::authority::AcceptedCredential>(&data) {
                let auth_short = if accepted.offer.key.authority_pubkey.len() > 16 {
                    format!("{}...", &accepted.offer.key.authority_pubkey[..16])
                } else {
                    accepted.offer.key.authority_pubkey.clone()
                };
                ("accepted".to_string(), accepted.offer.credential_type, auth_short)
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

            println!("{:<36} {:<12} {:<20} {:<20}", id, status_str, cred_type, authority_pk);
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

    let vault = state.vault_access.as_ref().ok_or_else(|| {
        RootError::Internal("vault not initialized".into())
    })?;

    let signer = state.signer.as_ref().ok_or_else(|| {
        RootError::Internal("vault signer not initialized".into())
    })?;

    let offer_label = format!("{}{}", CRED_OFFER_PREFIX, offer_id);
    let offer_data = vault
        .get(&offer_label, signet_core::Tier::Tier2)
        .map_err(|e| RootError::Internal(format!("get failed: {}", e)))?
        .ok_or_else(|| RootError::Internal(format!("offer {} not found", offer_id)))?;

    let offer: signet_cred::authority::AuthorityOffer =
        serde_json::from_slice(&offer_data).map_err(|e| {
            RootError::Serialization(format!("failed to decode offer: {}", e))
        })?;

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
                println!("    Rate limit: {}/{}s (grace: {})", rl.max_per_window, rl.window_seconds, rl.grace);
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

    let accepted = signet_cred::authority::accept_offer(&offer, signer).map_err(|e| {
        RootError::Internal(format!("accept failed: {}", e))
    })?;

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

    let vault = state.vault_access.as_ref().ok_or_else(|| {
        RootError::Internal("vault not initialized".into())
    })?;

    let status = signet_cred::authority::OfferStatus::Rejected { reason: reason.clone() };
    let status_label = format!("{}{}", CRED_STATUS_PREFIX, offer_id);
    let status_data = serde_json::to_vec(&status).map_err(|e| {
        RootError::Serialization(format!("failed to encode status: {}", e))
    })?;
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

    let vault = state.vault_access.as_ref().ok_or_else(|| {
        RootError::Internal("vault not initialized".into())
    })?;

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
        if let Ok(accepted) = serde_json::from_slice::<signet_cred::authority::AcceptedCredential>(&data) {
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

    let vault = state.vault_access.as_ref().ok_or_else(|| {
        RootError::Internal("vault not initialized".into())
    })?;

    let revocation = signet_cred::RevocationInfo {
        revoked_by: signet_cred::RevokedBy::User,
        revoked_at: chrono::Utc::now().to_rfc3339(),
        reason: reason.clone(),
    };
    let status_label = format!("{}{}", CRED_STATUS_PREFIX, credential_id);
    let status_data = serde_json::to_vec(&revocation).map_err(|e| {
        RootError::Serialization(format!("failed to encode revocation: {}", e))
    })?;
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
    println!("  The authority will be notified. Check back with 'signet credential show {}'.", credential_id);

    Ok(())
}
