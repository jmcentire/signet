//! `signet-passkey-relay`: run the mailbox relay.
use clap::Parser;
use signet_passkey::relay::normalize_relay_url;
use signet_passkey_relay::{loopback_audiences, serve, RelayConfig};
use std::net::SocketAddr;

/// Store-and-forward relay for Signet remote passkey approval.
///
/// Carries sealed envelopes between a phone and the computers paired with it.
/// It cannot read them. It keeps nothing on disk. Put TLS in front of it for
/// any address other than this machine.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Address to listen on. Port 0 picks a free port and prints it.
    #[arg(long, default_value = "127.0.0.1:8787")]
    listen: SocketAddr,
    /// The address devices use to reach this relay, for example
    /// https://relay.example. May be given more than once. Required unless
    /// listening on a loopback address.
    #[arg(long = "public-url")]
    public_urls: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let args = Args::parse();
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    let address = listener.local_addr()?;
    let audiences = if args.public_urls.is_empty() {
        loopback_audiences(address).ok_or(
            "listening on a public address: say which address devices use with --public-url",
        )?
    } else {
        args.public_urls
            .iter()
            .map(|url| normalize_relay_url(url).map_err(|error| format!("{url}: {error}")))
            .collect::<Result<Vec<_>, _>>()?
    };
    // Printed on stdout so a script that asked for port 0 can read it.
    println!("listening {address}");
    tracing::info!(?audiences, "relay ready");
    serve(listener, RelayConfig::new(audiences)).await?;
    Ok(())
}
