//! `signet-passkey`: set this computer up, pair it with a phone, and answer
//! the browser extension.
//!
//! Chrome starts this same program as its native-messaging host, passing the
//! extension's origin as the only argument. Anything else is the command line.
use clap::{Parser, Subcommand};
use signet_passkey::IdentityKeys;
use signet_passkey_desktop::browser::{self, Browser};
use signet_passkey_desktop::native::{self, HostReply, HostRequest, HOST_NAME};
use signet_passkey_desktop::{flow, pair, store, system_now, DesktopError, RelayClient, Store};
use std::io::Write;
use std::path::PathBuf;

/// The computer side of Signet remote passkey approval.
#[derive(Parser)]
#[command(name = "signet-passkey", version)]
struct Cli {
    /// Folder for this computer's key and settings. Defaults to
    /// SIGNET_PASSKEY_DIR, then the per-user configuration folder.
    #[arg(long, global = true)]
    dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create this computer's key and settings.
    Init {
        /// The name the phone shows for this computer.
        #[arg(long)]
        name: String,
        /// The relay's address.
        #[arg(long)]
        relay: String,
    },
    /// Pair with a phone. Shows a ticket, then asks for the code on the phone.
    Pair,
    /// Stop using a phone, named by its name, fingerprint or pairing id.
    Unpair { phone: String },
    /// Show this computer's identity, phones, sites and relay.
    Status,
    /// Sites whose sign-ins go to the phone.
    Sites {
        #[command(subcommand)]
        action: SitesAction,
    },
    /// Whether new passkeys are created on the phone (on) or left to the
    /// browser (off).
    NewPasskeys { setting: Switch },
    /// Browser integration.
    Browser {
        #[command(subcommand)]
        action: BrowserAction,
    },
}

#[derive(Subcommand)]
enum SitesAction {
    List,
    /// Send this site's sign-ins to the phone, for a passkey that was created
    /// from another computer.
    Add {
        site: String,
    },
    Remove {
        site: String,
    },
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum Switch {
    On,
    Off,
}

#[derive(Subcommand)]
enum BrowserAction {
    /// Tell a browser where this program is, for one extension.
    Install {
        /// The extension's 32-letter id, from the browser's extensions page.
        #[arg(long)]
        extension_id: String,
        #[arg(long, value_enum, default_value = "chrome")]
        browser: Browser,
        /// Write the manifest here instead of the browser's usual folder.
        #[arg(long)]
        manifest_dir: Option<PathBuf>,
    },
}

fn open_store(dir: Option<PathBuf>) -> Result<Store, DesktopError> {
    Ok(Store::open(match dir {
        Some(dir) => dir,
        None => store::default_dir()?,
    }))
}

/// Answer the browser extension: one request per connection.
fn native_host() -> i32 {
    let mut input = std::io::stdin().lock();
    let request = match native::read_message(&mut input) {
        Ok(Some(bytes)) => bytes,
        _ => return 0,
    };
    drop(input);
    let send = |reply: &HostReply, id: &str| {
        let _ = native::write_message(&mut std::io::stdout().lock(), &reply.to_message(id));
    };
    let request: HostRequest = match serde_json::from_slice(&request) {
        Ok(request) => request,
        Err(_) => {
            send(&HostReply::native("request not understood"), "");
            return 0;
        }
    };
    let id = request.id.clone();
    let store = match open_store(None) {
        Ok(store) => store,
        Err(error) => {
            send(&HostReply::native(&error.to_string()), &id);
            return 0;
        }
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            send(&HostReply::native(&error.to_string()), &id);
            return 0;
        }
    };
    // The extension closes the connection to cancel. A second thread watches
    // for that, because the request may be waiting on the phone for minutes.
    let (closed, mut was_closed) = tokio::sync::oneshot::channel::<()>();
    std::thread::spawn(move || {
        let mut input = std::io::stdin().lock();
        while let Ok(Some(_)) = native::read_message(&mut input) {}
        let _ = closed.send(());
    });
    runtime.block_on(async {
        let mut progress = |reply: &HostReply| send(reply, &id);
        tokio::select! {
            reply = flow::handle(&store, request, &system_now, &mut progress) => send(&reply, &id),
            _ = &mut was_closed => {}
        }
    });
    0
}

fn prompt(question: &str) -> std::io::Result<String> {
    print!("{question}");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_owned())
}

async fn run(cli: Cli) -> Result<(), DesktopError> {
    let store = open_store(cli.dir.clone())?;
    match cli.command {
        Command::Init { name, relay } => {
            let public = store.init(&name, &relay)?;
            println!("This computer: {name}");
            println!("Fingerprint:   {}", public.fingerprint());
            println!("Settings:      {}", store.dir().display());
            println!("Next: signet-passkey pair");
        }
        Command::Pair => {
            let started = pair::start(&store, system_now())?;
            println!("Open Signet on the phone and scan or paste this ticket.");
            println!("It works once and expires in 10 minutes. Anyone who sees it can pair");
            println!("in your place, so show it only to your own phone.\n");
            println!("{}\n", started.ticket);
            println!("Waiting for the phone...");
            let Some(answered) = started.wait(&system_now).await? else {
                return Err(DesktopError::Other(
                    "the ticket expired before a phone answered".into(),
                ));
            };
            println!(
                "A device calling itself \"{}\" answered ({}).",
                answered.phone_name(),
                answered.phone_fingerprint()
            );
            let typed = prompt("Type the 6-digit code shown on the phone: ")
                .map_err(|e| DesktopError::Other(format!("could not read the code: {e}")))?;
            let pairing = answered.confirm(&store, &typed)?;
            println!("Paired with {}.", pairing.peer_name);
        }
        Command::Unpair { phone } => {
            let removed = pair::unpair(&store, &phone)?;
            if removed.is_empty() {
                return Err(DesktopError::Other(format!(
                    "no paired phone matches \"{phone}\""
                )));
            }
            for name in removed {
                println!("Removed {name}. Remove this computer on the phone as well.");
            }
        }
        Command::Status => {
            let state = store.load()?;
            let identity = store.identity()?;
            println!("This computer: {}", state.device_name);
            println!("Fingerprint:   {}", identity.public().fingerprint());
            println!("Settings:      {}", store.dir().display());
            let reachable = match RelayClient::new(&state.relay) {
                Ok(relay) => match relay.health().await {
                    Ok(()) => "reachable".to_owned(),
                    Err(error) => error.to_string(),
                },
                Err(error) => error.to_string(),
            };
            println!("Relay:         {} ({reachable})", state.relay);
            println!(
                "New passkeys:  {}",
                if state.new_passkeys {
                    "on the phone"
                } else {
                    "left to the browser"
                }
            );
            let phones: Vec<_> = state.pairings.iter().filter(|p| !p.revoked).collect();
            if phones.is_empty() {
                println!("Phones:        none. Run: signet-passkey pair");
            }
            for phone in phones {
                println!(
                    "Phone:         {} ({})",
                    phone.peer_name,
                    phone.peer.fingerprint()
                );
            }
            if state.sites.is_empty() {
                println!("Sites:         none yet");
            } else {
                println!(
                    "Sites:         {}",
                    state.sites.iter().cloned().collect::<Vec<_>>().join(", ")
                );
            }
        }
        Command::Sites { action } => match action {
            SitesAction::List => {
                for site in store.load()?.sites {
                    println!("{site}");
                }
            }
            SitesAction::Add { site } => {
                let site = site.trim().to_ascii_lowercase();
                signet_passkey::rp::validate_rp_id(&site)?;
                store.update(|state| state.sites.insert(site.clone()))?;
                println!("Sign-ins to {site} now go to the phone.");
            }
            SitesAction::Remove { site } => {
                let site = site.trim().to_ascii_lowercase();
                if !store.update(|state| state.sites.remove(&site))? {
                    return Err(DesktopError::Other(format!("{site} is not listed")));
                }
                println!("Sign-ins to {site} are left to the browser.");
            }
        },
        Command::NewPasskeys { setting } => {
            let on = matches!(setting, Switch::On);
            store.update(|state| state.new_passkeys = on)?;
            println!(
                "New passkeys are {}.",
                if on {
                    "created on the phone"
                } else {
                    "left to the browser"
                }
            );
        }
        Command::Browser {
            action:
                BrowserAction::Install {
                    extension_id,
                    browser,
                    manifest_dir,
                },
        } => {
            let folder = match manifest_dir {
                Some(folder) => folder,
                None => std::env::var_os("HOME")
                    .map(PathBuf::from)
                    .and_then(|home| browser::manifest_dir(browser, &home))
                    .ok_or_else(|| {
                        DesktopError::Other(
                            "on this system the browser finds the program through the registry; \
                             not supported yet. Use --manifest-dir to write the file anyway"
                                .into(),
                        )
                    })?,
            };
            let program = std::env::current_exe()
                .and_then(std::fs::canonicalize)
                .map_err(|e| DesktopError::Other(format!("cannot locate this program: {e}")))?;
            // The browser starts the program with no arguments of ours, so a
            // folder given on this command line has to be carried by a launcher.
            let custom = cli.dir.as_deref();
            let written = browser::install(&folder, &program, &extension_id, custom)?;
            println!("Wrote {}", written.display());
            println!("Host name: {HOST_NAME}");
        }
    }
    Ok(())
}

fn main() {
    let from_browser = std::env::args()
        .nth(1)
        .is_some_and(|argument| argument.starts_with("chrome-extension://"));
    if from_browser {
        // Exit without waiting for the thread blocked on standard input.
        std::process::exit(native_host());
    }
    let cli = Cli::parse();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime starts");
    if let Err(error) = runtime.block_on(run(cli)) {
        eprintln!("signet-passkey: {error}");
        std::process::exit(1);
    }
}
