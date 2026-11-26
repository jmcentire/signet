//! A phone simulator for local trials and the browser end-to-end test.
//!
//! It answers one pairing ticket, prints the confirmation code, then approves
//! or declines requests as told. Its keys live in this process's memory and are
//! gone when it exits. Do not register it with an account you care about: it
//! is a test double, not an authenticator.
//!
//!     cargo run -p signet-passkey-desktop --example phone_sim -- --ticket 'signet-pair:...'
#[path = "../tests/common/phone.rs"]
mod phone;

use clap::Parser;
use phone::Phone;
use signet_passkey::{Approval, Approver, OperationKind, RequestView};
use std::collections::VecDeque;
use std::io::Write;

#[derive(Parser)]
struct Args {
    /// The ticket printed by `signet-passkey pair`.
    #[arg(long)]
    ticket: String,
    /// The name this simulated phone gives itself.
    #[arg(long, default_value = "Simulated phone")]
    name: String,
    /// Answers for the first requests, in order: approve or deny, comma
    /// separated.
    #[arg(long, value_delimiter = ',')]
    decisions: Vec<Answer>,
    /// What to do once the list is used up.
    #[arg(long, value_enum, default_value = "ask")]
    then: Then,
}

#[derive(Clone, Copy, PartialEq, clap::ValueEnum)]
enum Answer {
    Approve,
    Deny,
}

#[derive(Clone, Copy, PartialEq, clap::ValueEnum)]
enum Then {
    Approve,
    Deny,
    /// Ask on the terminal.
    Ask,
}

struct Owner {
    decisions: VecDeque<Answer>,
    then: Then,
}

impl Approver for Owner {
    fn decide(&mut self, view: &RequestView) -> Approval {
        let what = match view.operation {
            OperationKind::SignIn => "sign-in",
            OperationKind::CreatePasskey => "create",
        };
        let account = view
            .accounts
            .first()
            .map(|account| account.user_name.as_str())
            .unwrap_or("-");
        let app = view
            .context
            .as_ref()
            .and_then(|context| context.app.as_deref())
            .unwrap_or("-");
        let summary = format!(
            "request {what} site={} origin={} account={account} from=\"{}\" app={app}",
            view.rp_id,
            view.origin.as_deref().unwrap_or("-"),
            view.requester_name,
        );
        let approve = match self.decisions.pop_front() {
            Some(answer) => answer == Answer::Approve,
            None => match self.then {
                Then::Approve => true,
                Then::Deny => false,
                Then::Ask => {
                    eprint!("{summary}\nApprove? [y/N] ");
                    let mut line = String::new();
                    let _ = std::io::stdin().read_line(&mut line);
                    matches!(line.trim(), "y" | "Y" | "yes")
                }
            },
        };
        println!(
            "{summary} -> {}",
            if approve { "approved" } else { "denied" }
        );
        let _ = std::io::stdout().flush();
        if approve {
            Approval::Approve {
                account: 0,
                // A real phone reports whether the biometric check passed.
                // The simulator has none, and says it did.
                user_verified: true,
            }
        } else {
            Approval::Deny
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = Args::parse();
    eprintln!("Phone simulator: a test double. Keys are in memory and are lost on exit.");
    let now = signet_passkey_desktop::system_now;
    let mut phone = Phone::new(&args.name);
    match phone.pair(&args.ticket, now()).await {
        Ok(code) => {
            println!("code {code}");
            let _ = std::io::stdout().flush();
        }
        Err(error) => {
            eprintln!("pairing failed: {error}");
            std::process::exit(1);
        }
    }
    let mut owner = Owner {
        decisions: args.decisions.into(),
        then: args.then,
    };
    phone.serve(&mut owner, &now).await;
}
