//! What this computer keeps on disk: its machine key and its settings.
//!
//! Two files in one folder. `machine-key.json` holds the machine's private
//! keys and is created readable by the owner only. `state.json` holds the
//! paired phones, the relay address and which sites go to the phone; nothing
//! in it is secret.
//!
//! Several processes may run at once, one per passkey call in the browser, so
//! every change to `state.json` is made under a lock file and written by
//! rename.
use crate::DesktopError;
use signet_passkey::{IdentityKeys, Pairing, PublicIdentity, SoftwareIdentity};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

const KEY_FILE: &str = "machine-key.json";
const STATE_FILE: &str = "state.json";
const LOCK_FILE: &str = "state.lock";
const STATE_VERSION: u8 = 1;

/// Settings and pairings.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub v: u8,
    /// The name this computer gives itself when pairing. Shown on the phone.
    pub device_name: String,
    /// The relay, in normal form.
    pub relay: String,
    pub pairings: Vec<Pairing>,
    /// Sites, by relying-party identifier, whose sign-ins go to the phone.
    /// A site is added when a passkey is created for it through this computer.
    pub sites: BTreeSet<String>,
    /// Whether new passkeys are created on the phone. When off, creation stays
    /// with the browser.
    pub new_passkeys: bool,
    /// Recent requests sent to the phone, as `(origin, time)`, kept only long
    /// enough to stop one page from flooding it.
    #[serde(default)]
    pub recent: Vec<(String, i64)>,
}

impl State {
    /// The phone requests are sent to: the first pairing that is still active.
    pub fn active_pairing(&self) -> Option<&Pairing> {
        self.pairings.iter().find(|pairing| !pairing.revoked)
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyFile {
    v: u8,
    kind: String,
    /// The machine's private keys, base64url.
    secret: String,
}

/// The folder this computer's files live in.
#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
}

struct Lock(PathBuf);

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// The folder used when none is given: `SIGNET_PASSKEY_DIR` if set, otherwise
/// the per-user configuration folder for this operating system.
pub fn default_dir() -> Result<PathBuf, DesktopError> {
    if let Some(dir) = std::env::var_os("SIGNET_PASSKEY_DIR").filter(|dir| !dir.is_empty()) {
        return Ok(PathBuf::from(dir));
    }
    let var = |name: &str| std::env::var_os(name).filter(|value| !value.is_empty());
    let base = if cfg!(target_os = "windows") {
        var("APPDATA").map(PathBuf::from)
    } else if cfg!(target_os = "macos") {
        var("HOME").map(|home| PathBuf::from(home).join("Library/Application Support"))
    } else {
        var("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| var("HOME").map(|home| PathBuf::from(home).join(".config")))
    };
    base.map(|base| base.join("signet-passkey"))
        .ok_or_else(|| DesktopError::Storage("no home folder; pass --dir".into()))
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

impl Store {
    pub fn open(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn is_initialized(&self) -> bool {
        self.dir.join(KEY_FILE).exists() && self.dir.join(STATE_FILE).exists()
    }

    /// Create the machine key and empty settings. Refuses to replace an
    /// existing key: that would silently orphan every pairing.
    pub fn init(&self, device_name: &str, relay: &str) -> Result<PublicIdentity, DesktopError> {
        let relay = signet_passkey::relay::normalize_relay_url(relay)?;
        if device_name.trim().is_empty()
            || device_name.len() > 60
            || device_name.chars().any(char::is_control)
        {
            return Err(DesktopError::Other(
                "the device name must be 1 to 60 printable characters".into(),
            ));
        }
        if self.dir.join(KEY_FILE).exists() {
            return Err(DesktopError::AlreadyInitialized(
                self.dir.display().to_string(),
            ));
        }
        std::fs::create_dir_all(&self.dir)
            .map_err(|e| DesktopError::storage("create folder", e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| DesktopError::storage("restrict folder", e))?;
        }
        let identity = SoftwareIdentity::generate();
        let key = KeyFile {
            v: STATE_VERSION,
            kind: "signet-passkey-machine-key".into(),
            secret: signet_passkey::relay::encode(&identity.to_secret_bytes()),
        };
        let mut encoded =
            zeroize::Zeroizing::new(serde_json::to_vec_pretty(&key).expect("key file serializes"));
        encoded.push(b'\n');
        write_private(&self.dir.join(KEY_FILE), &encoded)
            .map_err(|e| DesktopError::storage("write machine key", e))?;
        self.write_state(&State {
            v: STATE_VERSION,
            device_name: device_name.trim().to_owned(),
            relay,
            pairings: Vec::new(),
            sites: BTreeSet::new(),
            new_passkeys: true,
            recent: Vec::new(),
        })?;
        Ok(identity.public())
    }

    /// The machine key.
    pub fn identity(&self) -> Result<SoftwareIdentity, DesktopError> {
        let path = self.dir.join(KEY_FILE);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => zeroize::Zeroizing::new(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(DesktopError::NotInitialized)
            }
            Err(error) => return Err(DesktopError::storage("read machine key", error)),
        };
        let mut key: KeyFile = serde_json::from_slice(&bytes)
            .map_err(|_| DesktopError::Storage("machine key file is damaged".into()))?;
        let secret = zeroize::Zeroizing::new(
            signet_passkey::relay::decode(&key.secret)
                .map_err(|_| DesktopError::Storage("machine key file is damaged".into()))?,
        );
        zeroize::Zeroize::zeroize(&mut key.secret);
        if key.v != STATE_VERSION {
            return Err(DesktopError::Storage(
                "machine key file is from another version".into(),
            ));
        }
        SoftwareIdentity::from_secret_bytes(&secret)
            .map_err(|_| DesktopError::Storage("machine key file is damaged".into()))
    }

    pub fn load(&self) -> Result<State, DesktopError> {
        let bytes = match std::fs::read(self.dir.join(STATE_FILE)) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(DesktopError::NotInitialized)
            }
            Err(error) => return Err(DesktopError::storage("read settings", error)),
        };
        let state: State = serde_json::from_slice(&bytes)
            .map_err(|e| DesktopError::storage("settings file is damaged", e))?;
        if state.v != STATE_VERSION {
            return Err(DesktopError::Storage(
                "settings file is from another version".into(),
            ));
        }
        Ok(state)
    }

    fn write_state(&self, state: &State) -> Result<(), DesktopError> {
        let mut bytes = serde_json::to_vec_pretty(state).expect("settings serialize");
        bytes.push(b'\n');
        let temporary = self
            .dir
            .join(format!("{STATE_FILE}.{}.tmp", std::process::id()));
        std::fs::write(&temporary, &bytes)
            .map_err(|e| DesktopError::storage("write settings", e))?;
        std::fs::rename(&temporary, self.dir.join(STATE_FILE)).map_err(|e| {
            let _ = std::fs::remove_file(&temporary);
            DesktopError::storage("replace settings", e)
        })
    }

    fn lock(&self) -> Result<Lock, DesktopError> {
        let path = self.dir.join(LOCK_FILE);
        let started = Instant::now();
        loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(_) => return Ok(Lock(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    // A holder that died leaves the file behind. Changes take
                    // milliseconds, so a lock this old has no owner.
                    let stale = std::fs::metadata(&path)
                        .and_then(|meta| meta.modified())
                        .ok()
                        .and_then(|modified| SystemTime::now().duration_since(modified).ok())
                        .is_some_and(|age| age > Duration::from_secs(10));
                    if stale {
                        let _ = std::fs::remove_file(&path);
                        continue;
                    }
                    if started.elapsed() > Duration::from_secs(5) {
                        return Err(DesktopError::Storage(
                            "settings are locked by another process".into(),
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(15));
                }
                Err(error) => return Err(DesktopError::storage("lock settings", error)),
            }
        }
    }

    /// Change the settings. The closure sees the latest saved state, and what
    /// it returns is passed back after the change is saved.
    pub fn update<T>(&self, change: impl FnOnce(&mut State) -> T) -> Result<T, DesktopError> {
        let _lock = self.lock()?;
        let mut state = self.load()?;
        let result = change(&mut state);
        self.write_state(&state)?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_store_keeps_one_identity_and_refuses_to_replace_it() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("signet"));
        assert!(matches!(store.load(), Err(DesktopError::NotInitialized)));
        assert!(matches!(
            store.identity(),
            Err(DesktopError::NotInitialized)
        ));

        let public = store.init("Work laptop", "http://127.0.0.1:8787/").unwrap();
        assert_eq!(store.identity().unwrap().public(), public);
        let state = store.load().unwrap();
        assert_eq!(state.relay, "http://127.0.0.1:8787");
        assert_eq!(state.device_name, "Work laptop");
        assert!(state.new_passkeys);

        assert!(matches!(
            store.init("Again", "http://127.0.0.1:8787"),
            Err(DesktopError::AlreadyInitialized(_))
        ));
        assert_eq!(store.identity().unwrap().public(), public);
    }

    #[cfg(unix)]
    #[test]
    fn the_machine_key_is_readable_by_its_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("signet"));
        store.init("Work laptop", "http://127.0.0.1:8787").unwrap();
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&store.dir().join(KEY_FILE)), 0o600);
        assert_eq!(mode(store.dir()), 0o700);
    }

    #[test]
    fn bad_names_and_relays_are_refused_before_anything_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("signet"));
        assert!(store.init("", "http://127.0.0.1:8787").is_err());
        assert!(store.init("Laptop", "http://relay.example").is_err());
        assert!(!store.dir().exists());
    }

    #[test]
    fn concurrent_changes_are_all_kept() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("signet"));
        store.init("Work laptop", "http://127.0.0.1:8787").unwrap();
        let threads: Vec<_> = (0..8)
            .map(|n| {
                let store = store.clone();
                std::thread::spawn(move || {
                    for m in 0..5 {
                        store
                            .update(|state| state.sites.insert(format!("site-{n}-{m}.example")))
                            .unwrap();
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(store.load().unwrap().sites.len(), 40);
    }
}
