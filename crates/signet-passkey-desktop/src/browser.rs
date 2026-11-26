//! Telling a browser where this program is.
//!
//! Chrome finds a native-messaging host through a small JSON manifest in a
//! per-user folder. The manifest names the program and the one extension
//! allowed to start it.
use crate::native::HOST_NAME;
use crate::DesktopError;
use std::path::{Path, PathBuf};

/// Browsers whose manifest folder is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Browser {
    Chrome,
    ChromeForTesting,
    Chromium,
    Brave,
    Edge,
}

/// Whether `id` is shaped like a Chrome extension id: 32 letters, a to p.
pub fn is_extension_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| (b'a'..=b'p').contains(&b))
}

/// The per-user folder `browser` reads native-messaging manifests from, on
/// macOS and Linux. `None` on Windows, where Chrome uses the registry.
pub fn manifest_dir(browser: Browser, home: &Path) -> Option<PathBuf> {
    let (mac, linux) = match browser {
        Browser::Chrome => ("Google/Chrome", "google-chrome"),
        Browser::ChromeForTesting => ("Google/Chrome for Testing", "google-chrome-for-testing"),
        Browser::Chromium => ("Chromium", "chromium"),
        Browser::Brave => ("BraveSoftware/Brave-Browser", "BraveSoftware/Brave-Browser"),
        Browser::Edge => ("Microsoft Edge", "microsoft-edge"),
    };
    if cfg!(target_os = "macos") {
        Some(
            home.join("Library/Application Support")
                .join(mac)
                .join("NativeMessagingHosts"),
        )
    } else if cfg!(unix) {
        Some(
            home.join(".config")
                .join(linux)
                .join("NativeMessagingHosts"),
        )
    } else {
        None
    }
}

/// The manifest's contents.
pub fn manifest(program: &Path, extension_id: &str) -> serde_json::Value {
    serde_json::json!({
        "name": HOST_NAME,
        "description": "Signet remote passkey approval",
        "path": program,
        "type": "stdio",
        "allowed_origins": [format!("chrome-extension://{extension_id}/")],
    })
}

/// Write the manifest into `folder`. Returns the file written.
///
/// A manifest can name a program but cannot pass it arguments or environment.
/// When `store_dir` is given, the settings live somewhere other than the
/// default folder, so the manifest points at a two-line launcher script that
/// sets the folder and starts the program.
pub fn install(
    folder: &Path,
    program: &Path,
    extension_id: &str,
    store_dir: Option<&Path>,
) -> Result<PathBuf, DesktopError> {
    if !is_extension_id(extension_id) {
        return Err(DesktopError::Other(
            "the extension id is the 32-letter id shown on the browser's extensions page".into(),
        ));
    }
    if !program.is_absolute() {
        return Err(DesktopError::Other(
            "the program path must be absolute".into(),
        ));
    }
    std::fs::create_dir_all(folder).map_err(|e| DesktopError::storage("create folder", e))?;
    let target = match store_dir {
        None => program.to_path_buf(),
        Some(dir) => write_launcher(dir, program)?,
    };
    let path = folder.join(format!("{HOST_NAME}.json"));
    let mut body =
        serde_json::to_vec_pretty(&manifest(&target, extension_id)).expect("manifest serializes");
    body.push(b'\n');
    std::fs::write(&path, body).map_err(|e| DesktopError::storage("write manifest", e))?;
    Ok(path)
}

#[cfg(unix)]
fn write_launcher(store_dir: &Path, program: &Path) -> Result<PathBuf, DesktopError> {
    use std::os::unix::fs::PermissionsExt;
    let quoted = |path: &Path| -> Result<String, DesktopError> {
        let text = path
            .to_str()
            .filter(|text| !text.contains('\''))
            .ok_or_else(|| DesktopError::Other("a path contains a quote or is not UTF-8".into()))?;
        Ok(format!("'{text}'"))
    };
    let store_dir = std::fs::canonicalize(store_dir)
        .map_err(|e| DesktopError::storage("settings folder", e))?;
    let script = format!(
        "#!/bin/sh\nSIGNET_PASSKEY_DIR={} exec {} \"$@\"\n",
        quoted(&store_dir)?,
        quoted(program)?
    );
    let path = store_dir.join("native-host.sh");
    std::fs::write(&path, script).map_err(|e| DesktopError::storage("write launcher", e))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| DesktopError::storage("write launcher", e))?;
    Ok(path)
}

#[cfg(not(unix))]
fn write_launcher(_store_dir: &Path, _program: &Path) -> Result<PathBuf, DesktopError> {
    Err(DesktopError::Other(
        "a custom settings folder is not supported for the browser host on this system".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "abcdefghijklmnopabcdefghijklmnop";

    #[test]
    fn the_manifest_names_one_program_and_one_extension() {
        let dir = tempfile::tempdir().unwrap();
        let program = dir.path().join("signet-passkey");
        let path = install(&dir.path().join("hosts"), &program, ID, None).unwrap();
        assert!(path.ends_with("io.github.jmcentire.signet_passkey.json"));
        let written: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(written["name"], HOST_NAME);
        assert_eq!(written["type"], "stdio");
        assert_eq!(written["path"], program.to_str().unwrap());
        assert_eq!(
            written["allowed_origins"],
            serde_json::json!([format!("chrome-extension://{ID}/")])
        );
    }

    #[test]
    fn malformed_ids_and_relative_paths_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let program = dir.path().join("signet-passkey");
        for bad in [
            "",
            "abc",
            "ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP",
            "abcdefghijklmnopabcdefghijklmnoz",
            "*",
        ] {
            assert!(install(dir.path(), &program, bad, None).is_err(), "{bad}");
        }
        assert!(install(dir.path(), Path::new("signet-passkey"), ID, None).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_custom_settings_folder_gets_a_launcher() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("settings");
        std::fs::create_dir_all(&store).unwrap();
        let program = dir.path().join("signet-passkey");
        let path = install(&dir.path().join("hosts"), &program, ID, Some(&store)).unwrap();
        let written: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let launcher = PathBuf::from(written["path"].as_str().unwrap());
        let script = std::fs::read_to_string(&launcher).unwrap();
        assert!(script.starts_with("#!/bin/sh\nSIGNET_PASSKEY_DIR='"));
        assert!(script.contains(&format!("exec '{}' \"$@\"", program.display())));
    }
}
