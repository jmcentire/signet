//! Operator-provisioned software signer. File permissions are not same-user isolation.
use super::*;
use ed25519_dalek::{Signer as _, SigningKey};
use std::io::Read;
use zeroize::Zeroizing;

struct FileSigner(SigningKey);
impl Signer for FileSigner {
    fn sign_ed25519(&self, bytes: &[u8]) -> signet_core::SignetResult<[u8; 64]> {
        Ok(self.0.sign(bytes).to_bytes())
    }
    fn public_key_ed25519(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
}
/// Load an existing 32-byte binary Ed25519 seed, never generate or print one.
/// The service must run in an account whose files and process the agent cannot access.
pub fn load(path: &Path) -> Result<Box<dyn Signer>> {
    check_parent(path)?;
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() != 32 {
        return reject("owner signer requires a regular 32-byte private seed file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if meta.permissions().mode() & 0o077 != 0 || meta.nlink() != 1 {
            return reject("owner signer file requires mode 0600 and no hard links");
        }
    }
    let file = fs::File::open(path)?;
    let opened = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.dev() != opened.dev() || meta.ino() != opened.ino() {
            return reject("owner signer file changed while opening");
        }
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(33).read_to_end(&mut bytes)?;
    if bytes.len() != 32 {
        return reject("owner signer requires exactly 32 bytes");
    }
    let mut seed = Zeroizing::new([0_u8; 32]);
    seed.copy_from_slice(&bytes);
    Ok(Box::new(FileSigner(SigningKey::from_bytes(&seed))))
}
