use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use directories::ProjectDirs;
use zeroize::Zeroizing;

use crate::crypto::{open_vault, seal_vault, VaultHeader};
use crate::error::{Result, VaultError};
use crate::hardening::{fill_random, LockedKey};
use crate::vault::Vault;

const MAX_BACKUPS: usize = 5;

/// Default XDG vault path (`~/.local/share/omavault/vault.omav`).
pub fn default_vault_path() -> PathBuf {
    if let Ok(env_path) = std::env::var("OMAVAULT_PATH") {
        if !env_path.trim().is_empty() {
            return PathBuf::from(env_path);
        }
    }
    if let Some(dirs) = ProjectDirs::from("io", "omarchy", "omavault") {
        dirs.data_dir().join("vault.omav")
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("omavault")
            .join("vault.omav")
    }
}

/// Ensure a directory exists with strict owner-only permissions (`0o700`).
pub fn ensure_private_dir(dir: &Path) -> Result<()> {
    if !dir.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
    }
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// Write `data` atomically with `0o600` permissions, full `fsync`, and parent directory `fsync`.
///
/// Never leaves a half-written file or a world-readable temporary file on disk.
pub fn atomic_write_private(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| VaultError::InvalidFormat("vault path has no parent directory".into()))?;
    ensure_private_dir(parent)?;

    let mut suffix = [0u8; 8];
    fill_random(&mut suffix)?;
    let hex_suffix: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("vault.omav");
    let tmp_path = parent.join(format!(".{file_name}.tmp.{hex_suffix}"));

    // Create exclusively with 0o600 permissions so it is never readable by other users.
    let write_result = (|| -> Result<()> {
        let mut tmp_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)?;
        tmp_file.write_all(data)?;
        tmp_file.sync_all()?;
        Ok(())
    })();

    if let Err(e) = write_result {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }

    // Rotate encrypted backup of existing vault before atomic swap.
    if path.exists() {
        let _ = rotate_encrypted_backup(path);
    }

    if let Err(e) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(VaultError::Io(e));
    }

    // Best-effort fsync of parent directory so the rename is durable across power loss.
    if let Ok(dir_file) = File::open(parent) {
        let _ = dir_file.sync_all();
    }

    Ok(())
}

/// Keep up to `MAX_BACKUPS` encrypted rolling backups (`vault.omav.bak.1`..`.5`) with `0o600`.
fn rotate_encrypted_backup(path: &Path) -> Result<()> {
    let base = path.as_os_str().to_string_lossy();
    for i in (1..MAX_BACKUPS).rev() {
        let src = PathBuf::from(format!("{base}.bak.{i}"));
        let dst = PathBuf::from(format!("{base}.bak.{}", i + 1));
        if src.exists() {
            let _ = fs::rename(&src, &dst);
        }
    }
    let bak1 = PathBuf::from(format!("{base}.bak.1"));
    let existing = fs::read(path)?;
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&bak1)?;
    f.write_all(&existing)?;
    f.sync_all()?;
    Ok(())
}

/// Read only the authenticated header from an encrypted vault file on disk.
pub fn read_header_from_disk(path: &Path, enforce_kdf_policy: bool) -> Result<VaultHeader> {
    if !path.exists() {
        return Err(VaultError::VaultNotFound(path.display().to_string()));
    }
    let blob = fs::read(path)?;
    let (header, _) = VaultHeader::parse(&blob, enforce_kdf_policy)?;
    Ok(header)
}

/// Serialize, encrypt (rotating `save_salt` + `nonce`), and atomically save the vault.
pub fn save_vault_to_disk(
    path: &Path,
    master_key: &LockedKey<32>,
    header: &mut VaultHeader,
    vault: &Vault,
) -> Result<()> {
    let plaintext = Zeroizing::new(
        serde_json::to_vec(vault).map_err(|e| VaultError::Serialization(e.to_string()))?,
    );
    let blob = seal_vault(master_key, header, &plaintext)?;
    atomic_write_private(path, &blob)
}

/// Read, authenticate, decrypt, and deserialize a vault from disk.
pub fn load_vault_from_disk(
    path: &Path,
    master_key: &LockedKey<32>,
    enforce_kdf_policy: bool,
) -> Result<(VaultHeader, Vault)> {
    if !path.exists() {
        return Err(VaultError::VaultNotFound(path.display().to_string()));
    }
    let blob = fs::read(path)?;
    let (header, plaintext) = open_vault(master_key, &blob, enforce_kdf_policy)?;
    let vault: Vault = serde_json::from_slice(&plaintext)
        .map_err(|e| VaultError::Serialization(e.to_string()))?;
    Ok((header, vault))
}

/// Generate a high-entropy 64-byte (512-bit) cryptographic keyfile with `0o600` permissions.
pub fn generate_keyfile(path: &Path) -> Result<()> {
    if path.exists() {
        return Err(VaultError::VaultAlreadyExists(format!(
            "refusing to overwrite existing keyfile at {}",
            path.display()
        )));
    }
    let mut secret = Zeroizing::new([0u8; 64]);
    fill_random(&mut *secret)?;

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            ensure_private_dir(parent)?;
        }
    }

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&*secret)?;
    file.sync_all()?;
    Ok(())
}
