use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use directories::ProjectDirs;
use zeroize::Zeroizing;

use crate::crypto::{open_vault, seal_vault, VaultHeader, MAX_VAULT_FILE_BYTES};
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
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("omavault")
            .join("vault.omav")
    } else {
        PathBuf::from("vault.omav")
    }
}

/// Safely resolve the parent directory of a file path (mapping empty `""` to `"."`).
fn resolve_parent(path: &Path) -> Result<&Path> {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => Ok(p),
        Some(_) => Ok(Path::new(".")),
        None => Err(VaultError::InvalidFormat(
            "path has no parent directory".into(),
        )),
    }
}

/// Ensure a dedicated private directory exists without following symlinks (`O_NOFOLLOW`),
/// verifying ownership by current `euid`, and applying `fchmod(0o700)` on the open fd.
///
/// If `chmod_existing` is `false`, pre-existing generic directories (like `$HOME`) are verified
/// to be real non-symlink directories owned by `euid` without mutating their permissions.
pub fn ensure_private_dir_strict(dir: &Path, chmod_existing: bool) -> Result<()> {
    let created = if !dir.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        true
    } else {
        false
    };

    // Open with O_RDONLY | O_DIRECTORY | O_NOFOLLOW to prevent symlink TOCTOU attacks.
    let dir_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(dir)
        .map_err(|e| {
            VaultError::Io(std::io::Error::new(
                e.kind(),
                format!("private directory '{}' rejected (symlink or inaccessible): {e}", dir.display()),
            ))
        })?;

    let meta = dir_file.metadata()?;
    let my_uid = unsafe { libc::geteuid() };
    if meta.uid() != my_uid {
        return Err(VaultError::Hardening(format!(
            "directory '{}' is not owned by current user",
            dir.display()
        )));
    }

    if created || chmod_existing {
        let rc = unsafe { libc::fchmod(dir_file.as_raw_fd(), 0o700) };
        if rc != 0 {
            return Err(VaultError::Io(std::io::Error::last_os_error()));
        }
    }

    Ok(())
}

/// Ensure a dedicated `omavault` directory exists with strict `0o700` owner-only permissions.
pub fn ensure_private_dir(dir: &Path) -> Result<()> {
    // Only enforce chmod 0700 on newly created dirs or dirs explicitly named/containing omavault;
    // never unexpectedly chmod a user's $HOME or /tmp mount root.
    let is_dedicated = dir
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.contains("omavault") || n.contains("private"));
    ensure_private_dir_strict(dir, is_dedicated)
}

/// Advisory exclusive file lock (`flock(LOCK_EX)`) scoped via RAII.
struct FileLockGuard {
    file: File,
}

impl FileLockGuard {
    fn acquire(vault_path: &Path) -> Result<Self> {
        let lock_path = append_os_suffix(vault_path, ".lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&lock_path)?;
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            return Err(VaultError::Io(std::io::Error::last_os_error()));
        }
        Ok(Self { file })
    }
}

impl Drop for FileLockGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn append_os_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut os = OsString::from(path.as_os_str());
    os.push(suffix);
    PathBuf::from(os)
}

/// Write `data` atomically with `0o600` permissions, exclusive `flock`, `fsync`, and parent `fsync`.
pub fn atomic_write_private(path: &Path, data: &[u8]) -> Result<()> {
    let parent = resolve_parent(path)?;
    ensure_private_dir(parent)?;

    let _lock = FileLockGuard::acquire(path)?;
    atomic_write_unlocked(path, parent, data, true)
}

fn atomic_write_unlocked(
    path: &Path,
    parent: &Path,
    data: &[u8],
    create_backup: bool,
) -> Result<()> {
    let mut suffix = [0u8; 8];
    fill_random(&mut suffix)?;
    let hex_suffix: String = suffix.iter().map(|b| format!("{b:02x}")).collect();

    let mut tmp_name = OsString::from(".");
    tmp_name.push(path.file_name().unwrap_or_else(|| std::ffi::OsStr::new("vault.omav")));
    tmp_name.push(format!(".tmp.{hex_suffix}"));
    let tmp_path = parent.join(tmp_name);

    let write_result = (|| -> Result<()> {
        let mut tmp_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp_path)?;
        tmp_file.write_all(data)?;
        tmp_file.sync_all()?;
        Ok(())
    })();

    if let Err(e) = write_result {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }

    if create_backup && path.exists() {
        rotate_encrypted_backup(path, parent)?;
    }

    if let Err(e) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(VaultError::Io(e));
    }

    if let Ok(dir_file) = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(parent)
    {
        let _ = dir_file.sync_all();
    }

    Ok(())
}

/// Keep up to `MAX_BACKUPS` encrypted rolling backups (`vault.omav.bak.1`..`.5`) atomically
/// with `0o600` permissions and UTF-8-safe `OsString` paths (never follows symlinks).
fn rotate_encrypted_backup(path: &Path, parent: &Path) -> Result<()> {
    for i in (1..MAX_BACKUPS).rev() {
        let src = append_os_suffix(path, &format!(".bak.{i}"));
        let dst = append_os_suffix(path, &format!(".bak.{}", i + 1));
        if fs::symlink_metadata(&src).is_ok() {
            fs::rename(&src, &dst)?;
        }
    }

    let existing = read_bounded_regular_file(path, MAX_VAULT_FILE_BYTES)?;
    let bak1 = append_os_suffix(path, ".bak.1");
    atomic_write_unlocked(&bak1, parent, &existing, false)?;
    Ok(())
}

/// Remove all encrypted rolling backup files (`vault.omav.bak.1`..`.5`) — used during `rekey`
/// so vaults encrypted under a compromised old master key do not linger on disk.
pub fn purge_encrypted_backups(path: &Path) -> Result<usize> {
    let mut removed = 0usize;
    for i in 1..=MAX_BACKUPS {
        let bak = append_os_suffix(path, &format!(".bak.{i}"));
        if fs::symlink_metadata(&bak).is_ok() {
            fs::remove_file(&bak)?;
            removed += 1;
        }
    }
    Ok(removed)
}

/// Read a regular file with strict `is_file()` verification and an upper byte cap
/// (prevents infinite hangs/OOM on `/dev/zero`, FIFOs, or sockets).
fn read_bounded_regular_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let file = File::open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            VaultError::VaultNotFound(path.display().to_string())
        } else {
            VaultError::Io(e)
        }
    })?;
    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        return Err(VaultError::InvalidFormat(
            "vault path must be a regular file (special files/FIFOs/devices are rejected)".into(),
        ));
    }
    if meta.len() > max_bytes {
        return Err(VaultError::InvalidFormat(format!(
            "vault file exceeds maximum allowed size ({max_bytes} bytes)"
        )));
    }
    let mut buf = Vec::with_capacity(meta.len() as usize);
    let mut limited = file.take(max_bytes.saturating_add(1));
    limited.read_to_end(&mut buf)?;
    if (buf.len() as u64) > max_bytes {
        return Err(VaultError::InvalidFormat(format!(
            "vault file exceeds maximum allowed size ({max_bytes} bytes)"
        )));
    }
    Ok(buf)
}

/// Read only the authenticated header from an encrypted vault file on disk.
pub fn read_header_from_disk(path: &Path, enforce_kdf_policy: bool) -> Result<VaultHeader> {
    let blob = read_bounded_regular_file(path, MAX_VAULT_FILE_BYTES)?;
    let (header, _) = VaultHeader::parse(&blob, enforce_kdf_policy)?;
    Ok(header)
}

/// Serialize into a pre-allocated zeroizing buffer, encrypt (rotating `save_salt` + `nonce`),
/// and atomically save the vault.
pub fn save_vault_to_disk(
    path: &Path,
    master_key: &LockedKey<32>,
    header: &mut VaultHeader,
    vault: &Vault,
) -> Result<()> {
    // Pre-allocate generous capacity to minimize heap reallocations of plaintext JSON.
    let estimated = 4096usize.saturating_add(vault.entries.len().saturating_mul(512));
    let mut plaintext = Zeroizing::new(Vec::with_capacity(estimated));
    serde_json::to_writer(&mut *plaintext, vault)
        .map_err(|_| VaultError::Serialization("failed serializing vault".into()))?;
    let blob = seal_vault(master_key, header, &plaintext)?;
    atomic_write_private(path, &blob)
}

/// Read, authenticate, decrypt, and deserialize a vault from disk.
pub fn load_vault_from_disk(
    path: &Path,
    master_key: &LockedKey<32>,
    enforce_kdf_policy: bool,
) -> Result<(VaultHeader, Vault)> {
    let blob = read_bounded_regular_file(path, MAX_VAULT_FILE_BYTES)?;
    let (header, plaintext) = open_vault(master_key, &blob, enforce_kdf_policy)?;
    let vault: Vault = serde_json::from_slice(&plaintext)
        .map_err(|_| VaultError::Serialization("failed deserializing decrypted vault".into()))?;
    Ok((header, vault))
}

/// Generate a high-entropy 64-byte (512-bit) cryptographic keyfile with `0o600` permissions,
/// cleaning up partial files on error and syncing the parent directory.
pub fn generate_keyfile(path: &Path) -> Result<()> {
    if fs::symlink_metadata(path).is_ok() {
        return Err(VaultError::VaultAlreadyExists(format!(
            "refusing to overwrite existing keyfile at {}",
            path.display()
        )));
    }
    let mut secret = Zeroizing::new([0u8; 64]);
    fill_random(&mut *secret)?;

    let parent = resolve_parent(path)?;
    ensure_private_dir(parent)?;

    let write_res = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        file.write_all(&*secret)?;
        file.sync_all()?;
        Ok(())
    })();

    if let Err(e) = write_res {
        let _ = fs::remove_file(path);
        return Err(e);
    }

    if let Ok(dir_file) = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(parent)
    {
        let _ = dir_file.sync_all();
    }

    Ok(())
}

/// Helper to keep unused `OsStringExt` import clean on Unix if needed.
#[allow(dead_code)]
fn _os_bytes(s: OsString) -> Vec<u8> {
    s.into_vec()
}
