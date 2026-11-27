use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use directories::ProjectDirs;
use zeroize::Zeroizing;

use crate::crypto::kdf::{derive_master_key_from_pw_hash, derive_passphrase_hash};
use crate::crypto::{
    header_revision, open_vault, seal_vault, unwrap_master_key_from_slot, VaultHeader,
    MAX_VAULT_FILE_BYTES, VAULT_VERSION_V1, VAULT_VERSION_V2,
};
use crate::error::{Result, VaultError};
use crate::hardening::{fill_random, CountingWriter, LockedKey};
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
/// verifying ownership by current `euid`, rejecting group/world-writable directories,
/// and applying `fchmod(0o700)` on the open fd when creating or enforcing dedicated dirs.
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
                format!(
                    "private directory '{}' rejected (symlink or inaccessible): {e}",
                    dir.display()
                ),
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
    } else if (meta.mode() & 0o022) != 0 {
        return Err(VaultError::Hardening(format!(
            "directory '{}' is group/world-writable (mode {:04o})",
            dir.display(),
            meta.mode() & 0o7777
        )));
    }

    Ok(())
}

/// Ensure a dedicated `omavault` directory exists with strict `0o700` owner-only permissions.
pub fn ensure_private_dir(dir: &Path) -> Result<()> {
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
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&lock_path)?;
        let meta = file.metadata()?;
        let my_uid = unsafe { libc::geteuid() };
        if !meta.file_type().is_file() || meta.uid() != my_uid {
            return Err(VaultError::Hardening(format!(
                "lock file '{}' is not a regular file owned by current user",
                lock_path.display()
            )));
        }
        let rc_chmod = unsafe { libc::fchmod(file.as_raw_fd(), 0o600) };
        if rc_chmod != 0 {
            return Err(VaultError::Io(std::io::Error::last_os_error()));
        }
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

/// RAII temp-file guard that unlinks the temporary path on any error or unwind unless disarmed.
struct TempFileGuard {
    path: Option<PathBuf>,
}

impl TempFileGuard {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Some(p) = self.path.take() {
            let _ = fs::remove_file(p);
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
    atomic_write_unlocked(path, parent, data, true, false)
}

/// Write `data` to `path` via a fsynced `0600` temp file.
///
/// With `no_replace`, the temp file is published with `link(2)` (fails atomically with
/// `EEXIST`) instead of `rename(2)`, so an existing vault can never be overwritten.
fn atomic_write_unlocked(
    path: &Path,
    parent: &Path,
    data: &[u8],
    create_backup: bool,
    no_replace: bool,
) -> Result<()> {
    let mut suffix = [0u8; 8];
    fill_random(&mut suffix)?;
    let hex_suffix: String = suffix.iter().map(|b| format!("{b:02x}")).collect();

    let mut tmp_name = OsString::from(".");
    tmp_name.push(
        path.file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("vault.omav")),
    );
    tmp_name.push(format!(".tmp.{hex_suffix}"));
    let tmp_path = parent.join(tmp_name);

    let mut tmp_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp_path)?;
    let mut tmp_guard = TempFileGuard::new(tmp_path.clone());

    tmp_file.write_all(data)?;
    tmp_file.sync_all()?;
    drop(tmp_file);

    if create_backup {
        if let Ok(meta) = fs::symlink_metadata(path) {
            if !meta.file_type().is_file() {
                return Err(VaultError::InvalidFormat(
                    "refusing to back up symlink or non-regular vault path".into(),
                ));
            }
            rotate_encrypted_backup(path, parent)?;
        }
    }

    if no_replace {
        // TempFileGuard removes the temp name on every path (success or EEXIST).
        fs::hard_link(&tmp_path, path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                VaultError::VaultAlreadyExists(path.display().to_string())
            } else {
                VaultError::Io(e)
            }
        })?;
    } else {
        fs::rename(&tmp_path, path)?;
        tmp_guard.disarm();
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
///
/// Reads `path` FIRST so a read error can never shift/destroy `.bak.5`.
fn rotate_encrypted_backup(path: &Path, parent: &Path) -> Result<()> {
    let existing = read_bounded_regular_file(path, MAX_VAULT_FILE_BYTES)?;

    for i in (1..MAX_BACKUPS).rev() {
        let src = append_os_suffix(path, &format!(".bak.{i}"));
        let dst = append_os_suffix(path, &format!(".bak.{}", i + 1));
        if fs::symlink_metadata(&src).is_ok() {
            fs::rename(&src, &dst)?;
        }
    }

    let bak1 = append_os_suffix(path, ".bak.1");
    atomic_write_unlocked(&bak1, parent, &existing, false, false)?;
    Ok(())
}

/// Remove all encrypted rolling backup files (`vault.omav.bak.1`..`.5`) under exclusive `flock`
/// so vaults encrypted under a compromised old master key do not linger on disk.
pub fn purge_encrypted_backups(path: &Path) -> Result<usize> {
    let parent = resolve_parent(path)?;
    ensure_private_dir(parent)?;
    let _lock = FileLockGuard::acquire(path)?;
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

/// Read a regular file with `O_NONBLOCK | O_NOFOLLOW`, strict `is_file()` verification, and
/// an upper byte cap (prevents infinite blocking on FIFOs, symlink following, and OOM).
fn read_bounded_regular_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| {
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

/// Serialize `vault` into an exact-size `Zeroizing<Vec<u8>>` without intermediate `Vec` reallocations.
fn serialize_vault_exact(vault: &Vault) -> Result<Zeroizing<Vec<u8>>> {
    let mut counter = CountingWriter::default();
    serde_json::to_writer(&mut counter, vault)
        .map_err(|_| VaultError::Serialization("failed measuring vault payload".into()))?;
    let mut plaintext = Zeroizing::new(Vec::with_capacity(counter.bytes));
    serde_json::to_writer(&mut *plaintext, vault)
        .map_err(|_| VaultError::Serialization("failed serializing vault".into()))?;
    Ok(plaintext)
}

/// Atomically verify `expected_revision` (when provided), serialize without realloc copies,
/// seal (rotating `save_salt` + `nonce`), and write to disk under ONE exclusive `flock(LOCK_EX)`.
///
/// The caller's `header` is authoritative and is NEVER replaced by the on-disk header: callers
/// such as `rekey` and `fido2 add/remove` intentionally write a different header (new KDF salt,
/// key slots, or version). `header` is only updated (with the rotated `save_salt`/`nonce`) after
/// the new file has been durably committed, so a failed write leaves it in sync with disk.
pub fn save_vault_to_disk_checked(
    path: &Path,
    master_key: &LockedKey<32>,
    header: &mut VaultHeader,
    vault: &Vault,
    expected_revision: Option<&str>,
    enforce_kdf_policy: bool,
    create_backup: bool,
) -> Result<()> {
    let parent = resolve_parent(path)?;
    ensure_private_dir(parent)?;
    let _lock = FileLockGuard::acquire(path)?;

    if let Some(expected) = expected_revision {
        let disk_hdr = read_header_from_disk(path, enforce_kdf_policy)?;
        if header_revision(&disk_hdr) != expected {
            return Err(VaultError::Daemon(
                "vault was modified concurrently on disk; reload and retry".into(),
            ));
        }
    }

    let plaintext = serialize_vault_exact(vault)?;
    let mut next_header = header.clone();
    let blob = seal_vault(master_key, &mut next_header, &plaintext)?;
    atomic_write_unlocked(path, parent, &blob, create_backup, false)?;
    *header = next_header;
    Ok(())
}

/// Serialize into an exact-size zeroizing buffer, encrypt (rotating `save_salt` + `nonce`),
/// and atomically save the vault with rolling backups.
pub fn save_vault_to_disk(
    path: &Path,
    master_key: &LockedKey<32>,
    header: &mut VaultHeader,
    vault: &Vault,
) -> Result<()> {
    save_vault_to_disk_checked(path, master_key, header, vault, None, false, true)
}

/// Create a brand-new vault file, failing with `VaultAlreadyExists` (never overwriting) if any
/// file already exists at `path` — checked under the vault `flock` and enforced atomically by
/// publishing with `link(2)`.
pub fn create_new_vault_on_disk(
    path: &Path,
    master_key: &LockedKey<32>,
    header: &mut VaultHeader,
    vault: &Vault,
) -> Result<()> {
    let parent = resolve_parent(path)?;
    ensure_private_dir(parent)?;
    let _lock = FileLockGuard::acquire(path)?;
    if fs::symlink_metadata(path).is_ok() {
        return Err(VaultError::VaultAlreadyExists(path.display().to_string()));
    }

    let plaintext = serialize_vault_exact(vault)?;
    let mut next_header = header.clone();
    let blob = seal_vault(master_key, &mut next_header, &plaintext)?;
    atomic_write_unlocked(path, parent, &blob, false, true)?;
    *header = next_header;
    Ok(())
}

/// Independently re-open a freshly written vault from disk using ONLY user credentials,
/// before any old-key backups are purged.
///
/// This deliberately does not trust the in-memory master key: it
/// 1. requires the on-disk header to be byte-identical to `expected_header` (the header that
///    was just written: version, flags, KDF params, `kdf_salt`, key slots),
/// 2. re-runs Argon2id against the ON-DISK `kdf_salt` / KDF params,
/// 3. re-derives (v1) or unwraps (v2, via the slot labelled `fido2_slot_secret.0`) the master
///    key from the on-disk header, and
/// 4. authenticates + decrypts the payload with that re-derived key and checks the entry count.
pub fn verify_saved_vault(
    path: &Path,
    expected_header: &VaultHeader,
    passphrase: &[u8],
    keyfile_digest: Option<&[u8; 32]>,
    fido2_slot_secret: Option<(&str, &[u8; 32])>,
    expected_entries: usize,
    enforce_kdf_policy: bool,
) -> Result<()> {
    let fail = |what: &str| {
        VaultError::InvalidFormat(format!(
            "post-save verification failed: {what}; old backups were NOT purged"
        ))
    };

    let disk_hdr = read_header_from_disk(path, enforce_kdf_policy)?;
    if disk_hdr.to_bytes()? != expected_header.to_bytes()? {
        return Err(fail(
            "on-disk header does not match the header that was written",
        ));
    }

    let pw_hash = derive_passphrase_hash(
        passphrase,
        &disk_hdr.kdf_salt,
        disk_hdr.kdf_params,
        enforce_kdf_policy,
    )?;
    let key = match disk_hdr.version {
        VAULT_VERSION_V1 => {
            let fido2 = if disk_hdr.requires_fido2() {
                Some(
                    fido2_slot_secret
                        .map(|(_, s)| s)
                        .ok_or_else(|| fail("missing FIDO2 secret for v1 vault"))?,
                )
            } else {
                None
            };
            derive_master_key_from_pw_hash(&pw_hash, &disk_hdr.kdf_salt, keyfile_digest, fido2)?
        }
        VAULT_VERSION_V2 => {
            let (label, secret) =
                fido2_slot_secret.ok_or_else(|| fail("missing FIDO2 secret for v2 vault"))?;
            let slot = disk_hdr
                .fido2_slots
                .iter()
                .find(|s| s.label.eq_ignore_ascii_case(label))
                .ok_or_else(|| fail("expected FIDO2 key slot is missing from disk header"))?;
            unwrap_master_key_from_slot(&disk_hdr, slot, &pw_hash, keyfile_digest, secret)
                .map_err(|_| fail("could not unwrap master key from on-disk key slot"))?
        }
        other => return Err(VaultError::UnsupportedVersion(other)),
    };

    let (_, vault) = load_vault_from_disk(path, &key, enforce_kdf_policy)
        .map_err(|_| fail("vault does not decrypt with re-derived credentials"))?;
    if vault.entries.len() != expected_entries {
        return Err(fail("entry count mismatch after save"));
    }
    Ok(())
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
/// atomically refusing to overwrite (or delete!) any pre-existing keyfile on `EEXIST`.
pub fn generate_keyfile(path: &Path) -> Result<()> {
    let mut secret = Zeroizing::new([0u8; 64]);
    fill_random(&mut *secret)?;

    let parent = resolve_parent(path)?;
    ensure_private_dir(parent)?;

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                VaultError::VaultAlreadyExists(format!(
                    "refusing to overwrite existing keyfile at {}",
                    path.display()
                ))
            } else {
                VaultError::Io(e)
            }
        })?;

    // Only register cleanup guard AFTER `create_new` succeeded so a pre-existing file is never deleted.
    let mut guard = TempFileGuard::new(path.to_path_buf());
    file.write_all(&*secret)?;
    file.sync_all()?;
    drop(file);
    guard.disarm();

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
