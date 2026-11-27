//! Rollback / file-swap detection.
//!
//! Every save increments `Vault::generation` and stamps a stable `Vault::vault_id`; both live
//! INSIDE the AEAD-authenticated payload, so an attacker without the key cannot forge them.
//! An old-but-authentic vault file (an old copy, a `.bak.N`, a sync conflict, or the copy from
//! before a `fido2 remove`) still decrypts, though — so we remember, per vault **path**, the
//! highest generation and the vault ID last seen there:
//!
//! - same ID, lower generation            → rollback (refused)
//! - previously versioned, now no ID      → downgrade to a pre-v0.4 copy (refused)
//! - different ID at the same path        → a different vault was swapped in (refused)
//! - same generation, different ciphertext → swap of another save at that counter (refused)
//!
//! `--allow-rollback` accepts a deliberate restore for that open. It does **not** lower the
//! remembered generation or replace the ciphertext identity, so the next save continues at
//! `max(previous high-water, opened generation) + 1` and the restored ciphertext stays
//! unreplayable.
//!
//! Limits (documented in SECURITY.md): this protects against replacing the vault file, not
//! against an attacker who can also rewrite `~/.local/state/omavault/seen/`.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::MAX_VAULT_FILE_BYTES;
use crate::error::{Result, VaultError};
use crate::hardening::fill_random;
use crate::vault::Vault;

const MAX_RECORD_BYTES: u64 = 4096;
const DIGEST_HEX_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SeenRecord {
    vault_id: Option<Uuid>,
    max_generation: u64,
    /// BLAKE3 (hex) of the ciphertext last recorded at `max_generation`.
    /// Absent on records written before this field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ciphertext_blake3: Option<String>,
}

/// Directory-backed store of the highest generation seen per vault path.
#[derive(Debug, Clone)]
pub struct RollbackStore {
    dir: PathBuf,
}

/// Held exclusive `flock` on the sidecar lock file. The record itself is replaced by rename,
/// so the lock must live on an inode that writers do not replace.
struct RecordLock {
    _file: File,
}

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

impl RollbackStore {
    /// `$XDG_STATE_HOME/omavault/seen`, falling back to `$HOME/.local/state/omavault/seen`.
    pub fn from_env() -> Option<Self> {
        let base = std::env::var_os("XDG_STATE_HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME")
                    .filter(|v| !v.is_empty())
                    .map(|h| PathBuf::from(h).join(".local").join("state"))
            })?;
        Some(Self::in_dir(base.join("omavault").join("seen")))
    }

    pub fn in_dir(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn record_path(&self, vault_path: &Path) -> PathBuf {
        let canonical = canonical_vault_path(vault_path);
        let mut h = blake3::Hasher::new();
        h.update(b"omavault-seen-path-v1\0");
        h.update(canonical.as_os_str().as_bytes());
        let hex = h.finalize().to_hex();
        self.dir.join(&hex.as_str()[..32])
    }

    fn lock_path(&self, vault_path: &Path) -> PathBuf {
        let mut os = self.record_path(vault_path).into_os_string();
        os.push(".lock");
        PathBuf::from(os)
    }

    fn ensure_dir(&self) -> Result<()> {
        if !self.dir.exists() {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&self.dir)?;
        }
        let meta = fs::symlink_metadata(&self.dir)?;
        let me = unsafe { libc::geteuid() };
        if !meta.file_type().is_dir() || meta.uid() != me || (meta.mode() & 0o022) != 0 {
            return Err(VaultError::Hardening(format!(
                "rollback state directory '{}' must be a private directory owned by you",
                self.dir.display()
            )));
        }
        Ok(())
    }

    fn acquire_lock(&self, vault_path: &Path) -> Result<RecordLock> {
        self.ensure_dir()?;
        let path = self.lock_path(vault_path);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)?;
        let meta = file.metadata()?;
        let me = unsafe { libc::geteuid() };
        // Reject a hard link BEFORE fchmod, which would otherwise change the other name.
        if !meta.file_type().is_file() || meta.uid() != me || meta.nlink() != 1 {
            return Err(VaultError::Hardening(
                "rollback state lock is not a private regular file".into(),
            ));
        }
        let _ = unsafe { libc::fchmod(file.as_raw_fd(), 0o600) };
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(VaultError::Io(std::io::Error::last_os_error()));
        }
        Ok(RecordLock { _file: file })
    }

    /// Highest generation recorded for `vault_path`, or 0 when no record exists.
    ///
    /// Read-only: does not create the state directory or a record. A non-empty unparseable
    /// record is an error, not "nothing seen yet".
    pub fn high_water(&self, vault_path: &Path) -> Result<u64> {
        if !self.dir.exists() {
            return Ok(0);
        }
        let path = self.record_path(vault_path);
        if !path.exists() {
            return Ok(0);
        }
        Ok(read_record(&path)?.map(|r| r.max_generation).unwrap_or(0))
    }

    /// Verify `vault` (just decrypted from `vault_path`) is not older than what we have seen
    /// there, then record it when the high-water mark moves forward.
    ///
    /// With `allow_rollback`, an older or swapped file is accepted for this call and the
    /// on-disk high-water mark is left unchanged.
    pub fn check(&self, vault_path: &Path, vault: &Vault, allow_rollback: bool) -> Result<()> {
        let _lock = self.acquire_lock(vault_path)?;
        let path = self.record_path(vault_path);
        let seen = read_record(&path)?;
        let digest = ciphertext_blake3(vault_path)?;
        let next = match seen {
            None => SeenRecord {
                vault_id: vault.vault_id,
                max_generation: vault.generation,
                ciphertext_blake3: digest,
            },
            Some(ref prev) => match evaluate(prev, vault, digest.as_deref(), vault_path)? {
                Eval::Reject(msg) if !allow_rollback => {
                    return Err(VaultError::RollbackDetected(msg));
                }
                Eval::Reject(_) => return Ok(()),
                Eval::Keep => return Ok(()),
                Eval::Advance(rec) => rec,
            },
        };
        if seen.as_ref() != Some(&next) {
            write_record_atomic(&self.dir, &path, &next)?;
        }
        Ok(())
    }

    /// Record a vault we just wrote. Never lowers `max_generation`.
    pub fn record(&self, vault_path: &Path, vault: &Vault) -> Result<()> {
        let _lock = self.acquire_lock(vault_path)?;
        let path = self.record_path(vault_path);
        let seen = read_record(&path)?;
        if let Some(prev) = &seen {
            if vault.generation < prev.max_generation {
                return Ok(());
            }
        }
        let digest = ciphertext_blake3(vault_path)?;
        let next = SeenRecord {
            vault_id: vault.vault_id.or(seen.as_ref().and_then(|p| p.vault_id)),
            max_generation: seen
                .as_ref()
                .map(|p| p.max_generation)
                .unwrap_or(0)
                .max(vault.generation),
            ciphertext_blake3: digest.or(seen.and_then(|p| p.ciphertext_blake3)),
        };
        write_record_atomic(&self.dir, &path, &next)?;
        Ok(())
    }
}

enum Eval {
    /// Caller should refuse (unless `--allow-rollback`, which then writes nothing).
    Reject(String),
    /// High-water mark already covers this file.
    Keep,
    /// Persist this record (generation moved forward, or a missing digest was filled in).
    Advance(SeenRecord),
}

fn evaluate(
    prev: &SeenRecord,
    vault: &Vault,
    digest: Option<&str>,
    vault_path: &Path,
) -> Result<Eval> {
    if let Some(stored) = prev.ciphertext_blake3.as_deref() {
        validate_digest(stored)?;
    }
    match (prev.vault_id, vault.vault_id) {
        (Some(a), Some(b)) if a != b => {
            return Ok(Eval::Reject(format!(
                "a DIFFERENT vault (id {b}) is now at '{}' where vault {a} was last seen",
                vault_path.display()
            )));
        }
        (Some(_), None) => {
            return Ok(Eval::Reject(format!(
                "'{}' is an older unversioned (pre-v0.4) copy of a vault last seen at generation {}",
                vault_path.display(),
                prev.max_generation
            )));
        }
        _ => {}
    }
    if vault.generation < prev.max_generation {
        return Ok(Eval::Reject(format!(
            "'{}' is generation {} but generation {} was already seen (an older copy was restored)",
            vault_path.display(),
            vault.generation,
            prev.max_generation
        )));
    }
    if vault.generation == prev.max_generation {
        if let (Some(stored), Some(current)) = (prev.ciphertext_blake3.as_deref(), digest) {
            if stored != current {
                return Ok(Eval::Reject(format!(
                    "'{}' matches generation {} but is a different ciphertext than the one last saved there",
                    vault_path.display(),
                    vault.generation
                )));
            }
        }
        if prev.ciphertext_blake3.is_none() && digest.is_some() {
            return Ok(Eval::Advance(SeenRecord {
                vault_id: vault.vault_id.or(prev.vault_id),
                max_generation: prev.max_generation,
                ciphertext_blake3: digest.map(str::to_string),
            }));
        }
        return Ok(Eval::Keep);
    }
    Ok(Eval::Advance(SeenRecord {
        vault_id: vault.vault_id.or(prev.vault_id),
        max_generation: vault.generation,
        ciphertext_blake3: digest.map(str::to_string),
    }))
}

/// Canonical path, including before the vault file itself exists (create).
fn canonical_vault_path(vault_path: &Path) -> PathBuf {
    if let Ok(c) = fs::canonicalize(vault_path) {
        return c;
    }
    if let (Some(parent), Some(name)) = (vault_path.parent(), vault_path.file_name()) {
        if let Ok(parent) = fs::canonicalize(parent) {
            return parent.join(name);
        }
    }
    vault_path.to_path_buf()
}

fn validate_digest(stored: &str) -> Result<()> {
    if stored.len() == DIGEST_HEX_LEN && stored.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(corrupt_record())
    }
}

fn is_corrupt_record(err: &VaultError) -> bool {
    matches!(
        err,
        VaultError::Hardening(msg) if msg.contains("rollback state record is corrupt")
    )
}

fn corrupt_record() -> VaultError {
    VaultError::Hardening(
        "rollback state record is corrupt; refusing to treat it as a first open".into(),
    )
}

/// Absent or empty → `Ok(None)`. Non-empty and unparseable → error.
fn read_record(path: &Path) -> Result<Option<SeenRecord>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(VaultError::Io(e)),
    };
    let meta = file.metadata()?;
    let me = unsafe { libc::geteuid() };
    if !meta.file_type().is_file() || meta.uid() != me || meta.nlink() != 1 {
        return Err(VaultError::Hardening(
            "rollback state record is not a private regular file".into(),
        ));
    }
    if meta.len() == 0 {
        return Ok(None);
    }
    if meta.len() > MAX_RECORD_BYTES {
        return Err(corrupt_record());
    }
    let mut s = String::new();
    (&file).take(MAX_RECORD_BYTES).read_to_string(&mut s)?;
    if s.trim().is_empty() {
        return Ok(None);
    }
    match serde_json::from_str::<SeenRecord>(&s) {
        Ok(rec) => {
            if let Some(d) = rec.ciphertext_blake3.as_deref() {
                validate_digest(d)?;
            }
            Ok(Some(rec))
        }
        Err(_) => Err(corrupt_record()),
    }
}

fn write_record_atomic(dir: &Path, record_path: &Path, rec: &SeenRecord) -> Result<()> {
    let body =
        serde_json::to_vec(rec).map_err(|_| VaultError::Serialization("rollback record".into()))?;
    let name = record_path
        .file_name()
        .ok_or_else(|| VaultError::InvalidFormat("rollback record has no file name".into()))?;
    let mut suffix = [0u8; 8];
    fill_random(&mut suffix)?;
    let hex_suffix: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(name);
    tmp_name.push(format!(".tmp.{hex_suffix}"));
    let tmp_path = dir.join(tmp_name);

    let mut tmp = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp_path)?;
    let mut guard = TempFileGuard::new(tmp_path.clone());
    tmp.write_all(&body)?;
    tmp.sync_all()?;
    drop(tmp);

    fs::rename(&tmp_path, record_path)?;
    guard.disarm();

    let dir_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(dir)?;
    dir_file.sync_all()?;
    Ok(())
}

fn ciphertext_blake3(path: &Path) -> Result<Option<String>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(VaultError::Io(e)),
    };
    let meta = file.metadata()?;
    if !meta.file_type().is_file() || meta.nlink() != 1 {
        return Err(VaultError::Hardening(
            "refusing to hash a vault path that is not a regular unlinked file".into(),
        ));
    }
    if meta.len() == 0 {
        return Ok(None);
    }
    if meta.len() > MAX_VAULT_FILE_BYTES {
        return Err(VaultError::InvalidFormat(
            "vault file exceeds maximum size while recording rollback state".into(),
        ));
    }
    let mut bytes = Vec::new();
    (&file).take(MAX_VAULT_FILE_BYTES).read_to_end(&mut bytes)?;
    Ok(Some(blake3::hash(&bytes).to_hex().to_string()))
}

/// Generation stamped on the next save so a restored older vault cannot reuse a counter
/// that was already published.
pub fn next_save_generation(seen_max: u64, opened_generation: u64) -> u64 {
    seen_max.max(opened_generation).saturating_add(1)
}

/// Apply the rollback policy using an explicit store (or `from_env()` when `None`).
///
/// Only a DETECTED rollback is fatal. I/O problems with the state store itself (read-only home,
/// unusual permissions) produce a warning and do not block unlocking — an attacker able to break
/// the store could simply delete it anyway, so failing closed would add no security.
/// A **corrupt** record is not that case: it is returned to the caller so it cannot be mistaken
/// for a first open and overwritten with a lower generation.
pub fn enforce_rollback_policy(
    store: Option<&RollbackStore>,
    vault_path: &Path,
    vault: &Vault,
    allow_rollback: bool,
) -> Result<()> {
    let owned;
    let store = match store {
        Some(s) => s,
        None => match RollbackStore::from_env() {
            Some(s) => {
                owned = s;
                &owned
            }
            None => return Ok(()),
        },
    };
    match store.check(vault_path, vault, allow_rollback) {
        Err(e @ VaultError::RollbackDetected(_)) => Err(e),
        Err(e) if is_corrupt_record(&e) => Err(e),
        Err(e) => {
            crate::error::warn(&format!("rollback detection unavailable: {e}"));
            Ok(())
        }
        Ok(()) => Ok(()),
    }
}

/// Record a freshly saved vault (best effort; a detected rollback is not expected here).
pub fn record_saved_vault(store: Option<&RollbackStore>, vault_path: &Path, vault: &Vault) {
    let owned;
    let store = match store {
        Some(s) => s,
        None => match RollbackStore::from_env() {
            Some(s) => {
                owned = s;
                &owned
            }
            None => return,
        },
    };
    if let Err(e) = store.record(vault_path, vault) {
        crate::error::warn(&format!("rollback detection unavailable: {e}"));
    }
}
