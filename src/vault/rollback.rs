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
//!
//! `--allow-rollback` accepts the file once and resets the record.
//!
//! Limits (documented in SECURITY.md): this protects against replacing the vault file, not
//! against an attacker who can also rewrite `~/.local/state/omavault/seen/`.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{Result, VaultError};
use crate::vault::Vault;

const MAX_RECORD_BYTES: u64 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct SeenRecord {
    vault_id: Option<Uuid>,
    max_generation: u64,
}

/// Directory-backed store of the highest generation seen per vault path.
#[derive(Debug, Clone)]
pub struct RollbackStore {
    dir: PathBuf,
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
        let canonical = fs::canonicalize(vault_path).unwrap_or_else(|_| vault_path.to_path_buf());
        let mut h = blake3::Hasher::new();
        h.update(b"omavault-seen-path-v1\0");
        h.update(canonical.as_os_str().as_bytes());
        let hex = h.finalize().to_hex();
        self.dir.join(&hex.as_str()[..32])
    }

    fn open_locked(&self, vault_path: &Path) -> Result<File> {
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
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(self.record_path(vault_path))?;
        let fmeta = file.metadata()?;
        if !fmeta.file_type().is_file() || fmeta.uid() != me || fmeta.nlink() != 1 {
            return Err(VaultError::Hardening(
                "rollback state record is not a private regular file".into(),
            ));
        }
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(VaultError::Io(std::io::Error::last_os_error()));
        }
        Ok(file)
    }

    fn read(file: &mut File) -> Option<SeenRecord> {
        let mut s = String::new();
        file.seek(SeekFrom::Start(0)).ok()?;
        file.take(MAX_RECORD_BYTES).read_to_string(&mut s).ok()?;
        if s.trim().is_empty() {
            return None;
        }
        serde_json::from_str(&s).ok()
    }

    fn write(file: &mut File, rec: SeenRecord) -> Result<()> {
        let body = serde_json::to_vec(&rec)
            .map_err(|_| VaultError::Serialization("rollback record".into()))?;
        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&body)?;
        file.sync_all()?;
        Ok(())
    }

    /// Verify `vault` (just decrypted from `vault_path`) is not older than what we have seen
    /// there, then record it. With `allow_rollback`, accept and reset the record.
    pub fn check(&self, vault_path: &Path, vault: &Vault, allow_rollback: bool) -> Result<()> {
        let mut file = self.open_locked(vault_path)?;
        let seen = Self::read(&mut file);
        let current = SeenRecord {
            vault_id: vault.vault_id,
            max_generation: vault.generation,
        };
        let next = match seen {
            None => current,
            Some(_) if allow_rollback => current,
            Some(prev) => {
                match (prev.vault_id, vault.vault_id) {
                    (Some(a), Some(b)) if a != b => {
                        return Err(VaultError::RollbackDetected(format!(
                            "a DIFFERENT vault (id {b}) is now at '{}' where vault {a} was last seen",
                            vault_path.display()
                        )));
                    }
                    (Some(_), None) => {
                        return Err(VaultError::RollbackDetected(format!(
                            "'{}' is an older unversioned (pre-v0.4) copy of a vault last seen at generation {}",
                            vault_path.display(),
                            prev.max_generation
                        )));
                    }
                    (Some(_), Some(_)) if vault.generation < prev.max_generation => {
                        return Err(VaultError::RollbackDetected(format!(
                            "'{}' is generation {} but generation {} was already seen (an older copy was restored)",
                            vault_path.display(),
                            vault.generation,
                            prev.max_generation
                        )));
                    }
                    _ => {}
                }
                SeenRecord {
                    vault_id: vault.vault_id.or(prev.vault_id),
                    max_generation: prev.max_generation.max(vault.generation),
                }
            }
        };
        if seen != Some(next) {
            Self::write(&mut file, next)?;
        }
        Ok(())
    }

    /// Record a vault we just wrote (never errors on "rollback": we are the writer).
    pub fn record(&self, vault_path: &Path, vault: &Vault) -> Result<()> {
        self.check(vault_path, vault, true)
    }
}

/// Apply the rollback policy using an explicit store (or `from_env()` when `None`).
///
/// Only a DETECTED rollback is fatal. I/O problems with the state store itself (read-only home,
/// unusual permissions) produce a warning and do not block unlocking — an attacker able to break
/// the store could simply delete it anyway, so failing closed would add no security.
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
        Err(e) => {
            crate::error::warn(&format!("rollback detection unavailable: {e}"));
            Ok(())
        }
        Ok(()) => Ok(()),
    }
}

/// Record a freshly saved vault (best effort; see [`enforce_rollback_policy`]).
pub fn record_saved_vault(store: Option<&RollbackStore>, vault_path: &Path, vault: &Vault) {
    let _ = enforce_rollback_policy(store, vault_path, vault, true);
}
