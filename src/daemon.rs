use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::clipboard::clear_clipboard_best_effort;
use crate::crypto::fido2::{Fido2Provider, LibFido2Cli};
use crate::crypto::kdf::{derive_master_key, hash_keyfile};
use crate::crypto::VaultHeader;
use crate::error::{Result, VaultError};
use crate::hardening::{
    boottime_monotonic_skew_ms, boottime_secs, is_screen_locker_active, LockedKey,
};
use crate::vault::storage::{
    ensure_private_dir_strict, load_vault_from_disk, read_header_from_disk, save_vault_to_disk,
};
use crate::vault::Vault;

pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 300; // 5 minutes
const MAX_IPC_FRAME_BYTES: usize = 16 * 1024 * 1024;
const MAX_CONCURRENT_WORKERS: usize = 8;
const IPC_FRAME_DEADLINE: Duration = Duration::from_secs(10);
const SUSPEND_SKEW_THRESHOLD_MS: u64 = 2000;

/// Default runtime path for the daemon Unix socket:
/// 1. `$OMAVAULT_SOCKET` if explicitly set
/// 2. `$XDG_RUNTIME_DIR/omavault/daemon.sock` (tmpfs, owner-only `0700`)
/// 3. `$HOME/.local/state/omavault/daemon.sock` (never `/tmp`!)
pub fn default_socket_path() -> PathBuf {
    if let Ok(path) = std::env::var("OMAVAULT_SOCKET") {
        if !path.trim().is_empty() {
            return PathBuf::from(path);
        }
    }
    if let Ok(runtime) = std::env::var("XDG_RUNTIME_DIR") {
        if !runtime.trim().is_empty() {
            return PathBuf::from(runtime).join("omavault").join("daemon.sock");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.trim().is_empty() {
            return PathBuf::from(home)
                .join(".local")
                .join("state")
                .join("omavault")
                .join("daemon.sock");
        }
    }
    PathBuf::from(".omavault-daemon.sock")
}

/// Serde-compatible zeroizing string wrapper so secrets in IPC requests never linger unzeroized.
#[derive(Clone, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct SecretString(pub String);

#[derive(Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum DaemonRequest {
    Status,
    Unlock {
        vault_path: PathBuf,
        passphrase: SecretString,
        keyfile_path: Option<PathBuf>,
        fido2_device: Option<String>,
    },
    Lock,
    LoadVault {
        vault_path: PathBuf,
    },
    SaveVault {
        vault_path: PathBuf,
        vault: Vault,
        #[serde(default)]
        expected_revision: Option<String>,
    },
    Shutdown,
}

impl Zeroize for DaemonRequest {
    fn zeroize(&mut self) {
        match self {
            DaemonRequest::Unlock { passphrase, .. } => passphrase.zeroize(),
            DaemonRequest::SaveVault { vault, .. } => vault.zeroize(),
            _ => {}
        }
    }
}

/// CRITICAL: Explicit `Drop` impl guarantees `DaemonRequest::zeroize()` ALWAYS executes on drop.
impl Drop for DaemonRequest {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DaemonRequest {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub unlocked: bool,
    pub vault_path: Option<PathBuf>,
    pub remaining_secs: u64,
    pub idle_timeout_secs: u64,
    pub mlocked: bool,
    pub guard_protected: bool,
    pub last_lock_reason: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum DaemonResponse {
    Ok,
    Status(DaemonStatus),
    Vault {
        vault: Vault,
        #[serde(default)]
        revision: String,
    },
    Error {
        message: String,
    },
}

struct UnlockedSession {
    vault_path: PathBuf,
    master_key: LockedKey<32>,
    header: VaultHeader,
    /// Last activity recorded on `CLOCK_BOOTTIME` (advances during suspend!).
    last_activity_boot_secs: u64,
}

struct DaemonState {
    session: Option<UnlockedSession>,
    idle_timeout_secs: u64,
    last_lock_reason: Option<String>,
    shutdown_requested: bool,
}

impl DaemonState {
    fn new(idle_timeout_secs: u64) -> Self {
        Self {
            session: None,
            idle_timeout_secs,
            last_lock_reason: None,
            shutdown_requested: false,
        }
    }

    /// Drop the unlocked session (triggering volatile-zeroize + munlock + munmap).
    /// Returns `true` if a session was active so the caller clears clipboard *outside* the mutex.
    fn lock_inner(&mut self, reason: &str) -> bool {
        if self.session.take().is_some() {
            self.last_lock_reason = Some(reason.to_string());
            true
        } else {
            false
        }
    }

    fn status(&self) -> DaemonStatus {
        match &self.session {
            Some(s) => {
                let now = current_boot_secs();
                let elapsed = now.saturating_sub(s.last_activity_boot_secs);
                let remaining = self.idle_timeout_secs.saturating_sub(elapsed);
                DaemonStatus {
                    unlocked: true,
                    vault_path: Some(s.vault_path.clone()),
                    remaining_secs: remaining,
                    idle_timeout_secs: self.idle_timeout_secs,
                    mlocked: s.master_key.is_mlocked(),
                    guard_protected: s.master_key.is_guard_protected(),
                    last_lock_reason: self.last_lock_reason.clone(),
                }
            }
            None => DaemonStatus {
                unlocked: false,
                vault_path: None,
                remaining_secs: 0,
                idle_timeout_secs: self.idle_timeout_secs,
                mlocked: false,
                guard_protected: false,
                last_lock_reason: self.last_lock_reason.clone(),
            },
        }
    }
}

fn current_boot_secs() -> u64 {
    boottime_secs().unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    })
}

fn header_revision(header: &VaultHeader) -> String {
    header.save_salt.iter().map(|b| format!("{b:02x}")).collect()
}

/// Exclusive non-blocking lockfile ensuring two daemons never race or orphan each other's socket.
struct DaemonInstanceLock {
    _file: File,
}

impl DaemonInstanceLock {
    fn acquire(socket_path: &Path) -> Result<Self> {
        let parent = socket_path
            .parent()
            .ok_or_else(|| VaultError::Daemon("invalid socket path".into()))?;
        let lock_path = parent.join("daemon.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&lock_path)?;
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            return Err(VaultError::Daemon(
                "another omavault daemon instance is already running for this socket".into(),
            ));
        }
        Ok(Self { _file: file })
    }
}

/// Run the auto-locking background daemon listening on `socket_path`.
pub fn run_daemon(
    socket_path: &Path,
    idle_timeout_secs: u64,
    enforce_kdf_policy: bool,
) -> Result<()> {
    let parent = socket_path
        .parent()
        .ok_or_else(|| VaultError::Daemon("invalid socket path".into()))?;
    ensure_private_dir_strict(parent, true)?;

    // Acquire exclusive instance lock BEFORE touching any existing socket file.
    let _instance_lock = DaemonInstanceLock::acquire(socket_path)?;

    let my_uid = unsafe { libc::geteuid() };

    // Only unlink stale socket if symlink_metadata confirms it is actually a Unix socket.
    if let Ok(meta) = fs::symlink_metadata(socket_path) {
        if meta.file_type().is_socket() {
            fs::remove_file(socket_path)?;
        } else {
            return Err(VaultError::Daemon(format!(
                "refusing to unlink non-socket path '{}'",
                socket_path.display()
            )));
        }
    }

    // Set restrictive umask defensively (even for library callers) before bind.
    let old_umask = unsafe { libc::umask(0o077) };
    let bind_res = UnixListener::bind(socket_path);
    unsafe {
        libc::umask(old_umask);
    }
    let listener = bind_res
        .map_err(|e| VaultError::Daemon(format!("failed binding daemon socket: {e}")))?;
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;

    let state = Arc::new(Mutex::new(DaemonState::new(idle_timeout_secs.max(10))));
    let io_lock = Arc::new(Mutex::new(()));
    let active_workers = Arc::new(AtomicUsize::new(0));
    let signal_stop = Arc::new(AtomicBool::new(false));

    // Register graceful shutdown signal handlers (SIGTERM, SIGINT, SIGHUP).
    let _ = signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&signal_stop));
    let _ = signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&signal_stop));
    let _ = signal_hook::flag::register(signal_hook::consts::SIGHUP, Arc::clone(&signal_stop));

    // Spawn security watchdog thread (CLOCK_BOOTTIME idle timeout, /proc/status Hyprlock,
    // and CLOCK_BOOTTIME - CLOCK_MONOTONIC suspend/resume detection).
    let watchdog_state = Arc::clone(&state);
    let watchdog_signal = Arc::clone(&signal_stop);
    let watchdog_handle = thread::spawn(move || {
        let mut last_sleep_skew = boottime_monotonic_skew_ms();
        loop {
            thread::sleep(Duration::from_secs(1));

            if watchdog_signal.load(Ordering::SeqCst) {
                let should_clear = watchdog_state
                    .lock()
                    .map(|mut g| {
                        g.shutdown_requested = true;
                        g.lock_inner("signal shutdown")
                    })
                    .unwrap_or(false);
                if should_clear {
                    clear_clipboard_best_effort();
                }
                break;
            }

            let current_skew = boottime_monotonic_skew_ms();
            let slept = match (last_sleep_skew, current_skew) {
                (Some(prev), Some(curr)) => curr.saturating_sub(prev) >= SUSPEND_SKEW_THRESHOLD_MS,
                _ => false,
            };
            last_sleep_skew = current_skew;

            let locker_active = is_screen_locker_active(my_uid);

            let mut clear_clip = false;
            {
                let Ok(mut guard) = watchdog_state.lock() else {
                    break;
                };
                if guard.shutdown_requested {
                    break;
                }
                if slept {
                    clear_clip = guard.lock_inner("system suspend/resume detected");
                } else if locker_active {
                    clear_clip = guard.lock_inner("screen lock (hyprlock) detected");
                } else if let Some(session) = &guard.session {
                    let elapsed = current_boot_secs().saturating_sub(session.last_activity_boot_secs);
                    if elapsed >= guard.idle_timeout_secs {
                        clear_clip = guard.lock_inner("inactivity timeout");
                    }
                }
            }

            // Clear clipboard OUTSIDE the state mutex so watchdog never blocks IPC.
            if clear_clip {
                clear_clipboard_best_effort();
            }
        }
    });

    // Main accept loop dispatching to bounded worker threads so slow clients or slow
    // Argon2id/FIDO2 unlocks NEVER starve emergency `omavault lock` requests.
    loop {
        if signal_stop.load(Ordering::SeqCst) {
            break;
        }
        if let Ok(guard) = state.lock() {
            if guard.shutdown_requested {
                break;
            }
        }

        match listener.accept() {
            Ok((mut stream, _)) => {
                if verify_peer_uid(&stream, my_uid).is_err() {
                    eprintln!("omavaultd: rejected IPC connection with mismatched peer UID");
                    continue;
                }
                let prev = active_workers.fetch_add(1, Ordering::AcqRel);
                if prev >= MAX_CONCURRENT_WORKERS {
                    active_workers.fetch_sub(1, Ordering::AcqRel);
                    let _ = write_frame(
                        &mut stream,
                        &DaemonResponse::Error {
                            message: "daemon busy (too many concurrent connections)".into(),
                        },
                    );
                    continue;
                }

                let st = Arc::clone(&state);
                let io_l = Arc::clone(&io_lock);
                let workers = Arc::clone(&active_workers);
                thread::spawn(move || {
                    struct WorkerGuard(Arc<AtomicUsize>);
                    impl Drop for WorkerGuard {
                        fn drop(&mut self) {
                            self.0.fetch_sub(1, Ordering::AcqRel);
                        }
                    }
                    let _wg = WorkerGuard(workers);

                    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                    let response = handle_connection(&mut stream, &st, &io_l, my_uid, enforce_kdf_policy);
                    let _ = write_frame(&mut stream, &response);
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(_) => {
                thread::sleep(Duration::from_millis(100));
            }
        }
    }

    let should_clear = state
        .lock()
        .map(|mut g| {
            g.shutdown_requested = true;
            g.lock_inner("daemon shutdown")
        })
        .unwrap_or(false);
    if should_clear {
        clear_clipboard_best_effort();
    }
    let _ = fs::remove_file(socket_path);
    let _ = watchdog_handle.join();
    Ok(())
}

fn handle_connection(
    stream: &mut UnixStream,
    state: &Arc<Mutex<DaemonState>>,
    io_lock: &Arc<Mutex<()>>,
    my_uid: u32,
    enforce_kdf_policy: bool,
) -> DaemonResponse {
    let raw = match read_frame(stream) {
        Ok(b) => b,
        Err(e) => {
            return DaemonResponse::Error {
                message: e.to_string(),
            }
        }
    };

    let req: DaemonRequest = match serde_json::from_slice(&raw) {
        Ok(r) => r,
        Err(_) => {
            return DaemonResponse::Error {
                message: "invalid IPC request".into(),
            }
        }
    };
    // Immediately wipe & drop raw JSON bytes (containing passphrase/vault) before heavy crypto.
    drop(raw);

    match req {
        DaemonRequest::Status => {
            let Ok(guard) = state.lock() else {
                return DaemonResponse::Error {
                    message: "daemon state lock poisoned".into(),
                };
            };
            DaemonResponse::Status(guard.status())
        }
        DaemonRequest::Lock => {
            let clear_clip = match state.lock() {
                Ok(mut guard) => guard.lock_inner("manual lock"),
                Err(_) => {
                    return DaemonResponse::Error {
                        message: "daemon state lock poisoned".into(),
                    }
                }
            };
            if clear_clip {
                clear_clipboard_best_effort();
            }
            DaemonResponse::Ok
        }
        DaemonRequest::Shutdown => {
            let clear_clip = match state.lock() {
                Ok(mut guard) => {
                    guard.shutdown_requested = true;
                    guard.lock_inner("daemon shutdown")
                }
                Err(_) => {
                    return DaemonResponse::Error {
                        message: "daemon state lock poisoned".into(),
                    }
                }
            };
            if clear_clip {
                clear_clipboard_best_effort();
            }
            DaemonResponse::Ok
        }
        DaemonRequest::Unlock {
            ref vault_path,
            ref passphrase,
            ref keyfile_path,
            ref fido2_device,
        } => {
            if is_screen_locker_active(my_uid) {
                return DaemonResponse::Error {
                    message: "refusing to unlock while screen locker is active".into(),
                };
            }

            let result = (|| -> Result<UnlockedSession> {
                let canonical = canonical_or_owned(vault_path);
                let header = read_header_from_disk(&canonical, enforce_kdf_policy)?;

                let kf_digest = if header.requires_keyfile() {
                    let kf_path = keyfile_path.as_ref().ok_or(VaultError::KeyfileRequired)?;
                    Some(hash_keyfile(kf_path)?)
                } else {
                    None
                };

                let fido2_secret = if header.requires_fido2() {
                    let meta = header.fido2.as_ref().ok_or(VaultError::Fido2Required)?;
                    let provider = LibFido2Cli;
                    Some(provider.get_hmac_secret(meta, fido2_device.as_deref())?)
                } else {
                    None
                };

                let master_key = derive_master_key(
                    passphrase.0.as_bytes(),
                    &header.kdf_salt,
                    header.kdf_params,
                    kf_digest.as_deref(),
                    fido2_secret.as_deref(),
                    enforce_kdf_policy,
                )?;

                let (verified_header, _vault) =
                    load_vault_from_disk(&canonical, &master_key, enforce_kdf_policy)?;

                Ok(UnlockedSession {
                    vault_path: canonical,
                    master_key,
                    header: verified_header,
                    last_activity_boot_secs: current_boot_secs(),
                })
            })();

            match result {
                Ok(session) => {
                    let Ok(mut guard) = state.lock() else {
                        return DaemonResponse::Error {
                            message: "daemon state lock poisoned".into(),
                        };
                    };
                    // Re-check shutdown & screen locker before committing unlocked session.
                    if guard.shutdown_requested || is_screen_locker_active(my_uid) {
                        return DaemonResponse::Error {
                            message: "unlock cancelled due to concurrent lock/shutdown".into(),
                        };
                    }
                    guard.session = Some(session);
                    guard.last_lock_reason = None;
                    DaemonResponse::Ok
                }
                Err(e) => DaemonResponse::Error {
                    message: e.to_string(),
                },
            }
        }
        DaemonRequest::LoadVault { ref vault_path } => {
            let canonical = canonical_or_owned(vault_path);
            let key_clone = {
                let Ok(mut guard) = state.lock() else {
                    return DaemonResponse::Error {
                        message: "daemon state lock poisoned".into(),
                    };
                };
                let Some(session) = guard.session.as_mut() else {
                    return DaemonResponse::Error {
                        message: "vault is locked".into(),
                    };
                };
                if session.vault_path != canonical {
                    return DaemonResponse::Error {
                        message: "daemon is unlocked for a different vault path".into(),
                    };
                }
                session.last_activity_boot_secs = current_boot_secs();
                match session.master_key.try_clone() {
                    Ok(k) => k,
                    Err(e) => {
                        return DaemonResponse::Error {
                            message: e.to_string(),
                        }
                    }
                }
            };

            let _io = match io_lock.lock() {
                Ok(g) => g,
                Err(_) => {
                    return DaemonResponse::Error {
                        message: "daemon I/O lock poisoned".into(),
                    }
                }
            };
            match load_vault_from_disk(&canonical, &key_clone, enforce_kdf_policy) {
                Ok((header, vault)) => {
                    let rev = header_revision(&header);
                    if let Ok(mut guard) = state.lock() {
                        if let Some(session) = guard.session.as_mut() {
                            if session.vault_path == canonical {
                                session.header = header;
                            }
                        }
                    }
                    DaemonResponse::Vault {
                        vault,
                        revision: rev,
                    }
                }
                Err(e) => DaemonResponse::Error {
                    message: e.to_string(),
                },
            }
        }
        DaemonRequest::SaveVault {
            ref vault_path,
            ref vault,
            ref expected_revision,
        } => {
            let canonical = canonical_or_owned(vault_path);
            let (key_clone, mut header_copy) = {
                let Ok(mut guard) = state.lock() else {
                    return DaemonResponse::Error {
                        message: "daemon state lock poisoned".into(),
                    };
                };
                let Some(session) = guard.session.as_mut() else {
                    return DaemonResponse::Error {
                        message: "vault is locked".into(),
                    };
                };
                if session.vault_path != canonical {
                    return DaemonResponse::Error {
                        message: "daemon is unlocked for a different vault path".into(),
                    };
                }
                session.last_activity_boot_secs = current_boot_secs();
                match session.master_key.try_clone() {
                    Ok(k) => (k, session.header.clone()),
                    Err(e) => {
                        return DaemonResponse::Error {
                            message: e.to_string(),
                        }
                    }
                }
            };

            let _io = match io_lock.lock() {
                Ok(g) => g,
                Err(_) => {
                    return DaemonResponse::Error {
                        message: "daemon I/O lock poisoned".into(),
                    }
                }
            };

            // Optimistic concurrency check against on-disk revision when provided.
            if let Some(expected) = expected_revision {
                match read_header_from_disk(&canonical, enforce_kdf_policy) {
                    Ok(disk_hdr) => {
                        if header_revision(&disk_hdr) != *expected {
                            return DaemonResponse::Error {
                                message: "vault was modified concurrently on disk; reload and retry"
                                    .into(),
                            };
                        }
                        header_copy = disk_hdr;
                    }
                    Err(e) => {
                        return DaemonResponse::Error {
                            message: e.to_string(),
                        }
                    }
                }
            }

            match save_vault_to_disk(&canonical, &key_clone, &mut header_copy, vault) {
                Ok(()) => {
                    if let Ok(mut guard) = state.lock() {
                        if let Some(session) = guard.session.as_mut() {
                            if session.vault_path == canonical {
                                session.header = header_copy;
                            }
                        }
                    }
                    DaemonResponse::Ok
                }
                Err(e) => DaemonResponse::Error {
                    message: e.to_string(),
                },
            }
        }
    }
}

/// Client helper for communicating with the local `omavault` daemon.
pub struct DaemonClient {
    socket_path: PathBuf,
}

impl DaemonClient {
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    /// Verify socket & parent directory ownership/permissions before connecting (never follows symlinks).
    fn validate_socket_security(&self) -> Result<()> {
        let my_uid = unsafe { libc::geteuid() };
        let parent = self
            .socket_path
            .parent()
            .ok_or_else(|| VaultError::Daemon("invalid socket path".into()))?;
        let pmeta = fs::symlink_metadata(parent)?;
        if !pmeta.file_type().is_dir() || pmeta.uid() != my_uid || (pmeta.permissions().mode() & 0o077) != 0
        {
            return Err(VaultError::Daemon(format!(
                "refusing to connect: unsafe socket directory '{}'",
                parent.display()
            )));
        }
        let smeta = fs::symlink_metadata(&self.socket_path)?;
        if !smeta.file_type().is_socket()
            || smeta.uid() != my_uid
            || (smeta.permissions().mode() & 0o077) != 0
        {
            return Err(VaultError::Daemon(format!(
                "refusing to connect: unsafe socket '{}'",
                self.socket_path.display()
            )));
        }
        Ok(())
    }

    pub fn is_available(&self) -> bool {
        self.status().is_ok()
    }

    pub fn request(&self, req: &DaemonRequest) -> Result<DaemonResponse> {
        self.validate_socket_security()?;
        let mut stream = UnixStream::connect(&self.socket_path).map_err(|e| {
            VaultError::Daemon(format!(
                "cannot connect to omavault daemon at '{}': {e}",
                self.socket_path.display()
            ))
        })?;
        // CRITICAL: Mutual SO_PEERCRED — verify the SERVER belongs to our exact UID BEFORE
        // sending any master passphrase or decrypted vault bytes!
        let my_uid = unsafe { libc::geteuid() };
        verify_peer_uid(&stream, my_uid)?;

        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
        write_frame(&mut stream, req)?;
        let raw = read_frame(&mut stream)?;
        let resp: DaemonResponse = serde_json::from_slice(&raw)
            .map_err(|_| VaultError::Daemon("invalid daemon response".into()))?;
        drop(raw);
        Ok(resp)
    }

    pub fn status(&self) -> Result<DaemonStatus> {
        match self.request(&DaemonRequest::Status)? {
            DaemonResponse::Status(s) => Ok(s),
            DaemonResponse::Error { message } => Err(VaultError::Daemon(message)),
            _ => Err(VaultError::Daemon("unexpected response to status".into())),
        }
    }

    pub fn unlock(
        &self,
        vault_path: &Path,
        mut passphrase: Zeroizing<String>,
        keyfile_path: Option<PathBuf>,
        fido2_device: Option<String>,
    ) -> Result<()> {
        let secret = SecretString(std::mem::take(&mut *passphrase));
        let req = DaemonRequest::Unlock {
            vault_path: vault_path.to_path_buf(),
            passphrase: secret,
            keyfile_path,
            fido2_device,
        };
        match self.request(&req)? {
            DaemonResponse::Ok => Ok(()),
            DaemonResponse::Error { message } => Err(VaultError::Daemon(message)),
            _ => Err(VaultError::Daemon("unexpected response to unlock".into())),
        }
    }

    pub fn lock(&self) -> Result<()> {
        match self.request(&DaemonRequest::Lock)? {
            DaemonResponse::Ok => Ok(()),
            DaemonResponse::Error { message } => Err(VaultError::Daemon(message)),
            _ => Err(VaultError::Daemon("unexpected response to lock".into())),
        }
    }

    pub fn load_vault(&self, vault_path: &Path) -> Result<(Vault, String)> {
        match self.request(&DaemonRequest::LoadVault {
            vault_path: vault_path.to_path_buf(),
        })? {
            DaemonResponse::Vault { vault, revision } => Ok((vault, revision)),
            DaemonResponse::Error { message } => Err(VaultError::Daemon(message)),
            _ => Err(VaultError::Daemon("unexpected response to load_vault".into())),
        }
    }

    pub fn save_vault(
        &self,
        vault_path: &Path,
        vault: &Vault,
        expected_revision: Option<String>,
    ) -> Result<()> {
        let req = DaemonRequest::SaveVault {
            vault_path: vault_path.to_path_buf(),
            vault: vault.clone(),
            expected_revision,
        };
        match self.request(&req)? {
            DaemonResponse::Ok => Ok(()),
            DaemonResponse::Error { message } => Err(VaultError::Daemon(message)),
            _ => Err(VaultError::Daemon("unexpected response to save_vault".into())),
        }
    }

    pub fn shutdown(&self) -> Result<()> {
        match self.request(&DaemonRequest::Shutdown)? {
            DaemonResponse::Ok => Ok(()),
            DaemonResponse::Error { message } => Err(VaultError::Daemon(message)),
            _ => Err(VaultError::Daemon("unexpected response to shutdown".into())),
        }
    }
}

/// Verify the Unix socket peer belongs to the exact same UID via `SO_PEERCRED`.
#[cfg(target_os = "linux")]
fn verify_peer_uid(stream: &UnixStream, expected_uid: u32) -> Result<()> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: u32::MAX,
        gid: u32::MAX,
    };
    let expected_len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let mut len = expected_len;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 || len != expected_len || cred.pid <= 0 || cred.uid != expected_uid {
        return Err(VaultError::Daemon("peer UID verification failed".into()));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn verify_peer_uid(_stream: &UnixStream, _expected_uid: u32) -> Result<()> {
    Err(VaultError::Daemon(
        "SO_PEERCRED peer verification is required and only supported on Linux".into(),
    ))
}

fn canonical_or_owned(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<()> {
    let mut payload = Zeroizing::new(Vec::with_capacity(4096));
    serde_json::to_writer(&mut *payload, value)
        .map_err(|_| VaultError::Serialization("failed serializing IPC frame".into()))?;
    if payload.len() > MAX_IPC_FRAME_BYTES {
        return Err(VaultError::Daemon("IPC payload exceeds maximum size".into()));
    }
    let len = (payload.len() as u32).to_le_bytes();
    stream.write_all(&len)?;
    stream.write_all(&payload)?;
    stream.flush()?;
    Ok(())
}

/// Read an IPC frame with an absolute monotonic deadline and incremental chunked allocation
/// (prevents slow-loris stalls and blind 16 MiB OOM allocations from untrusted length headers).
fn read_frame(stream: &mut UnixStream) -> Result<Zeroizing<Vec<u8>>> {
    let deadline = Instant::now() + IPC_FRAME_DEADLINE;
    let mut len_buf = [0u8; 4];
    read_exact_with_deadline(stream, &mut len_buf, deadline)?;
    let total_len = u32::from_le_bytes(len_buf) as usize;
    if total_len == 0 || total_len > MAX_IPC_FRAME_BYTES {
        return Err(VaultError::Daemon("invalid IPC frame length".into()));
    }

    let initial_cap = total_len.min(64 * 1024);
    let mut out = Zeroizing::new(Vec::with_capacity(initial_cap));
    let mut chunk = Zeroizing::new([0u8; 16 * 1024]);
    let mut remaining = total_len;
    while remaining > 0 {
        let want = remaining.min(chunk.len());
        let n = read_some_with_deadline(stream, &mut chunk[..want], deadline)?;
        if n == 0 {
            return Err(VaultError::Daemon("unexpected EOF reading IPC frame".into()));
        }
        out.extend_from_slice(&chunk[..n]);
        remaining -= n;
    }
    Ok(out)
}

fn read_exact_with_deadline(
    stream: &mut UnixStream,
    mut buf: &mut [u8],
    deadline: Instant,
) -> Result<()> {
    while !buf.is_empty() {
        let n = read_some_with_deadline(stream, buf, deadline)?;
        if n == 0 {
            return Err(VaultError::Daemon("unexpected EOF reading IPC header".into()));
        }
        buf = &mut buf[n..];
    }
    Ok(())
}

fn read_some_with_deadline(
    stream: &mut UnixStream,
    buf: &mut [u8],
    deadline: Instant,
) -> Result<usize> {
    loop {
        if Instant::now() >= deadline {
            return Err(VaultError::Daemon("IPC frame read timed out".into()));
        }
        match stream.read(buf) {
            Ok(n) => return Ok(n),
            Err(e)
                if e.kind() == std::io::ErrorKind::Interrupted
                    || e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => return Err(VaultError::Io(e)),
        }
    }
}
