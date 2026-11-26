use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
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
use crate::hardening::LockedKey;
use crate::vault::storage::{
    ensure_private_dir, load_vault_from_disk, read_header_from_disk, save_vault_to_disk,
};
use crate::vault::Vault;

pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 300; // 5 minutes
const MAX_IPC_FRAME_BYTES: usize = 16 * 1024 * 1024;
const SCREEN_LOCKERS: &[&str] = &["hyprlock", "swaylock", "gtklock", "waylock", "i3lock"];

/// Default runtime directory for the Unix socket (`$XDG_RUNTIME_DIR/omavault/daemon.sock`, on tmpfs).
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
    let uid = unsafe { libc::geteuid() };
    PathBuf::from(format!("/tmp/omavault-{uid}/daemon.sock"))
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum DaemonRequest {
    Status,
    Unlock {
        vault_path: PathBuf,
        passphrase: String,
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
    },
    Shutdown,
}

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
    Vault { vault: Vault },
    Error { message: String },
}

struct UnlockedSession {
    vault_path: PathBuf,
    master_key: LockedKey<32>,
    header: VaultHeader,
    last_activity: Instant,
}

struct DaemonState {
    session: Option<UnlockedSession>,
    idle_timeout: Duration,
    last_lock_reason: Option<String>,
    shutdown_requested: bool,
}

impl DaemonState {
    fn new(idle_timeout: Duration) -> Self {
        Self {
            session: None,
            idle_timeout,
            last_lock_reason: None,
            shutdown_requested: false,
        }
    }

    fn lock(&mut self, reason: &str) {
        if self.session.take().is_some() {
            // Dropping `UnlockedSession` drops `LockedKey<32>`, which volatile-zeroizes,
            // munlocks, and munmaps the master key page.
            self.last_lock_reason = Some(reason.to_string());
            clear_clipboard_best_effort();
        }
    }

    fn status(&self) -> DaemonStatus {
        match &self.session {
            Some(s) => {
                let elapsed = s.last_activity.elapsed();
                let remaining = self.idle_timeout.saturating_sub(elapsed).as_secs();
                DaemonStatus {
                    unlocked: true,
                    vault_path: Some(s.vault_path.clone()),
                    remaining_secs: remaining,
                    idle_timeout_secs: self.idle_timeout.as_secs(),
                    mlocked: s.master_key.is_mlocked(),
                    guard_protected: s.master_key.is_guard_protected(),
                    last_lock_reason: self.last_lock_reason.clone(),
                }
            }
            None => DaemonStatus {
                unlocked: false,
                vault_path: None,
                remaining_secs: 0,
                idle_timeout_secs: self.idle_timeout.as_secs(),
                mlocked: false,
                guard_protected: false,
                last_lock_reason: self.last_lock_reason.clone(),
            },
        }
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
    ensure_private_dir(parent)?;

    // Verify parent directory is owned by current UID (prevents symlink/tmp squatting).
    let meta = fs::metadata(parent)?;
    let my_uid = unsafe { libc::geteuid() };
    if meta.uid() != my_uid {
        return Err(VaultError::Daemon(format!(
            "socket directory '{}' is not owned by current user",
            parent.display()
        )));
    }

    if socket_path.exists() {
        let _ = fs::remove_file(socket_path);
    }

    let listener = UnixListener::bind(socket_path)
        .map_err(|e| VaultError::Daemon(format!("failed binding daemon socket: {e}")))?;
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;

    let state = Arc::new(Mutex::new(DaemonState::new(Duration::from_secs(
        idle_timeout_secs.max(10),
    ))));

    // Spawn security watchdog thread (idle timeout, Hyprlock detection, suspend/lid-close detection).
    let watchdog_state = Arc::clone(&state);
    thread::spawn(move || {
        let mut last_sleep_skew = boottime_monotonic_skew_secs();
        loop {
            thread::sleep(Duration::from_secs(1));

            let mut guard = match watchdog_state.lock() {
                Ok(g) => g,
                Err(_) => break,
            };
            if guard.shutdown_requested {
                break;
            }

            // 1. Check suspend/resume via CLOCK_BOOTTIME - CLOCK_MONOTONIC skew jump.
            let current_skew = boottime_monotonic_skew_secs();
            if let (Some(prev), Some(curr)) = (last_sleep_skew, current_skew) {
                if curr.saturating_sub(prev) >= 5 {
                    guard.lock("system suspend/resume detected");
                }
            }
            last_sleep_skew = current_skew;

            if let Some(session) = &guard.session {
                // 2. Check inactivity timeout.
                if session.last_activity.elapsed() >= guard.idle_timeout {
                    guard.lock("inactivity timeout");
                    continue;
                }
                // 3. Check if Hyprlock / screen locker is active for this UID.
                if is_screen_locker_active(my_uid) {
                    guard.lock("screen lock (hyprlock) detected");
                    continue;
                }
            }
        }
    });

    // Main accept loop.
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                if verify_peer_uid(&stream, my_uid).is_err() {
                    continue;
                }
                let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
                let response = handle_connection(&mut stream, &state, enforce_kdf_policy);
                let _ = write_frame(&mut stream, &response);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if let Ok(guard) = state.lock() {
                    if guard.shutdown_requested {
                        break;
                    }
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(_) => {
                thread::sleep(Duration::from_millis(100));
            }
        }
    }

    if let Ok(mut guard) = state.lock() {
        guard.lock("daemon shutdown");
    }
    let _ = fs::remove_file(socket_path);
    Ok(())
}

fn handle_connection(
    stream: &mut UnixStream,
    state: &Arc<Mutex<DaemonState>>,
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
        Err(e) => {
            return DaemonResponse::Error {
                message: format!("invalid IPC request: {e}"),
            }
        }
    };

    match req {
        DaemonRequest::Status => {
            let guard = state.lock().unwrap();
            DaemonResponse::Status(guard.status())
        }
        DaemonRequest::Lock => {
            let mut guard = state.lock().unwrap();
            guard.lock("manual lock");
            DaemonResponse::Ok
        }
        DaemonRequest::Shutdown => {
            let mut guard = state.lock().unwrap();
            guard.lock("daemon shutdown");
            guard.shutdown_requested = true;
            DaemonResponse::Ok
        }
        DaemonRequest::Unlock {
            vault_path,
            mut passphrase,
            keyfile_path,
            fido2_device,
        } => {
            let result = (|| -> Result<UnlockedSession> {
                let canonical = canonical_or_owned(&vault_path);
                let header = read_header_from_disk(&canonical, enforce_kdf_policy)?;

                let kf_digest = if header.requires_keyfile() {
                    let kf_path = keyfile_path.ok_or(VaultError::KeyfileRequired)?;
                    Some(hash_keyfile(&kf_path)?)
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
                    passphrase.as_bytes(),
                    &header.kdf_salt,
                    header.kdf_params,
                    kf_digest.as_deref(),
                    fido2_secret.as_deref(),
                    enforce_kdf_policy,
                )?;
                passphrase.zeroize();

                // Verify key actually decrypts & authenticates the vault before caching!
                let (verified_header, _vault) =
                    load_vault_from_disk(&canonical, &master_key, enforce_kdf_policy)?;

                Ok(UnlockedSession {
                    vault_path: canonical,
                    master_key,
                    header: verified_header,
                    last_activity: Instant::now(),
                })
            })();

            passphrase.zeroize();
            match result {
                Ok(session) => {
                    let mut guard = state.lock().unwrap();
                    guard.session = Some(session);
                    guard.last_lock_reason = None;
                    DaemonResponse::Ok
                }
                Err(e) => DaemonResponse::Error {
                    message: e.to_string(),
                },
            }
        }
        DaemonRequest::LoadVault { vault_path } => {
            let mut guard = state.lock().unwrap();
            let canonical = canonical_or_owned(&vault_path);
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
            session.last_activity = Instant::now();
            match load_vault_from_disk(&canonical, &session.master_key, enforce_kdf_policy) {
                Ok((header, vault)) => {
                    session.header = header;
                    DaemonResponse::Vault { vault }
                }
                Err(e) => DaemonResponse::Error {
                    message: e.to_string(),
                },
            }
        }
        DaemonRequest::SaveVault { vault_path, vault } => {
            let mut guard = state.lock().unwrap();
            let canonical = canonical_or_owned(&vault_path);
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
            session.last_activity = Instant::now();
            match save_vault_to_disk(
                &canonical,
                &session.master_key,
                &mut session.header,
                &vault,
            ) {
                Ok(()) => DaemonResponse::Ok,
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

    pub fn is_available(&self) -> bool {
        self.socket_path.exists() && UnixStream::connect(&self.socket_path).is_ok()
    }

    pub fn request(&self, req: &DaemonRequest) -> Result<DaemonResponse> {
        let mut stream = UnixStream::connect(&self.socket_path).map_err(|e| {
            VaultError::Daemon(format!(
                "cannot connect to omavault daemon at '{}': {e}",
                self.socket_path.display()
            ))
        })?;
        let _ = stream.set_read_timeout(Some(Duration::from_secs(60)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
        write_frame(&mut stream, req)?;
        let raw = read_frame(&mut stream)?;
        let resp: DaemonResponse = serde_json::from_slice(&raw)
            .map_err(|e| VaultError::Daemon(format!("invalid daemon response: {e}")))?;
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
        passphrase: Zeroizing<String>,
        keyfile_path: Option<PathBuf>,
        fido2_device: Option<String>,
    ) -> Result<()> {
        let req = DaemonRequest::Unlock {
            vault_path: vault_path.to_path_buf(),
            passphrase: passphrase.to_string(),
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

    pub fn load_vault(&self, vault_path: &Path) -> Result<Vault> {
        match self.request(&DaemonRequest::LoadVault {
            vault_path: vault_path.to_path_buf(),
        })? {
            DaemonResponse::Vault { vault } => Ok(vault),
            DaemonResponse::Error { message } => Err(VaultError::Daemon(message)),
            _ => Err(VaultError::Daemon("unexpected response to load_vault".into())),
        }
    }

    pub fn save_vault(&self, vault_path: &Path, vault: &Vault) -> Result<()> {
        match self.request(&DaemonRequest::SaveVault {
            vault_path: vault_path.to_path_buf(),
            vault: vault.clone(),
        })? {
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

/// Verify the connecting Unix socket peer belongs to the exact same UID via `SO_PEERCRED`.
#[cfg(target_os = "linux")]
fn verify_peer_uid(stream: &UnixStream, expected_uid: u32) -> Result<()> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: u32::MAX,
        gid: u32::MAX,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 || cred.uid != expected_uid {
        return Err(VaultError::Daemon("peer UID verification failed".into()));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn verify_peer_uid(_stream: &UnixStream, _expected_uid: u32) -> Result<()> {
    Ok(())
}

/// Measure `CLOCK_BOOTTIME - CLOCK_MONOTONIC` in seconds.
///
/// On Linux, `CLOCK_BOOTTIME` includes suspend time while `CLOCK_MONOTONIC` pauses during
/// suspend. Any jump in their difference immediately detects laptop lid-close / sleep!
#[cfg(target_os = "linux")]
fn boottime_monotonic_skew_secs() -> Option<u64> {
    let mut mono = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let mut boot = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        if libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut mono) != 0 {
            return None;
        }
        if libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut boot) != 0 {
            return None;
        }
    }
    let diff = boot.tv_sec.saturating_sub(mono.tv_sec);
    Some(diff.max(0) as u64)
}

#[cfg(not(target_os = "linux"))]
fn boottime_monotonic_skew_secs() -> Option<u64> {
    None
}

/// Scan `/proc` without spawning subprocesses to detect if `hyprlock` (or another
/// Wayland screen locker) is currently active for `target_uid`.
#[cfg(target_os = "linux")]
fn is_screen_locker_active(target_uid: u32) -> bool {
    let Ok(entries) = fs::read_dir("/proc") else {
        return false;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if !name_str.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let pid_dir = entry.path();
        let Ok(comm) = fs::read_to_string(pid_dir.join("comm")) else {
            continue;
        };
        let proc_name = comm.trim();
        if !SCREEN_LOCKERS.contains(&proc_name) {
            continue;
        }
        if let Ok(meta) = fs::metadata(&pid_dir) {
            if meta.uid() == target_uid {
                return true;
            }
        }
    }
    false
}

#[cfg(not(target_os = "linux"))]
fn is_screen_locker_active(_target_uid: u32) -> bool {
    false
}

fn canonical_or_owned(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<()> {
    let payload = Zeroizing::new(
        serde_json::to_vec(value).map_err(|e| VaultError::Serialization(e.to_string()))?,
    );
    if payload.len() > MAX_IPC_FRAME_BYTES {
        return Err(VaultError::Daemon("IPC payload exceeds maximum size".into()));
    }
    let len = (payload.len() as u32).to_le_bytes();
    stream.write_all(&len)?;
    stream.write_all(&payload)?;
    stream.flush()?;
    Ok(())
}

fn read_frame(stream: &mut UnixStream) -> Result<Zeroizing<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 || len > MAX_IPC_FRAME_BYTES {
        return Err(VaultError::Daemon("invalid IPC frame length".into()));
    }
    let mut buf = Zeroizing::new(vec![0u8; len]);
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

/// Zeroizing wrapper for IPC request secrets if dropped directly.
impl Zeroize for DaemonRequest {
    fn zeroize(&mut self) {
        match self {
            DaemonRequest::Unlock { passphrase, .. } => passphrase.zeroize(),
            DaemonRequest::SaveVault { vault, .. } => vault.zeroize(),
            _ => {}
        }
    }
}

impl ZeroizeOnDrop for DaemonRequest {}
