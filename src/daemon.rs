use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::clipboard::clear_clipboard_best_effort;
use crate::crypto::fido2::LibFido2Cli;
use crate::crypto::kdf::hash_keyfile;
use crate::crypto::{header_revision, resolve_master_key, VaultHeader};
use crate::error::{Result, VaultError};
use crate::hardening::{
    boottime_monotonic_skew_ms, boottime_secs, is_screen_locker_active, CountingWriter,
    HardeningStatus, LockedKey,
};
use crate::vault::storage::{
    ensure_private_dir, ensure_private_dir_strict, load_vault_from_disk, read_header_from_disk,
    save_vault_to_disk_checked,
};
use crate::vault::Vault;

pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 300; // 5 minutes
const MAX_IPC_FRAME_BYTES: usize = 16 * 1024 * 1024;
/// Maximum total concurrent IPC worker threads (reserves 8 dedicated control slots for Lock/Shutdown/Status).
const MAX_TOTAL_WORKERS: usize = 16;
/// Maximum concurrent heavy workers (`Unlock`, `LoadVault`, `SaveVault`) so emergency `Lock` is never starved.
const MAX_HEAVY_WORKERS: usize = 8;
const IPC_FRAME_DEADLINE: Duration = Duration::from_secs(10);
/// Extended client-side wait window for `DaemonRequest::Unlock` to accommodate
/// Argon2id derivation plus the 45-second FIDO2 physical touch timeout.
const IPC_UNLOCK_DEADLINE: Duration = Duration::from_secs(60);
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
    #[serde(default)]
    pub kernel_hardened: bool,
    #[serde(default)]
    pub dumpable_disabled: bool,
    #[serde(default)]
    pub core_dumps_disabled: bool,
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
    /// Monotonic epoch incremented on EVERY lock/shutdown event so in-flight `Unlock` or
    /// `SaveVault` operations can never race past a concurrent `Lock` and silently re-unlock.
    lock_epoch: u64,
    hardening: HardeningStatus,
}

impl DaemonState {
    fn new(idle_timeout_secs: u64, hardening: HardeningStatus) -> Self {
        Self {
            session: None,
            idle_timeout_secs,
            last_lock_reason: None,
            shutdown_requested: false,
            lock_epoch: 0,
            hardening,
        }
    }

    /// Increment `lock_epoch` and drop any unlocked session (triggering volatile-zeroize + munlock + munmap).
    /// Returns `true` if a session was active (or clipboard should be cleared).
    fn lock_inner(&mut self, reason: &str) -> bool {
        self.lock_epoch = self.lock_epoch.wrapping_add(1);
        let had_session = self.session.take().is_some();
        if had_session {
            self.last_lock_reason = Some(reason.to_string());
        }
        had_session
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
                    kernel_hardened: s.master_key.is_kernel_hardened(),
                    dumpable_disabled: self.hardening.dumpable_disabled,
                    core_dumps_disabled: self.hardening.core_dumps_disabled,
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
                kernel_hardened: false,
                dumpable_disabled: self.hardening.dumpable_disabled,
                core_dumps_disabled: self.hardening.core_dumps_disabled,
                last_lock_reason: self.last_lock_reason.clone(),
            },
        }
    }
}

fn current_boot_secs() -> u64 {
    static MONOTONIC_ANCHOR: OnceLock<Instant> = OnceLock::new();
    boottime_secs().unwrap_or_else(|| {
        let anchor = MONOTONIC_ANCHOR.get_or_init(Instant::now);
        anchor.elapsed().as_secs()
    })
}

/// Exclusive non-blocking lockfile ensuring two daemons never race or orphan each other's socket.
struct DaemonInstanceLock {
    _file: File,
}

impl DaemonInstanceLock {
    fn acquire(socket_path: &Path) -> Result<Self> {
        let parent = resolve_socket_parent(socket_path)?;
        let lock_path = parent.join("daemon.lock");
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
            return Err(VaultError::Daemon(
                "daemon.lock is not a regular file owned by current user".into(),
            ));
        }
        let _ = unsafe { libc::fchmod(file.as_raw_fd(), 0o600) };
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            return Err(VaultError::Daemon(
                "another omavault daemon instance is already running for this socket".into(),
            ));
        }
        Ok(Self { _file: file })
    }
}

fn resolve_socket_parent(socket_path: &Path) -> Result<&Path> {
    match socket_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => Ok(p),
        Some(_) => Ok(Path::new(".")),
        None => Err(VaultError::Daemon("invalid socket path".into())),
    }
}

/// Spawn an optional `busctl --system monitor` thread listening for systemd-logind's
/// `PrepareForSleep(true)` signal over `AF_UNIX` so `omavaultd` wipes keys *before* S3/S4 sleep.
#[cfg(target_os = "linux")]
fn spawn_presleep_monitor(state: Arc<Mutex<DaemonState>>, signal_stop: Arc<AtomicBool>) {
    let busctl = Path::new("/usr/bin/busctl");
    if !busctl.is_file() {
        return;
    }
    let _ = thread::Builder::new()
        .name("omavaultd-presleep".into())
        .spawn(move || {
            let mut cmd = Command::new(busctl);
            cmd.args([
                "--system",
                "monitor",
                "--match",
                "type='signal',interface='org.freedesktop.login1.Manager',member='PrepareForSleep'",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
            unsafe {
                cmd.pre_exec(|| {
                    let _ = libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM, 0, 0, 0);
                    Ok(())
                });
            }
            let Ok(mut child) = cmd.spawn() else {
                return;
            };
            let Some(stdout) = child.stdout.take() else {
                let _ = child.kill();
                let _ = child.wait();
                return;
            };
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                if signal_stop.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(text) = line else {
                    break;
                };
                if text.contains("boolean true") {
                    let should_clear = {
                        let mut guard = state.lock().unwrap_or_else(|e| e.into_inner());
                        guard.lock_inner("system pre-sleep/hibernate detected")
                    };
                    if should_clear {
                        clear_clipboard_best_effort();
                    }
                }
            }
            let _ = child.kill();
            let _ = child.wait();
        });
}

/// Run the auto-locking background daemon listening on `socket_path`.
pub fn run_daemon(
    socket_path: &Path,
    idle_timeout_secs: u64,
    enforce_kdf_policy: bool,
) -> Result<()> {
    run_daemon_with_hardening(
        socket_path,
        idle_timeout_secs,
        enforce_kdf_policy,
        HardeningStatus::default(),
    )
}

/// Run the auto-locking background daemon with recorded `HardeningStatus` telemetry.
pub fn run_daemon_with_hardening(
    socket_path: &Path,
    idle_timeout_secs: u64,
    enforce_kdf_policy: bool,
    hardening: HardeningStatus,
) -> Result<()> {
    let parent = resolve_socket_parent(socket_path)?;
    // Use strict 0700 for dedicated omavault/private dirs without accidentally chmodding $HOME.
    let is_dedicated = parent
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.contains("omavault") || n.contains("private"));
    if is_dedicated {
        ensure_private_dir_strict(parent, true)?;
    } else {
        ensure_private_dir(parent)?;
    }

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

    let state = Arc::new(Mutex::new(DaemonState::new(
        idle_timeout_secs.max(10),
        hardening,
    )));
    let io_lock = Arc::new(Mutex::new(()));
    let active_total_workers = Arc::new(AtomicUsize::new(0));
    let active_heavy_workers = Arc::new(AtomicUsize::new(0));
    let signal_stop = Arc::new(AtomicBool::new(false));
    let signal_lock = Arc::new(AtomicBool::new(false));

    // Register graceful shutdown signals (SIGTERM, SIGINT, SIGHUP) and out-of-band emergency lock (SIGUSR1).
    let _ = signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&signal_stop));
    let _ = signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&signal_stop));
    let _ = signal_hook::flag::register(signal_hook::consts::SIGHUP, Arc::clone(&signal_stop));
    let _ = signal_hook::flag::register(signal_hook::consts::SIGUSR1, Arc::clone(&signal_lock));

    #[cfg(target_os = "linux")]
    spawn_presleep_monitor(Arc::clone(&state), Arc::clone(&signal_stop));

    // Spawn security watchdog thread (CLOCK_BOOTTIME idle timeout, Hyprland/proc screen lock,
    // SIGUSR1 emergency lock, and CLOCK_BOOTTIME - CLOCK_MONOTONIC suspend/resume detection).
    let watchdog_state = Arc::clone(&state);
    let watchdog_signal = Arc::clone(&signal_stop);
    let watchdog_lock_sig = Arc::clone(&signal_lock);
    let watchdog_handle = thread::Builder::new()
        .name("omavaultd-watchdog".into())
        .spawn(move || {
            let mut last_sleep_skew = boottime_monotonic_skew_ms();
            loop {
                thread::sleep(Duration::from_secs(1));

                if watchdog_signal.load(Ordering::SeqCst) {
                    let should_clear = {
                        let mut g = watchdog_state.lock().unwrap_or_else(|e| e.into_inner());
                        g.shutdown_requested = true;
                        g.lock_inner("signal shutdown")
                    };
                    if should_clear {
                        clear_clipboard_best_effort();
                    }
                    break;
                }

                if watchdog_lock_sig.swap(false, Ordering::SeqCst) {
                    let _ = {
                        let mut g = watchdog_state.lock().unwrap_or_else(|e| e.into_inner());
                        g.lock_inner("emergency SIGUSR1 lock")
                    };
                    clear_clipboard_best_effort();
                }

                let current_skew = boottime_monotonic_skew_ms();
                let slept = match (last_sleep_skew, current_skew) {
                    (Some(prev), Some(curr)) => {
                        curr.saturating_sub(prev) >= SUSPEND_SKEW_THRESHOLD_MS
                    }
                    _ => false,
                };
                last_sleep_skew = current_skew;

                let locker_active = is_screen_locker_active(my_uid);

                let mut clear_clip = false;
                {
                    let (mut guard, poisoned) = match watchdog_state.lock() {
                        Ok(g) => (g, false),
                        Err(e) => (e.into_inner(), true),
                    };
                    if poisoned {
                        guard.shutdown_requested = true;
                        clear_clip = guard.lock_inner("mutex poisoned — emergency lock");
                    } else if guard.shutdown_requested {
                        break;
                    } else if slept {
                        clear_clip = guard.lock_inner("system suspend/resume detected");
                    } else if locker_active {
                        clear_clip = guard.lock_inner("screen lock detected");
                    } else if let Some(session) = &guard.session {
                        let elapsed =
                            current_boot_secs().saturating_sub(session.last_activity_boot_secs);
                        if elapsed >= guard.idle_timeout_secs {
                            clear_clip = guard.lock_inner("inactivity timeout");
                        }
                    }
                    if poisoned {
                        drop(guard);
                        if clear_clip {
                            clear_clipboard_best_effort();
                        }
                        break;
                    }
                }

                // Clear clipboard OUTSIDE the state mutex so watchdog never blocks IPC.
                if clear_clip {
                    clear_clipboard_best_effort();
                }
            }
        })
        .map_err(|e| VaultError::Daemon(format!("failed spawning watchdog thread: {e}")))?;

    // Main accept loop dispatching to bounded worker threads with dedicated control headroom
    // so slow Argon2id/FIDO2 unlocks NEVER starve emergency `omavault lock` requests.
    loop {
        if signal_stop.load(Ordering::SeqCst) {
            break;
        }
        {
            let (guard, poisoned) = match state.lock() {
                Ok(g) => (g, false),
                Err(e) => (e.into_inner(), true),
            };
            if poisoned || guard.shutdown_requested {
                break;
            }
        }

        match listener.accept() {
            Ok((mut stream, _)) => {
                if verify_peer_uid(&stream, my_uid).is_err() {
                    eprintln!("omavaultd: rejected IPC connection with mismatched peer UID");
                    continue;
                }
                let prev = active_total_workers.fetch_add(1, Ordering::AcqRel);
                if prev >= MAX_TOTAL_WORKERS {
                    active_total_workers.fetch_sub(1, Ordering::AcqRel);
                    let _ = stream.set_write_timeout(Some(Duration::from_millis(250)));
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
                let total_workers = Arc::clone(&active_total_workers);
                let heavy_workers = Arc::clone(&active_heavy_workers);
                let spawn_res = thread::Builder::new().spawn(move || {
                    struct WorkerGuard(Arc<AtomicUsize>);
                    impl Drop for WorkerGuard {
                        fn drop(&mut self) {
                            self.0.fetch_sub(1, Ordering::AcqRel);
                        }
                    }
                    let _wg = WorkerGuard(total_workers);

                    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                    let response = handle_connection(
                        &mut stream,
                        &st,
                        &io_l,
                        &heavy_workers,
                        my_uid,
                        enforce_kdf_policy,
                    );
                    let _ = write_frame(&mut stream, &response);
                });
                if spawn_res.is_err() {
                    active_total_workers.fetch_sub(1, Ordering::AcqRel);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(_) => {
                thread::sleep(Duration::from_millis(100));
            }
        }
    }

    let should_clear = {
        let mut g = state.lock().unwrap_or_else(|e| e.into_inner());
        g.shutdown_requested = true;
        g.lock_inner("daemon shutdown")
    };
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
    heavy_workers: &Arc<AtomicUsize>,
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

    // Control requests (Status, Lock, Shutdown) NEVER contend with heavy worker slots.
    match req {
        DaemonRequest::Status => {
            let guard = state.lock().unwrap_or_else(|e| e.into_inner());
            DaemonResponse::Status(guard.status())
        }
        DaemonRequest::Lock => {
            let _had_session = {
                let mut guard = state.lock().unwrap_or_else(|e| e.into_inner());
                guard.lock_inner("manual lock")
            };
            // Always clear clipboard on explicit Lock (even if vault was already locked or unlocking).
            clear_clipboard_best_effort();
            DaemonResponse::Ok
        }
        DaemonRequest::Shutdown => {
            let _ = {
                let mut guard = state.lock().unwrap_or_else(|e| e.into_inner());
                guard.shutdown_requested = true;
                guard.lock_inner("daemon shutdown")
            };
            clear_clipboard_best_effort();
            DaemonResponse::Ok
        }
        heavy_req => {
            let prev = heavy_workers.fetch_add(1, Ordering::AcqRel);
            if prev >= MAX_HEAVY_WORKERS {
                heavy_workers.fetch_sub(1, Ordering::AcqRel);
                return DaemonResponse::Error {
                    message: "daemon busy (too many concurrent unlock/vault operations)".into(),
                };
            }
            struct HeavyGuard<'a>(&'a AtomicUsize);
            impl Drop for HeavyGuard<'_> {
                fn drop(&mut self) {
                    self.0.fetch_sub(1, Ordering::AcqRel);
                }
            }
            let _hg = HeavyGuard(heavy_workers);
            handle_heavy_request(heavy_req, state, io_lock, my_uid, enforce_kdf_policy)
        }
    }
}

fn handle_heavy_request(
    mut req: DaemonRequest,
    state: &Arc<Mutex<DaemonState>>,
    io_lock: &Arc<Mutex<()>>,
    my_uid: u32,
    enforce_kdf_policy: bool,
) -> DaemonResponse {
    match &mut req {
        DaemonRequest::Unlock {
            vault_path,
            passphrase,
            keyfile_path,
            fido2_device,
        } => {
            if is_screen_locker_active(my_uid) {
                return DaemonResponse::Error {
                    message: "refusing to unlock while screen locker is active".into(),
                };
            }

            // Capture current lock_epoch BEFORE slow Argon2id / FIDO2 touch so any concurrent
            // `omavault lock`, TUI cancel, suspend, or screen lock aborts this unlock cleanly.
            let start_epoch = {
                let Ok(guard) = state.lock() else {
                    return DaemonResponse::Error {
                        message: "daemon state lock poisoned".into(),
                    };
                };
                if guard.shutdown_requested {
                    return DaemonResponse::Error {
                        message: "daemon shutting down".into(),
                    };
                }
                guard.lock_epoch
            };

            let vault_path_owned = vault_path.clone();
            let kf_path_owned = keyfile_path.clone();
            let fido2_dev_owned = fido2_device.clone();
            let pass_owned = Zeroizing::new(std::mem::take(&mut passphrase.0));

            let result = (|| -> Result<UnlockedSession> {
                let canonical = canonical_or_owned(&vault_path_owned);
                let header = read_header_from_disk(&canonical, enforce_kdf_policy)?;

                let kf_digest = if header.requires_keyfile() {
                    let kf_path = kf_path_owned.as_ref().ok_or(VaultError::KeyfileRequired)?;
                    Some(hash_keyfile(kf_path)?)
                } else {
                    None
                };

                let resolution = resolve_master_key(
                    &header,
                    pass_owned.as_bytes(),
                    kf_digest.as_deref(),
                    &LibFido2Cli,
                    fido2_dev_owned.as_deref(),
                    enforce_kdf_policy,
                )?;
                // Drop & zeroize plaintext passphrase IMMEDIATELY after key derivation.
                drop(pass_owned);
                let master_key = resolution.master_key;

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
                    // Re-check lock_epoch, shutdown & screen locker before committing unlocked session.
                    if guard.shutdown_requested
                        || guard.lock_epoch != start_epoch
                        || is_screen_locker_active(my_uid)
                    {
                        return DaemonResponse::Error {
                            message: "unlock cancelled due to concurrent lock/shutdown".into(),
                        };
                    }
                    guard.session = Some(session);
                    DaemonResponse::Ok
                }
                Err(e) => DaemonResponse::Error {
                    message: e.to_string(),
                },
            }
        }
        DaemonRequest::LoadVault { vault_path } => {
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
                Ok((hdr, vault)) => {
                    let rev = header_revision(&hdr);
                    if let Ok(mut guard) = state.lock() {
                        if let Some(session) = guard.session.as_mut() {
                            if session.vault_path == canonical {
                                session.header = hdr;
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
            vault_path,
            vault,
            expected_revision,
        } => {
            let canonical = canonical_or_owned(vault_path);
            let (key_clone, mut header_copy, start_epoch) = {
                let Ok(mut guard) = state.lock() else {
                    return DaemonResponse::Error {
                        message: "daemon state lock poisoned".into(),
                    };
                };
                let epoch = guard.lock_epoch;
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
                let key = match session.master_key.try_clone() {
                    Ok(k) => k,
                    Err(e) => {
                        return DaemonResponse::Error {
                            message: e.to_string(),
                        }
                    }
                };
                (key, session.header.clone(), epoch)
            };

            let _io = match io_lock.lock() {
                Ok(g) => g,
                Err(_) => {
                    return DaemonResponse::Error {
                        message: "daemon I/O lock poisoned".into(),
                    }
                }
            };

            // Verify session was not locked while waiting for io_lock.
            {
                let Ok(guard) = state.lock() else {
                    return DaemonResponse::Error {
                        message: "daemon state lock poisoned".into(),
                    };
                };
                if guard.shutdown_requested || guard.lock_epoch != start_epoch {
                    return DaemonResponse::Error {
                        message: "save cancelled: vault was locked concurrently".into(),
                    };
                }
            }

            // Use the latest known header revision if caller omitted expected_revision.
            let effective_rev = expected_revision
                .clone()
                .unwrap_or_else(|| header_revision(&header_copy));

            match save_vault_to_disk_checked(
                &canonical,
                &key_clone,
                &mut header_copy,
                vault,
                Some(&effective_rev),
                enforce_kdf_policy,
                true,
            ) {
                Ok(()) => {
                    if let Ok(mut guard) = state.lock() {
                        if guard.lock_epoch == start_epoch {
                            if let Some(session) = guard.session.as_mut() {
                                if session.vault_path == canonical {
                                    session.header = header_copy;
                                }
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
        _ => DaemonResponse::Error {
            message: "unexpected control request in heavy handler".into(),
        },
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
        let parent = resolve_socket_parent(&self.socket_path)?;
        let pmeta = fs::symlink_metadata(parent)?;
        if !pmeta.file_type().is_dir()
            || pmeta.uid() != my_uid
            || (pmeta.permissions().mode() & 0o077) != 0
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

    /// Returns true if the daemon socket path exists on disk.
    pub fn socket_exists(&self) -> bool {
        fs::symlink_metadata(&self.socket_path).is_ok()
    }

    pub fn request(&self, req: &DaemonRequest) -> Result<DaemonResponse> {
        self.request_with_deadline(req, IPC_FRAME_DEADLINE)
    }

    fn request_with_deadline(
        &self,
        req: &DaemonRequest,
        response_deadline: Duration,
    ) -> Result<DaemonResponse> {
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
        let raw = read_frame_with_deadline(&mut stream, response_deadline)?;
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
        match self.request_with_deadline(&req, IPC_UNLOCK_DEADLINE)? {
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

/// Two-pass exact-size frame serializer so `Zeroizing<Vec<u8>>` NEVER reallocates and leaks
/// unzeroized plaintext JSON into freed heap chunks.
fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<()> {
    let mut counter = CountingWriter::default();
    serde_json::to_writer(&mut counter, value)
        .map_err(|_| VaultError::Serialization("failed measuring IPC frame".into()))?;
    if counter.bytes > MAX_IPC_FRAME_BYTES {
        return Err(VaultError::Daemon("IPC payload exceeds maximum size".into()));
    }
    let mut payload = Zeroizing::new(Vec::with_capacity(counter.bytes));
    serde_json::to_writer(&mut *payload, value)
        .map_err(|_| VaultError::Serialization("failed serializing IPC frame".into()))?;
    let len = (payload.len() as u32).to_le_bytes();
    stream.write_all(&len)?;
    stream.write_all(&payload)?;
    stream.flush()?;
    Ok(())
}

/// Read an IPC frame with an absolute monotonic deadline and exact pre-sized `Zeroizing<Vec<u8>>`
/// (peer UID is already authenticated via `SO_PEERCRED` before calling).
fn read_frame(stream: &mut UnixStream) -> Result<Zeroizing<Vec<u8>>> {
    read_frame_with_deadline(stream, IPC_FRAME_DEADLINE)
}

fn read_frame_with_deadline(
    stream: &mut UnixStream,
    timeout: Duration,
) -> Result<Zeroizing<Vec<u8>>> {
    let deadline = Instant::now() + timeout;
    let mut len_buf = [0u8; 4];
    read_exact_with_deadline(stream, &mut len_buf, deadline)?;
    let total_len = u32::from_le_bytes(len_buf) as usize;
    if total_len == 0 || total_len > MAX_IPC_FRAME_BYTES {
        return Err(VaultError::Daemon("invalid IPC frame length".into()));
    }

    let mut out = Zeroizing::new(Vec::with_capacity(total_len));
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
