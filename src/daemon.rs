use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
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
use crate::procsig::{signal_daemon_lock, write_pid_into};
use crate::sleep::{SleepMonitor, SleepMonitorState};
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
/// Absolute maximum time a vault may stay unlocked in the daemon, regardless of IPC activity.
pub const DEFAULT_MAX_SESSION_SECS: u64 = 3600;
pub const MIN_MAX_SESSION_SECS: u64 = 60;
pub const MAX_MAX_SESSION_SECS: u64 = 24 * 3600;
const MAX_IPC_FRAME_BYTES: usize = 16 * 1024 * 1024;
/// General-purpose concurrent IPC workers (any request type).
const MAX_GENERAL_WORKERS: usize = 16;
/// Extra worker slots used ONLY when the general pool is full, and only for requests whose
/// first frame parses as `Lock` / `Status` / `Shutdown` within `CONTROL_FIRST_FRAME_DEADLINE`.
const RESERVED_CONTROL_WORKERS: usize = 8;
/// Maximum concurrent heavy workers (`Unlock`, `LoadVault`, `SaveVault`).
const MAX_HEAVY_WORKERS: usize = 8;
/// The 4-byte length header of the first request frame must arrive within this window, so idle
/// "slowloris" connections release their worker slot quickly.
const IPC_HEADER_DEADLINE: Duration = Duration::from_secs(1);
const CONTROL_FIRST_FRAME_DEADLINE: Duration = Duration::from_millis(250);
const IPC_FRAME_DEADLINE: Duration = Duration::from_secs(10);
/// Overall deadline for writing one response frame (a slow reader cannot pin plaintext).
const IPC_WRITE_DEADLINE: Duration = Duration::from_secs(10);
/// Initial receive buffer; grown once to the exact frame size after this much has arrived.
const IPC_INITIAL_RECV_CAPACITY: usize = 64 * 1024;
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
    /// Seconds until the absolute session lifetime forces a lock (0 when locked).
    #[serde(default)]
    pub session_remaining_secs: u64,
    #[serde(default)]
    pub max_session_secs: u64,
    /// Human-readable state of the logind pre-sleep monitor.
    #[serde(default)]
    pub presleep_monitor: String,
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
    /// Successful `SaveVault`, carrying the new revision token (no plaintext round-trip needed).
    Saved {
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
    /// When the session was unlocked (`CLOCK_BOOTTIME`); never refreshed by activity.
    unlocked_at_boot_secs: u64,
}

struct DaemonState {
    session: Option<UnlockedSession>,
    idle_timeout_secs: u64,
    max_session_secs: u64,
    presleep: Option<Arc<Mutex<SleepMonitorState>>>,
    last_lock_reason: Option<String>,
    shutdown_requested: bool,
    /// Monotonic epoch incremented on EVERY lock/shutdown event so in-flight `Unlock` or
    /// `SaveVault` operations can never race past a concurrent `Lock` and silently re-unlock.
    lock_epoch: u64,
    hardening: HardeningStatus,
}

impl DaemonState {
    fn new(idle_timeout_secs: u64, max_session_secs: u64, hardening: HardeningStatus) -> Self {
        Self {
            session: None,
            idle_timeout_secs,
            max_session_secs,
            presleep: None,
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

    fn presleep_description(&self) -> String {
        match &self.presleep {
            Some(st) => st
                .lock()
                .map(|s| s.describe())
                .unwrap_or_else(|e| e.into_inner().describe()),
            None => "disabled".into(),
        }
    }

    fn status(&self) -> DaemonStatus {
        let presleep_monitor = self.presleep_description();
        match &self.session {
            Some(s) => {
                let now = current_boot_secs();
                let elapsed = now.saturating_sub(s.last_activity_boot_secs);
                let remaining = self.idle_timeout_secs.saturating_sub(elapsed);
                let session_remaining = self
                    .max_session_secs
                    .saturating_sub(now.saturating_sub(s.unlocked_at_boot_secs));
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
                    session_remaining_secs: session_remaining,
                    max_session_secs: self.max_session_secs,
                    presleep_monitor,
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
                session_remaining_secs: 0,
                max_session_secs: self.max_session_secs,
                presleep_monitor,
            },
        }
    }

    /// Lock reason if the session has exceeded the idle timeout or absolute lifetime.
    fn expiry_reason(&self, now: u64) -> Option<&'static str> {
        let s = self.session.as_ref()?;
        if now.saturating_sub(s.unlocked_at_boot_secs) >= self.max_session_secs {
            Some("maximum session lifetime reached")
        } else if now.saturating_sub(s.last_activity_boot_secs) >= self.idle_timeout_secs {
            Some("inactivity timeout")
        } else {
            None
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
        // Publish our PID so `omavault lock` can fall back to SIGUSR1 if the socket is flooded.
        let mut file = file;
        write_pid_into(&mut file)?;
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

/// Daemon runtime configuration.
#[derive(Clone, Debug)]
pub struct DaemonConfig {
    pub idle_timeout_secs: u64,
    /// Absolute unlocked-session lifetime; clamped to `MIN_MAX_SESSION_SECS..=MAX_MAX_SESSION_SECS`.
    pub max_session_secs: u64,
    pub enforce_kdf_policy: bool,
    pub hardening: HardeningStatus,
    /// Subscribe to systemd-logind `PrepareForSleep` (disabled in tests).
    pub presleep_monitor: bool,
}

impl DaemonConfig {
    pub fn new(idle_timeout_secs: u64, enforce_kdf_policy: bool) -> Self {
        Self {
            idle_timeout_secs,
            max_session_secs: DEFAULT_MAX_SESSION_SECS,
            enforce_kdf_policy,
            hardening: HardeningStatus::default(),
            presleep_monitor: false,
        }
    }
}

/// Validate a user-supplied `--max-session` value.
pub fn validate_max_session_secs(secs: u64) -> Result<u64> {
    if !(MIN_MAX_SESSION_SECS..=MAX_MAX_SESSION_SECS).contains(&secs) {
        return Err(VaultError::Daemon(format!(
            "--max-session must be between {MIN_MAX_SESSION_SECS} and {MAX_MAX_SESSION_SECS} seconds"
        )));
    }
    Ok(secs)
}

/// Run the auto-locking background daemon listening on `socket_path`.
pub fn run_daemon(
    socket_path: &Path,
    idle_timeout_secs: u64,
    enforce_kdf_policy: bool,
) -> Result<()> {
    run_daemon_with_config(
        socket_path,
        DaemonConfig::new(idle_timeout_secs, enforce_kdf_policy),
    )
}

/// Run the auto-locking background daemon with recorded `HardeningStatus` telemetry.
pub fn run_daemon_with_hardening(
    socket_path: &Path,
    idle_timeout_secs: u64,
    enforce_kdf_policy: bool,
    hardening: HardeningStatus,
) -> Result<()> {
    let mut cfg = DaemonConfig::new(idle_timeout_secs, enforce_kdf_policy);
    cfg.hardening = hardening;
    cfg.presleep_monitor = true;
    run_daemon_with_config(socket_path, cfg)
}

fn lock_and_clear(state: &Mutex<DaemonState>, reason: &str) {
    {
        let mut g = state.lock().unwrap_or_else(|e| e.into_inner());
        g.lock_inner(reason);
    }
    clear_clipboard_best_effort();
}

/// Run the daemon with an explicit [`DaemonConfig`].
pub fn run_daemon_with_config(socket_path: &Path, cfg: DaemonConfig) -> Result<()> {
    let enforce_kdf_policy = cfg.enforce_kdf_policy;
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

    // The CLI enforces MIN_MAX_SESSION_SECS..=MAX_MAX_SESSION_SECS via
    // `validate_max_session_secs`; library callers (tests) may use shorter lifetimes.
    let max_session = cfg.max_session_secs.clamp(1, MAX_MAX_SESSION_SECS);
    let state = Arc::new(Mutex::new(DaemonState::new(
        cfg.idle_timeout_secs.max(10),
        max_session,
        cfg.hardening,
    )));
    let io_lock = Arc::new(Mutex::new(()));
    let general_workers = Arc::new(AtomicUsize::new(0));
    let control_workers = Arc::new(AtomicUsize::new(0));
    let active_heavy_workers = Arc::new(AtomicUsize::new(0));
    let signal_stop = Arc::new(AtomicBool::new(false));

    // Graceful shutdown signals (SIGTERM, SIGINT, SIGHUP).
    let _ = signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&signal_stop));
    let _ = signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&signal_stop));
    let _ = signal_hook::flag::register(signal_hook::consts::SIGHUP, Arc::clone(&signal_stop));

    // Out-of-band emergency lock (SIGUSR1), handled IMMEDIATELY on a dedicated thread. This is
    // the fallback path `omavault lock` uses when the socket is flooded.
    let mut sigusr1 = signal_hook::iterator::Signals::new([signal_hook::consts::SIGUSR1])
        .map_err(|e| VaultError::Daemon(format!("failed registering SIGUSR1: {e}")))?;
    let sigusr1_handle = sigusr1.handle();
    let sigusr1_state = Arc::clone(&state);
    let sigusr1_thread = thread::Builder::new()
        .name("omavaultd-sigusr1".into())
        .spawn(move || {
            for _ in sigusr1.forever() {
                lock_and_clear(&sigusr1_state, "emergency SIGUSR1 lock");
            }
        })
        .map_err(|e| VaultError::Daemon(format!("failed spawning signal thread: {e}")))?;

    // Pre-sleep / hibernate lock via unprivileged systemd-logind subscription + delay inhibitor.
    let _sleep_monitor = if cfg.presleep_monitor {
        let sleep_state = Arc::clone(&state);
        let monitor = SleepMonitor::spawn(move || {
            lock_and_clear(&sleep_state, "system pre-sleep/hibernate");
        });
        state.lock().unwrap_or_else(|e| e.into_inner()).presleep = Some(monitor.state_handle());
        Some(monitor)
    } else {
        None
    };

    // Spawn security watchdog thread (CLOCK_BOOTTIME idle timeout + absolute session lifetime,
    // Hyprland/proc screen lock, and CLOCK_BOOTTIME - CLOCK_MONOTONIC suspend/resume detection).
    let watchdog_state = Arc::clone(&state);
    let watchdog_signal = Arc::clone(&signal_stop);
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
                    } else if let Some(reason) = guard.expiry_reason(current_boot_secs()) {
                        clear_clip = guard.lock_inner(reason);
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

    // Main accept loop. Connections go to the general pool; when it is full, a small reserved
    // pool accepts ONLY control requests (Lock/Status/Shutdown) that arrive within 250 ms, so a
    // flood of idle or slow connections cannot starve `omavault lock`.
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
                let (pool, control_only) = if try_acquire(&general_workers, MAX_GENERAL_WORKERS)
                {
                    (Arc::clone(&general_workers), false)
                } else if try_acquire(&control_workers, RESERVED_CONTROL_WORKERS) {
                    (Arc::clone(&control_workers), true)
                } else {
                    reject_busy(&mut stream);
                    continue;
                };

                let st = Arc::clone(&state);
                let io_l = Arc::clone(&io_lock);
                let heavy_workers = Arc::clone(&active_heavy_workers);
                let pool_for_thread = Arc::clone(&pool);
                let spawn_res = thread::Builder::new().spawn(move || {
                    struct WorkerGuard(Arc<AtomicUsize>);
                    impl Drop for WorkerGuard {
                        fn drop(&mut self) {
                            self.0.fetch_sub(1, Ordering::AcqRel);
                        }
                    }
                    let _wg = WorkerGuard(pool_for_thread);

                    if stream.set_nonblocking(false).is_err() {
                        return;
                    }
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(250)));
                    let response = handle_connection(
                        &mut stream,
                        &st,
                        &io_l,
                        &heavy_workers,
                        my_uid,
                        enforce_kdf_policy,
                        control_only,
                    );
                    let _ = write_frame(&mut stream, &response);
                });
                if spawn_res.is_err() {
                    pool.fetch_sub(1, Ordering::AcqRel);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
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
    sigusr1_handle.close();
    let _ = sigusr1_thread.join();
    Ok(())
}

/// Increment `counter` only if it is below `max`.
fn try_acquire(counter: &AtomicUsize, max: usize) -> bool {
    let mut cur = counter.load(Ordering::Acquire);
    while cur < max {
        match counter.compare_exchange_weak(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(actual) => cur = actual,
        }
    }
    false
}

/// Best-effort, NON-blocking busy reply so a full peer buffer can never stall the accept loop.
fn reject_busy(stream: &mut UnixStream) {
    let _ = stream.set_nonblocking(true);
    let msg = DaemonResponse::Error {
        message: "daemon busy (too many concurrent connections)".into(),
    };
    if let Ok(payload) = serde_json::to_vec(&msg) {
        let mut frame = (payload.len() as u32).to_le_bytes().to_vec();
        frame.extend_from_slice(&payload);
        let _ = stream.write(&frame);
    }
}

fn handle_connection(
    stream: &mut UnixStream,
    state: &Arc<Mutex<DaemonState>>,
    io_lock: &Arc<Mutex<()>>,
    heavy_workers: &Arc<AtomicUsize>,
    my_uid: u32,
    enforce_kdf_policy: bool,
    control_only: bool,
) -> DaemonResponse {
    let (header_deadline, frame_deadline) = if control_only {
        (CONTROL_FIRST_FRAME_DEADLINE, CONTROL_FIRST_FRAME_DEADLINE)
    } else {
        (IPC_HEADER_DEADLINE, IPC_FRAME_DEADLINE)
    };
    let raw = match read_frame_with_deadlines(stream, header_deadline, frame_deadline) {
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
            // Always clear clipboard on explicit Lock (even if vault was already locked or unlocking).
            lock_and_clear(state, "manual lock");
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
        _ if control_only => DaemonResponse::Error {
            message: "daemon busy (only lock/status/shutdown accepted right now)".into(),
        },
        heavy_req => {
            if !try_acquire(heavy_workers, MAX_HEAVY_WORKERS) {
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

                let now = current_boot_secs();
                Ok(UnlockedSession {
                    vault_path: canonical,
                    master_key,
                    header: verified_header,
                    last_activity_boot_secs: now,
                    unlocked_at_boot_secs: now,
                })
            })();

            match result {
                Ok(session) => {
                    // Probe the (potentially slow) screen locker BEFORE taking the state mutex so
                    // a wedged compositor socket can never block Lock/Status/SIGUSR1/sleep.
                    let locker_active = is_screen_locker_active(my_uid);
                    let Ok(mut guard) = state.lock() else {
                        return DaemonResponse::Error {
                            message: "daemon state lock poisoned".into(),
                        };
                    };
                    // Re-check lock_epoch, shutdown & screen locker before committing unlocked session.
                    if guard.shutdown_requested || guard.lock_epoch != start_epoch || locker_active
                    {
                        return DaemonResponse::Error {
                            message: "unlock cancelled due to concurrent lock/shutdown".into(),
                        };
                    }
                    // A session switch is an epoch boundary: in-flight Load/Save for the previous
                    // session must not complete against the new one.
                    guard.lock_epoch = guard.lock_epoch.wrapping_add(1);
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
            let (key_clone, start_epoch) = {
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
                match session.master_key.try_clone() {
                    Ok(k) => (k, epoch),
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
            if !session_still_current(state, start_epoch, &canonical) {
                return DaemonResponse::Error {
                    message: "load cancelled: vault was locked concurrently".into(),
                };
            }
            let loaded = load_vault_from_disk(&canonical, &key_clone, enforce_kdf_policy);
            drop(key_clone);
            match loaded {
                Ok((hdr, vault)) => {
                    let rev = header_revision(&hdr);
                    // Re-check under the state mutex right before releasing plaintext: a Lock,
                    // suspend, or shutdown that raced the disk read wins and the vault is dropped.
                    let Ok(mut guard) = state.lock() else {
                        return DaemonResponse::Error {
                            message: "daemon state lock poisoned".into(),
                        };
                    };
                    if guard.shutdown_requested || guard.lock_epoch != start_epoch {
                        return DaemonResponse::Error {
                            message: "load cancelled: vault was locked concurrently".into(),
                        };
                    }
                    match guard.session.as_mut() {
                        Some(session) if session.vault_path == canonical => {
                            session.header = hdr;
                        }
                        _ => {
                            return DaemonResponse::Error {
                                message: "load cancelled: vault was locked concurrently".into(),
                            }
                        }
                    }
                    drop(guard);
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

            // Verify session was not locked or switched while waiting for io_lock.
            if !session_still_current(state, start_epoch, &canonical) {
                return DaemonResponse::Error {
                    message: "save cancelled: vault was locked concurrently".into(),
                };
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
                    let revision = header_revision(&header_copy);
                    if let Ok(mut guard) = state.lock() {
                        if guard.lock_epoch == start_epoch {
                            if let Some(session) = guard.session.as_mut() {
                                if session.vault_path == canonical {
                                    session.header = header_copy;
                                }
                            }
                        }
                    }
                    DaemonResponse::Saved { revision }
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

/// True iff no lock/shutdown/session-switch happened since `start_epoch` and the unlocked
/// session is still for `canonical`.
fn session_still_current(state: &Mutex<DaemonState>, start_epoch: u64, canonical: &Path) -> bool {
    let Ok(guard) = state.lock() else {
        return false;
    };
    !guard.shutdown_requested
        && guard.lock_epoch == start_epoch
        && guard
            .session
            .as_ref()
            .is_some_and(|s| s.vault_path == canonical)
}

/// Client helper for communicating with the local `omavault` daemon.
pub struct DaemonClient {
    socket_path: PathBuf,
}

/// How an emergency lock reached the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockOutcome {
    Socket,
    /// Socket path failed; `SIGUSR1` was delivered to this verified daemon PID.
    Signal(u32),
}

impl DaemonClient {
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    /// Verify socket & parent directory ownership/permissions before connecting (never follows symlinks).
    fn validate_socket_security(&self) -> Result<()> {
        let my_uid = unsafe { libc::geteuid() };
        let parent = resolve_socket_parent(&self.socket_path)?;
        let not_running = |e: std::io::Error| {
            if e.kind() == std::io::ErrorKind::NotFound {
                VaultError::DaemonUnavailable(format!(
                    "no daemon socket at '{}'",
                    self.socket_path.display()
                ))
            } else {
                VaultError::Io(e)
            }
        };
        let pmeta = fs::symlink_metadata(parent).map_err(not_running)?;
        if !pmeta.file_type().is_dir()
            || pmeta.uid() != my_uid
            || (pmeta.permissions().mode() & 0o077) != 0
        {
            return Err(VaultError::Daemon(format!(
                "refusing to connect: unsafe socket directory '{}'",
                parent.display()
            )));
        }
        let smeta = fs::symlink_metadata(&self.socket_path).map_err(not_running)?;
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
            let msg = format!(
                "cannot connect to omavault daemon at '{}': {e}",
                self.socket_path.display()
            );
            match e.kind() {
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
                    VaultError::DaemonUnavailable(msg)
                }
                _ => VaultError::Daemon(msg),
            }
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

    /// Lock via the socket, falling back to a verified `SIGUSR1` to the daemon process if the
    /// socket request fails for any reason other than "daemon not running" (e.g. a connection
    /// flood exhausting worker slots).
    pub fn lock_with_fallback(&self) -> Result<LockOutcome> {
        // A "busy" reply means the daemon is alive but its pools are saturated: retry briefly
        // (reserved control slots free up within 250 ms), then fall back to SIGUSR1.
        let mut result = self.lock();
        for _ in 0..3 {
            match &result {
                Err(VaultError::Daemon(m)) if m.contains("busy") => {
                    thread::sleep(Duration::from_millis(100));
                    result = self.lock();
                }
                _ => break,
            }
        }
        match result {
            Ok(()) => Ok(LockOutcome::Socket),
            Err(VaultError::DaemonUnavailable(m)) => {
                // A stale or removed socket can still leave a live daemon behind.
                match signal_daemon_lock(&self.socket_path) {
                    Some(pid) => Ok(LockOutcome::Signal(pid)),
                    None => Err(VaultError::DaemonUnavailable(m)),
                }
            }
            Err(e) => match signal_daemon_lock(&self.socket_path) {
                Some(pid) => Ok(LockOutcome::Signal(pid)),
                None => Err(e),
            },
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

    /// Save via the daemon. Returns the new revision token when the daemon reports it.
    pub fn save_vault(
        &self,
        vault_path: &Path,
        vault: &Vault,
        expected_revision: Option<String>,
    ) -> Result<Option<String>> {
        let req = DaemonRequest::SaveVault {
            vault_path: vault_path.to_path_buf(),
            vault: vault.clone(),
            expected_revision,
        };
        match self.request(&req)? {
            DaemonResponse::Saved { revision } => Ok(Some(revision)),
            DaemonResponse::Ok => Ok(None),
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
    let deadline = Instant::now() + IPC_WRITE_DEADLINE;
    write_all_with_deadline(stream, &len, deadline)?;
    write_all_with_deadline(stream, &payload, deadline)?;
    Ok(())
}

/// `write_all` bounded by ONE overall monotonic deadline (not per-syscall), so a peer that
/// reads a byte every few seconds cannot keep a plaintext response pinned in daemon memory.
fn write_all_with_deadline(stream: &mut UnixStream, mut buf: &[u8], deadline: Instant) -> Result<()> {
    while !buf.is_empty() {
        let now = Instant::now();
        if now >= deadline {
            return Err(VaultError::Daemon("IPC frame write timed out".into()));
        }
        let remaining = (deadline - now).max(Duration::from_millis(1));
        let _ = stream.set_write_timeout(Some(remaining));
        let end = buf.len().min(64 * 1024);
        match stream.write(&buf[..end]) {
            Ok(0) => return Err(VaultError::Daemon("IPC peer closed during write".into())),
            Ok(n) => buf = &buf[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => return Err(VaultError::Io(e)),
        }
    }
    Ok(())
}

fn read_frame_with_deadline(
    stream: &mut UnixStream,
    timeout: Duration,
) -> Result<Zeroizing<Vec<u8>>> {
    read_frame_with_deadlines(stream, timeout, timeout)
}

/// Read one IPC frame: the 4-byte length header must arrive within `header_timeout`, the whole
/// frame within `frame_timeout` (both measured from now).
///
/// Memory is reserved incrementally: at most `IPC_INITIAL_RECV_CAPACITY` up front, then ONE
/// exact-size `Zeroizing` buffer once that much has actually arrived (the small buffer is wiped
/// on drop), so a peer cannot make the daemon reserve 16 MiB with a 4-byte header.
fn read_frame_with_deadlines(
    stream: &mut UnixStream,
    header_timeout: Duration,
    frame_timeout: Duration,
) -> Result<Zeroizing<Vec<u8>>> {
    let start = Instant::now();
    let header_deadline = start + header_timeout;
    let deadline = start + frame_timeout.max(header_timeout);
    let mut len_buf = [0u8; 4];
    read_exact_with_deadline(stream, &mut len_buf, header_deadline)?;
    let total_len = u32::from_le_bytes(len_buf) as usize;
    if total_len == 0 || total_len > MAX_IPC_FRAME_BYTES {
        return Err(VaultError::Daemon("invalid IPC frame length".into()));
    }

    let mut out = Zeroizing::new(Vec::with_capacity(total_len.min(IPC_INITIAL_RECV_CAPACITY)));
    let mut chunk = Zeroizing::new([0u8; 16 * 1024]);
    let mut remaining = total_len;
    while remaining > 0 {
        let want = remaining.min(chunk.len());
        let n = read_some_with_deadline(stream, &mut chunk[..want], deadline)?;
        if n == 0 {
            return Err(VaultError::Daemon("unexpected EOF reading IPC frame".into()));
        }
        if out.len() + n > out.capacity() {
            let mut grown = Zeroizing::new(Vec::with_capacity(total_len));
            grown.extend_from_slice(&out);
            out = grown; // previous buffer is zeroized on drop
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
