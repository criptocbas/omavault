use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use wl_clipboard_rs::copy::{self, ClipboardType, MimeType, Options, Seat, ServeRequests, Source};
use zeroize::Zeroizing;

use crate::error::{Result, VaultError};
use crate::hardening::fill_random;
use crate::vault::storage::ensure_private_dir_strict;

/// Default number of seconds before copied secrets are automatically wiped from Wayland clipboard.
pub const DEFAULT_CLIPBOARD_TIMEOUT_SECS: u64 = 15;
pub const MIN_CLIPBOARD_TIMEOUT_SECS: u64 = 1;
pub const MAX_CLIPBOARD_TIMEOUT_SECS: u64 = 300;
const MAX_CLIPBOARD_SECRET_BYTES: u64 = 64 * 1024;
const MAX_CLIP_STATE_BYTES: u64 = 256;
/// Bound for `flock` on `clip.lock` in the helper, the daemon, and `copy_secret`.
const CLIP_LOCK_TIMEOUT: Duration = Duration::from_secs(3);
/// Bound for the helper's readiness line. The clipboard lock is held while waiting, so this MUST
/// stay well below `CLIP_LOCK_TIMEOUT`: otherwise a superseded helper (or an emergency clear) could
/// give up waiting for the lock and fail-closed-clear a new copy that is still being set up.
const CLIP_READY_TIMEOUT: Duration = Duration::from_secs(2);
const _: () = assert!(CLIP_READY_TIMEOUT.as_millis() + 500 < CLIP_LOCK_TIMEOUT.as_millis());

#[derive(Debug, Clone, Copy)]
pub struct ClipboardOptions {
    pub timeout_secs: u64,
    pub paste_once: bool,
}

impl Default for ClipboardOptions {
    fn default() -> Self {
        Self {
            timeout_secs: DEFAULT_CLIPBOARD_TIMEOUT_SECS,
            paste_once: false,
        }
    }
}

/// Validate clipboard auto-clear timeout is within `1..=300` seconds (never `0`).
pub fn validate_clipboard_timeout(timeout_secs: u64) -> Result<u64> {
    if !(MIN_CLIPBOARD_TIMEOUT_SECS..=MAX_CLIPBOARD_TIMEOUT_SECS).contains(&timeout_secs) {
        return Err(VaultError::Clipboard(format!(
            "clipboard timeout must be between {MIN_CLIPBOARD_TIMEOUT_SECS} and {MAX_CLIPBOARD_TIMEOUT_SECS} seconds"
        )));
    }
    Ok(timeout_secs)
}

/// Directory that holds `clip.state` and `clip.lock`.
///
/// Tests use [`ClipStore::in_dir`] so they never touch the real session directory.
#[derive(Clone)]
pub(crate) struct ClipStore {
    dir: PathBuf,
}

impl ClipStore {
    /// Same directory selection as the historical `clip_state_path()`:
    /// `$XDG_RUNTIME_DIR/omavault`, else `~/.local/state/omavault`.
    pub(crate) fn from_env() -> Option<Self> {
        if let Ok(runtime) = std::env::var("XDG_RUNTIME_DIR") {
            if !runtime.trim().is_empty() {
                return Some(Self {
                    dir: PathBuf::from(runtime).join("omavault"),
                });
            }
        }
        if let Ok(home) = std::env::var("HOME") {
            if !home.trim().is_empty() {
                return Some(Self {
                    dir: PathBuf::from(home)
                        .join(".local")
                        .join("state")
                        .join("omavault"),
                });
            }
        }
        None
    }

    #[cfg(test)]
    pub(crate) fn in_dir(dir: PathBuf) -> Self {
        Self { dir }
    }

    fn state_path(&self) -> PathBuf {
        self.dir.join("clip.state")
    }

    fn lock_path(&self) -> PathBuf {
        self.dir.join("clip.lock")
    }

    /// Exclusive `flock` on `clip.lock`. Waits at most `timeout` (non-blocking polls, 10 ms apart).
    pub(crate) fn lock(&self, timeout: Duration) -> Result<ClipLockGuard> {
        ensure_private_dir_strict(&self.dir, true)?;
        let path = self.lock_path();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
            .map_err(|e| {
                VaultError::Clipboard(format!(
                    "failed to open clipboard lock '{}': {e}",
                    path.display()
                ))
            })?;
        let meta = file.metadata().map_err(VaultError::Io)?;
        let my_uid = unsafe { libc::geteuid() };
        if !meta.file_type().is_file() || meta.uid() != my_uid || meta.nlink() != 1 {
            return Err(VaultError::Clipboard(format!(
                "clipboard lock '{}' is not a private regular file owned by the current user (symlinks and hard links are refused)",
                path.display()
            )));
        }
        let rc_chmod = unsafe { libc::fchmod(file.as_raw_fd(), 0o600) };
        if rc_chmod != 0 {
            return Err(VaultError::Io(std::io::Error::last_os_error()));
        }

        let started = Instant::now();
        loop {
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if rc == 0 {
                return Ok(ClipLockGuard {
                    file,
                    dir: self.dir.clone(),
                });
            }
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(e) if e == libc::EWOULDBLOCK || e == libc::EAGAIN => {}
                _ => {
                    return Err(VaultError::Clipboard(format!(
                        "clipboard lock failed: {err}"
                    )))
                }
            }
            if started.elapsed() >= timeout {
                return Err(VaultError::Clipboard(
                    "timed out waiting for clipboard lock".into(),
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}

/// `flock(LOCK_EX)` on `clip.lock`, held until drop. All clipboard state changes go through it.
pub(crate) struct ClipLockGuard {
    file: File,
    dir: PathBuf,
}

impl ClipLockGuard {
    fn state_path(&self) -> PathBuf {
        self.dir.join("clip.state")
    }

    fn read(&self) -> Option<(u32, String)> {
        read_state_file(&self.state_path())
    }

    fn write(&self, pid: u32, gen: &str) -> Result<()> {
        let path = self.state_path();
        let parent = path
            .parent()
            .ok_or_else(|| VaultError::Clipboard("invalid clipboard state path".into()))?;
        let tmp = parent.join(format!(".clip.state.tmp.{pid}.{gen}"));
        let write_res = (|| -> std::io::Result<()> {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&tmp)?;
            f.write_all(format!("{pid}:{gen}\n").as_bytes())?;
            Ok(())
        })();
        if let Err(e) = write_res {
            let _ = fs::remove_file(&tmp);
            return Err(VaultError::Clipboard(format!(
                "failed writing clipboard state: {e}"
            )));
        }
        if let Err(e) = fs::rename(&tmp, &path) {
            let _ = fs::remove_file(&tmp);
            return Err(VaultError::Clipboard(format!(
                "failed committing clipboard state: {e}"
            )));
        }
        Ok(())
    }

    /// Unlink `clip.state` only when it still names `gen`. Caller holds the lock, so this
    /// cannot delete a generation published after the read.
    fn remove_if(&self, gen: &str) {
        if let Some((_, current)) = self.read() {
            if current == gen {
                let _ = fs::remove_file(self.state_path());
            }
        }
    }

    fn remove(&self) {
        let _ = fs::remove_file(self.state_path());
    }
}

impl Drop for ClipLockGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn read_state_file(path: &Path) -> Option<(u32, String)> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let meta = file.metadata().ok()?;
    if !meta.file_type().is_file() || meta.len() > MAX_CLIP_STATE_BYTES {
        return None;
    }
    let mut contents = String::new();
    file.take(MAX_CLIP_STATE_BYTES + 1)
        .read_to_string(&mut contents)
        .ok()?;
    let (pid_str, gen_str) = contents.trim().split_once(':')?;
    let pid = pid_str.parse::<u32>().ok()?;
    if pid == 0 || pid > i32::MAX as u32 || gen_str.is_empty() {
        return None;
    }
    Some((pid, gen_str.to_string()))
}

/// May helper `my_gen` globally clear the clipboard?
/// Missing state is fail-closed (`true`): a helper that cannot prove it was superseded still clears.
fn may_clear(my_gen: &str, state: Option<&(u32, String)>) -> bool {
    match state {
        None => true,
        Some((_, gen)) => gen == my_gen,
    }
}

/// Publish `generation` and only then signal the helper recorded before this copy.
/// A superseded helper that locks before clearing therefore observes the new generation.
fn commit_new_generation(
    guard: &ClipLockGuard,
    pid: u32,
    generation: &str,
    previous: &Option<(u32, String)>,
    mut signal: impl FnMut(u32, &str),
) -> Result<()> {
    guard.write(pid, generation)?;
    if let Some((old_pid, old_gen)) = previous {
        signal(*old_pid, old_gen);
    }
    Ok(())
}

/// Verify `/proc/<pid>/cmdline` belongs specifically to `omavault __clip-serve --generation <gen>`
/// so PID reuse can never send `SIGTERM` to `omavaultd`, `omavault tui`, or `omavault rekey`.
#[cfg(target_os = "linux")]
fn pid_matches_clip_helper(pid: u32, expected_gen: &str) -> bool {
    if pid == 0 || pid > i32::MAX as u32 || pid == std::process::id() {
        return false;
    }
    let Ok(cmdline) = fs::read(format!("/proc/{pid}/cmdline")) else {
        return false;
    };
    let args: Vec<&[u8]> = cmdline
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .collect();
    let has_subcmd = args.iter().any(|a| *a == b"__clip-serve");
    let has_gen = args
        .windows(2)
        .any(|w| w[0] == b"--generation" && w[1] == expected_gen.as_bytes());
    has_subcmd && has_gen
}

fn signal_clip_helper(pid: u32, expected_gen: &str) {
    #[cfg(target_os = "linux")]
    {
        if !pid_matches_clip_helper(pid, expected_gen) {
            return;
        }
        unsafe {
            let _ = libc::kill(pid as libc::pid_t, libc::SIGTERM);
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (pid, expected_gen);
    }
}

fn kill_reap(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn read_helper_ack(stdout: ChildStdout) -> std::result::Result<String, RecvTimeoutError> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        let _ = reader.read_line(&mut line);
        let _ = tx.send(line);
    });
    rx.recv_timeout(CLIP_READY_TIMEOUT)
        .map(|line| line.trim().to_string())
}

fn clear_wayland_selections() {
    if std::env::var_os("WAYLAND_DISPLAY").is_some() {
        let _ = copy::clear(ClipboardType::Regular, Seat::All);
        let _ = copy::clear(ClipboardType::Primary, Seat::All);
    }
}

/// Copy a secret into the Wayland clipboard with `x-kde-passwordManagerHint` (`sensitive`)
/// tagging so Omarchy's universal clipboard history skips it.
///
/// Security properties:
/// - Rejects empty secrets and out-of-range timeouts (`0` is forbidden).
/// - Holds `clip.lock` across spawn, readiness, state publish, and the signal to the previous helper.
/// - Writes `clip.state` for the new helper before signalling the previous one, so the old helper
///   cannot globally clear a secret it no longer owns.
/// - A failed spawn or a helper that never becomes ready leaves the previous copy untouched.
/// - Feeds the secret exclusively over an anonymous stdin pipe (never `argv` or tempfiles).
/// - Reaps the child on a background thread so long-lived TUI sessions never accumulate zombies.
pub fn copy_secret(secret: &str, opts: ClipboardOptions) -> Result<()> {
    if secret.is_empty() {
        return Err(VaultError::Clipboard(
            "refusing to copy an empty secret".into(),
        ));
    }
    if (secret.len() as u64) > MAX_CLIPBOARD_SECRET_BYTES {
        return Err(VaultError::Clipboard(
            "secret exceeds maximum 64 KiB clipboard limit".into(),
        ));
    }
    let timeout = validate_clipboard_timeout(opts.timeout_secs)?;

    if std::env::var_os("WAYLAND_DISPLAY").is_none() {
        return Err(VaultError::Clipboard(
            "WAYLAND_DISPLAY is not set; Wayland secret clipboard requires an active Wayland/Hyprland session".into(),
        ));
    }

    let store = ClipStore::from_env()
        .ok_or_else(|| VaultError::Clipboard("cannot determine clipboard state path".into()))?;
    let guard = store.lock(CLIP_LOCK_TIMEOUT)?;
    // Captured under the lock, signalled only after the new generation is published.
    let previous = guard.read();

    let mut gen_bytes = [0u8; 8];
    fill_random(&mut gen_bytes)?;
    let generation: String = gen_bytes.iter().map(|b| format!("{b:02x}")).collect();

    let exe = std::env::current_exe()
        .map_err(|e| VaultError::Clipboard(format!("cannot resolve current executable: {e}")))?;

    let mut cmd = Command::new(exe);
    cmd.arg("__clip-serve")
        .arg("--timeout")
        .arg(timeout.to_string())
        .arg("--generation")
        .arg(&generation);
    if opts.paste_once {
        cmd.arg("--paste-once");
    }

    let mut child = match cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            return Err(VaultError::Clipboard(format!(
                "failed to spawn clipboard helper: {e}"
            )))
        }
    };

    if let Some(mut stdin) = child.stdin.take() {
        if let Err(e) = stdin.write_all(secret.as_bytes()) {
            drop(stdin);
            kill_reap(&mut child);
            return Err(VaultError::Clipboard(format!(
                "failed piping secret to clipboard helper: {e}"
            )));
        }
    }

    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            kill_reap(&mut child);
            return Err(VaultError::Clipboard(
                "clipboard helper did not become ready".into(),
            ));
        }
    };
    let ack = match read_helper_ack(stdout) {
        Ok(ack) => ack,
        Err(RecvTimeoutError::Timeout) => {
            kill_reap(&mut child);
            return Err(VaultError::Clipboard(
                "clipboard helper did not become ready".into(),
            ));
        }
        Err(RecvTimeoutError::Disconnected) => String::new(),
    };

    if ack != "OK" {
        kill_reap(&mut child);
        let detail = ack
            .strip_prefix("ERR:")
            .unwrap_or("Wayland clipboard prepare failed");
        return Err(VaultError::Clipboard(detail.to_string()));
    }

    if let Err(e) = commit_new_generation(
        &guard,
        child.id(),
        &generation,
        &previous,
        signal_clip_helper,
    ) {
        kill_reap(&mut child);
        return Err(e);
    }
    drop(guard);

    thread::spawn(move || {
        let _ = child.wait();
    });

    Ok(())
}

/// Internal entrypoint executed by `omavault __clip-serve`.
pub fn run_clipboard_server(
    timeout_secs: u64,
    paste_once: bool,
    generation: Option<String>,
) -> Result<()> {
    let timeout = validate_clipboard_timeout(timeout_secs)?;
    let generation = generation.unwrap_or_else(|| std::process::id().to_string());

    // L-11: the handler must be installed before we tell the parent we are ready, and before
    // prepare_copy claims the selection. `SigId` is `Copy` and is not unregistered on drop.
    let finished = Arc::new(AtomicBool::new(false));
    let terminated = Arc::new(AtomicBool::new(false));
    let _ = signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&terminated));
    let _ = signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&terminated));

    let mut raw = Zeroizing::new(Vec::with_capacity(4096));
    std::io::stdin()
        .take(MAX_CLIPBOARD_SECRET_BYTES.saturating_add(1))
        .read_to_end(&mut raw)
        .map_err(|e| VaultError::Clipboard(format!("failed reading secret from stdin: {e}")))?;

    if raw.is_empty() || (raw.len() as u64) > MAX_CLIPBOARD_SECRET_BYTES {
        let _ = writeln!(std::io::stdout(), "ERR:invalid secret size");
        return Ok(());
    }

    let mut opts = Options::new();
    opts.clipboard(ClipboardType::Regular)
        .seat(Seat::All)
        .foreground(true)
        .sensitive(true);

    if paste_once {
        opts.serve_requests(ServeRequests::Only(1));
    } else {
        opts.serve_requests(ServeRequests::Unlimited);
    }

    let payload: Box<[u8]> = raw.as_slice().into();
    drop(raw);

    let prepared = match opts.prepare_copy(Source::Bytes(payload), MimeType::Text) {
        Ok(p) => p,
        Err(e) => {
            let _ = writeln!(std::io::stdout(), "ERR:{e}");
            let _ = std::io::stdout().flush();
            return Err(VaultError::Clipboard(format!(
                "Wayland clipboard prepare failed: {e}"
            )));
        }
    };

    // Signal readiness to parent `copy_secret` and close stdout.
    let _ = writeln!(std::io::stdout(), "OK");
    let _ = std::io::stdout().flush();

    let finished_wd = Arc::clone(&finished);
    let terminated_wd = Arc::clone(&terminated);
    let gen_wd = generation.clone();
    let store_wd = ClipStore::from_env();

    thread::spawn(move || {
        let mut remaining_ms = timeout.saturating_mul(1000);
        while remaining_ms > 0 {
            if finished_wd.load(Ordering::SeqCst) {
                return;
            }
            if terminated_wd.load(Ordering::SeqCst) {
                break;
            }
            let step = remaining_ms.min(100);
            thread::sleep(Duration::from_millis(step));
            remaining_ms -= step;
        }

        if finished_wd.load(Ordering::SeqCst) {
            return;
        }

        // Clear globally only if this generation still owns `clip.state` (or the state is gone).
        // A superseded helper just exits: dropping its data source withdraws only its own offer.
        match &store_wd {
            Some(store) => match store.lock(CLIP_LOCK_TIMEOUT) {
                Ok(guard) => {
                    if may_clear(&gen_wd, guard.read().as_ref()) {
                        let _ = copy::clear(ClipboardType::Regular, Seat::All);
                        guard.remove_if(&gen_wd);
                    }
                }
                Err(_) => {
                    let _ = copy::clear(ClipboardType::Regular, Seat::All);
                }
            },
            None => {
                let _ = copy::clear(ClipboardType::Regular, Seat::All);
            }
        }

        // Brief grace period for `prepared.serve()` to observe cancellation and unwind cleanly;
        // ALWAYS exit afterwards so a helper can never linger past timeout or SIGTERM.
        thread::sleep(Duration::from_millis(300));
        if !finished_wd.load(Ordering::SeqCst) {
            std::process::exit(0);
        }
    });

    // Blocks until clipboard ownership is replaced, paste-once completes, or watchdog clears.
    let _ = prepared.serve();
    finished.store(true, Ordering::SeqCst);
    if let Some(store) = ClipStore::from_env() {
        if let Ok(guard) = store.lock(CLIP_LOCK_TIMEOUT) {
            guard.remove_if(&generation);
        }
    }

    // Note: when `paste_once` completes, `wl-clipboard-rs` destroys the data source and closing
    // the Wayland socket atomically drops the selection without a secondary `copy::clear()` race.
    Ok(())
}

/// Immediately stop any active clipboard helper (triggering its own Wayland clipboard wipe even
/// when called from a headless daemon lacking `WAYLAND_DISPLAY`) and clear both Regular and
/// Primary Wayland selections if `WAYLAND_DISPLAY` is available.
pub fn clear_clipboard_best_effort() {
    if let Some(store) = ClipStore::from_env() {
        match store.lock(CLIP_LOCK_TIMEOUT) {
            Ok(guard) => {
                if let Some((pid, gen)) = guard.read() {
                    signal_clip_helper(pid, &gen);
                }
                guard.remove();
                // Clear while the lock is still held so a concurrent `copy_secret` cannot
                // publish a new secret between the state removal and the Wayland clear.
                clear_wayland_selections();
            }
            Err(_) => {
                // Emergency path: never skip the clear because the lock was busy.
                if let Some((pid, gen)) = read_state_file(&store.state_path()) {
                    signal_clip_helper(pid, &gen);
                }
                let _ = fs::remove_file(store.state_path());
                clear_wayland_selections();
            }
        }
    } else {
        clear_wayland_selections();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    fn jitter(n: u32) {
        let micros = (n.wrapping_mul(1_103_515_245).wrapping_add(12_345) >> 16) % 40;
        thread::sleep(Duration::from_micros(u64::from(micros) * 50));
    }

    #[test]
    fn may_clear_truth_table() {
        assert!(may_clear("G1", None));
        let same = (7u32, "G1".to_string());
        assert!(may_clear("G1", Some(&same)));
        let other = (7u32, "G2".to_string());
        assert!(!may_clear("G1", Some(&other)));
    }

    #[test]
    fn write_read_round_trip_and_remove_if_matches_generation_only() {
        let dir = tempfile::tempdir().unwrap();
        let store = ClipStore::in_dir(dir.path().to_path_buf());
        let guard = store.lock(CLIP_LOCK_TIMEOUT).unwrap();
        assert!(guard.read().is_none());
        guard.write(1234, "G1").unwrap();
        assert_eq!(guard.read(), Some((1234, "G1".to_string())));
        guard.remove_if("G2");
        assert_eq!(guard.read().unwrap().1, "G1");
        guard.remove_if("G1");
        assert!(guard.read().is_none());
        guard.write(9, "G9").unwrap();
        guard.remove();
        assert!(guard.read().is_none());
    }

    #[test]
    fn lock_refuses_symlink_and_hardlink_and_is_mode_0600() {
        let dir = tempfile::tempdir().unwrap();
        let store = ClipStore::in_dir(dir.path().to_path_buf());
        drop(store.lock(CLIP_LOCK_TIMEOUT).unwrap());
        let lock_path = dir.path().join("clip.lock");
        let mode = fs::metadata(&lock_path).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600, "clip.lock mode is {mode:04o}");

        let hard = dir.path().join("clip.lock.hard");
        fs::hard_link(&lock_path, &hard).unwrap();
        assert!(
            store.lock(CLIP_LOCK_TIMEOUT).is_err(),
            "hard-linked clip.lock must be refused"
        );

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("not-the-lock");
        fs::write(&target, b"x").unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join("clip.lock")).unwrap();
        let store = ClipStore::in_dir(dir.path().to_path_buf());
        assert!(
            store.lock(CLIP_LOCK_TIMEOUT).is_err(),
            "symlinked clip.lock must be refused"
        );
    }

    #[test]
    fn lock_timeout_is_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let store = ClipStore::in_dir(dir.path().to_path_buf());
        let _held = store.lock(CLIP_LOCK_TIMEOUT).unwrap();
        let store2 = ClipStore::in_dir(dir.path().to_path_buf());
        let started = Instant::now();
        let err = store2.lock(Duration::from_millis(100));
        let elapsed = started.elapsed();
        assert!(err.is_err(), "second lock must time out");
        assert!(
            elapsed >= Duration::from_millis(90),
            "returned too fast: {elapsed:?}"
        );
        assert!(
            elapsed <= Duration::from_millis(300),
            "returned too slow: {elapsed:?}"
        );
    }

    #[test]
    fn h3_state_is_published_before_previous_helper_is_signalled() {
        let dir = tempfile::tempdir().unwrap();
        let store = ClipStore::in_dir(dir.path().to_path_buf());
        let guard = store.lock(CLIP_LOCK_TIMEOUT).unwrap();
        guard.write(1, "G1").unwrap();
        let previous = guard.read();
        let mut seen_at_signal = String::new();
        commit_new_generation(&guard, 2, "G2", &previous, |_pid, _gen| {
            seen_at_signal = guard.read().map(|(_, gen)| gen).unwrap_or_default();
        })
        .unwrap();
        assert_eq!(
            seen_at_signal, "G2",
            "previous helper was signalled before the new generation was published"
        );
    }

    #[test]
    fn h3_superseded_helper_never_decides_to_clear() {
        let dir = tempfile::tempdir().unwrap();
        let store = ClipStore::in_dir(dir.path().to_path_buf());
        for i in 0..1000 {
            {
                let guard = store.lock(CLIP_LOCK_TIMEOUT).unwrap();
                guard.write(1, "G1").unwrap();
            }
            let observed = thread::scope(|scope| {
                let copier = scope.spawn(|| {
                    jitter(i);
                    let guard = store.lock(CLIP_LOCK_TIMEOUT).unwrap();
                    guard.write(2, "G2").unwrap();
                });
                let helper = scope.spawn(|| {
                    jitter(i.wrapping_mul(3).wrapping_add(1));
                    let guard = store.lock(CLIP_LOCK_TIMEOUT).unwrap();
                    let state = guard.read();
                    let decide = may_clear("G1", state.as_ref());
                    (decide, state)
                });
                copier.join().unwrap();
                helper.join().unwrap()
            });
            let (decide, state) = observed;
            if state.as_ref().is_some_and(|(_, gen)| gen == "G2") {
                assert!(!decide, "iteration {i}: cleared after observing G2");
            }
            let final_state = store.lock(CLIP_LOCK_TIMEOUT).unwrap().read();
            if final_state.as_ref().is_some_and(|(_, gen)| gen == "G2")
                && state.as_ref().is_some_and(|(_, gen)| gen == "G2")
            {
                assert!(
                    !decide,
                    "iteration {i}: final state is G2 and the helper decided to clear"
                );
            }
        }
    }

    #[test]
    fn m9_remove_if_cannot_orphan_newer_generation() {
        let dir = tempfile::tempdir().unwrap();
        let store = ClipStore::in_dir(dir.path().to_path_buf());
        for i in 0..1000 {
            {
                let guard = store.lock(CLIP_LOCK_TIMEOUT).unwrap();
                guard.write(1, "G1").unwrap();
            }
            thread::scope(|scope| {
                scope.spawn(|| {
                    jitter(i);
                    let guard = store.lock(CLIP_LOCK_TIMEOUT).unwrap();
                    guard.remove_if("G1");
                });
                scope.spawn(|| {
                    jitter(i.wrapping_add(9));
                    let guard = store.lock(CLIP_LOCK_TIMEOUT).unwrap();
                    guard.write(2, "G2").unwrap();
                });
            });
            let final_state = store.lock(CLIP_LOCK_TIMEOUT).unwrap().read();
            assert_eq!(
                final_state.as_ref().map(|(_, gen)| gen.as_str()),
                Some("G2"),
                "iteration {i}: G2 was orphaned"
            );
        }
    }
}
