use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

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

fn clip_state_path() -> Option<PathBuf> {
    if let Ok(runtime) = std::env::var("XDG_RUNTIME_DIR") {
        if !runtime.trim().is_empty() {
            return Some(PathBuf::from(runtime).join("omavault").join("clip.state"));
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.trim().is_empty() {
            return Some(
                PathBuf::from(home)
                    .join(".local")
                    .join("state")
                    .join("omavault")
                    .join("clip.state"),
            );
        }
    }
    None
}

fn read_clip_state() -> Option<(u32, String)> {
    let path = clip_state_path()?;
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

fn write_clip_state(pid: u32, generation: &str) -> Result<()> {
    let path = clip_state_path()
        .ok_or_else(|| VaultError::Clipboard("cannot determine clipboard state path".into()))?;
    let parent = path
        .parent()
        .ok_or_else(|| VaultError::Clipboard("invalid clipboard state path".into()))?;
    ensure_private_dir_strict(parent, true)?;
    let tmp = parent.join(format!(".clip.state.tmp.{pid}.{generation}"));
    let write_res = (|| -> std::io::Result<()> {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        f.write_all(format!("{pid}:{generation}\n").as_bytes())?;
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

fn remove_clip_state_if_current(generation: &str) {
    if let Some((_, current)) = read_clip_state() {
        if current == generation {
            if let Some(path) = clip_state_path() {
                let _ = fs::remove_file(path);
            }
        }
    }
}

/// Returns true iff `clip.state` explicitly records a DIFFERENT newer generation.
/// Fail-closed: missing or unreadable `clip.state` is treated as NOT superseded.
fn is_superseded_by_newer_generation(generation: &str) -> bool {
    matches!(read_clip_state(), Some((_, current)) if current != generation)
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

/// Terminate any previously running `omavault __clip-serve` helper (strictly verifying
/// `/proc/<pid>/cmdline` includes `__clip-serve` and the exact recorded generation token).
pub fn stop_previous_clipboard_helper() {
    let Some((pid, expected_gen)) = read_clip_state() else {
        return;
    };
    #[cfg(target_os = "linux")]
    {
        if !pid_matches_clip_helper(pid, &expected_gen) {
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

/// Copy a secret into the Wayland clipboard with `x-kde-passwordManagerHint` (`sensitive`)
/// tagging so Omarchy's universal clipboard history skips it.
///
/// Security properties:
/// - Rejects empty secrets and out-of-range timeouts (`0` is forbidden).
/// - Terminates any prior `__clip-serve` helper before spawning a new one.
/// - Feeds secret exclusively over an anonymous stdin pipe (never `argv` or tempfiles).
/// - Waits for a readiness ACK from `__clip-serve` before committing `clip.state` (so a failed
///   spawn never clobbers an active helper's state).
/// - Reaps the child on a background thread so long-lived TUI sessions never accumulate zombies.
pub fn copy_secret(secret: &str, opts: ClipboardOptions) -> Result<()> {
    if secret.is_empty() {
        return Err(VaultError::Clipboard("refusing to copy an empty secret".into()));
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

    stop_previous_clipboard_helper();

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

    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| VaultError::Clipboard(format!("failed to spawn clipboard helper: {e}")))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(secret.as_bytes()).map_err(|e| {
            let _ = child.kill();
            let _ = child.wait();
            VaultError::Clipboard(format!("failed piping secret to clipboard helper: {e}"))
        })?;
    }

    // Read 1-line readiness status from helper ("OK" or "ERR:<reason>").
    let ack = if let Some(stdout) = child.stdout.take() {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        let _ = reader.read_line(&mut line);
        line.trim().to_string()
    } else {
        String::new()
    };

    if ack != "OK" {
        let _ = child.kill();
        let _ = child.wait();
        let detail = ack.strip_prefix("ERR:").unwrap_or("Wayland clipboard prepare failed");
        return Err(VaultError::Clipboard(detail.to_string()));
    }

    if let Err(e) = write_clip_state(child.id(), &generation) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(e);
    }

    // Spawn lightweight reaper thread so TUI sessions accumulate zero zombie processes.
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

    let finished = Arc::new(AtomicBool::new(false));
    let terminated = Arc::new(AtomicBool::new(false));
    let _ = signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&terminated));
    let _ = signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&terminated));

    let finished_wd = Arc::clone(&finished);
    let terminated_wd = Arc::clone(&terminated);
    let gen_wd = generation.clone();

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

        // Fail-closed: whether triggered by SIGTERM (e.g. headless omavaultd auto-lock) or
        // timeout expiration, clear our Wayland clipboard using this helper's live Wayland
        // environment unless a strictly newer generation has already replaced `clip.state`.
        if !is_superseded_by_newer_generation(&gen_wd) {
            let _ = copy::clear(ClipboardType::Regular, Seat::All);
            remove_clip_state_if_current(&gen_wd);
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
    remove_clip_state_if_current(&generation);

    // Note: when `paste_once` completes, `wl-clipboard-rs` destroys the data source and closing
    // the Wayland socket atomically drops the selection without a secondary `copy::clear()` race.
    Ok(())
}

/// Immediately stop any active clipboard helper (triggering its own Wayland clipboard wipe even
/// when called from a headless daemon lacking `WAYLAND_DISPLAY`) and clear both Regular and
/// Primary Wayland selections if `WAYLAND_DISPLAY` is available.
pub fn clear_clipboard_best_effort() {
    stop_previous_clipboard_helper();
    if let Some(path) = clip_state_path() {
        let _ = fs::remove_file(path);
    }
    if std::env::var_os("WAYLAND_DISPLAY").is_some() {
        let _ = copy::clear(ClipboardType::Regular, Seat::All);
        let _ = copy::clear(ClipboardType::Primary, Seat::All);
    }
}
