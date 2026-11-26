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
    let contents = fs::read_to_string(path).ok()?;
    let (pid_str, gen_str) = contents.trim().split_once(':')?;
    let pid = pid_str.parse::<u32>().ok()?;
    Some((pid, gen_str.to_string()))
}

fn write_clip_state(pid: u32, generation: &str) {
    let Some(path) = clip_state_path() else {
        return;
    };
    let Some(parent) = path.parent() else {
        return;
    };
    if ensure_private_dir_strict(parent, true).is_err() {
        return;
    }
    let tmp = parent.join(format!(".clip.state.tmp.{pid}"));
    if let Ok(mut f) = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)
    {
        if f.write_all(format!("{pid}:{generation}\n").as_bytes()).is_ok() {
            let _ = fs::rename(&tmp, &path);
        } else {
            let _ = fs::remove_file(&tmp);
        }
    }
}

/// Terminate any previously running `omavault __clip-serve` helper (verifying `/proc/<pid>/comm`
/// so PID reuse can never signal an unrelated process).
pub fn stop_previous_clipboard_helper() {
    let Some((pid, _)) = read_clip_state() else {
        return;
    };
    if pid == std::process::id() {
        return;
    }
    #[cfg(target_os = "linux")]
    {
        let Ok(comm) = fs::read_to_string(format!("/proc/{pid}/comm")) else {
            return;
        };
        if comm.trim() != "omavault" {
            return;
        }
        unsafe {
            let _ = libc::kill(pid as libc::pid_t, libc::SIGTERM);
        }
    }
}

fn is_generation_current(generation: &str) -> bool {
    match read_clip_state() {
        Some((_, current)) => current == generation,
        None => false,
    }
}

/// Copy a secret into the Wayland clipboard with `x-kde-passwordManagerHint` (`sensitive`)
/// tagging so Omarchy's universal clipboard history (Walker / cliphist / Stash) skips it.
///
/// Security properties:
/// - Rejects empty secrets and out-of-range timeouts (`0` is forbidden).
/// - Terminates any prior `__clip-serve` helper before spawning a new one (eliminates
///   watchdog races and `paste_once` self-wipe collisions).
/// - Feeds secret exclusively over an anonymous stdin pipe (never `argv` or tempfiles).
/// - Waits for a readiness ACK from `__clip-serve` so Wayland failures are reported honestly.
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

    write_clip_state(child.id(), &generation);

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

    let finished_wd = Arc::clone(&finished);
    let terminated_wd = Arc::clone(&terminated);
    let gen_wd = generation.clone();

    thread::spawn(move || {
        let mut remaining_ms = timeout.saturating_mul(1000);
        while remaining_ms > 0 {
            if finished_wd.load(Ordering::SeqCst) || terminated_wd.load(Ordering::SeqCst) {
                return;
            }
            let step = remaining_ms.min(100);
            thread::sleep(Duration::from_millis(step));
            remaining_ms -= step;
        }
        if !finished_wd.load(Ordering::SeqCst)
            && !terminated_wd.load(Ordering::SeqCst)
            && is_generation_current(&gen_wd)
        {
            // Clearing our selection causes Wayland to emit `cancelled` so `prepared.serve()`
            // returns cleanly on the main thread and runs Rust destructors.
            let _ = copy::clear(ClipboardType::Regular, Seat::All);
            // Short grace period for main thread to unwind cleanly before forced fallback exit.
            thread::sleep(Duration::from_millis(400));
            if !finished_wd.load(Ordering::SeqCst) {
                std::process::exit(0);
            }
        }
    });

    // Blocks until clipboard ownership is replaced, paste-once completes, or timeout clears.
    let _ = prepared.serve();
    finished.store(true, Ordering::SeqCst);

    // Only clear after `paste_once` if our generation is STILL the active clipboard owner
    // (never clobber a newer copy that superseded this helper!).
    if paste_once && !terminated.load(Ordering::SeqCst) && is_generation_current(&generation) {
        let _ = copy::clear(ClipboardType::Regular, Seat::All);
    }

    Ok(())
}

/// Immediately stop any active clipboard helper and clear the Wayland clipboard.
pub fn clear_clipboard_best_effort() {
    stop_previous_clipboard_helper();
    if let Some(path) = clip_state_path() {
        let _ = fs::remove_file(path);
    }
    if std::env::var_os("WAYLAND_DISPLAY").is_some() {
        let _ = copy::clear(ClipboardType::Regular, Seat::All);
    }
}
