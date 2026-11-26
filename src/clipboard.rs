use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use wl_clipboard_rs::copy::{self, ClipboardType, MimeType, Options, Seat, ServeRequests, Source};
use zeroize::Zeroizing;

use crate::error::{Result, VaultError};

/// Default number of seconds before copied secrets are automatically wiped from Wayland clipboard.
pub const DEFAULT_CLIPBOARD_TIMEOUT_SECS: u64 = 15;

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

/// Copy a secret into the Wayland clipboard with `x-kde-passwordManagerHint` (`sensitive`)
/// tagging so Omarchy's universal clipboard history (Walker / cliphist / Stash) skips it.
///
/// Spawns a detached, memory-hardened child (`omavault __clip-serve`) and feeds the secret
/// exclusively over an anonymous stdin pipe (never via argv / `/proc/cmdline` or tempfiles).
/// That allows CLI commands to return immediately while the secret remains pasteable on
/// Wayland until either `timeout_secs` elapses, another app overwrites the clipboard, or
/// a single paste occurs (when `paste_once` is enabled).
pub fn copy_secret(secret: &str, opts: ClipboardOptions) -> Result<()> {
    if std::env::var_os("WAYLAND_DISPLAY").is_none() {
        return Err(VaultError::Clipboard(
            "WAYLAND_DISPLAY is not set; Wayland secret clipboard requires an active Wayland/Hyprland session".into(),
        ));
    }

    let exe = std::env::current_exe()
        .map_err(|e| VaultError::Clipboard(format!("cannot resolve current executable: {e}")))?;

    let mut cmd = Command::new(exe);
    cmd.arg("__clip-serve")
        .arg("--timeout")
        .arg(opts.timeout_secs.to_string());
    if opts.paste_once {
        cmd.arg("--paste-once");
    }

    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| VaultError::Clipboard(format!("failed to spawn clipboard helper: {e}")))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(secret.as_bytes()).map_err(|e| {
            VaultError::Clipboard(format!("failed piping secret to clipboard helper: {e}"))
        })?;
        // Dropping stdin closes the pipe so the helper knows EOF was reached.
    }

    Ok(())
}

/// Internal entrypoint executed by `omavault __clip-serve`.
///
/// Security guarantees:
/// - Process is already hardened by `harden_process()` (`PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`).
/// - Secret is read from stdin into a `Zeroizing<Vec<u8>>` buffer (never touches disk).
/// - Uses `wl-clipboard-rs` `Options::sensitive(true)` which advertises the
///   `x-kde-passwordManagerHint` MIME type so Omarchy's clipboard history ignores it.
/// - Targets `ClipboardType::Regular` only (never leaks to Primary middle-click selection).
/// - If another app replaces the clipboard before `timeout_secs`, exits cleanly without
///   clobbering the user's new clipboard contents.
/// - If `timeout_secs` expires while we still hold ownership, clears the Wayland clipboard
///   and exits cleanly.
pub fn run_clipboard_server(timeout_secs: u64, paste_once: bool) -> Result<()> {
    let mut raw = Zeroizing::new(Vec::new());
    std::io::stdin()
        .read_to_end(&mut raw)
        .map_err(|e| VaultError::Clipboard(format!("failed reading secret from stdin: {e}")))?;

    if raw.is_empty() {
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

    let prepared = opts
        .prepare_copy(Source::Bytes(payload), MimeType::Text)
        .map_err(|e| VaultError::Clipboard(format!("Wayland clipboard prepare failed: {e}")))?;

    let finished = Arc::new(AtomicBool::new(false));
    let finished_watchdog = Arc::clone(&finished);

    if timeout_secs > 0 {
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(timeout_secs));
            if !finished_watchdog.load(Ordering::SeqCst) {
                // Only clear clipboard if we are still actively serving our secret.
                let _ = copy::clear(ClipboardType::Regular, Seat::All);
                std::process::exit(0);
            }
        });
    }

    // Blocks until clipboard ownership is replaced by another app, paste-once completes,
    // or the watchdog clears and exits on timeout.
    let _ = prepared.serve();
    finished.store(true, Ordering::SeqCst);

    // If paste-once finished normally, clear our selection immediately.
    if paste_once {
        let _ = copy::clear(ClipboardType::Regular, Seat::All);
    }

    Ok(())
}

/// Immediately clear the Wayland clipboard (used when locking the vault).
pub fn clear_clipboard_best_effort() {
    if std::env::var_os("WAYLAND_DISPLAY").is_some() {
        let _ = copy::clear(ClipboardType::Regular, Seat::All);
    }
}
