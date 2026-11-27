//! Out-of-band emergency locking by signal (`SIGUSR1`).
//!
//! A flood of idle connections can exhaust the daemon's socket worker slots, but it cannot block
//! signal delivery. `omavault lock` therefore falls back to signalling the daemon directly, and
//! always signals any registered standalone TUI (which has no socket at all).
//!
//! PIDs are verified before signalling (same real+effective UID, `comm == "omavault"`, and the
//! expected subcommand in `/proc/<pid>/cmdline`) so PID reuse can never deliver `SIGUSR1`
//! (default action: terminate) to an unrelated process.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const TUI_REGISTRY_PREFIX: &str = "tui.";
const MAX_PID_FILE_BYTES: u64 = 32;

/// Which omavault process role a PID is expected to have.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OmavaultRole {
    Daemon,
    Tui,
}

fn my_euid() -> u32 {
    unsafe { libc::geteuid() }
}

/// Parse `Uid:` (real, effective) and `Name:` from `/proc/<pid>/status`.
fn proc_status(pid: u32) -> Option<(u32, u32, String)> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let mut uids = None;
    let mut name = None;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            let mut it = rest.split_whitespace();
            let real = it.next()?.parse().ok()?;
            let eff = it.next()?.parse().ok()?;
            uids = Some((real, eff));
        } else if let Some(rest) = line.strip_prefix("Name:") {
            name = Some(rest.trim().to_string());
        }
    }
    let (r, e) = uids?;
    Some((r, e, name?))
}

/// Verify `pid` is an omavault process owned by us with the expected role.
///
/// `/proc/<pid>/exe` is unreadable for our own non-dumpable processes, so identity is taken
/// from `status` (`Uid`, `Name`) plus `cmdline` (always readable).
pub fn verify_omavault_process(pid: u32, role: OmavaultRole) -> bool {
    if pid <= 1 || pid > i32::MAX as u32 || pid == std::process::id() {
        return false;
    }
    let me = my_euid();
    let Some((ruid, euid, name)) = proc_status(pid) else {
        return false;
    };
    if ruid != me || euid != me || name != "omavault" {
        return false;
    }
    let Ok(cmdline) = fs::read(format!("/proc/{pid}/cmdline")) else {
        return false;
    };
    let args: Vec<&[u8]> = cmdline
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .collect();
    let Some(argv0) = args.first() else {
        return false;
    };
    let base = argv0.rsplit(|&b| b == b'/').next().unwrap_or(argv0);
    if base != b"omavault" {
        return false;
    }
    let has = |w: &[u8]| args.iter().skip(1).any(|a| *a == w);
    match role {
        OmavaultRole::Daemon => has(b"daemon"),
        // `omavault` with no subcommand launches the TUI, so accept anything that is not one of
        // the long-running non-TUI roles.
        OmavaultRole::Tui => !has(b"daemon") && !has(b"__clip-serve"),
    }
}

fn send_sigusr1(pid: u32) -> bool {
    unsafe { libc::kill(pid as libc::pid_t, libc::SIGUSR1) == 0 }
}

/// Validate that `dir` is a real directory owned by us and not group/world accessible.
fn private_dir_ok(dir: &Path) -> bool {
    match fs::symlink_metadata(dir) {
        Ok(m) => m.file_type().is_dir() && m.uid() == my_euid() && (m.mode() & 0o077) == 0,
        Err(_) => false,
    }
}

fn read_pid_file(path: &Path) -> Option<u32> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let meta = file.metadata().ok()?;
    if !meta.file_type().is_file() || meta.uid() != my_euid() || meta.len() > MAX_PID_FILE_BYTES {
        return None;
    }
    let mut s = String::new();
    file.take(MAX_PID_FILE_BYTES).read_to_string(&mut s).ok()?;
    s.trim().parse().ok()
}

/// Write our PID into an already-`flock`ed daemon lock file.
pub fn write_pid_into(file: &mut File) -> std::io::Result<()> {
    file.set_len(0)?;
    let mut w: &File = file;
    std::io::Seek::seek(&mut w, std::io::SeekFrom::Start(0))?;
    w.write_all(format!("{}\n", std::process::id()).as_bytes())?;
    w.sync_all()
}

/// Send `SIGUSR1` (immediate lock + wipe) to the daemon owning `socket_path`.
/// Returns the signalled PID.
pub fn signal_daemon_lock(socket_path: &Path) -> Option<u32> {
    let dir = socket_path.parent()?;
    if !private_dir_ok(dir) {
        return None;
    }
    let pid = read_pid_file(&dir.join("daemon.lock"))?;
    if verify_omavault_process(pid, OmavaultRole::Daemon) && send_sigusr1(pid) {
        Some(pid)
    } else {
        None
    }
}

/// RAII registration of a running TUI so `omavault lock` can find and lock it.
pub struct TuiRegistration {
    path: PathBuf,
}

impl TuiRegistration {
    /// Register in the socket's private runtime directory (created `0700` if missing).
    pub fn register(socket_path: &Path) -> Option<Self> {
        let dir = socket_path.parent()?;
        if !dir.exists() {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .ok()?;
        }
        if !private_dir_ok(dir) {
            return None;
        }
        let path = dir.join(format!("{TUI_REGISTRY_PREFIX}{}", std::process::id()));
        let _ = fs::remove_file(&path); // stale entry from a recycled PID
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .ok()?;
        f.write_all(format!("{}\n", std::process::id()).as_bytes())
            .ok()?;
        Some(Self { path })
    }
}

impl Drop for TuiRegistration {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

use std::os::unix::fs::DirBuilderExt;

/// Signal every registered standalone/daemon-backed TUI to lock. Removes stale entries.
/// Returns the number of TUIs signalled.
pub fn signal_registered_tuis(socket_path: &Path) -> usize {
    let Some(dir) = socket_path.parent() else {
        return 0;
    };
    if !private_dir_ok(dir) {
        return 0;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    let mut signalled = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(pid_str) = name.strip_prefix(TUI_REGISTRY_PREFIX) else {
            continue;
        };
        let path = entry.path();
        let (Ok(pid_name), Some(pid_file)) = (pid_str.parse::<u32>(), read_pid_file(&path)) else {
            continue;
        };
        if pid_name != pid_file {
            continue;
        }
        if verify_omavault_process(pid_name, OmavaultRole::Tui) {
            if send_sigusr1(pid_name) {
                signalled += 1;
            }
        } else {
            let _ = fs::remove_file(&path); // stale registration
        }
    }
    signalled
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_to_verify_self_init_and_bogus_pids() {
        assert!(!verify_omavault_process(0, OmavaultRole::Daemon));
        assert!(!verify_omavault_process(1, OmavaultRole::Daemon));
        assert!(!verify_omavault_process(
            std::process::id(),
            OmavaultRole::Tui
        ));
        assert!(!verify_omavault_process(u32::MAX, OmavaultRole::Tui));
    }

    #[test]
    fn registry_roundtrip_and_cleanup() {
        let dir = tempfile::TempDir::new().unwrap();
        let rt = dir.path().join("omavault");
        let sock = rt.join("daemon.sock");
        let reg = TuiRegistration::register(&sock).expect("register");
        let entry = rt.join(format!("tui.{}", std::process::id()));
        assert!(entry.exists());
        // The test process is not an `omavault` binary, so it must not be signalled.
        assert_eq!(signal_registered_tuis(&sock), 0);
        drop(reg);
        assert!(!entry.exists());
    }
}
