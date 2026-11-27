//! Phase 2 regression tests: the daemon must lock reliably even under hostile same-UID IPC.
//!
//! - red-team daemon #1: polling `load_vault` must NOT keep the vault unlocked forever
//!   (absolute session lifetime).
//! - red-team daemon #2 / Gemini M-4: a flood of idle connections must NOT starve `Lock`
//!   (reserved control slots + short first-frame deadline).
//! - Gemini M-15: `SaveVault` returns the new revision directly.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use omavault::crypto::kdf::{derive_master_key, KdfParams};
use omavault::crypto::VaultHeader;
use omavault::daemon::{run_daemon_with_config, DaemonClient, DaemonConfig};
use omavault::error::VaultError;
use omavault::vault::storage::save_vault_to_disk;
use omavault::vault::{Entry, Vault};
use tempfile::TempDir;
use zeroize::Zeroizing;

const PASS: &str = "daemon-lock-test-pass";

fn fast_params() -> KdfParams {
    KdfParams {
        mem_kib: 8 * 1024,
        time_cost: 1,
        parallelism: 1,
    }
}

struct Harness {
    _tmp: TempDir,
    vault_path: PathBuf,
    sock_path: PathBuf,
    client: DaemonClient,
    handle: Option<thread::JoinHandle<()>>,
}

impl Harness {
    fn start(idle_timeout_secs: u64, max_session_secs: u64) -> Self {
        let tmp = TempDir::new().unwrap();
        let vault_path = tmp.path().join("vault.omav");
        let sock_path = tmp.path().join("omavault_run/daemon.sock");

        let mut header = VaultHeader::new(fast_params(), false, None).unwrap();
        let key = derive_master_key(
            PASS.as_bytes(),
            &header.kdf_salt,
            fast_params(),
            None,
            None,
            false,
        )
        .unwrap();
        save_vault_to_disk(&vault_path, &key, &mut header, &Vault::new()).unwrap();

        let mut cfg = DaemonConfig::new(idle_timeout_secs, false);
        cfg.max_session_secs = max_session_secs;
        let sock_for_thread = sock_path.clone();
        let handle = thread::spawn(move || {
            let _ = run_daemon_with_config(&sock_for_thread, cfg);
        });

        let client = DaemonClient::new(sock_path.clone());
        let deadline = Instant::now() + Duration::from_secs(5);
        while !client.is_available() {
            assert!(Instant::now() < deadline, "daemon failed to start");
            thread::sleep(Duration::from_millis(25));
        }
        Self {
            _tmp: tmp,
            vault_path,
            sock_path,
            client,
            handle: Some(handle),
        }
    }

    fn unlock(&self) {
        self.client
            .unlock(&self.vault_path, Zeroizing::new(PASS.into()), None, None)
            .expect("unlock");
        assert!(self.client.status().unwrap().unlocked);
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.client.shutdown();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn wait_until_locked(client: &DaemonClient, within: Duration) -> Option<String> {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if let Ok(st) = client.status() {
            if !st.unlocked {
                return st.last_lock_reason;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    None
}

#[test]
fn polling_load_vault_cannot_extend_session_past_max_lifetime() {
    // Idle timeout far in the future; absolute lifetime 3 s.
    let h = Harness::start(600, 3);
    h.unlock();
    let st = h.client.status().unwrap();
    assert_eq!(st.max_session_secs, 3);
    assert!(st.session_remaining_secs <= 3);

    // Hostile same-UID poller: refreshes the idle timer every 300 ms.
    let started = Instant::now();
    let mut locked_reason = None;
    while started.elapsed() < Duration::from_secs(8) {
        let _ = h.client.load_vault(&h.vault_path);
        let st = h.client.status().unwrap();
        if !st.unlocked {
            locked_reason = st.last_lock_reason;
            break;
        }
        thread::sleep(Duration::from_millis(300));
    }
    assert_eq!(
        locked_reason.as_deref(),
        Some("maximum session lifetime reached"),
        "IPC polling must not keep the vault unlocked past max_session_secs"
    );
    assert!(started.elapsed() < Duration::from_secs(6));
    assert!(h.client.load_vault(&h.vault_path).is_err());
}

fn hold_idle_connections(sock: &Path, n: usize) -> Vec<UnixStream> {
    (0..n)
        .filter_map(|_| UnixStream::connect(sock).ok())
        .collect()
}

/// Run the REAL `omavault daemon` binary as a separate process (so the SIGUSR1 fallback has a
/// distinct, verifiable PID), fully isolated from the developer's session.
struct ProcessDaemon {
    tmp: TempDir,
    child: Child,
}

impl ProcessDaemon {
    fn start() -> Self {
        let tmp = TempDir::new().unwrap();
        let run = tmp.path().join("run");
        fs::create_dir(&run).unwrap();
        fs::set_permissions(&run, fs::Permissions::from_mode(0o700)).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_omavault"))
            .args(["daemon", "--timeout", "600", "--max-session", "3600"])
            .env("HOME", tmp.path())
            .env("XDG_RUNTIME_DIR", &run)
            .env("OMAVAULT_SOCKET", run.join("omavault/daemon.sock"))
            .env_remove("WAYLAND_DISPLAY")
            .env_remove("HYPRLAND_INSTANCE_SIGNATURE")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn daemon");
        Self { tmp, child }
    }

    fn sock(&self) -> PathBuf {
        self.tmp.path().join("run/omavault/daemon.sock")
    }
}

impl Drop for ProcessDaemon {
    fn drop(&mut self) {
        unsafe {
            libc::kill(self.child.id() as libc::pid_t, libc::SIGTERM);
        }
        let _ = self.child.wait();
    }
}

#[test]
fn sustained_connection_flood_cannot_prevent_lock() {
    let d = ProcessDaemon::start();
    let client = DaemonClient::new(d.sock());
    let deadline = Instant::now() + Duration::from_secs(10);
    while !client.is_available() {
        assert!(Instant::now() < deadline, "daemon process failed to start");
        thread::sleep(Duration::from_millis(50));
    }

    // Production-policy vault (the binary enforces the KDF floor).
    let vault_path = d.tmp.path().join("vault.omav");
    let params = KdfParams {
        mem_kib: 64 * 1024,
        time_cost: 3,
        parallelism: 1,
    };
    let mut header = VaultHeader::new(params, false, None).unwrap();
    let key =
        derive_master_key(PASS.as_bytes(), &header.kdf_salt, params, None, None, true).unwrap();
    save_vault_to_disk(&vault_path, &key, &mut header, &Vault::new()).unwrap();
    client
        .unlock(&vault_path, Zeroizing::new(PASS.into()), None, None)
        .expect("unlock");
    assert!(client.status().unwrap().unlocked);

    // Aggressive attacker: keep ~64 idle connections open, constantly refilling.
    let sock = d.sock();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_t = std::sync::Arc::clone(&stop);
    let flooder = thread::spawn(move || {
        let mut held: Vec<UnixStream> = Vec::new();
        while !stop_t.load(std::sync::atomic::Ordering::SeqCst) {
            if held.len() >= 64 {
                held.drain(..16);
            }
            held.extend(hold_idle_connections(&sock, 64 - held.len()));
            thread::sleep(Duration::from_millis(5));
        }
    });
    thread::sleep(Duration::from_millis(400));

    let t0 = Instant::now();
    let outcome = client.lock_with_fallback();
    let elapsed = t0.elapsed();
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let _ = flooder.join();

    assert!(
        outcome.is_ok(),
        "lock under sustained flood failed: {outcome:?}"
    );
    assert!(elapsed < Duration::from_secs(2), "lock took {elapsed:?}");
    let reason = wait_until_locked(&client, Duration::from_secs(3));
    assert!(
        matches!(
            reason.as_deref(),
            Some("manual lock") | Some("emergency SIGUSR1 lock")
        ),
        "daemon not locked after flood (reason {reason:?}, outcome {outcome:?})"
    );
}

#[test]
fn heavy_requests_are_refused_in_reserved_control_slots() {
    let h = Harness::start(600, 3600);
    h.unlock();
    // Fill the general pool with idle connections; a heavy request now lands in a control slot.
    let _held = hold_idle_connections(&h.sock_path, 16);
    thread::sleep(Duration::from_millis(100));
    let res = h.client.load_vault(&h.vault_path);
    assert!(
        matches!(&res, Err(VaultError::Daemon(m)) if m.contains("busy")),
        "expected busy refusal, got {:?}",
        res.as_ref().map(|_| ())
    );
    // ...but Status still works there.
    assert!(h.client.status().unwrap().unlocked);
}

#[test]
fn save_vault_returns_new_revision() {
    let h = Harness::start(600, 3600);
    h.unlock();
    let (mut v, rev1) = h.client.load_vault(&h.vault_path).unwrap();
    v.add_entry(Entry::new("site".into(), "user".into(), "pw-123456".into()))
        .unwrap();
    let rev2 = h
        .client
        .save_vault(&h.vault_path, &v, Some(rev1.clone()))
        .unwrap()
        .expect("daemon returns Saved { revision }");
    assert_ne!(rev1, rev2);
    let (_, rev_loaded) = h.client.load_vault(&h.vault_path).unwrap();
    assert_eq!(rev2, rev_loaded);
    // Chaining with the returned revision works without a reload.
    h.client.save_vault(&h.vault_path, &v, Some(rev2)).unwrap();
}

#[test]
fn missing_socket_is_typed_daemon_unavailable() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().join("omavault");
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let client = DaemonClient::new(dir.join("daemon.sock"));
    assert!(matches!(
        client.lock(),
        Err(VaultError::DaemonUnavailable(_))
    ));
    assert!(matches!(
        client.lock_with_fallback(),
        Err(VaultError::DaemonUnavailable(_))
    ));
}
