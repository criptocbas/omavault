//! SIGUSR1 must lock the daemon immediately (Gemini L-2: previously polled once per second).
//!
//! Lives in its own test binary because it signals the whole test process.

use std::thread;
use std::time::{Duration, Instant};

use omavault::crypto::kdf::{derive_master_key, KdfParams};
use omavault::crypto::VaultHeader;
use omavault::daemon::{run_daemon, DaemonClient};
use omavault::vault::storage::save_vault_to_disk;
use omavault::vault::Vault;
use tempfile::TempDir;
use zeroize::Zeroizing;

#[test]
fn sigusr1_locks_daemon_immediately() {
    let tmp = TempDir::new().unwrap();
    std::env::set_var("XDG_STATE_HOME", tmp.path().join("state"));
    let vault_path = tmp.path().join("vault.omav");
    let sock_path = tmp.path().join("omavault_run/daemon.sock");
    let params = KdfParams {
        mem_kib: 8 * 1024,
        time_cost: 1,
        parallelism: 1,
    };
    let mut header = VaultHeader::new(params, false, None).unwrap();
    let key = derive_master_key(
        b"sigusr1-test-pass",
        &header.kdf_salt,
        params,
        None,
        None,
        false,
    )
    .unwrap();
    save_vault_to_disk(&vault_path, &key, &mut header, &mut Vault::new()).unwrap();

    let sock = sock_path.clone();
    let handle = thread::spawn(move || {
        let _ = run_daemon(&sock, 600, false);
    });
    let client = DaemonClient::new(sock_path.clone());
    let deadline = Instant::now() + Duration::from_secs(5);
    while !client.is_available() {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(25));
    }
    client
        .unlock(
            &vault_path,
            Zeroizing::new("sigusr1-test-pass".into()),
            None,
            None,
        )
        .unwrap();
    assert!(client.status().unwrap().unlocked);

    // The daemon publishes our PID in daemon.lock for the out-of-band fallback.
    let pid: u32 = std::fs::read_to_string(sock_path.parent().unwrap().join("daemon.lock"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert_eq!(pid, std::process::id());

    let t0 = Instant::now();
    unsafe {
        libc::kill(libc::getpid(), libc::SIGUSR1);
    }
    let mut locked_after = None;
    while t0.elapsed() < Duration::from_secs(2) {
        if !client.status().unwrap().unlocked {
            locked_after = Some(t0.elapsed());
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let locked_after = locked_after.expect("SIGUSR1 did not lock the daemon");
    assert!(
        locked_after < Duration::from_millis(500),
        "SIGUSR1 lock latency too high: {locked_after:?}"
    );
    assert_eq!(
        client.status().unwrap().last_lock_reason.as_deref(),
        Some("emergency SIGUSR1 lock")
    );

    client.shutdown().unwrap();
    let _ = handle.join();
}
