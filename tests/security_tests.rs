use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::thread;
use std::time::Duration;

use omavault::crypto::fido2::{Fido2Provider, MockFido2Provider};
use omavault::crypto::kdf::{derive_master_key, hash_keyfile, KdfParams};
use omavault::crypto::{open_vault, seal_vault, VaultHeader};
use omavault::daemon::{run_daemon, DaemonClient};
use omavault::error::VaultError;
use omavault::generator::{estimate_entropy_bits, generate_password, PasswordOptions};
use omavault::hardening::harden_process;
use omavault::totp::TotpConfig;
use omavault::vault::audit::run_audit;
use omavault::vault::storage::{
    generate_keyfile, load_vault_from_disk, save_vault_to_disk,
};
use omavault::vault::{Entry, Vault};
use tempfile::TempDir;
use zeroize::Zeroizing;

fn fast_params() -> KdfParams {
    KdfParams {
        mem_kib: 8 * 1024,
        time_cost: 1,
        parallelism: 1,
    }
}

#[test]
fn production_kdf_roundtrip_and_tamper_resistance() {
    // Use real production-floor KDF parameters (64 MiB, t=3, p=2) with policy enforcement ON.
    let prod_params = KdfParams {
        mem_kib: 65_536,
        time_cost: 3,
        parallelism: 2,
    };
    let mut header = VaultHeader::new(prod_params, false, None).expect("header");
    let key = derive_master_key(
        b"correct-horse-battery-staple-omarchy!",
        &header.kdf_salt,
        prod_params,
        None,
        None,
        true,
    )
    .expect("derive master key");

    let plaintext = b"{\"secret\":\"ultra-classified-token\"}";
    let blob = seal_vault(&key, &mut header, plaintext).expect("seal");

    // Valid open succeeds.
    let (parsed_hdr, recovered) = open_vault(&key, &blob, true).expect("open");
    assert_eq!(recovered.as_slice(), plaintext);
    assert_eq!(parsed_hdr.kdf_params, prod_params);

    // Wrong passphrase fails with AuthenticationFailed.
    let wrong_key = derive_master_key(
        b"wrong-passphrase-12345",
        &header.kdf_salt,
        prod_params,
        None,
        None,
        true,
    )
    .expect("derive wrong key");
    assert!(matches!(
        open_vault(&wrong_key, &blob, true),
        Err(VaultError::AuthenticationFailed)
    ));

    // Bit-flipping ANY byte in AAD (kdf_salt, save_salt, nonce, kdf_params) or ciphertext
    // MUST fail authentication!
    for &idx in &[20usize, 52, 84, blob.len() - 20, blob.len() - 1] {
        let mut tampered = blob.clone();
        tampered[idx] ^= 0x01;
        let res = open_vault(&key, &tampered, true);
        assert!(
            res.is_err(),
            "tampering byte at offset {idx} MUST fail authentication"
        );
    }
}

#[test]
fn rejects_kdf_downgrade_attack() {
    let weak = fast_params();
    let mut header = VaultHeader::new(weak, false, None).expect("header");
    let key = derive_master_key(b"strong-passphrase", &header.kdf_salt, weak, None, None, false)
        .expect("key");
    let blob = seal_vault(&key, &mut header, b"payload").expect("seal");

    // Opening with production policy enabled MUST reject the weak KDF header immediately.
    let err = open_vault(&key, &blob, true).unwrap_err();
    assert!(
        matches!(err, VaultError::WeakKdfParameters(_)),
        "expected WeakKdfParameters, got {err:?}"
    );
}

#[test]
fn every_save_rotates_subkey_and_nonce_and_hides_length() {
    let params = fast_params();
    let mut header = VaultHeader::new(params, false, None).expect("header");
    let key = derive_master_key(b"passphrase-rotation-test", &header.kdf_salt, params, None, None, false)
        .expect("key");

    let blob1 = seal_vault(&key, &mut header, b"short").expect("seal1");
    let salt1 = header.save_salt;
    let nonce1 = header.nonce;

    let blob2 = seal_vault(&key, &mut header, b"slightly longer secret payload").expect("seal2");
    let salt2 = header.save_salt;
    let nonce2 = header.nonce;

    // Fresh per-save subkey salt and nonce on every single save.
    assert_ne!(salt1, salt2);
    assert_ne!(nonce1, nonce2);
    assert_ne!(blob1, blob2);

    // Length-hiding 4 KiB block padding ensures both small payloads have identical blob size.
    assert_eq!(blob1.len(), blob2.len());
}

#[test]
fn triple_factor_passphrase_keyfile_and_fido2() {
    let tmp = TempDir::new().expect("tempdir");
    let kf_path = tmp.path().join("vault.key");
    let wrong_kf_path = tmp.path().join("other.key");
    generate_keyfile(&kf_path).expect("generate keyfile");
    generate_keyfile(&wrong_kf_path).expect("generate other keyfile");

    // Verify 0600 permissions on generated keyfile.
    let kf_mode = fs::metadata(&kf_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(kf_mode, 0o600);

    let token_a = MockFido2Provider {
        token_secret: [0x11u8; 32],
    };
    let token_b = MockFido2Provider {
        token_secret: [0x22u8; 32],
    };

    let fido_meta = token_a.enroll(None, true).expect("enroll mock fido2");
    let fido_secret_a = token_a.get_hmac_secret(&fido_meta, None).expect("assert A");
    let fido_secret_b = token_b.get_hmac_secret(&fido_meta, None).expect("assert B");

    let kf_digest = hash_keyfile(&kf_path).expect("hash keyfile");
    let wrong_kf_digest = hash_keyfile(&wrong_kf_path).expect("hash wrong keyfile");

    let params = fast_params();
    let mut header = VaultHeader::new(params, true, Some(fido_meta.clone())).expect("header");
    assert!(header.requires_keyfile());
    assert!(header.requires_fido2());

    let master_key = derive_master_key(
        b"triple-factor-master-passphrase",
        &header.kdf_salt,
        params,
        Some(&kf_digest),
        Some(&fido_secret_a),
        false,
    )
    .expect("master key");

    let blob = seal_vault(&master_key, &mut header, b"triple-factor-secret").expect("seal");

    // Succeeds with all three exact factors.
    let (_, recovered) = open_vault(&master_key, &blob, false).expect("open valid");
    assert_eq!(recovered.as_slice(), b"triple-factor-secret");

    // Fails if keyfile is wrong.
    let key_wrong_kf = derive_master_key(
        b"triple-factor-master-passphrase",
        &header.kdf_salt,
        params,
        Some(&wrong_kf_digest),
        Some(&fido_secret_a),
        false,
    )
    .expect("key wrong kf");
    assert!(matches!(
        open_vault(&key_wrong_kf, &blob, false),
        Err(VaultError::AuthenticationFailed)
    ));

    // Fails if FIDO2 hardware key is different.
    let key_wrong_fido = derive_master_key(
        b"triple-factor-master-passphrase",
        &header.kdf_salt,
        params,
        Some(&kf_digest),
        Some(&fido_secret_b),
        false,
    )
    .expect("key wrong fido");
    assert!(matches!(
        open_vault(&key_wrong_fido, &blob, false),
        Err(VaultError::AuthenticationFailed)
    ));
}

#[test]
fn atomic_disk_storage_permissions_and_rolling_backups() {
    let _ = harden_process();
    let tmp = TempDir::new().expect("tempdir");
    let vault_dir = tmp.path().join("private_dir");
    let vault_path = vault_dir.join("vault.omav");

    let params = fast_params();
    let mut header = VaultHeader::new(params, false, None).expect("header");
    let key = derive_master_key(b"storage-test-pass", &header.kdf_salt, params, None, None, false)
        .expect("key");

    let mut vault = Vault::new();
    let mut entry = Entry::new(
        "github.com".into(),
        "octocat".into(),
        generate_password(&PasswordOptions::default()).unwrap().to_string(),
    );
    entry.totp = Some(TotpConfig::parse("JBSWY3DPEHPK3PXP").unwrap());
    vault.add_entry(entry).unwrap();

    // First save.
    save_vault_to_disk(&vault_path, &key, &mut header, &vault).expect("first save");
    assert_eq!(fs::metadata(&vault_dir).unwrap().permissions().mode() & 0o777, 0o700);
    assert_eq!(fs::metadata(&vault_path).unwrap().permissions().mode() & 0o777, 0o600);

    // Second save creates encrypted rolling backup .bak.1 with 0600 permissions.
    vault
        .add_entry(Entry::new("gitlab.com".into(), "dev".into(), "S3cur3!Pass#2026".into()))
        .unwrap();
    save_vault_to_disk(&vault_path, &key, &mut header, &vault).expect("second save");

    let bak1 = tmp.path().join("private_dir/vault.omav.bak.1");
    assert!(bak1.exists());
    assert_eq!(fs::metadata(&bak1).unwrap().permissions().mode() & 0o777, 0o600);

    // Load latest vault and verify both entries + TOTP intact.
    let (_, loaded) = load_vault_from_disk(&vault_path, &key, false).expect("load");
    assert_eq!(loaded.entries.len(), 2);
    let gh = loaded.find_by_name("github.com").unwrap();
    assert!(gh.totp.is_some());
    assert_eq!(gh.totp.as_ref().unwrap().generate_now().unwrap().code.len(), 6);
}

#[test]
fn daemon_unlock_load_save_and_lock_lifecycle() {
    let tmp = TempDir::new().expect("tempdir");
    let vault_path = tmp.path().join("vault.omav");
    let sock_path = tmp.path().join("run/daemon.sock");

    let params = fast_params();
    let mut header = VaultHeader::new(params, false, None).expect("header");
    let key = derive_master_key(b"daemon-master-pass!", &header.kdf_salt, params, None, None, false)
        .expect("key");
    let vault = Vault::new();
    save_vault_to_disk(&vault_path, &key, &mut header, &vault).expect("init save");

    let sock_for_thread = sock_path.clone();
    let handle = thread::spawn(move || {
        let _ = run_daemon(&sock_for_thread, 60, false);
    });

    // Wait briefly for daemon socket to bind.
    let client = DaemonClient::new(sock_path.clone());
    for _ in 0..30 {
        if client.is_available() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(client.is_available(), "daemon socket failed to become ready");

    // Socket permissions must be 0600.
    assert_eq!(fs::metadata(&sock_path).unwrap().permissions().mode() & 0o777, 0o600);

    // Initially locked.
    assert!(!client.status().unwrap().unlocked);
    assert!(client.load_vault(&vault_path).is_err());

    // Wrong passphrase rejected.
    assert!(client
        .unlock(&vault_path, Zeroizing::new("wrong-pass".into()), None, None)
        .is_err());
    assert!(!client.status().unwrap().unlocked);

    // Correct passphrase unlocks daemon.
    client
        .unlock(
            &vault_path,
            Zeroizing::new("daemon-master-pass!".into()),
            None,
            None,
        )
        .expect("unlock daemon");
    let st = client.status().unwrap();
    assert!(st.unlocked);
    assert!(st.guard_protected);

    // Save an entry through the daemon (master key stays inside daemon LockedKey).
    let mut v = client.load_vault(&vault_path).expect("load via daemon");
    v.add_entry(Entry::new("archlinux.org".into(), "omarchy".into(), "SuperStrong!987654321".into()))
        .unwrap();
    client.save_vault(&vault_path, &v).expect("save via daemon");

    let reloaded = client.load_vault(&vault_path).expect("reload via daemon");
    assert_eq!(reloaded.entries.len(), 1);
    assert_eq!(reloaded.entries[0].name, "archlinux.org");

    // Instant lock wipes session key; subsequent load MUST fail.
    client.lock().expect("lock daemon");
    assert!(!client.status().unwrap().unlocked);
    assert!(client.load_vault(&vault_path).is_err());

    client.shutdown().expect("shutdown daemon");
    let _ = handle.join();
}

#[test]
fn audit_detects_weak_and_reused_passwords() {
    let mut vault = Vault::new();
    let strong = generate_password(&PasswordOptions::default()).unwrap().to_string();
    assert!(estimate_entropy_bits(&strong) > 100.0);

    vault.add_entry(Entry::new("bank".into(), "u1".into(), strong)).unwrap();
    vault.add_entry(Entry::new("forum-a".into(), "u2".into(), "password123".into())).unwrap();
    vault.add_entry(Entry::new("forum-b".into(), "u3".into(), "password123".into())).unwrap();

    let report = run_audit(&vault);
    assert_eq!(report.total_entries, 3);
    assert_eq!(report.weak_passwords.len(), 2);
    assert_eq!(report.reused_groups.len(), 1);
    assert_eq!(report.reused_groups[0].entry_names.len(), 2);
    assert!(report.overall_score < 60);
}
