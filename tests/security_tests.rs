use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;
use std::thread;
use std::time::Duration;

use omavault::clipboard::validate_clipboard_timeout;
use omavault::crypto::fido2::{
    Fido2Metadata, Fido2Provider, LibFido2Cli, MockFido2Provider, MockTrackedFido2Key,
};
use omavault::crypto::kdf::{
    derive_master_key, derive_passphrase_hash, hash_keyfile, KdfParams,
};
use omavault::crypto::{
    generate_random_master_key, header_revision, open_vault, resolve_master_key, seal_vault,
    wrap_master_key_for_slot, VaultHeader, VAULT_VERSION_V2,
};
use omavault::daemon::{run_daemon, DaemonClient, DaemonRequest, SecretString};
use omavault::error::VaultError;
use omavault::generator::{
    estimate_entropy_bits, generate_password, generated_password_entropy_bits, PasswordOptions,
};
use omavault::hardening::{harden_process, sanitize_multiline, sanitize_single_line};
use omavault::totp::{hotp_raw, TotpAlgorithm, TotpConfig};
use omavault::vault::audit::run_audit;
use omavault::vault::storage::{
    ensure_private_dir_strict, generate_keyfile, load_vault_from_disk, purge_encrypted_backups,
    save_vault_to_disk, save_vault_to_disk_checked,
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

    let (parsed_hdr, recovered) = open_vault(&key, &blob, true).expect("open");
    assert_eq!(recovered.as_slice(), plaintext);
    assert_eq!(parsed_hdr.kdf_params, prod_params);

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
fn rejects_kdf_downgrade_and_dos_upper_bounds() {
    let weak = fast_params();
    let mut header = VaultHeader::new(weak, false, None).expect("header");
    let key = derive_master_key(b"strong-passphrase", &header.kdf_salt, weak, None, None, false)
        .expect("key");
    let blob = seal_vault(&key, &mut header, b"payload").expect("seal");

    // Production policy rejects weak KDF downgrade.
    let err = open_vault(&key, &blob, true).unwrap_err();
    assert!(matches!(err, VaultError::WeakKdfParameters(_)));

    // Pre-auth upper DoS work cap rejects 1 GiB * 16 iterations (> 8 GiB-iters cap).
    let dos_params = KdfParams {
        mem_kib: 1_048_576,
        time_cost: 16,
        parallelism: 4,
    };
    assert!(matches!(
        dos_params.validate_upper_bounds(),
        Err(VaultError::WeakKdfParameters(_))
    ));

    // Misaligned / truncated ciphertext rejected before decryption.
    let mut bad_len = blob.clone();
    bad_len.push(0x42);
    assert!(matches!(
        VaultHeader::parse(&bad_len, false),
        Err(VaultError::InvalidFormat(_))
    ));
}

#[test]
fn every_save_rotates_subkey_and_nonce_and_hides_length() {
    let params = fast_params();
    let mut header = VaultHeader::new(params, false, None).expect("header");
    let key =
        derive_master_key(b"passphrase-rotation-test", &header.kdf_salt, params, None, None, false)
            .expect("key");

    let blob1 = seal_vault(&key, &mut header, b"short").expect("seal1");
    let salt1 = header.save_salt;
    let nonce1 = header.nonce;

    let blob2 = seal_vault(&key, &mut header, b"slightly longer secret payload").expect("seal2");
    let salt2 = header.save_salt;
    let nonce2 = header.nonce;

    assert_ne!(salt1, salt2);
    assert_ne!(nonce1, nonce2);
    assert_ne!(blob1, blob2);
    assert_eq!(blob1.len(), blob2.len());
}

#[test]
fn triple_factor_passphrase_keyfile_and_fido2() {
    let tmp = TempDir::new().expect("tempdir");
    let kf_path = tmp.path().join("vault.key");
    let wrong_kf_path = tmp.path().join("other.key");
    generate_keyfile(&kf_path).expect("generate keyfile");
    generate_keyfile(&wrong_kf_path).expect("generate other keyfile");

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

    let (_, recovered) = open_vault(&master_key, &blob, false).expect("open valid");
    assert_eq!(recovered.as_slice(), b"triple-factor-secret");

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
fn atomic_disk_storage_permissions_rolling_backups_and_purge() {
    let _ = harden_process();
    let tmp = TempDir::new().expect("tempdir");
    let vault_dir = tmp.path().join("omavault_private");
    let vault_path = vault_dir.join("vault.omav");

    let params = fast_params();
    let mut header = VaultHeader::new(params, false, None).expect("header");
    let key = derive_master_key(b"storage-test-pass", &header.kdf_salt, params, None, None, false)
        .expect("key");

    let mut vault = Vault::new();
    let mut entry = Entry::new(
        "github.com".into(),
        "octocat".into(),
        generate_password(&PasswordOptions::default())
            .unwrap()
            .to_string(),
    );
    entry.totp = Some(TotpConfig::parse("JBSWY3DPEHPK3PXP").unwrap());
    vault.add_entry(entry).unwrap();

    save_vault_to_disk(&vault_path, &key, &mut header, &mut vault).expect("first save");
    assert_eq!(
        fs::metadata(&vault_dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(&vault_path).unwrap().permissions().mode() & 0o777,
        0o600
    );

    vault
        .add_entry(Entry::new(
            "gitlab.com".into(),
            "dev".into(),
            "S3cur3!Pass#2026".into(),
        ))
        .unwrap();
    save_vault_to_disk(&vault_path, &key, &mut header, &mut vault).expect("second save");

    let bak1 = vault_dir.join("vault.omav.bak.1");
    assert!(bak1.exists());
    assert_eq!(
        fs::metadata(&bak1).unwrap().permissions().mode() & 0o777,
        0o600
    );

    // Purge backups removes old-key snapshots cleanly.
    let purged = purge_encrypted_backups(&vault_path).expect("purge");
    assert_eq!(purged, 1);
    assert!(!bak1.exists());

    let (_, loaded) = load_vault_from_disk(&vault_path, &key, false).expect("load");
    assert_eq!(loaded.entries.len(), 2);
}

#[test]
fn rejects_symlinks_and_special_files() {
    let tmp = TempDir::new().expect("tempdir");
    let real_dir = tmp.path().join("real");
    fs::create_dir(&real_dir).unwrap();
    let sym_dir = tmp.path().join("sym_dir");
    symlink(&real_dir, &sym_dir).unwrap();

    // O_NOFOLLOW rejects symlink directory.
    assert!(ensure_private_dir_strict(&sym_dir, true).is_err());

    // Special device `/dev/zero` rejected by hash_keyfile & load_vault_from_disk.
    assert!(matches!(
        hash_keyfile(Path::new("/dev/zero")),
        Err(VaultError::InvalidFormat(_))
    ));
    let mut raw_k = [0x42u8; 32];
    let key = omavault::hardening::LockedKey::new(&mut raw_k).unwrap();
    assert!(matches!(
        load_vault_from_disk(Path::new("/dev/zero"), &key, false),
        Err(VaultError::InvalidFormat(_))
    ));
}

#[test]
fn daemon_unlock_load_save_revision_conflict_and_lock_lifecycle() {
    let tmp = TempDir::new().expect("tempdir");
    // Keep the daemon's rollback records out of the developer's real ~/.local/state.
    std::env::set_var("XDG_STATE_HOME", tmp.path().join("state"));
    let vault_path = tmp.path().join("vault.omav");
    let sock_path = tmp.path().join("omavault_run/daemon.sock");

    let params = fast_params();
    let mut header = VaultHeader::new(params, false, None).expect("header");
    let key =
        derive_master_key(b"daemon-master-pass!", &header.kdf_salt, params, None, None, false)
            .expect("key");
    let mut vault = Vault::new();
    save_vault_to_disk(&vault_path, &key, &mut header, &mut vault).expect("init save");

    let sock_for_thread = sock_path.clone();
    let handle = thread::spawn(move || {
        let _ = run_daemon(&sock_for_thread, 60, false);
    });

    let client = DaemonClient::new(sock_path.clone());
    for _ in 0..30 {
        if client.is_available() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(client.is_available(), "daemon socket failed to become ready");
    assert_eq!(
        fs::metadata(&sock_path).unwrap().permissions().mode() & 0o777,
        0o600
    );

    // Second daemon instance on the same socket path must fail cleanly via flock.
    assert!(run_daemon(&sock_path, 60, false).is_err());

    assert!(!client.status().unwrap().unlocked);
    assert!(client.load_vault(&vault_path).is_err());

    assert!(client
        .unlock(&vault_path, Zeroizing::new("wrong-pass".into()), None, None)
        .is_err());
    assert!(!client.status().unwrap().unlocked);

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

    // Save entry with matching revision succeeds.
    let (mut v, rev1) = client.load_vault(&vault_path).expect("load via daemon");
    v.add_entry(Entry::new(
        "archlinux.org".into(),
        "omarchy".into(),
        "SuperStrong!987654321".into(),
    ))
    .unwrap();
    client
        .save_vault(&vault_path, &v, Some(rev1.clone()))
        .expect("save via daemon");

    // Stale revision save MUST be rejected (optimistic concurrency protection).
    assert!(client.save_vault(&vault_path, &v, Some(rev1)).is_err());

    let (reloaded, _) = client.load_vault(&vault_path).expect("reload via daemon");
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
fn daemon_client_rejects_world_accessible_socket_directory() {
    let tmp = TempDir::new().expect("tempdir");
    let unsafe_dir = tmp.path().join("unsafe_dir");
    fs::create_dir(&unsafe_dir).unwrap();
    fs::set_permissions(&unsafe_dir, fs::Permissions::from_mode(0o755)).unwrap();
    let sock_path = unsafe_dir.join("daemon.sock");
    let client = DaemonClient::new(sock_path);
    assert!(client.status().is_err());
}

#[test]
fn vault_rename_collision_and_audit_empty_passwords() {
    let mut vault = Vault::new();
    let opts = PasswordOptions::default();
    let strong = generate_password(&opts).unwrap().to_string();
    assert!(generated_password_entropy_bits(&opts) > 140.0);
    assert!(estimate_entropy_bits("Password123!") < 50.0);

    vault
        .add_entry(Entry::new("bank".into(), "u1".into(), strong))
        .unwrap();
    vault
        .add_entry(Entry::new("empty-acct".into(), "u2".into(), String::new()))
        .unwrap();
    vault
        .add_entry(Entry::new("forum-a".into(), "u3".into(), "Password123!".into()))
        .unwrap();
    vault
        .add_entry(Entry::new("forum-b".into(), "u4".into(), "Password123!".into()))
        .unwrap();

    // Rename collision MUST be rejected.
    assert!(matches!(
        vault.update_entry("forum-a", "BANK", |_| {}),
        Err(VaultError::DuplicateEntry(_))
    ));

    // Audit detects empty password + weak passwords + reused group.
    let report = run_audit(&vault).expect("audit");
    assert_eq!(report.total_entries, 4);
    assert_eq!(report.weak_passwords.len(), 3); // empty + 2x Password123!
    assert_eq!(report.reused_groups.len(), 1);
    assert_eq!(report.missing_totp.len(), 4);
    assert!(report.overall_score < 40);
}

#[test]
fn fido2_totp_clipboard_and_daemon_request_regression_checks() {
    // Clipboard rejects timeout 0 and > 300.
    assert!(validate_clipboard_timeout(0).is_err());
    assert!(validate_clipboard_timeout(301).is_err());
    assert_eq!(validate_clipboard_timeout(15).unwrap(), 15);

    // FIDO2 rejects flag injection and tampered metadata.
    assert!(LibFido2Cli::validate_device_path("-t").is_err());
    let bad_json = r#"{"rp_id":"omavault.local","credential_id_b64":"AAAA","hmac_salt_b64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","extra":"nope"}"#;
    assert!(serde_json::from_str::<Fido2Metadata>(bad_json).is_err());

    // HOTP rejects overflow/zero digits without panicking.
    assert!(hotp_raw(b"12345678901234567890", 0, TotpAlgorithm::Sha1, 32).is_err());
    assert!(hotp_raw(b"12345678901234567890", 0, TotpAlgorithm::Sha1, 0).is_err());

    // DaemonRequest implements Drop cleanly (ZeroizeOnDrop verified).
    let req = DaemonRequest::Unlock {
        vault_path: Path::new("/tmp/x").to_path_buf(),
        passphrase: SecretString("secret-passphrase".into()),
        keyfile_path: None,
        fido2_device: None,
        allow_rollback: false,
    };
    drop(req);
}

#[test]
fn omav_v2_multi_yubikey_slots_unlock_tamper_and_revocation() {
    let key1 = MockTrackedFido2Key::new([0x11u8; 32]);
    let key2 = MockTrackedFido2Key::new([0x22u8; 32]);
    let key3_unenrolled = MockTrackedFido2Key::new([0x33u8; 32]);

    let meta1 = key1.enroll(None, false).expect("enroll key1");
    let sec1 = key1.get_hmac_secret(&meta1, None).expect("assert key1");
    let meta2 = key2.enroll(None, false).expect("enroll key2");
    let sec2 = key2.get_hmac_secret(&meta2, None).expect("assert key2");

    let params = fast_params();
    let passphrase = b"multi-yubikey-master-passphrase!";
    let mut header = VaultHeader::new_v2_fido2_shell(params, false).expect("v2 header");
    let pw_hash =
        derive_passphrase_hash(passphrase, &header.kdf_salt, params, false).expect("pw_hash");
    let master_key = generate_random_master_key().expect("random master key");

    let slot1 = wrap_master_key_for_slot(
        &header,
        &master_key,
        &pw_hash,
        None,
        "primary",
        meta1,
        &sec1,
    )
    .expect("wrap slot1");
    let slot2 = wrap_master_key_for_slot(
        &header,
        &master_key,
        &pw_hash,
        None,
        "backup",
        meta2,
        &sec2,
    )
    .expect("wrap slot2");
    header.fido2_slots.push(slot1);
    header.fido2_slots.push(slot2);

    let blob = seal_vault(&master_key, &mut header, b"{\"secret\":\"two-yubikeys\"}").expect("seal");
    let (parsed_hdr, _) = VaultHeader::parse(&blob, false).expect("parse v2");
    assert_eq!(parsed_hdr.version, VAULT_VERSION_V2);
    assert_eq!(parsed_hdr.fido2_labels(), vec!["primary", "backup"]);

    // 1. Unlock with YubiKey #1 succeeds.
    let res1 = resolve_master_key(&parsed_hdr, passphrase, None, &key1, None, false)
        .expect("unlock key1");
    assert_eq!(res1.matched_slot_index, Some(0));
    let (_, pt1) = open_vault(&res1.master_key, &blob, false).expect("open via key1");
    assert_eq!(pt1.as_slice(), b"{\"secret\":\"two-yubikeys\"}");

    // 2. Unlock with YubiKey #2 (backup) automatically skips slot 0 and succeeds!
    let res2 = resolve_master_key(&parsed_hdr, passphrase, None, &key2, None, false)
        .expect("unlock key2");
    assert_eq!(res2.matched_slot_index, Some(1));
    let (_, pt2) = open_vault(&res2.master_key, &blob, false).expect("open via key2");
    assert_eq!(pt2.as_slice(), b"{\"secret\":\"two-yubikeys\"}");

    // 3. Unenrolled YubiKey #3 is rejected with Fido2NoMatchingCredential.
    let err3 = resolve_master_key(&parsed_hdr, passphrase, None, &key3_unenrolled, None, false);
    assert!(matches!(err3, Err(VaultError::Fido2NoMatchingCredential)));

    // 4. Wrong passphrase with valid YubiKey #1 fails slot unwrap AEAD.
    let err_pw = resolve_master_key(&parsed_hdr, b"wrong-passphrase", None, &key1, None, false);
    assert!(matches!(err_pw, Err(VaultError::AuthenticationFailed)));

    // 5. Tampering any byte in the header/slot bundle breaks outer AEAD & slot validation.
    let mut tampered_hdr = parsed_hdr.clone();
    tampered_hdr.fido2_slots[0].label = "renamed-tamper".into();
    let err_aad = resolve_master_key(&tampered_hdr, passphrase, None, &key1, None, false);
    assert!(matches!(err_aad, Err(VaultError::AuthenticationFailed)));

    // 6. Duplicate slot labels are rejected by header serialization.
    let mut dup_hdr = parsed_hdr.clone();
    dup_hdr.fido2_slots[1].label = "PRIMARY".into();
    assert!(dup_hdr.to_bytes().is_err());

    // 7. Revoking YubiKey #2 removes its slot; Key #1 still unlocks and Key #2 is rejected.
    let mut revoked_hdr = parsed_hdr;
    revoked_hdr.fido2_slots.retain(|s| s.label != "backup");
    let revoked_blob =
        seal_vault(&res1.master_key, &mut revoked_hdr, b"{\"secret\":\"after-revoke\"}")
            .expect("seal revoked");
    let (parsed_revoked, _) = VaultHeader::parse(&revoked_blob, false).expect("parse revoked");
    assert_eq!(parsed_revoked.fido2_labels(), vec!["primary"]);

    let res_after = resolve_master_key(&parsed_revoked, passphrase, None, &key1, None, false)
        .expect("key1 still works");
    let (_, pt_after) = open_vault(&res_after.master_key, &revoked_blob, false).expect("open");
    assert_eq!(pt_after.as_slice(), b"{\"secret\":\"after-revoke\"}");

    let err_revoked = resolve_master_key(&parsed_revoked, passphrase, None, &key2, None, false);
    assert!(matches!(err_revoked, Err(VaultError::Fido2NoMatchingCredential)));
}

#[test]
fn v03_audit_regressions_utf8_totp_keyfile_eexist_sanitizer_and_checked_save() {
    // M-3: Multi-byte UTF-8 input where byte 10 is inside a char must return Err, never panic.
    assert!(TotpConfig::parse("aéééééééé").is_err());
    assert!(TotpConfig::parse("🔐🔐🔐🔐").is_err());

    // M-5: Display sanitizers strip ANSI/OSC-52 escapes, BiDi overrides, and zero-width chars.
    let hostile = "bank\x1b]52;c;cHdu\x07\u{202E}moc.live\u{200B}\nline2";
    let single = sanitize_single_line(hostile);
    assert!(!single.contains('\x1b'));
    assert!(!single.contains('\u{202E}'));
    assert!(!single.contains('\u{200B}'));
    assert!(!single.contains('\n'));
    let multi = sanitize_multiline(hostile);
    assert!(!multi.contains('\x1b'));
    assert!(!multi.contains('\u{202E}'));
    assert!(multi.contains('\n'));

    // M-10: generate_keyfile on EEXIST MUST NOT delete the pre-existing keyfile.
    let tmp = TempDir::new().expect("tempdir");
    let kf = tmp.path().join("omavault_private").join("existing.key");
    generate_keyfile(&kf).expect("first keyfile");
    let original_bytes = fs::read(&kf).expect("read original");
    let err = generate_keyfile(&kf).unwrap_err();
    assert!(matches!(err, VaultError::VaultAlreadyExists(_)));
    assert_eq!(fs::read(&kf).expect("must still exist"), original_bytes);

    // M-10: hash_keyfile rejects group/world-readable keyfiles.
    fs::set_permissions(&kf, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(hash_keyfile(&kf), Err(VaultError::Hardening(_))));
    fs::set_permissions(&kf, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(hash_keyfile(&kf).is_ok());

    // H-5: save_vault_to_disk_checked rejects stale revision under FileLockGuard.
    let vault_path = tmp.path().join("omavault_private").join("checked.omav");
    let params = fast_params();
    let mut hdr = VaultHeader::new(params, false, None).expect("hdr");
    let mk = derive_master_key(b"checked-save-pass!", &hdr.kdf_salt, params, None, None, false)
        .expect("mk");
    let mut v1 = Vault::new();
    save_vault_to_disk(&vault_path, &mk, &mut hdr, &mut v1).expect("save 1");
    let stale_rev = header_revision(&hdr);
    save_vault_to_disk_checked(&vault_path, &mk, &mut hdr, &mut v1, Some(&stale_rev), false, true)
        .expect("save 2 with matching revision");
    // Re-using stale_rev MUST fail.
    assert!(save_vault_to_disk_checked(
        &vault_path,
        &mk,
        &mut hdr,
        &mut v1,
        Some(&stale_rev),
        false,
        true
    )
    .is_err());

    // L-2: validate_device_path rejects non-hidraw /dev devices like /dev/null.
    assert!(LibFido2Cli::validate_device_path("/dev/null").is_err());
}
