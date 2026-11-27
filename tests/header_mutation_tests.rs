//! Regression tests for the v0.3.0 header-clobber bug (red-team finding #1 / Gemini C-1).
//!
//! `save_vault_to_disk_checked` used to replace the caller's header with the on-disk header,
//! so `rekey`, `fido2 add`, and `fido2 remove` wrote a NEW payload key under the OLD header.
//! Every test here re-opens the vault FROM SCRATCH using only user credentials (passphrase +
//! mock YubiKey) — never the in-memory master key — which is exactly what the old
//! post-save "verification" failed to do.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

use omavault::crypto::fido2::{Fido2Provider, MockFido2Provider, MockTrackedFido2Key};
use omavault::crypto::kdf::{derive_master_key, derive_passphrase_hash, KdfParams};
use omavault::crypto::{
    generate_random_master_key, header_revision, resolve_master_key, wrap_master_key_for_slot,
    VaultHeader,
};
use omavault::error::VaultError;
use omavault::hardening::LockedKey;
use omavault::vault::storage::{
    create_new_vault_on_disk, load_vault_from_disk, read_header_from_disk,
    save_vault_to_disk_checked, verify_saved_vault,
};
use omavault::vault::{Entry, Vault};
use tempfile::TempDir;

const OLD_PASS: &[u8] = b"old-master-passphrase-123";
const NEW_PASS: &[u8] = b"new-master-passphrase-456";

fn fast_params() -> KdfParams {
    KdfParams {
        mem_kib: 8 * 1024,
        time_cost: 1,
        parallelism: 1,
    }
}

/// A passphrase-only provider: never consulted for vaults without FIDO2.
fn no_fido2() -> MockFido2Provider {
    MockFido2Provider {
        token_secret: [0u8; 32],
    }
}

fn sample_vault() -> Vault {
    let mut v = Vault::new();
    v.add_entry(Entry::new(
        "github".into(),
        "alice".into(),
        "gh-secret".into(),
    ))
    .unwrap();
    v.add_entry(Entry::new(
        "email".into(),
        "alice@x".into(),
        "mail-secret".into(),
    ))
    .unwrap();
    v
}

/// Unlock strictly from what is on disk, like a fresh `omavault` process would.
fn reopen<P: Fido2Provider>(path: &Path, pass: &[u8], fido2: &P) -> Result<Vault, VaultError> {
    let hdr = read_header_from_disk(path, false)?;
    let res = resolve_master_key(&hdr, pass, None, fido2, None, false)?;
    let (_, vault) = load_vault_from_disk(path, &res.master_key, false)?;
    Ok(vault)
}

fn v1_vault_on_disk(path: &Path) -> (VaultHeader, LockedKey<32>, Vault) {
    let mut hdr = VaultHeader::new(fast_params(), false, None).unwrap();
    let key = derive_master_key(OLD_PASS, &hdr.kdf_salt, fast_params(), None, None, false).unwrap();
    let mut vault = sample_vault();
    create_new_vault_on_disk(path, &key, &mut hdr, &mut vault).unwrap();
    (hdr, key, vault)
}

struct V2Fixture {
    hdr: VaultHeader,
    master_key: LockedKey<32>,
    vault: Vault,
}

/// Build an OMAV v2 vault whose slots are owned by the given (label, key) pairs.
fn v2_vault_on_disk(path: &Path, keys: &[(&str, &MockTrackedFido2Key)]) -> V2Fixture {
    let params = fast_params();
    let mut hdr = VaultHeader::new_v2_fido2_shell(params, false).unwrap();
    let pw_hash = derive_passphrase_hash(OLD_PASS, &hdr.kdf_salt, params, false).unwrap();
    let mk = generate_random_master_key().unwrap();
    for (label, key) in keys {
        let meta = key.enroll(None, false).unwrap();
        let sec = key.get_hmac_secret(&meta, None).unwrap();
        let slot = wrap_master_key_for_slot(&hdr, &mk, &pw_hash, None, label, meta, &sec).unwrap();
        hdr.fido2_slots.push(slot);
    }
    let mut vault = sample_vault();
    create_new_vault_on_disk(path, &mk, &mut hdr, &mut vault).unwrap();
    V2Fixture {
        hdr,
        master_key: mk,
        vault,
    }
}

#[test]
fn rekey_writes_new_header_and_new_passphrase_unlocks_from_disk() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.omav");
    let (old_hdr, _old_key, mut vault) = v1_vault_on_disk(&path);
    let expected_rev = header_revision(&old_hdr);

    // What `omavault rekey` does: fresh header (new kdf_salt) + key from the NEW passphrase.
    let mut new_hdr = VaultHeader::new(fast_params(), false, None).unwrap();
    let new_key = derive_master_key(
        NEW_PASS,
        &new_hdr.kdf_salt,
        fast_params(),
        None,
        None,
        false,
    )
    .unwrap();
    save_vault_to_disk_checked(
        &path,
        &new_key,
        &mut new_hdr,
        &mut vault,
        Some(&expected_rev),
        false,
        true,
    )
    .unwrap();

    let disk_hdr = read_header_from_disk(&path, false).unwrap();
    assert_eq!(
        disk_hdr.kdf_salt, new_hdr.kdf_salt,
        "new kdf_salt must reach disk"
    );
    assert_ne!(disk_hdr.kdf_salt, old_hdr.kdf_salt);

    let reopened = reopen(&path, NEW_PASS, &no_fido2()).expect("new passphrase must unlock");
    assert_eq!(reopened.entries.len(), 2);
    assert!(matches!(
        reopen(&path, OLD_PASS, &no_fido2()),
        Err(VaultError::AuthenticationFailed)
    ));

    verify_saved_vault(&path, &new_hdr, NEW_PASS, None, None, 2, false)
        .expect("independent post-save verification passes");

    // The old-key vault is preserved in the rolling backup until verification succeeds.
    let bak1 = dir.path().join("vault.omav.bak.1");
    assert!(
        bak1.exists(),
        "rekey must keep an old-key backup before verification"
    );
    let bak_vault = reopen(&bak1, OLD_PASS, &no_fido2()).expect("backup opens with old pass");
    assert_eq!(bak_vault.entries.len(), 2);
}

#[test]
fn fido2_add_v2_persists_new_slot_and_new_key_unlocks() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.omav");
    let key1 = MockTrackedFido2Key::new([0x11; 32]);
    let key2 = MockTrackedFido2Key::new([0x22; 32]);
    let mut fx = v2_vault_on_disk(&path, &[("primary", &key1)]);
    assert!(matches!(
        reopen(&path, OLD_PASS, &key2),
        Err(VaultError::Fido2NoMatchingCredential)
    ));

    // What `omavault fido2 add --label backup` does.
    let expected_rev = header_revision(&fx.hdr);
    let pw_hash =
        derive_passphrase_hash(OLD_PASS, &fx.hdr.kdf_salt, fx.hdr.kdf_params, false).unwrap();
    let meta2 = key2.enroll(None, false).unwrap();
    let sec2 = key2.get_hmac_secret(&meta2, None).unwrap();
    let mut updated = fx.hdr.clone();
    let slot2 = wrap_master_key_for_slot(
        &updated,
        &fx.master_key,
        &pw_hash,
        None,
        "backup",
        meta2,
        &sec2,
    )
    .unwrap();
    updated.fido2_slots.push(slot2);
    save_vault_to_disk_checked(
        &path,
        &fx.master_key,
        &mut updated,
        &mut fx.vault,
        Some(&expected_rev),
        false,
        true,
    )
    .unwrap();

    assert_eq!(
        read_header_from_disk(&path, false).unwrap().fido2_labels(),
        vec!["primary", "backup"],
        "new slot must be persisted"
    );
    assert_eq!(
        reopen(&path, OLD_PASS, &key2)
            .expect("backup key unlocks")
            .entries
            .len(),
        2
    );
    assert_eq!(
        reopen(&path, OLD_PASS, &key1)
            .expect("primary still unlocks")
            .entries
            .len(),
        2
    );
    verify_saved_vault(
        &path,
        &updated,
        OLD_PASS,
        None,
        Some(("backup", &sec2)),
        2,
        false,
    )
    .unwrap();
}

#[test]
fn fido2_remove_with_rotation_revokes_key_and_remaining_key_unlocks() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.omav");
    let key1 = MockTrackedFido2Key::new([0x11; 32]);
    let key2 = MockTrackedFido2Key::new([0x22; 32]);
    let mut fx = v2_vault_on_disk(&path, &[("primary", &key1), ("backup", &key2)]);
    let expected_rev = header_revision(&fx.hdr);

    // What `omavault fido2 remove backup` does: rotate kdf_salt + master key, re-wrap key1.
    let params = fx.hdr.kdf_params;
    let mut hdr = VaultHeader::new_v2_fido2_shell(params, false).unwrap();
    let pw_hash = derive_passphrase_hash(OLD_PASS, &hdr.kdf_salt, params, false).unwrap();
    let new_mk = generate_random_master_key().unwrap();
    let slot1_meta = fx.hdr.fido2_slots[0].fido2.clone();
    let sec1 = key1.get_hmac_secret(&slot1_meta, None).unwrap();
    let slot =
        wrap_master_key_for_slot(&hdr, &new_mk, &pw_hash, None, "primary", slot1_meta, &sec1)
            .unwrap();
    hdr.fido2_slots.push(slot);
    save_vault_to_disk_checked(
        &path,
        &new_mk,
        &mut hdr,
        &mut fx.vault,
        Some(&expected_rev),
        false,
        true,
    )
    .unwrap();

    assert_eq!(
        read_header_from_disk(&path, false).unwrap().fido2_labels(),
        vec!["primary"]
    );
    assert_eq!(
        reopen(&path, OLD_PASS, &key1)
            .expect("remaining key unlocks")
            .entries
            .len(),
        2
    );
    assert!(
        reopen(&path, OLD_PASS, &key2).is_err(),
        "removed key must no longer unlock"
    );
    verify_saved_vault(
        &path,
        &hdr,
        OLD_PASS,
        None,
        Some(("primary", &sec1)),
        2,
        false,
    )
    .unwrap();
}

#[test]
fn fido2_remove_no_rotate_drops_slot_from_disk() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.omav");
    let key1 = MockTrackedFido2Key::new([0x11; 32]);
    let key2 = MockTrackedFido2Key::new([0x22; 32]);
    let mut fx = v2_vault_on_disk(&path, &[("primary", &key1), ("backup", &key2)]);
    let expected_rev = header_revision(&fx.hdr);

    let mut hdr = fx.hdr.clone();
    hdr.fido2_slots.retain(|s| s.label != "backup");
    save_vault_to_disk_checked(
        &path,
        &fx.master_key,
        &mut hdr,
        &mut fx.vault,
        Some(&expected_rev),
        false,
        true,
    )
    .unwrap();

    assert_eq!(
        read_header_from_disk(&path, false).unwrap().fido2_labels(),
        vec!["primary"]
    );
    assert!(matches!(
        reopen(&path, OLD_PASS, &key2),
        Err(VaultError::Fido2NoMatchingCredential)
    ));
    assert_eq!(reopen(&path, OLD_PASS, &key1).unwrap().entries.len(), 2);
}

#[test]
fn verify_saved_vault_rejects_mismatches() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.omav");
    let (hdr, _key, _vault) = v1_vault_on_disk(&path);

    verify_saved_vault(&path, &hdr, OLD_PASS, None, None, 2, false).expect("baseline passes");

    // Header we *meant* to write differs from disk (the exact C-1 failure shape).
    let other = VaultHeader::new(fast_params(), false, None).unwrap();
    assert!(verify_saved_vault(&path, &other, OLD_PASS, None, None, 2, false).is_err());
    // Wrong credentials.
    assert!(verify_saved_vault(&path, &hdr, NEW_PASS, None, None, 2, false).is_err());
    // Entry count drift.
    assert!(verify_saved_vault(&path, &hdr, OLD_PASS, None, None, 3, false).is_err());
}

#[test]
fn stale_revision_is_still_rejected_and_header_untouched() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.omav");
    let (mut hdr, key, mut vault) = v1_vault_on_disk(&path);
    let stale_rev = header_revision(&hdr);

    // Concurrent writer moves the file forward.
    let mut writer_hdr = hdr.clone();
    save_vault_to_disk_checked(
        &path,
        &key,
        &mut writer_hdr,
        &mut vault,
        Some(&stale_rev),
        false,
        true,
    )
    .unwrap();

    let before = hdr.to_bytes().unwrap();
    let err = save_vault_to_disk_checked(
        &path,
        &key,
        &mut hdr,
        &mut vault,
        Some(&stale_rev),
        false,
        true,
    );
    assert!(err.is_err(), "stale revision must be rejected");
    assert_eq!(
        hdr.to_bytes().unwrap(),
        before,
        "caller header must not be modified on error"
    );
}

#[test]
fn failed_write_leaves_caller_header_in_sync_with_disk() {
    let dir = TempDir::new().unwrap();
    let vdir = dir.path().join("vdir");
    fs::create_dir(&vdir).unwrap();
    fs::set_permissions(&vdir, fs::Permissions::from_mode(0o700)).unwrap();
    let path = vdir.join("vault.omav");
    let (mut hdr, key, mut vault) = v1_vault_on_disk(&path);
    let rev = header_revision(&hdr);

    // Make the directory read-only so creating the temp file fails (e.g. like ENOSPC/EROFS).
    fs::set_permissions(&vdir, fs::Permissions::from_mode(0o500)).unwrap();
    let res =
        save_vault_to_disk_checked(&path, &key, &mut hdr, &mut vault, Some(&rev), false, true);
    fs::set_permissions(&vdir, fs::Permissions::from_mode(0o700)).unwrap();

    if unsafe { libc::geteuid() } == 0 {
        return; // root ignores directory permissions; nothing to assert.
    }
    assert!(res.is_err());
    assert_eq!(
        header_revision(&hdr),
        rev,
        "header must not advance when the write fails"
    );
    // A retry with the unchanged header succeeds (no permanent desync).
    save_vault_to_disk_checked(&path, &key, &mut hdr, &mut vault, Some(&rev), false, true).unwrap();
}

#[test]
fn create_new_vault_never_overwrites_existing_file() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.omav");
    let (_hdr, _key, _vault) = v1_vault_on_disk(&path);
    let original = fs::read(&path).unwrap();

    let mut hdr2 = VaultHeader::new(fast_params(), false, None).unwrap();
    let key2 =
        derive_master_key(NEW_PASS, &hdr2.kdf_salt, fast_params(), None, None, false).unwrap();
    let err = create_new_vault_on_disk(&path, &key2, &mut hdr2, &mut Vault::new());
    assert!(matches!(err, Err(VaultError::VaultAlreadyExists(_))));
    assert_eq!(
        fs::read(&path).unwrap(),
        original,
        "existing vault must be untouched"
    );

    // No stray temp files are left behind.
    let leftovers: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
        .collect();
    assert!(leftovers.is_empty(), "temp files leaked: {leftovers:?}");
}

// ---------------------------------------------------------------------------------------------
// End-to-end: drive the real `omavault` binary through init → add → rekey → reopen.
// This is the exact user-facing scenario that bricked vaults in v0.3.0.
// ---------------------------------------------------------------------------------------------

fn omavault(home: &Path, vault: &Path, args: &[&str], stdin: &str) -> std::process::Output {
    let runtime = home.join("run");
    fs::create_dir_all(&runtime).unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_omavault"))
        .arg("--vault")
        .arg(vault)
        .arg("--passphrase-stdin")
        .args(args)
        // Fully isolate from the developer's real session: no real daemon, no real clipboard.
        .env("HOME", home)
        .env("XDG_RUNTIME_DIR", &runtime)
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_STATE_HOME", home.join("state"))
        .env("OMAVAULT_SOCKET", runtime.join("no-daemon.sock"))
        .env_remove("OMAVAULT_PATH")
        .env_remove("OMAVAULT_KEYFILE")
        .env_remove("WAYLAND_DISPLAY")
        .env_remove("HYPRLAND_INSTANCE_SIGNATURE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn omavault");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn assert_ok(out: &std::process::Output, what: &str) {
    assert!(
        out.status.success(),
        "{what} failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn e2e_cli_rekey_then_reopen_with_new_passphrase() {
    let home = TempDir::new().unwrap();
    let vdir = home.path().join("data").join("omavault");
    let vault = vdir.join("vault.omav");
    let old = "old-passphrase-for-e2e";
    let new = "new-passphrase-for-e2e";

    let out = omavault(
        home.path(),
        &vault,
        &["init", "--mem-mib", "64", "--time", "3", "--lanes", "1"],
        &format!("{old}\n"),
    );
    assert_ok(&out, "init");

    let out = omavault(
        home.path(),
        &vault,
        &["add", "github", "--username", "alice", "--generate"],
        &format!("{old}\n"),
    );
    assert_ok(&out, "add");

    // Default rekey purges old-key backups — previously this left an unopenable vault.
    let out = omavault(home.path(), &vault, &["rekey"], &format!("{old}\n{new}\n"));
    assert_ok(&out, "rekey");

    let out = omavault(
        home.path(),
        &vault,
        &["get", "github", "--field", "username"],
        &format!("{new}\n"),
    );
    assert_ok(&out, "get with NEW passphrase after rekey");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "alice");

    let out = omavault(
        home.path(),
        &vault,
        &["get", "github", "--field", "username"],
        &format!("{old}\n"),
    );
    assert!(
        !out.status.success(),
        "OLD passphrase must fail after rekey"
    );

    // Old-key backups were purged only after successful verification.
    let backups: Vec<_> = fs::read_dir(&vdir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".bak."))
        .collect();
    assert!(
        backups.is_empty(),
        "old-key backups should be purged: {backups:?}"
    );
}
