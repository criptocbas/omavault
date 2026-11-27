//! Phase 3 regression tests: integrity (revision token, rollback) and output/input safety.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

use omavault::crypto::kdf::{derive_master_key, KdfParams};
use omavault::crypto::{header_revision, validate_slot_label, VaultHeader};
use omavault::error::VaultError;
use omavault::vault::rollback::RollbackStore;
use omavault::vault::storage::{
    create_new_vault_on_disk, ensure_private_dir_strict, load_vault_from_disk,
    purge_encrypted_backups, read_header_from_disk, save_vault_to_disk_checked,
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

fn new_vault_on_disk(path: &Path) -> (VaultHeader, omavault::hardening::LockedKey<32>, Vault) {
    let mut hdr = VaultHeader::new(fast_params(), false, None).unwrap();
    let key = derive_master_key(
        b"phase3-pass-1234",
        &hdr.kdf_salt,
        fast_params(),
        None,
        None,
        false,
    )
    .unwrap();
    let mut vault = Vault::new();
    create_new_vault_on_disk(path, &key, &mut hdr, &mut vault).unwrap();
    (hdr, key, vault)
}

// ------------------------------------------------------------------ 3.3 revision token

#[test]
fn revision_covers_whole_header_not_just_save_salt() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.omav");
    let (mut hdr, key, mut vault) = new_vault_on_disk(&path);
    let rev = header_revision(&hdr);

    // Attacker edits the on-disk header (Argon2 time cost, offset 12) but keeps save_salt.
    let mut blob = fs::read(&path).unwrap();
    blob[12] = blob[12].wrapping_add(1);
    fs::write(&path, &blob).unwrap();
    let tampered = read_header_from_disk(&path, false).unwrap();
    assert_eq!(tampered.save_salt, hdr.save_salt, "attack keeps save_salt");
    assert_ne!(header_revision(&tampered), rev);

    // The next save from a session holding the original revision must NOT silently re-seal
    // (and thereby re-authenticate) the forged header.
    let res =
        save_vault_to_disk_checked(&path, &key, &mut hdr, &mut vault, Some(&rev), false, true);
    assert!(
        res.is_err(),
        "tampered header must be detected as a concurrent modification"
    );
}

// ------------------------------------------------------------------ 3.2 rollback

#[test]
fn saves_stamp_id_and_monotonic_generation() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.omav");
    let (mut hdr, key, mut vault) = new_vault_on_disk(&path);
    let id = vault.vault_id.expect("vault id assigned");
    assert_eq!(vault.generation, 1);
    for expected in 2..=4 {
        let rev = header_revision(&hdr);
        save_vault_to_disk_checked(&path, &key, &mut hdr, &mut vault, Some(&rev), false, true)
            .unwrap();
        assert_eq!(vault.generation, expected);
    }
    let (_, on_disk) = load_vault_from_disk(&path, &key, false).unwrap();
    assert_eq!(on_disk.generation, 4);
    assert_eq!(on_disk.vault_id, Some(id));

    // A failed save (stale revision) must not advance the in-memory generation.
    let res = save_vault_to_disk_checked(
        &path,
        &key,
        &mut hdr,
        &mut vault,
        Some("stale"),
        false,
        true,
    );
    assert!(res.is_err());
    assert_eq!(vault.generation, 4);
}

#[test]
fn rollback_store_detects_restore_swap_and_downgrade() {
    let dir = TempDir::new().unwrap();
    let store = RollbackStore::in_dir(dir.path().join("seen"));
    let vpath = dir.path().join("vault.omav");
    fs::write(&vpath, b"x").unwrap();

    let mut v = Vault::new();
    v.generation = 5;
    store.check(&vpath, &v, false).unwrap();

    // Older copy of the same vault.
    let mut old = v.clone();
    old.generation = 3;
    assert!(matches!(
        store.check(&vpath, &old, false),
        Err(VaultError::RollbackDetected(_))
    ));
    // Same or newer generation is fine.
    store.check(&vpath, &v, false).unwrap();

    // A different vault swapped in at the same path.
    let other = Vault::new();
    assert!(matches!(
        store.check(&vpath, &other, false),
        Err(VaultError::RollbackDetected(_))
    ));

    // An unversioned (pre-v0.4) copy restored after the vault became versioned.
    let mut legacy = v.clone();
    legacy.vault_id = None;
    legacy.generation = 0;
    assert!(matches!(
        store.check(&vpath, &legacy, false),
        Err(VaultError::RollbackDetected(_))
    ));

    // --allow-rollback accepts once and resets the record.
    store.check(&vpath, &old, true).unwrap();
    store.check(&vpath, &old, false).unwrap();

    // Records are private.
    let mode = fs::metadata(dir.path().join("seen"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o077, 0);
}

// ------------------------------------------------------------------ 3.1 input validation

#[test]
fn entries_with_terminal_control_characters_are_rejected() {
    let mut v = Vault::new();
    let osc52 = "notes\x1b]52;c;Y3VybCBldmlsLnNoIHwgc2g=\x07";

    let mut e = Entry::new("site".into(), "user".into(), "pw-12345678".into());
    e.set_notes(Zeroizing::new(osc52.into()));
    assert!(v.add_entry(e).is_err());

    assert!(v
        .add_entry(Entry::new("evil\x1b[2J".into(), "u".into(), "pw".into()))
        .is_err());
    assert!(v
        .add_entry(Entry::new(
            "bidi\u{202E}moc.knab".into(),
            "u".into(),
            "pw".into()
        ))
        .is_err());
    assert!(v
        .add_entry(Entry::new("site".into(), "u".into(), "pw\x1b[31m".into()))
        .is_err());

    // Newlines/tabs in notes are fine; CRLF is normalized.
    let mut ok = Entry::new("site".into(), "user".into(), "pw-12345678".into());
    ok.set_notes(Zeroizing::new("line1\r\nline2\twith tab".into()));
    v.add_entry(ok).unwrap();
    assert_eq!(v.entries[0].notes, "line1\nline2\twith tab");

    // A rejected edit leaves the stored entry untouched.
    let res = v.update_entry("site", "site", |e| {
        e.set_notes(Zeroizing::new(osc52.into()));
    });
    assert!(res.is_err());
    assert_eq!(v.entries[0].notes, "line1\nline2\twith tab");
}

#[test]
fn new_slot_labels_reject_invisible_characters() {
    assert!(validate_slot_label("backup").is_ok());
    assert!(validate_slot_label("back\u{202E}pu").is_err());
    assert!(validate_slot_label("zero\u{200B}width").is_err());
    assert!(validate_slot_label("bell\x07").is_err());
}

// ------------------------------------------------------------------ 3.4 filesystem trust

#[test]
fn reads_refuse_untrusted_vault_files_and_directories() {
    let dir = TempDir::new().unwrap();
    let vdir = dir.path().join("v");
    fs::create_dir(&vdir).unwrap();
    fs::set_permissions(&vdir, fs::Permissions::from_mode(0o700)).unwrap();
    let path = vdir.join("vault.omav");
    let (_hdr, key, _vault) = new_vault_on_disk(&path);
    load_vault_from_disk(&path, &key, false).expect("baseline");

    // Group/world-writable vault file.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(read_header_from_disk(&path, false).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    // Hard-linked vault file (could be swapped/observed via the other name).
    let link = dir.path().join("hardlink.omav");
    fs::hard_link(&path, &link).unwrap();
    assert!(read_header_from_disk(&path, false).is_err());
    fs::remove_file(&link).unwrap();

    // World-writable directory: refused on read, and NOT silently chmod'ed on write.
    fs::set_permissions(&vdir, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(load_vault_from_disk(&path, &key, false).is_err());
    assert!(ensure_private_dir_strict(&vdir, true).is_err());
    assert_eq!(
        fs::metadata(&vdir).unwrap().permissions().mode() & 0o777,
        0o777,
        "an attacker-writable dir must be refused, not quietly fixed"
    );
    fs::set_permissions(&vdir, fs::Permissions::from_mode(0o700)).unwrap();
    load_vault_from_disk(&path, &key, false).expect("trusted again");
}

#[test]
fn hardlinked_lock_file_is_refused() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.omav");
    let (mut hdr, key, mut vault) = new_vault_on_disk(&path);
    let victim = dir.path().join("victim.txt");
    fs::write(&victim, b"x").unwrap();
    fs::set_permissions(&victim, fs::Permissions::from_mode(0o644)).unwrap();
    let lock = dir.path().join("vault.omav.lock");
    let _ = fs::remove_file(&lock);
    fs::hard_link(&victim, &lock).unwrap();

    let rev = header_revision(&hdr);
    assert!(
        save_vault_to_disk_checked(&path, &key, &mut hdr, &mut vault, Some(&rev), false, true)
            .is_err()
    );
    assert_eq!(
        fs::metadata(&victim).unwrap().permissions().mode() & 0o777,
        0o644,
        "fchmod must not reach the hard-link target"
    );
}

#[test]
fn purge_removes_orphaned_temp_files() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.omav");
    let _ = new_vault_on_disk(&path);
    let orphan1 = dir.path().join(".vault.omav.tmp.deadbeef");
    let orphan2 = dir.path().join(".vault.omav.bak.1.tmp.cafebabe");
    let unrelated = dir.path().join(".other.tmp.1234");
    for p in [&orphan1, &orphan2, &unrelated] {
        fs::write(p, b"old-key ciphertext").unwrap();
    }
    let removed = purge_encrypted_backups(&path).unwrap();
    assert!(removed >= 2);
    assert!(!orphan1.exists() && !orphan2.exists());
    assert!(
        unrelated.exists(),
        "only this vault's temp files are purged"
    );
    assert!(path.exists());
}

// ------------------------------------------------------------------ end-to-end CLI

fn omavault(home: &Path, vault: &Path, args: &[&str], stdin: &str) -> std::process::Output {
    let runtime = home.join("run");
    fs::create_dir_all(&runtime).unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_omavault"))
        .arg("--vault")
        .arg(vault)
        .arg("--passphrase-stdin")
        .args(args)
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
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

const E2E_PASS: &str = "phase3-e2e-passphrase";

fn e2e_init(home: &Path, vault: &Path) {
    let out = omavault(
        home,
        vault,
        &["init", "--mem-mib", "64", "--time", "3", "--lanes", "1"],
        &format!("{E2E_PASS}\n"),
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn e2e_add(home: &Path, vault: &Path, name: &str) {
    let out = omavault(
        home,
        vault,
        &["add", name, "--username", "alice", "--generate"],
        &format!("{E2E_PASS}\n"),
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn e2e_restoring_an_older_vault_copy_is_refused() {
    let home = TempDir::new().unwrap();
    let vault = home.path().join("data/omavault/vault.omav");
    e2e_init(home.path(), &vault);
    e2e_add(home.path(), &vault, "first");
    let snapshot = fs::read(&vault).unwrap();
    e2e_add(home.path(), &vault, "second");

    // Attacker restores the older (authentic) copy.
    fs::write(&vault, &snapshot).unwrap();
    let get = |extra: &[&str]| {
        let mut args = extra.to_vec();
        args.extend_from_slice(&["get", "first", "--field", "username"]);
        omavault(home.path(), &vault, &args, &format!("{E2E_PASS}\n"))
    };
    let out = get(&[]);
    assert!(!out.status.success(), "rollback must be refused");
    assert!(String::from_utf8_lossy(&out.stderr).contains("ROLLBACK DETECTED"));

    let out = get(&["--allow-rollback"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Accepted once; the record is reset so normal use continues.
    assert!(get(&[]).status.success());
}

#[test]
fn e2e_output_is_sanitized_even_when_piped() {
    let home = TempDir::new().unwrap();
    let vault = home.path().join("data/omavault/vault.omav");
    // Plant a malicious entry the way a pre-v0.4 vault could contain one: build the payload
    // directly (bypassing `add_entry` validation) and save it with production KDF params.
    fs::create_dir_all(vault.parent().unwrap()).unwrap();
    fs::set_permissions(vault.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
    let params = KdfParams {
        mem_kib: 64 * 1024,
        time_cost: 3,
        parallelism: 1,
    };
    let mut hdr = VaultHeader::new(params, false, None).unwrap();
    let key =
        derive_master_key(E2E_PASS.as_bytes(), &hdr.kdf_salt, params, None, None, true).unwrap();
    let mut v = Vault::new();
    let mut evil = Entry::new(
        "evil\x1b]0;PWNED\x07".into(),
        "user\x1b]8;;https://evil/\x07".into(),
        "pw".into(),
    );
    evil.notes = "hello\x1b]52;c;aGFja2Vk\x07".into();
    v.entries.push(evil);
    create_new_vault_on_disk(&vault, &key, &mut hdr, &mut v).unwrap();

    let out = omavault(home.path(), &vault, &["list"], &format!("{E2E_PASS}\n"));
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !out.stdout.contains(&0x1b),
        "list output must not contain ESC even when piped"
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("evil"));

    let out = omavault(
        home.path(),
        &vault,
        &["--raw", "list"],
        &format!("{E2E_PASS}\n"),
    );
    assert!(out.stdout.contains(&0x1b), "--raw opts out of sanitizing");
}

/// `get --reveal` on a REAL terminal (via `script(1)` pty): notes are stripped of control
/// sequences and a password containing them is refused. Skipped if `script` is unavailable.
#[test]
fn e2e_reveal_on_terminal_never_emits_escape_sequences() {
    if Command::new("script").arg("--version").output().is_err() {
        eprintln!("skipping: script(1) not available");
        return;
    }
    let home = TempDir::new().unwrap();
    let vault = home.path().join("data/omavault/vault.omav");
    fs::create_dir_all(vault.parent().unwrap()).unwrap();
    fs::set_permissions(vault.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
    let params = KdfParams {
        mem_kib: 64 * 1024,
        time_cost: 3,
        parallelism: 1,
    };
    let mut hdr = VaultHeader::new(params, false, None).unwrap();
    let key =
        derive_master_key(E2E_PASS.as_bytes(), &hdr.kdf_salt, params, None, None, true).unwrap();
    let mut v = Vault::new();
    let mut evil = Entry::new("evil".into(), "user".into(), "pw\x1b[31mred".into());
    evil.notes = "hello\x1b]52;c;aGFja2Vk\x07world".into();
    v.entries.push(evil);
    create_new_vault_on_disk(&vault, &key, &mut hdr, &mut v).unwrap();

    let run_in_pty = |field: &str| {
        let cmd = format!(
            "printf '%s\\n' '{E2E_PASS}' | {} --vault {} --passphrase-stdin get evil --field {field} --reveal",
            env!("CARGO_BIN_EXE_omavault"),
            vault.display()
        );
        let runtime = home.path().join("run");
        fs::create_dir_all(&runtime).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        Command::new("script")
            .args(["-qec", &cmd, "/dev/null"])
            .env("HOME", home.path())
            .env("XDG_RUNTIME_DIR", &runtime)
            .env("XDG_STATE_HOME", home.path().join("state"))
            .env("OMAVAULT_SOCKET", runtime.join("no-daemon.sock"))
            .env_remove("WAYLAND_DISPLAY")
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };

    let out = run_in_pty("notes");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("hello") && text.contains("world"), "{text}");
    assert!(
        !text.contains("\x1b]52"),
        "OSC 52 must not reach the terminal: {text:?}"
    );

    let out = run_in_pty("password");
    assert!(
        !out.status.success(),
        "control-char password must not print to a terminal"
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("control characters"), "{text}");
    assert!(!text.contains("\x1b[31m"));
}
