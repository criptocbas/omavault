use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, IsTerminal, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand, ValueEnum};
use zeroize::Zeroizing;

use crate::clipboard::{
    clear_clipboard_best_effort, copy_secret, run_clipboard_server, ClipboardOptions,
    DEFAULT_CLIPBOARD_TIMEOUT_SECS, MAX_CLIPBOARD_TIMEOUT_SECS, MIN_CLIPBOARD_TIMEOUT_SECS,
};
use crate::crypto::fido2::{Fido2Provider, LibFido2Cli};
use crate::crypto::kdf::{
    derive_master_key, derive_passphrase_hash, hash_keyfile, KdfParams, DEFAULT_ARGON2_LANES,
    DEFAULT_ARGON2_MEM_KIB, DEFAULT_ARGON2_TIME,
};
use crate::crypto::{
    generate_random_master_key, header_revision, resolve_master_key, validate_slot_label,
    wrap_master_key_for_slot, VaultHeader, MAX_FIDO2_SLOTS, VAULT_VERSION_V1, VAULT_VERSION_V2,
};
use crate::daemon::{
    default_socket_path, run_daemon_with_config, validate_max_session_secs, DaemonClient,
    DaemonConfig, LockOutcome, DEFAULT_IDLE_TIMEOUT_SECS, DEFAULT_MAX_SESSION_SECS,
};
use crate::error::{Result, VaultError};
use crate::generator::{
    estimate_entropy_bits, generate_passphrase, generate_password, generated_password_entropy_bits,
    passphrase_entropy_bits, strength_label, PassphraseOptions, PasswordOptions,
};
use crate::hardening::{
    fill_random, is_dangerous_display_char, sanitize_multiline, sanitize_single_line,
    HardeningStatus, LockedKey,
};
use crate::procsig::signal_registered_tuis;
use crate::totp::TotpConfig;
use crate::tui::{run_tui, TuiConfig};
use crate::vault::audit::run_audit;
use crate::vault::storage::{
    default_vault_path, generate_keyfile, load_vault_from_disk, purge_encrypted_backups,
    create_new_vault_on_disk, read_header_from_disk, save_vault_to_disk_checked,
    verify_saved_vault,
};
use crate::vault::rollback::{enforce_rollback_policy, record_saved_vault};
use crate::vault::{Entry, Vault};

fn parse_clip_timeout(s: &str) -> std::result::Result<u64, String> {
    let val: u64 = s.parse().map_err(|_| "invalid timeout integer".to_string())?;
    if !(MIN_CLIPBOARD_TIMEOUT_SECS..=MAX_CLIPBOARD_TIMEOUT_SECS).contains(&val) {
        return Err(format!(
            "timeout must be between {MIN_CLIPBOARD_TIMEOUT_SECS} and {MAX_CLIPBOARD_TIMEOUT_SECS} seconds"
        ));
    }
    Ok(val)
}

#[derive(Parser, Debug)]
#[command(
    name = "omavault",
    version = crate::VERSION,
    about = "Bulletproof, memory-hardened password manager for Omarchy Linux (Arch + Hyprland + Wayland)",
    long_about = "Encrypted with Argon2id + HKDF-SHA512 + XChaCha20-Poly1305.\n\
                  Hardened with mlock/PROT_NONE/anti-ptrace, Wayland secret clipboard tagging, \
                  built-in TOTP, keyfile/FIDO2 2FA, and Hyprlock-synced auto-locking."
)]
pub struct Cli {
    /// Path to encrypted vault file (defaults to ~/.local/share/omavault/vault.omav)
    #[arg(long, global = true, env = "OMAVAULT_PATH")]
    pub vault: Option<PathBuf>,

    /// Path to optional second-factor keyfile
    #[arg(short = 'k', long, global = true, env = "OMAVAULT_KEYFILE")]
    pub keyfile: Option<PathBuf>,

    /// Explicit FIDO2 HID device path (canonical /dev/hidraw* character device; auto-detected if omitted)
    #[arg(long, global = true)]
    pub fido2_device: Option<String>,

    /// Path to daemon Unix socket
    #[arg(long, global = true, env = "OMAVAULT_SOCKET")]
    pub socket: Option<PathBuf>,

    /// Read master passphrase line from stdin (for non-interactive scripts only)
    #[arg(long, global = true)]
    pub passphrase_stdin: bool,

    /// Accept a vault file that is OLDER than (or different from) the one last seen at this path
    /// (only use this if you restored a backup on purpose)
    #[arg(long, global = true)]
    pub allow_rollback: bool,

    /// Print stored text byte-exact on stdout (disables stripping of terminal escape sequences)
    #[arg(long, global = true)]
    pub raw: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Launch the interactive Omarchy Ratatui TUI (default command)
    Tui {
        /// Auto-lock inactivity timeout in seconds
        #[arg(long, default_value_t = DEFAULT_IDLE_TIMEOUT_SECS)]
        idle_timeout: u64,
        /// Clipboard auto-clear timeout in seconds (1..=300)
        #[arg(long, default_value_t = DEFAULT_CLIPBOARD_TIMEOUT_SECS, value_parser = parse_clip_timeout)]
        clip_timeout: u64,
        /// Clear clipboard immediately after a single paste
        #[arg(long)]
        paste_once: bool,
    },

    /// Initialize a new encrypted omavault
    Init {
        /// Require a FIDO2 hardware key (YubiKey hmac-secret) in addition to master passphrase
        #[arg(long)]
        fido2: bool,
        /// Label for the initial enrolled FIDO2 key slot (used with --fido2, e.g. "primary")
        #[arg(long, default_value = "primary")]
        fido2_label: String,
        /// Require FIDO2 User Verification (PIN / biometric) during touch
        #[arg(long)]
        fido2_uv: bool,
        /// Argon2id memory cost in MiB (default: 128, range: 64..=1024)
        #[arg(long, default_value_t = DEFAULT_ARGON2_MEM_KIB / 1024)]
        mem_mib: u32,
        /// Argon2id time cost / iterations (default: 4, range: 3..=16)
        #[arg(long, default_value_t = DEFAULT_ARGON2_TIME)]
        time: u32,
        /// Argon2id parallel lanes (default: 4, range: 1..=16)
        #[arg(long, default_value_t = DEFAULT_ARGON2_LANES)]
        lanes: u32,
    },

    /// List entries (optionally filtered by search query)
    List {
        /// Optional fuzzy search filter
        query: Option<String>,
    },

    /// Add a new password/credential entry
    Add {
        /// Unique name for this entry (e.g. "github.com")
        name: String,
        #[arg(short, long, default_value = "")]
        username: String,
        #[arg(long, default_value = "")]
        url: String,
        /// Prompt interactively for sensitive notes (avoids shell history / argv exposure)
        #[arg(long)]
        notes_prompt: bool,
        /// Comma-separated tags
        #[arg(long, default_value = "")]
        tags: String,
        /// Prompt securely (no echo) for TOTP Base32 secret or otpauth:// URI
        #[arg(long, conflicts_with = "totp_file")]
        totp: bool,
        /// Read TOTP Base32 secret or otpauth:// URI from a private file (for scripts)
        #[arg(long, conflicts_with = "totp")]
        totp_file: Option<PathBuf>,
        /// Automatically generate a strong CSPRNG password instead of prompting
        #[arg(short, long)]
        generate: bool,
        /// Generated password length (used with --generate)
        #[arg(long, default_value_t = 24)]
        length: usize,
        /// Copy generated password to Wayland secret clipboard
        #[arg(short, long)]
        copy: bool,
    },

    /// Retrieve an entry field (copies securely or prints)
    Get {
        name: String,
        #[arg(short, long, value_enum, default_value_t = GetField::Password)]
        field: GetField,
        /// Copy secret to Wayland clipboard with x-kde-passwordManagerHint
        #[arg(short, long)]
        copy: bool,
        /// Print sensitive fields (password/notes) to stdout
        #[arg(long)]
        reveal: bool,
        /// Clear clipboard immediately after one paste
        #[arg(long)]
        paste_once: bool,
        /// Clipboard auto-clear timeout in seconds (1..=300)
        #[arg(long, default_value_t = DEFAULT_CLIPBOARD_TIMEOUT_SECS, value_parser = parse_clip_timeout)]
        timeout: u64,
    },

    /// Generate live 2FA TOTP code for an entry
    Totp {
        name: String,
        /// Copy TOTP code to Wayland secret clipboard
        #[arg(short, long)]
        copy: bool,
        #[arg(long)]
        paste_once: bool,
        #[arg(long, default_value_t = DEFAULT_CLIPBOARD_TIMEOUT_SECS, value_parser = parse_clip_timeout)]
        timeout: u64,
    },

    /// Edit an existing entry
    Edit {
        name: String,
        #[arg(short, long)]
        username: Option<String>,
        #[arg(long)]
        url: Option<String>,
        /// Prompt interactively for updated notes
        #[arg(long)]
        notes_prompt: bool,
        /// Prompt securely (no echo) for new TOTP Base32 secret or otpauth:// URI
        #[arg(long, conflicts_with = "totp_file")]
        totp: bool,
        /// Read new TOTP secret or otpauth:// URI from a file
        #[arg(long, conflicts_with = "totp")]
        totp_file: Option<PathBuf>,
        /// Prompt for a new password (archives old password in history)
        #[arg(long, conflicts_with = "generate")]
        rotate_password: bool,
        /// Generate a brand new CSPRNG password (archives old password in history)
        #[arg(short, long, conflicts_with = "rotate_password")]
        generate: bool,
        #[arg(long, default_value_t = 24)]
        length: usize,
        /// Copy newly generated password to Wayland secret clipboard
        #[arg(short, long)]
        copy: bool,
    },

    /// Delete an entry from the vault
    Rm {
        name: String,
        #[arg(short, long)]
        yes: bool,
    },

    /// Generate a cryptographic password or Diceware passphrase
    Gen {
        /// Generate a memorable Diceware passphrase instead of random characters
        #[arg(short, long)]
        passphrase: bool,
        /// Character length for random password
        #[arg(short, long, default_value_t = 24)]
        length: usize,
        /// Word count for passphrase mode (10..=24, recommend >= 12)
        #[arg(short, long, default_value_t = 12)]
        words: usize,
        /// Exclude symbols in random password mode
        #[arg(long)]
        no_symbols: bool,
        /// Exclude visually ambiguous characters (I, l, 1, O, 0)
        #[arg(long)]
        no_ambiguous: bool,
        /// Copy directly to Wayland secret clipboard instead of printing
        /// (the default when stdout is a terminal in a Wayland session)
        #[arg(short, long, conflicts_with = "print")]
        copy: bool,
        /// Print the secret to stdout even on a terminal (lands in scrollback)
        #[arg(long)]
        print: bool,
        #[arg(long)]
        paste_once: bool,
        #[arg(long, default_value_t = DEFAULT_CLIPBOARD_TIMEOUT_SECS, value_parser = parse_clip_timeout)]
        timeout: u64,
    },

    /// Run local password hygiene & security audit (weak, reused, stale, missing 2FA)
    Audit,

    /// Rotate master passphrase, Argon2id parameters, keyfile, or FIDO2 enrollment
    Rekey {
        /// New keyfile path to bind to the vault
        #[arg(long, conflicts_with = "remove_keyfile")]
        new_keyfile: Option<PathBuf>,
        /// Remove existing keyfile requirement
        #[arg(long, conflicts_with = "new_keyfile")]
        remove_keyfile: bool,
        /// Enroll a new FIDO2 hardware key
        #[arg(long, conflicts_with = "remove_fido2")]
        enable_fido2: bool,
        /// Label for the newly enrolled FIDO2 key slot (used with --enable-fido2)
        #[arg(long, default_value = "primary")]
        fido2_label: String,
        /// Require User Verification on the newly enrolled FIDO2 key
        #[arg(long)]
        fido2_uv: bool,
        /// Remove existing FIDO2 requirement
        #[arg(long, conflicts_with = "enable_fido2")]
        remove_fido2: bool,
        /// Argon2id memory cost in MiB (defaults to preserving existing vault setting)
        #[arg(long)]
        mem_mib: Option<u32>,
        /// Argon2id time cost / iterations (defaults to preserving existing vault setting)
        #[arg(long)]
        time: Option<u32>,
        /// Argon2id parallel lanes (defaults to preserving existing vault setting)
        #[arg(long)]
        lanes: Option<u32>,
        /// Keep rolling `.bak.*` files encrypted under the previous key (default: purged after verification)
        #[arg(long, conflicts_with = "purge_old_backups")]
        keep_old_backups: bool,
        /// (Deprecated — now the default) Remove rolling `.bak.*` files encrypted under the previous master key
        #[arg(long, hide = true, conflicts_with = "keep_old_backups")]
        purge_old_backups: bool,
    },

    /// Manage 512-bit cryptographic keyfiles
    Keyfile {
        #[command(subcommand)]
        action: KeyfileAction,
    },

    /// Manage enrolled FIDO2 / YubiKey hardware key slots (add backup keys, list, remove)
    Fido2 {
        #[command(subcommand)]
        action: Fido2Action,
    },

    /// Run the background auto-lock daemon (syncs with Hyprlock, suspend, and idle timeout)
    Daemon {
        /// Auto-lock timeout in seconds (default: 300)
        #[arg(long, default_value_t = DEFAULT_IDLE_TIMEOUT_SECS)]
        timeout: u64,
        /// Absolute maximum unlocked-session lifetime in seconds, regardless of activity
        /// (default: 3600, range: 60..=86400)
        #[arg(long, default_value_t = DEFAULT_MAX_SESSION_SECS)]
        max_session: u64,
    },

    /// Unlock the vault in the running daemon
    Unlock,

    /// Immediately lock the daemon, wipe keys from RAM, and clear clipboard
    Lock,

    /// Display daemon lock state, memory hardening telemetry, and vault crypto parameters
    Status,

    /// Stop the running daemon cleanly
    StopDaemon,

    /// Internal Wayland secret clipboard helper (reads secret from stdin)
    #[command(name = "__clip-serve", hide = true)]
    ClipServe {
        #[arg(long, default_value_t = DEFAULT_CLIPBOARD_TIMEOUT_SECS, value_parser = parse_clip_timeout)]
        timeout: u64,
        #[arg(long)]
        paste_once: bool,
        #[arg(long)]
        generation: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum KeyfileAction {
    /// Generate a fresh 512-bit CSPRNG keyfile with 0600 permissions
    Generate { path: PathBuf },
}

#[derive(Subcommand, Debug)]
pub enum Fido2Action {
    /// List enrolled FIDO2 / YubiKey hardware slots in this vault
    List,
    /// Enroll an additional FIDO2 / YubiKey hardware backup slot
    Add {
        /// Unique human-friendly label for this key (e.g. "backup", "usb-c")
        #[arg(short, long)]
        label: String,
        /// Require FIDO2 User Verification (PIN / biometric) for this key slot
        #[arg(long)]
        uv: bool,
    },
    /// Remove an enrolled FIDO2 / YubiKey hardware slot by label
    Remove {
        /// Label of the FIDO2 key slot to remove
        label: String,
        /// Skip rotating the vault master key when removing a slot (NOT recommended if key was lost/stolen)
        #[arg(long)]
        no_rotate: bool,
        /// Keep rolling `.bak.*` files that still contain the removed key slot (default: purged)
        #[arg(long, conflicts_with = "purge_old_backups")]
        keep_old_backups: bool,
        /// (Deprecated — now the default) Remove rolling `.bak.*` files containing the removed slot
        #[arg(long, hide = true, conflicts_with = "keep_old_backups")]
        purge_old_backups: bool,
    },
}

#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum GetField {
    Password,
    Username,
    Totp,
    Url,
    Notes,
}

enum VaultSession {
    Daemon {
        client: DaemonClient,
        vault_path: PathBuf,
        vault: Vault,
        revision: String,
    },
    Standalone {
        vault_path: PathBuf,
        master_key: LockedKey<32>,
        header: VaultHeader,
        vault: Vault,
    },
}

impl VaultSession {
    fn vault(&self) -> &Vault {
        match self {
            Self::Daemon { vault, .. } | Self::Standalone { vault, .. } => vault,
        }
    }

    fn vault_mut(&mut self) -> &mut Vault {
        match self {
            Self::Daemon { vault, .. } | Self::Standalone { vault, .. } => vault,
        }
    }

    fn save(&mut self) -> Result<()> {
        match self {
            Self::Daemon {
                client,
                vault_path,
                vault,
                revision,
            } => client
                .save_vault(vault_path, vault, Some(revision.clone()))
                .map(|_| ()),
            Self::Standalone {
                vault_path,
                master_key,
                header,
                vault,
            } => {
                let expected_rev = header_revision(header);
                save_vault_to_disk_checked(
                    vault_path,
                    master_key,
                    header,
                    vault,
                    Some(&expected_rev),
                    true,
                    true,
                )?;
                record_saved_vault(None, vault_path, vault);
                Ok(())
            }
        }
    }
}

fn absolutize_path(path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else if let Ok(cwd) = std::env::current_dir() {
        cwd.join(path)
    } else {
        path
    }
}

/// Set from `--raw`: print stored text byte-exact on stdout.
static RAW_STDOUT: AtomicBool = AtomicBool::new(false);

/// Sanitize stored/untrusted text for STDOUT. Applied whether or not stdout is a TTY, because
/// `omavault list | less -R`, `| grep`, or `$(omavault get …)` still end up in a terminal.
/// `--raw` opts out for scripts that need exact bytes.
fn tty_safe(s: &str) -> String {
    if RAW_STDOUT.load(Ordering::Relaxed) {
        s.to_string()
    } else {
        sanitize_single_line(s)
    }
}

/// Sanitize stored/untrusted text for STDERR (always; `--raw` only affects stdout).
fn err_safe(s: &str) -> String {
    sanitize_single_line(s)
}

pub fn execute(mut cli: Cli, hardening: HardeningStatus) -> Result<()> {
    RAW_STDOUT.store(cli.raw, Ordering::Relaxed);
    let vault_path = absolutize_path(cli.vault.clone().unwrap_or_else(default_vault_path));
    let socket_path = absolutize_path(cli.socket.clone().unwrap_or_else(default_socket_path));
    cli.keyfile = cli.keyfile.map(absolutize_path);

    let cmd = cli.command.unwrap_or(Commands::Tui {
        idle_timeout: DEFAULT_IDLE_TIMEOUT_SECS,
        clip_timeout: DEFAULT_CLIPBOARD_TIMEOUT_SECS,
        paste_once: false,
    });

    match cmd {
        Commands::ClipServe {
            timeout,
            paste_once,
            generation,
        } => run_clipboard_server(timeout, paste_once, generation),

        Commands::Keyfile {
            action: KeyfileAction::Generate { path },
        } => {
            generate_keyfile(&path)?;
            println!(
                "Generated 512-bit keyfile at '{}' (permissions 0600).\n\
                 Keep a backup copy offline — losing this keyfile makes the vault unrecoverable!",
                path.display()
            );
            Ok(())
        }

        Commands::Fido2 { action } => match action {
            Fido2Action::List => {
                let header = read_header_from_disk(&vault_path, true)?;
                if !header.requires_fido2() {
                    println!("No FIDO2 hardware keys enrolled.");
                    println!("Tip: Run `omavault rekey --enable-fido2` to add a YubiKey.");
                    return Ok(());
                }
                if header.version == VAULT_VERSION_V2 {
                    println!(
                        "Enrolled FIDO2 hardware key slots ({}/{}):",
                        header.fido2_slots.len(),
                        MAX_FIDO2_SLOTS
                    );
                    for (idx, slot) in header.fido2_slots.iter().enumerate() {
                        let fp: String = slot.fido2.credential_id_b64.chars().take(12).collect();
                        println!(
                            "  {}. {:<20} uv={}  cred={}...",
                            idx + 1,
                            tty_safe(&slot.label),
                            slot.fido2.require_uv,
                            tty_safe(&fp)
                        );
                    }
                    eprintln!(
                        "Note: read from the vault header without unlocking (not yet authenticated); unlock to verify."
                    );
                } else if let Some(meta) = &header.fido2 {
                    let fp: String = meta.credential_id_b64.chars().take(12).collect();
                    println!("Legacy OMAV v1 single FIDO2 key enrolled:");
                    println!("  1. legacy-v1            uv={}  cred={}...", meta.require_uv, fp);
                    println!(
                        "Tip: Run `omavault fido2 add --label backup` to upgrade to OMAV v2 multi-key slots."
                    );
                }
                Ok(())
            }

            Fido2Action::Add { label, uv } => {
                validate_slot_label(&label)?;

                let client = DaemonClient::new(socket_path);
                let _ = client.lock();
                clear_clipboard_best_effort();

                let old_header = read_header_from_disk(&vault_path, true)?;
                if !old_header.requires_fido2() {
                    return Err(VaultError::Fido2Error(
                        "this vault does not have FIDO2 enabled yet; run `omavault rekey --enable-fido2` first"
                            .into(),
                    ));
                }
                if old_header.version == VAULT_VERSION_V2 {
                    if old_header.has_fido2_label(&label) {
                        return Err(VaultError::Fido2Error(format!(
                            "a FIDO2 key slot labeled '{label}' already exists"
                        )));
                    }
                    if old_header.fido2_slots.len() >= MAX_FIDO2_SLOTS {
                        return Err(VaultError::Fido2Error(format!(
                            "vault already has the maximum of {MAX_FIDO2_SLOTS} FIDO2 key slots"
                        )));
                    }
                }

                let passphrase =
                    prompt_passphrase("Master passphrase: ", cli.passphrase_stdin)?;
                let kf_digest = if old_header.requires_keyfile() {
                    let p = cli.keyfile.as_deref().ok_or(VaultError::KeyfileRequired)?;
                    Some(hash_keyfile(p)?)
                } else {
                    None
                };

                eprintln!(
                    "Touch an EXISTING enrolled YubiKey to authorize adding '{label}'..."
                );
                let res = resolve_master_key(
                    &old_header,
                    passphrase.as_bytes(),
                    kf_digest.as_deref(),
                    &LibFido2Cli,
                    cli.fido2_device.as_deref(),
                    true,
                )?;
                let (_, mut vault) = load_vault_from_disk(&vault_path, &res.master_key, true)?;
                enforce_rollback_policy(None, &vault_path, &vault, cli.allow_rollback)?;

                wait_for_yubikey_swap(&format!(
                    "Now plug in ONLY the NEW YubiKey to enroll as '{label}', then press Enter..."
                ))?;

                if cli.fido2_device.is_none() {
                    let connected = LibFido2Cli::discover_devices()?;
                    if connected.len() > 1 {
                        return Err(VaultError::Fido2Error(format!(
                            "multiple FIDO2 keys are connected ({}); unplug the existing key or pass --fido2-device <path> to avoid enrolling the wrong key",
                            connected.join(", ")
                        )));
                    }
                }

                let provider = LibFido2Cli;
                let new_meta = provider.enroll(cli.fido2_device.as_deref(), uv)?;
                eprintln!("Touch the NEW YubiKey ('{label}') once more to verify enrollment...");
                let new_secret =
                    provider.assert_on_any_device(&new_meta, cli.fido2_device.as_deref())?;

                if old_header.version == VAULT_VERSION_V2 {
                    let expected_rev = header_revision(&old_header);
                    let mut updated_header = old_header.clone();
                    let new_slot = wrap_master_key_for_slot(
                        &updated_header,
                        &res.master_key,
                        &res.pw_hash,
                        kf_digest.as_deref(),
                        &label,
                        new_meta,
                        &new_secret,
                    )?;
                    updated_header.fido2_slots.push(new_slot);
                    save_vault_to_disk_checked(
                        &vault_path,
                        &res.master_key,
                        &mut updated_header,
                        &mut vault,
                        Some(&expected_rev),
                        true,
                        true,
                    )?;
                    // Prove the NEW key's slot actually unlocks the vault as written on disk.
                    verify_saved_vault(
                        &vault_path,
                        &updated_header,
                        passphrase.as_bytes(),
                        kf_digest.as_deref(),
                        Some((label.as_str(), &*new_secret)),
                        vault.entries.len(),
                        true,
                    )?;
                    record_saved_vault(None, &vault_path, &vault);
                    drop(passphrase);
                    println!(
                        "Enrolled FIDO2 key '{}' ({}/{} slots). You can now unlock with any enrolled key: {}",
                        tty_safe(&label),
                        updated_header.fido2_slots.len(),
                        MAX_FIDO2_SLOTS,
                        tty_safe(&updated_header.fido2_labels().join(", "))
                    );
                } else {
                    // Seamless upgrade from OMAV v1 single-key FIDO2 to OMAV v2 multi-key slots!
                    let old_meta = old_header
                        .fido2
                        .clone()
                        .ok_or(VaultError::Fido2Required)?;
                    let old_secret = res
                        .matched_fido2_secret
                        .as_ref()
                        .ok_or(VaultError::Fido2Required)?;
                    let first_label = if label.eq_ignore_ascii_case("primary") {
                        "key-1"
                    } else {
                        "primary"
                    };

                    let mut v2_header = VaultHeader::new_v2_fido2_shell(
                        old_header.kdf_params,
                        old_header.requires_keyfile(),
                    )?;
                    v2_header.kdf_salt = old_header.kdf_salt;

                    let new_master_key = generate_random_master_key()?;
                    let slot1 = wrap_master_key_for_slot(
                        &v2_header,
                        &new_master_key,
                        &res.pw_hash,
                        kf_digest.as_deref(),
                        first_label,
                        old_meta,
                        old_secret,
                    )?;
                    let slot2 = wrap_master_key_for_slot(
                        &v2_header,
                        &new_master_key,
                        &res.pw_hash,
                        kf_digest.as_deref(),
                        &label,
                        new_meta,
                        &new_secret,
                    )?;
                    v2_header.fido2_slots.push(slot1);
                    v2_header.fido2_slots.push(slot2);

                    let expected_rev = header_revision(&old_header);
                    save_vault_to_disk_checked(
                        &vault_path,
                        &new_master_key,
                        &mut v2_header,
                        &mut vault,
                        Some(&expected_rev),
                        true,
                        true,
                    )?;
                    drop(new_master_key);
                    verify_saved_vault(
                        &vault_path,
                        &v2_header,
                        passphrase.as_bytes(),
                        kf_digest.as_deref(),
                        Some((label.as_str(), &*new_secret)),
                        vault.entries.len(),
                        true,
                    )?;
                    record_saved_vault(None, &vault_path, &vault);
                    drop(passphrase);
                    println!(
                        "Upgraded vault to OMAV v2 and enrolled '{label}' ({}/{} slots: {}).",
                        v2_header.fido2_slots.len(),
                        MAX_FIDO2_SLOTS,
                        tty_safe(&v2_header.fido2_labels().join(", "))
                    );
                }
                Ok(())
            }

            Fido2Action::Remove {
                label,
                no_rotate,
                keep_old_backups,
                purge_old_backups: _,
            } => {
                let should_purge = !keep_old_backups;
                let client = DaemonClient::new(socket_path);
                let _ = client.lock();
                clear_clipboard_best_effort();

                let old_header = read_header_from_disk(&vault_path, true)?;
                if old_header.version != VAULT_VERSION_V2 || !old_header.requires_fido2() {
                    return Err(VaultError::Fido2Error(
                        "this vault does not have multiple OMAV v2 FIDO2 slots; use `omavault rekey --remove-fido2` to disable FIDO2"
                            .into(),
                    ));
                }
                if !old_header.has_fido2_label(&label) {
                    return Err(VaultError::Fido2Error(format!(
                        "no FIDO2 key slot labeled '{label}' found (enrolled: {})",
                        old_header.fido2_labels().join(", ")
                    )));
                }
                if old_header.fido2_slots.len() <= 1 {
                    return Err(VaultError::Fido2Error(
                        "refusing to remove the last remaining FIDO2 key (use `omavault rekey --remove-fido2` to disable FIDO2 completely)"
                            .into(),
                    ));
                }

                let passphrase =
                    prompt_passphrase("Master passphrase: ", cli.passphrase_stdin)?;
                let kf_digest = if old_header.requires_keyfile() {
                    let p = cli.keyfile.as_deref().ok_or(VaultError::KeyfileRequired)?;
                    Some(hash_keyfile(p)?)
                } else {
                    None
                };

                eprintln!(
                    "Touch one of your REMAINING enrolled YubiKeys (not '{label}') to authorize removal..."
                );
                let res = resolve_master_key(
                    &old_header,
                    passphrase.as_bytes(),
                    kf_digest.as_deref(),
                    &LibFido2Cli,
                    cli.fido2_device.as_deref(),
                    true,
                )?;
                let matched_idx = res
                    .matched_slot_index
                    .ok_or(VaultError::Fido2Required)?;
                if old_header.fido2_slots[matched_idx]
                    .label
                    .eq_ignore_ascii_case(&label)
                {
                    return Err(VaultError::Fido2Error(format!(
                        "you touched '{label}' (the key being removed); touch one of your other enrolled YubiKeys instead"
                    )));
                }
                let (_, mut vault) = load_vault_from_disk(&vault_path, &res.master_key, true)?;
                enforce_rollback_policy(None, &vault_path, &vault, cli.allow_rollback)?;
                let expected_rev = header_revision(&old_header);

                let remaining_slots: Vec<(usize, _)> = old_header
                    .fido2_slots
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| !s.label.eq_ignore_ascii_case(&label))
                    .map(|(i, s)| (i, s.clone()))
                    .collect();

                let updated_header = if !no_rotate {
                    // Cryptographically revoke the removed key by rotating BOTH `kdf_salt` and
                    // `vault_master_key`, and re-wrapping every remaining key slot!
                    let mut hdr = VaultHeader::new_v2_fido2_shell(
                        old_header.kdf_params,
                        old_header.requires_keyfile(),
                    )?;
                    fill_random(&mut hdr.kdf_salt)?;
                    let new_pw_hash = derive_passphrase_hash(
                        passphrase.as_bytes(),
                        &hdr.kdf_salt,
                        old_header.kdf_params,
                        true,
                    )?;
                    let new_mk = generate_random_master_key()?;
                    let provider = LibFido2Cli;

                    for (orig_idx, rem_slot) in remaining_slots {
                        let sec = if orig_idx == matched_idx {
                            res.matched_fido2_secret
                                .clone()
                                .ok_or(VaultError::Fido2Required)?
                        } else {
                            wait_for_yubikey_swap(&format!(
                                "Plug in remaining YubiKey '{}' to re-wrap under the rotated master key, then press Enter...",
                                err_safe(&rem_slot.label)
                            ))?;
                            eprintln!(
                                "Touch YubiKey '{}' to complete master-key rotation...",
                                err_safe(&rem_slot.label)
                            );
                            provider.assert_on_any_device(
                                &rem_slot.fido2,
                                cli.fido2_device.as_deref(),
                            )?
                        };
                        let wrapped = wrap_master_key_for_slot(
                            &hdr,
                            &new_mk,
                            &new_pw_hash,
                            kf_digest.as_deref(),
                            &rem_slot.label,
                            rem_slot.fido2,
                            &sec,
                        )?;
                        hdr.fido2_slots.push(wrapped);
                    }
                    save_vault_to_disk_checked(
                        &vault_path,
                        &new_mk,
                        &mut hdr,
                        &mut vault,
                        Some(&expected_rev),
                        true,
                        true,
                    )?;
                    hdr
                } else {
                    let mut hdr = old_header.clone();
                    hdr.fido2_slots = remaining_slots.into_iter().map(|(_, s)| s).collect();
                    save_vault_to_disk_checked(
                        &vault_path,
                        &res.master_key,
                        &mut hdr,
                        &mut vault,
                        Some(&expected_rev),
                        true,
                        true,
                    )?;
                    hdr
                };

                // Re-open from disk with the passphrase + the key that authorized removal,
                // which also proves the removed slot is gone from the written header.
                let matched_label = old_header.fido2_slots[matched_idx].label.clone();
                let matched_secret = res
                    .matched_fido2_secret
                    .as_ref()
                    .ok_or(VaultError::Fido2Required)?;
                verify_saved_vault(
                    &vault_path,
                    &updated_header,
                    passphrase.as_bytes(),
                    kf_digest.as_deref(),
                    Some((matched_label.as_str(), &**matched_secret)),
                    vault.entries.len(),
                    true,
                )?;
                record_saved_vault(None, &vault_path, &vault);
                drop(passphrase);
                if updated_header.has_fido2_label(&label) {
                    return Err(VaultError::Fido2Error(format!(
                        "post-save verification failed: slot '{label}' is still present; old backups were NOT purged"
                    )));
                }

                if should_purge {
                    let removed = purge_encrypted_backups(&vault_path)?;
                    println!(
                        "Removed FIDO2 key '{}' and purged {removed} old backup file(s). Remaining keys: {}",
                        tty_safe(&label),
                        tty_safe(&updated_header.fido2_labels().join(", "))
                    );
                } else {
                    println!(
                        "Removed FIDO2 key '{}'. Remaining keys: {}",
                        tty_safe(&label),
                        tty_safe(&updated_header.fido2_labels().join(", "))
                    );
                }
                if !no_rotate {
                    println!("Vault master key and KDF salt were rotated for all remaining keys.");
                } else {
                    eprintln!(
                        "WARNING: --no-rotate kept the previous vault master key. Run `omavault rekey` if '{label}' was lost or stolen."
                    );
                }
                Ok(())
            }
        },

        Commands::Gen {
            passphrase,
            length,
            words,
            no_symbols,
            no_ambiguous,
            copy,
            print,
            paste_once,
            timeout,
        } => {
            let (secret, bits) = if passphrase {
                let opts = PassphraseOptions {
                    words,
                    ..PassphraseOptions::default()
                };
                (generate_passphrase(&opts)?, passphrase_entropy_bits(&opts))
            } else {
                let opts = PasswordOptions {
                    length,
                    symbols: !no_symbols,
                    exclude_ambiguous: no_ambiguous,
                    ..PasswordOptions::default()
                };
                (generate_password(&opts)?, generated_password_entropy_bits(&opts))
            };
            // On an interactive terminal, printing would leave the secret in scrollback, so the
            // default is the secret-tagged clipboard; pipes/scripts still get stdout.
            let default_to_clipboard = !print
                && io::stdout().is_terminal()
                && std::env::var_os("WAYLAND_DISPLAY").is_some();
            if copy || default_to_clipboard {
                copy_secret(
                    &secret,
                    ClipboardOptions {
                        timeout_secs: timeout,
                        paste_once,
                    },
                )?;
                eprintln!(
                    "Copied generated secret ({bits:.0} bits · {}) to Wayland secret clipboard (clears in {timeout}s).{}",
                    strength_label(bits),
                    if copy { "" } else { " Use --print to print it instead." }
                );
            } else {
                println!("{}", *secret);
                eprintln!("Entropy: {bits:.0} bits ({})", strength_label(bits));
            }
            Ok(())
        }

        Commands::Daemon {
            timeout,
            max_session,
        } => {
            let max_session = validate_max_session_secs(max_session)?;
            eprintln!(
                "omavault daemon listening on '{}' (idle timeout: {}s, max session: {}s, {})",
                socket_path.display(),
                timeout,
                max_session,
                hardening.summary()
            );
            let mut cfg = DaemonConfig::new(timeout, true);
            cfg.max_session_secs = max_session;
            cfg.hardening = hardening;
            cfg.presleep_monitor = true;
            run_daemon_with_config(&socket_path, cfg)
        }

        Commands::StopDaemon => {
            let client = DaemonClient::new(socket_path);
            client.shutdown()?;
            clear_clipboard_best_effort();
            println!("omavault daemon locked and stopped.");
            Ok(())
        }

        Commands::Lock => {
            // Always clear Wayland clipboard & stop local clipboard helper in the user's session
            // (even if omavaultd lacks WAYLAND_DISPLAY).
            clear_clipboard_best_effort();
            // Standalone and daemon-backed TUIs lock themselves on SIGUSR1.
            let tuis = signal_registered_tuis(&socket_path);
            if tuis > 0 {
                println!("Signalled {tuis} running omavault TUI(s) to lock.");
            }
            let client = DaemonClient::new(socket_path);
            match client.lock_with_fallback() {
                Ok(LockOutcome::Socket) => {
                    println!("Vault locked (master key wiped from RAM, clipboard cleared).");
                    Ok(())
                }
                Ok(LockOutcome::Signal(pid)) => {
                    println!(
                        "Daemon socket unavailable; sent emergency lock signal to omavaultd (pid {pid}). Clipboard cleared."
                    );
                    Ok(())
                }
                Err(VaultError::DaemonUnavailable(_)) => {
                    println!("Daemon not running; local clipboard cleared.");
                    Ok(())
                }
                Err(e) => Err(VaultError::Daemon(format!(
                    "local clipboard cleared, but FAILED to lock running daemon: {e}"
                ))),
            }
        }

        Commands::Unlock => {
            let client = DaemonClient::new(socket_path);
            if client.status().is_err() {
                return Err(VaultError::Daemon(
                    "omavault daemon is not running (start it with `omavault daemon` or `systemctl --user start omavaultd`)".into(),
                ));
            }
            let header = read_header_from_disk(&vault_path, true)?;
            let passphrase = prompt_passphrase("Master passphrase: ", cli.passphrase_stdin)?;
            if header.requires_fido2() {
                eprintln!("Touch your FIDO2 security key when it blinks...");
            }
            client.unlock_with_options(
                &vault_path,
                passphrase,
                cli.keyfile.clone(),
                cli.fido2_device.clone(),
                cli.allow_rollback,
            )?;
            println!("Vault unlocked in daemon.");
            Ok(())
        }

        Commands::Status => {
            println!("omavault version:  {}", crate::VERSION);
            println!("Process hardening: {}", hardening.summary());
            println!("Vault path:        {}", vault_path.display());
            if vault_path.exists() {
                let header = read_header_from_disk(&vault_path, true)?;
                println!(
                    "Vault crypto:      OMAV v{} · Argon2id ({} MiB, t={}, p={}) + HKDF-SHA512 + XChaCha20-Poly1305",
                    header.version,
                    header.kdf_params.mem_kib / 1024,
                    header.kdf_params.time_cost,
                    header.kdf_params.parallelism
                );
                let fido_desc = if header.version == VAULT_VERSION_V2 {
                    format!(
                        " + FIDO2 ({} {}: {})",
                        header.fido2_slots.len(),
                        if header.fido2_slots.len() == 1 { "key" } else { "keys" },
                        tty_safe(&header.fido2_labels().join(", "))
                    )
                } else if header.requires_fido2() {
                    " + FIDO2 (legacy v1)".to_string()
                } else {
                    String::new()
                };
                println!(
                    "Required factors:  Passphrase{}{}",
                    if header.requires_keyfile() { " + Keyfile" } else { "" },
                    fido_desc,
                );
            } else {
                println!("Vault state:       Not initialized (run `omavault init`)");
            }
            let client = DaemonClient::new(socket_path);
            if let Ok(st) = client.status() {
                println!(
                    "Daemon status:     {} (mlock: {}, guard-page: {}, kernel-madv: {}, idle remaining: {}s)",
                    if st.unlocked { "UNLOCKED" } else { "LOCKED" },
                    st.mlocked,
                    st.guard_protected,
                    st.kernel_hardened,
                    st.remaining_secs
                );
                if st.unlocked {
                    println!(
                        "Session lifetime:  {}s remaining (max {}s, regardless of activity)",
                        st.session_remaining_secs, st.max_session_secs
                    );
                }
                println!(
                    "Daemon hardening:  ptrace-block:{} core-dump-off:{}",
                    if st.dumpable_disabled { "ON" } else { "OFF" },
                    if st.core_dumps_disabled { "ON" } else { "OFF" },
                );
                if !st.presleep_monitor.is_empty() {
                    println!("Pre-sleep lock:    {}", tty_safe(&st.presleep_monitor));
                }
                if let Some(reason) = st.last_lock_reason {
                    println!("Last lock reason:  {}", tty_safe(&reason));
                }
            } else {
                println!("Daemon status:     Not running (standalone mode)");
            }
            Ok(())
        }

        Commands::Init {
            fido2,
            fido2_label,
            fido2_uv,
            mem_mib,
            time,
            lanes,
        } => {
            if vault_path.exists() {
                return Err(VaultError::VaultAlreadyExists(
                    vault_path.display().to_string(),
                ));
            }
            if fido2 {
                validate_slot_label(&fido2_label)?;
            }

            let params = KdfParams {
                mem_kib: mem_mib.saturating_mul(1024),
                time_cost: time,
                parallelism: lanes,
            };
            params.validate()?;

            let passphrase = prompt_new_passphrase(cli.passphrase_stdin)?;

            let kf_digest = match &cli.keyfile {
                Some(path) => Some(hash_keyfile(path)?),
                None => None,
            };

            let (mut header, master_key) = if fido2 {
                let provider = LibFido2Cli;
                let meta = provider.enroll(cli.fido2_device.as_deref(), fido2_uv)?;
                eprintln!(
                    "Touch your FIDO2 security key ('{fido2_label}') once more to finish initialization..."
                );
                let secret = provider.get_hmac_secret(&meta, cli.fido2_device.as_deref())?;

                let mut hdr = VaultHeader::new_v2_fido2_shell(params, kf_digest.is_some())?;
                let pw_hash =
                    derive_passphrase_hash(passphrase.as_bytes(), &hdr.kdf_salt, params, true)?;
                let mk = generate_random_master_key()?;
                let slot = wrap_master_key_for_slot(
                    &hdr,
                    &mk,
                    &pw_hash,
                    kf_digest.as_deref(),
                    &fido2_label,
                    meta,
                    &secret,
                )?;
                hdr.fido2_slots.push(slot);
                (hdr, mk)
            } else {
                let hdr = VaultHeader::new(params, kf_digest.is_some(), None)?;
                let mk = derive_master_key(
                    passphrase.as_bytes(),
                    &hdr.kdf_salt,
                    params,
                    kf_digest.as_deref(),
                    None,
                    true,
                )?;
                (hdr, mk)
            };

            let mut vault = Vault::new();
            create_new_vault_on_disk(&vault_path, &master_key, &mut header, &mut vault)?;
            record_saved_vault(None, &vault_path, &vault);

            println!(
                "Initialized encrypted OMAV v{} vault at '{}'",
                header.version,
                vault_path.display()
            );
            println!(
                "Cipher: Argon2id ({} MiB, t={}, p={}) + HKDF-SHA512 + XChaCha20-Poly1305",
                params.mem_kib / 1024,
                params.time_cost,
                params.parallelism
            );
            println!(
                "Memory lock: {}",
                if master_key.is_mlocked() {
                    "ACTIVE (mlock + guard pages + PROT_NONE)"
                } else {
                    "fallback (check RLIMIT_MEMLOCK)"
                }
            );
            if fido2 {
                println!("Enrolled FIDO2 key slot: '{fido2_label}'");
                println!("Tip: Add a backup YubiKey with: omavault fido2 add --label backup");
            }
            Ok(())
        }

        Commands::Tui {
            idle_timeout,
            clip_timeout,
            paste_once,
        } => {
            if !vault_path.exists() {
                return Err(VaultError::VaultNotFound(format!(
                    "{} (run `omavault init` first)",
                    vault_path.display()
                )));
            }
            run_tui(TuiConfig {
                vault_path,
                keyfile_path: cli.keyfile,
                fido2_device: cli.fido2_device,
                socket_path,
                idle_timeout_secs: idle_timeout,
                clipboard_timeout_secs: clip_timeout,
                paste_once,
                hardening,
                allow_rollback: cli.allow_rollback,
            })
        }

        Commands::List { query } => {
            let session = open_session(
                &vault_path,
                &socket_path,
                cli.keyfile.as_deref(),
                cli.fido2_device.as_deref(),
                cli.passphrase_stdin,
                cli.allow_rollback,
            )?;
            let q = query.as_deref().unwrap_or("");
            let entries = session.vault().search(q);
            if entries.is_empty() {
                println!("(no matching entries)");
            } else {
                for e in entries {
                    let totp_tag = if e.totp.is_some() { " [2FA]" } else { "" };
                    let user = if e.username.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", tty_safe(&e.username))
                    };
                    println!("{}{}{}", tty_safe(&e.name), user, totp_tag);
                }
            }
            Ok(())
        }

        Commands::Add {
            name,
            username,
            url,
            notes_prompt,
            tags,
            totp,
            totp_file,
            generate,
            length,
            copy,
        } => {
            let trimmed_name = name.trim().to_string();
            if trimmed_name.is_empty() {
                return Err(VaultError::InvalidFormat(
                    "entry name cannot be empty".into(),
                ));
            }

            let mut session = open_session(
                &vault_path,
                &socket_path,
                cli.keyfile.as_deref(),
                cli.fido2_device.as_deref(),
                cli.passphrase_stdin,
                cli.allow_rollback,
            )?;

            if session.vault().find_by_name(&trimmed_name).is_some() {
                return Err(VaultError::DuplicateEntry(trimmed_name));
            }

            let password = if generate {
                generate_password(&PasswordOptions {
                    length,
                    ..PasswordOptions::default()
                })?
            } else {
                prompt_confirmed_entry_password(&trimmed_name)?
            };

            let totp_cfg = read_totp_input(totp, totp_file.as_deref())?;
            let notes = if notes_prompt {
                prompt_tty_secret("Sensitive notes (hidden): ")?
            } else {
                Zeroizing::new(String::new())
            };

            let parsed_tags: Vec<String> = tags
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            let mut entry = Entry::new(trimmed_name.clone(), username, password.to_string());
            entry.url = url;
            entry.notes = notes.to_string();
            entry.tags = parsed_tags;
            entry.totp = totp_cfg;

            session.vault_mut().add_entry(entry)?;
            session.save()?;

            if copy {
                copy_secret(&password, ClipboardOptions::default())?;
                println!(
                    "Added '{}' and copied password to Wayland secret clipboard.",
                    tty_safe(&trimmed_name)
                );
            } else {
                println!("Added '{}' to encrypted vault.", tty_safe(&trimmed_name));
            }
            Ok(())
        }

        Commands::Get {
            name,
            field,
            copy,
            reveal,
            paste_once,
            timeout,
        } => {
            let session = open_session(
                &vault_path,
                &socket_path,
                cli.keyfile.as_deref(),
                cli.fido2_device.as_deref(),
                cli.passphrase_stdin,
                cli.allow_rollback,
            )?;
            let entry = session
                .vault()
                .find_by_name(&name)
                .ok_or_else(|| VaultError::EntryNotFound(name.clone()))?;

            let value: Zeroizing<String> = match field {
                GetField::Password => Zeroizing::new(entry.password.clone()),
                GetField::Username => Zeroizing::new(entry.username.clone()),
                GetField::Url => Zeroizing::new(entry.url.clone()),
                GetField::Notes => Zeroizing::new(entry.notes.clone()),
                GetField::Totp => {
                    let totp = entry.totp.as_ref().ok_or_else(|| {
                        VaultError::InvalidTotp(format!("entry '{name}' has no TOTP configured"))
                    })?;
                    let code = totp.generate_now()?;
                    eprintln!("TOTP valid for {}s", code.remaining_secs);
                    Zeroizing::new(code.code.clone())
                }
            };

            if copy {
                copy_secret(
                    &value,
                    ClipboardOptions {
                        timeout_secs: timeout,
                        paste_once,
                    },
                )?;
                eprintln!(
                    "Copied {field:?} for '{}' (Wayland secret-tagged, clears in {timeout}s).",
                    err_safe(&name)
                );
            } else if matches!(field, GetField::Password | GetField::Notes) && !reveal {
                return Err(VaultError::InvalidFormat(
                    "refusing to print password or sensitive notes without `--reveal` (use `--copy` for Wayland secret clipboard)".into(),
                ));
            } else if matches!(field, GetField::Password | GetField::Notes) {
                print_revealed_secret(&value, matches!(field, GetField::Notes))?;
            } else {
                println!("{}", tty_safe(&value));
            }
            Ok(())
        }

        Commands::Totp {
            name,
            copy,
            paste_once,
            timeout,
        } => {
            let session = open_session(
                &vault_path,
                &socket_path,
                cli.keyfile.as_deref(),
                cli.fido2_device.as_deref(),
                cli.passphrase_stdin,
                cli.allow_rollback,
            )?;
            let entry = session
                .vault()
                .find_by_name(&name)
                .ok_or_else(|| VaultError::EntryNotFound(name.clone()))?;
            let totp = entry.totp.as_ref().ok_or_else(|| {
                VaultError::InvalidTotp(format!("entry '{name}' has no TOTP configured"))
            })?;
            let code = totp.generate_now()?;
            if copy {
                copy_secret(
                    &code.code,
                    ClipboardOptions {
                        timeout_secs: timeout,
                        paste_once,
                    },
                )?;
                eprintln!(
                    "Copied TOTP for '{}' ({}s remaining, secret-tagged).",
                    err_safe(&name),
                    code.remaining_secs
                );
            } else {
                println!("{} ({}s remaining)", code.code, code.remaining_secs);
            }
            Ok(())
        }

        Commands::Edit {
            name,
            username,
            url,
            notes_prompt,
            totp,
            totp_file,
            rotate_password,
            generate,
            length,
            copy,
        } => {
            if username.is_none()
                && url.is_none()
                && !notes_prompt
                && !totp
                && totp_file.is_none()
                && !rotate_password
                && !generate
            {
                return Err(VaultError::InvalidFormat(
                    "no fields specified to update (pass --username, --url, --totp, --rotate-password, --generate, or --notes-prompt)".into(),
                ));
            }

            let mut session = open_session(
                &vault_path,
                &socket_path,
                cli.keyfile.as_deref(),
                cli.fido2_device.as_deref(),
                cli.passphrase_stdin,
                cli.allow_rollback,
            )?;

            // Verify entry exists BEFORE prompting for secrets or generating passwords.
            if session.vault().find_by_name(&name).is_none() {
                return Err(VaultError::EntryNotFound(name));
            }

            let new_pw = if generate {
                Some(generate_password(&PasswordOptions {
                    length,
                    ..PasswordOptions::default()
                })?)
            } else if rotate_password {
                Some(prompt_confirmed_entry_password(&name)?)
            } else {
                None
            };

            let parsed_totp = read_totp_input(totp, totp_file.as_deref())?;
            let new_notes = if notes_prompt {
                Some(prompt_tty_secret("Updated notes (hidden): ")?)
            } else {
                None
            };

            let copy_pw = new_pw.clone();

            let entry = session
                .vault_mut()
                .find_by_name_mut(&name)
                .ok_or_else(|| VaultError::EntryNotFound(name.clone()))?;

            if let Some(u) = username {
                entry.set_username(u);
            }
            if let Some(u) = url {
                entry.set_url(u);
            }
            if let Some(n) = new_notes {
                entry.set_notes(n);
            }
            if let Some(t) = parsed_totp {
                entry.totp = Some(t);
            }
            if let Some(pw) = new_pw {
                entry.set_password(pw);
            }
            entry.updated_at = chrono::Utc::now();

            session.save()?;
            if copy {
                if let Some(pw) = copy_pw {
                    copy_secret(&pw, ClipboardOptions::default())?;
                    println!(
                        "Updated '{}' and copied new password to Wayland secret clipboard.",
                        tty_safe(&name)
                    );
                    return Ok(());
                }
            }
            println!("Updated '{}' and re-encrypted vault.", tty_safe(&name));
            Ok(())
        }

        Commands::Rm { name, yes } => {
            let mut session = open_session(
                &vault_path,
                &socket_path,
                cli.keyfile.as_deref(),
                cli.fido2_device.as_deref(),
                cli.passphrase_stdin,
                cli.allow_rollback,
            )?;
            if session.vault().find_by_name(&name).is_none() {
                return Err(VaultError::EntryNotFound(name));
            }
            if !yes {
                print!("Permanently delete '{}'? [y/N]: ", tty_safe(&name));
                io::stdout().flush()?;
                let mut answer = String::new();
                io::stdin().read_line(&mut answer)?;
                if !answer.trim().eq_ignore_ascii_case("y") {
                    println!("Cancelled.");
                    return Ok(());
                }
            }
            session.vault_mut().remove_by_name(&name)?;
            session.save()?;
            println!("Deleted '{}'.", tty_safe(&name));
            Ok(())
        }

        Commands::Audit => {
            let session = open_session(
                &vault_path,
                &socket_path,
                cli.keyfile.as_deref(),
                cli.fido2_device.as_deref(),
                cli.passphrase_stdin,
                cli.allow_rollback,
            )?;
            let report = run_audit(session.vault())?;
            println!("=== omavault Security Audit ===");
            println!("Score:          {}/100", report.overall_score);
            println!("Total entries:  {}", report.total_entries);
            println!(
                "2FA (TOTP):     {}/{} ({} missing 2FA)",
                report.totp_enabled_count,
                report.total_entries,
                report.missing_totp.len()
            );
            if !report.weak_passwords.is_empty() {
                println!("\nWeak / empty passwords ({}):", report.weak_passwords.len());
                for w in &report.weak_passwords {
                    println!(
                        "  - {} ({:.0} bits · {} · len {})",
                        tty_safe(&w.entry_name),
                        w.entropy_bits,
                        w.label,
                        w.length
                    );
                }
            }
            if !report.reused_groups.is_empty() {
                println!("\nReused passwords ({} groups):", report.reused_groups.len());
                for g in &report.reused_groups {
                    let safe_names: Vec<String> = g.entry_names.iter().map(|n| tty_safe(n)).collect();
                    println!("  - {}", safe_names.join(", "));
                }
            }
            if !report.stale_entries.is_empty() {
                println!("\nPasswords older than 1 year ({}):", report.stale_entries.len());
                for (name, days) in &report.stale_entries {
                    println!("  - {} ({days} days)", tty_safe(name));
                }
            }
            Ok(())
        }

        Commands::Rekey {
            new_keyfile,
            remove_keyfile,
            enable_fido2,
            fido2_label,
            fido2_uv,
            remove_fido2,
            mem_mib,
            time,
            lanes,
            keep_old_backups,
            purge_old_backups: _,
        } => {
            let should_purge = !keep_old_backups;
            if enable_fido2 {
                validate_slot_label(&fido2_label)?;
            }

            // Lock daemon BEFORE reading/writing so no concurrent session can revert the rekey.
            let client = DaemonClient::new(socket_path);
            let _ = client.lock();
            clear_clipboard_best_effort();

            let old_header = read_header_from_disk(&vault_path, true)?;
            if enable_fido2 && old_header.requires_fido2() {
                return Err(VaultError::Fido2Error(
                    "vault already has FIDO2 enabled; use `omavault fido2 add --label <name>` to add another key, or `omavault rekey` without --enable-fido2 to rotate keys".into(),
                ));
            }
            if cli.keyfile.is_some() && !old_header.requires_keyfile() && new_keyfile.is_none() {
                eprintln!(
                    "Warning: global --keyfile is ignored for rekey on a passphrase-only vault; pass --new-keyfile to add a keyfile."
                );
            }

            let old_pass = prompt_passphrase("Current master passphrase: ", cli.passphrase_stdin)?;
            let old_kf = if old_header.requires_keyfile() {
                let p = cli.keyfile.as_deref().ok_or(VaultError::KeyfileRequired)?;
                Some(hash_keyfile(p)?)
            } else {
                None
            };
            if old_header.requires_fido2() {
                eprintln!("Touch an enrolled FIDO2 security key to unlock current vault...");
            }
            let old_res = resolve_master_key(
                &old_header,
                old_pass.as_bytes(),
                old_kf.as_deref(),
                &LibFido2Cli,
                cli.fido2_device.as_deref(),
                true,
            )?;
            drop(old_pass);

            let (_, mut vault) = load_vault_from_disk(&vault_path, &old_res.master_key, true)?;
            enforce_rollback_policy(None, &vault_path, &vault, cli.allow_rollback)?;
            let expected_rev = header_revision(&old_header);
            let old_matched_idx = old_res.matched_slot_index;
            let old_fido2_secret = old_res.matched_fido2_secret;
            // Immediately wipe old master key from RAM before prompting for new credentials.
            drop(old_res.master_key);

            // Preserve existing hardened KDF params whenever flags are omitted!
            let new_params = KdfParams {
                mem_kib: mem_mib
                    .map(|m| m.saturating_mul(1024))
                    .unwrap_or(old_header.kdf_params.mem_kib),
                time_cost: time.unwrap_or(old_header.kdf_params.time_cost),
                parallelism: lanes.unwrap_or(old_header.kdf_params.parallelism),
            };
            new_params.validate()?;

            let new_pass = prompt_new_passphrase(cli.passphrase_stdin)?;

            let new_kf = if remove_keyfile {
                None
            } else if let Some(p) = new_keyfile.as_deref() {
                Some(hash_keyfile(p)?)
            } else {
                old_kf
            };

            // Each branch also returns one (slot label, hmac-secret) pair so the saved vault can
            // be independently re-opened from disk before old-key backups are purged.
            let (mut new_header, new_master_key, verify_secret) = if remove_fido2
                || (!enable_fido2 && !old_header.requires_fido2())
            {
                let hdr = VaultHeader::new(new_params, new_kf.is_some(), None)?;
                let mk = derive_master_key(
                    new_pass.as_bytes(),
                    &hdr.kdf_salt,
                    new_params,
                    new_kf.as_deref(),
                    None,
                    true,
                )?;
                (hdr, mk, None)
            } else if enable_fido2 {
                let provider = LibFido2Cli;
                let meta = provider.enroll(cli.fido2_device.as_deref(), fido2_uv)?;
                eprintln!(
                    "Touch your FIDO2 security key ('{fido2_label}') once more to finish re-keying..."
                );
                let sec = provider.assert_on_any_device(&meta, cli.fido2_device.as_deref())?;

                let mut hdr = VaultHeader::new_v2_fido2_shell(new_params, new_kf.is_some())?;
                let new_pw_hash =
                    derive_passphrase_hash(new_pass.as_bytes(), &hdr.kdf_salt, new_params, true)?;
                let mk = generate_random_master_key()?;
                let slot = wrap_master_key_for_slot(
                    &hdr,
                    &mk,
                    &new_pw_hash,
                    new_kf.as_deref(),
                    &fido2_label,
                    meta,
                    &sec,
                )?;
                hdr.fido2_slots.push(slot);
                (hdr, mk, Some((fido2_label.clone(), sec)))
            } else if old_header.version == VAULT_VERSION_V1 {
                // Keep existing legacy single FIDO2 key while upgrading to OMAV v2 slots.
                let old_meta = old_header.fido2.clone().ok_or(VaultError::Fido2Required)?;
                let sec = old_fido2_secret.ok_or(VaultError::Fido2Required)?;
                let mut hdr = VaultHeader::new_v2_fido2_shell(new_params, new_kf.is_some())?;
                let new_pw_hash =
                    derive_passphrase_hash(new_pass.as_bytes(), &hdr.kdf_salt, new_params, true)?;
                let mk = generate_random_master_key()?;
                let slot = wrap_master_key_for_slot(
                    &hdr,
                    &mk,
                    &new_pw_hash,
                    new_kf.as_deref(),
                    "primary",
                    old_meta,
                    &sec,
                )?;
                hdr.fido2_slots.push(slot);
                (hdr, mk, Some(("primary".to_string(), sec)))
            } else {
                // Re-key existing OMAV v2 multi-slot vault: rotate vault_master_key and re-wrap
                // the active YubiKey (reusing its secret) plus any other enrolled YubiKeys.
                let mut hdr = VaultHeader::new_v2_fido2_shell(new_params, new_kf.is_some())?;
                let new_pw_hash =
                    derive_passphrase_hash(new_pass.as_bytes(), &hdr.kdf_salt, new_params, true)?;
                let mk = generate_random_master_key()?;
                let provider = LibFido2Cli;
                let mut verify_secret = None;

                for (idx, old_slot) in old_header.fido2_slots.iter().enumerate() {
                    if Some(idx) == old_matched_idx {
                        let sec = old_fido2_secret
                            .as_ref()
                            .ok_or(VaultError::Fido2Required)?;
                        verify_secret = Some((old_slot.label.clone(), sec.clone()));
                        let wrapped = wrap_master_key_for_slot(
                            &hdr,
                            &mk,
                            &new_pw_hash,
                            new_kf.as_deref(),
                            &old_slot.label,
                            old_slot.fido2.clone(),
                            sec,
                        )?;
                        hdr.fido2_slots.push(wrapped);
                    } else {
                        let keep = prompt_rewrap_or_skip(&old_slot.label)?;
                        if keep {
                            eprintln!(
                                "Touch YubiKey '{}' to re-wrap its key slot...",
                                err_safe(&old_slot.label)
                            );
                            let sec = provider.assert_on_any_device(
                                &old_slot.fido2,
                                cli.fido2_device.as_deref(),
                            )?;
                            let wrapped = wrap_master_key_for_slot(
                                &hdr,
                                &mk,
                                &new_pw_hash,
                                new_kf.as_deref(),
                                &old_slot.label,
                                old_slot.fido2.clone(),
                                &sec,
                            )?;
                            hdr.fido2_slots.push(wrapped);
                        } else {
                            eprintln!(
                                "Dropped FIDO2 key slot '{}' during rekey.",
                                err_safe(&old_slot.label)
                            );
                        }
                    }
                }
                let verify_secret = verify_secret.ok_or(VaultError::Fido2Required)?;
                (hdr, mk, Some(verify_secret))
            };

            // Always keep a rolling backup of the old-key vault until the new one is verified.
            save_vault_to_disk_checked(
                &vault_path,
                &new_master_key,
                &mut new_header,
                &mut vault,
                Some(&expected_rev),
                true,
                true,
            )?;
            drop(new_master_key);
            // Re-open from disk with ONLY the new credentials before purging old-key backups.
            verify_saved_vault(
                &vault_path,
                &new_header,
                new_pass.as_bytes(),
                new_kf.as_deref(),
                verify_secret
                    .as_ref()
                    .map(|(label, sec)| (label.as_str(), &**sec)),
                vault.entries.len(),
                true,
            )?;
            record_saved_vault(None, &vault_path, &vault);
            drop(new_pass);

            if should_purge {
                let removed = purge_encrypted_backups(&vault_path)?;
                println!(
                    "Vault re-keyed (OMAV v{}, {} MiB, t={}, p={}) and purged {removed} old-key backup file(s).",
                    new_header.version,
                    new_params.mem_kib / 1024,
                    new_params.time_cost,
                    new_params.parallelism
                );
            } else {
                println!(
                    "Vault re-keyed successfully (OMAV v{}, {} MiB, t={}, p={}).",
                    new_header.version,
                    new_params.mem_kib / 1024,
                    new_params.time_cost,
                    new_params.parallelism
                );
                eprintln!(
                    "Note: --keep-old-backups retained rolling backups (*.bak.*) encrypted under the old key."
                );
            }
            Ok(())
        }
    }
}

fn open_session(
    vault_path: &Path,
    socket_path: &Path,
    keyfile_path: Option<&Path>,
    fido2_device: Option<&str>,
    passphrase_stdin: bool,
    allow_rollback: bool,
) -> Result<VaultSession> {
    let client = DaemonClient::new(socket_path.to_path_buf());
    if let Ok((vault, revision)) = client.load_vault(vault_path) {
        return Ok(VaultSession::Daemon {
            client,
            vault_path: vault_path.to_path_buf(),
            vault,
            revision,
        });
    }

    let header = read_header_from_disk(vault_path, true)?;
    let passphrase = prompt_passphrase("Master passphrase: ", passphrase_stdin)?;

    let kf_digest = if header.requires_keyfile() {
        let p = keyfile_path.ok_or(VaultError::KeyfileRequired)?;
        Some(hash_keyfile(p)?)
    } else {
        None
    };

    if header.requires_fido2() {
        eprintln!("Touch your FIDO2 security key when it blinks...");
    }
    let res = resolve_master_key(
        &header,
        passphrase.as_bytes(),
        kf_digest.as_deref(),
        &LibFido2Cli,
        fido2_device,
        true,
    )?;

    let (verified_header, vault) = load_vault_from_disk(vault_path, &res.master_key, true)?;
    enforce_rollback_policy(None, vault_path, &vault, allow_rollback)?;
    Ok(VaultSession::Standalone {
        vault_path: vault_path.to_path_buf(),
        master_key: res.master_key,
        header: verified_header,
        vault,
    })
}

/// Print a revealed password/note.
///
/// On a terminal (and without `--raw`), stored bytes must never be able to drive the terminal: an
/// OSC 52 sequence in a note could silently replace the clipboard, and CSI sequences could forge
/// prompts. Notes are printed with control/BiDi characters stripped; a password containing such
/// characters is refused (printing an altered password would be wrong) — use `--copy`.
/// When stdout is a pipe/file, the exact bytes are emitted (e.g. `| wl-copy`).
fn print_revealed_secret(value: &str, is_notes: bool) -> Result<()> {
    let to_terminal = io::stdout().is_terminal() && !RAW_STDOUT.load(Ordering::Relaxed);
    if !to_terminal {
        let mut out = io::stdout().lock();
        out.write_all(value.as_bytes())?;
        out.write_all(b"\n")?;
        return Ok(());
    }
    if is_notes {
        let shown = Zeroizing::new(sanitize_multiline(value));
        if shown.len() != value.len() {
            eprintln!("note: terminal control characters were removed from this display (use --copy, or pipe the output, for exact bytes)");
        }
        println!("{}", *shown);
        return Ok(());
    }
    if value.chars().any(is_dangerous_display_char) {
        return Err(VaultError::InvalidFormat(
            "this password contains terminal control characters; refusing to print it to a terminal (use --copy, or pipe the output)".into(),
        ));
    }
    println!("{value}");
    Ok(())
}

/// Read an interactive confirmation line directly from `/dev/tty`, flushing any buffered
/// stray input (e.g. accidental YubiKey OTP keyboard bursts) first and refusing non-TTY EOF.
fn read_clean_tty_line(prompt: &str) -> Result<String> {
    let tty = OpenOptions::new().read(true).open("/dev/tty").map_err(|e| {
        VaultError::Fido2Error(format!(
            "interactive TTY (/dev/tty) required for YubiKey swap prompt: {e}"
        ))
    })?;
    unsafe {
        let _ = libc::tcflush(tty.as_raw_fd(), libc::TCIFLUSH);
    }
    eprint!("{prompt}");
    io::stderr().flush()?;
    let mut reader = BufReader::new(tty);
    let mut line = String::new();
    let n = reader.read_line(&mut line)?;
    if n == 0 {
        return Err(VaultError::Fido2Error(
            "unexpected EOF on /dev/tty during YubiKey prompt".into(),
        ));
    }
    Ok(line.trim().to_string())
}

fn wait_for_yubikey_swap(prompt: &str) -> Result<()> {
    loop {
        let reply = read_clean_tty_line(prompt)?;
        if reply.is_empty() || reply.eq_ignore_ascii_case("ok") || reply.eq_ignore_ascii_case("yes")
        {
            return Ok(());
        }
        eprintln!(
            "Ignored unexpected input (possible stray YubiKey OTP burst) — press Enter once the key is plugged in."
        );
    }
}

fn prompt_rewrap_or_skip(label: &str) -> Result<bool> {
    loop {
        let reply = read_clean_tty_line(&format!(
            "Plug in YubiKey '{}' and press Enter to re-wrap it (or type 'skip' to drop it): ",
            err_safe(label)
        ))?;
        if reply.is_empty() || reply.eq_ignore_ascii_case("yes") || reply.eq_ignore_ascii_case("ok")
        {
            return Ok(true);
        }
        if reply.eq_ignore_ascii_case("skip") {
            return Ok(false);
        }
        eprintln!(
            "Ignored unexpected input (possible stray YubiKey OTP burst) — press Enter to keep '{}' or type 'skip'.",
            err_safe(label)
        );
    }
}

fn read_totp_input(prompt_flag: bool, file_path: Option<&Path>) -> Result<Option<TotpConfig>> {
    if let Some(path) = file_path {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
            .open(path)?;
        let meta = file.metadata()?;
        if !meta.file_type().is_file() {
            return Err(VaultError::InvalidTotp(
                "TOTP file must be a regular file".into(),
            ));
        }
        if meta.uid() != unsafe { libc::geteuid() } || (meta.mode() & 0o077) != 0 {
            return Err(VaultError::InvalidTotp(format!(
                "TOTP secret file '{}' must be owned by you with owner-only permissions (chmod 600)",
                path.display()
            )));
        }
        if meta.len() > 4096 {
            return Err(VaultError::InvalidTotp(
                "TOTP secret file exceeds 4096 bytes".into(),
            ));
        }
        let mut raw = Zeroizing::new(String::with_capacity(256));
        file.take(4096).read_to_string(&mut raw)?;
        return Ok(Some(TotpConfig::parse(raw.trim())?));
    }
    if prompt_flag {
        let raw = prompt_tty_secret("TOTP Base32 secret or otpauth:// URI (hidden): ")?;
        return Ok(Some(TotpConfig::parse(raw.trim())?));
    }
    Ok(None)
}

fn prompt_tty_secret(prompt: &str) -> Result<Zeroizing<String>> {
    let pw = rpassword::prompt_password(prompt)
        .map_err(|e| VaultError::Io(io::Error::other(format!("secret prompt failed: {e}"))))?;
    Ok(Zeroizing::new(pw))
}

fn prompt_confirmed_entry_password(name: &str) -> Result<Zeroizing<String>> {
    if !io::stdin().is_terminal() {
        return Err(VaultError::InvalidFormat(
            "refusing to read entry password from non-interactive stdin (use --generate or run interactively)".into(),
        ));
    }
    loop {
        let p1 = prompt_tty_secret(&format!("Password for '{name}': "))?;
        if p1.is_empty() {
            eprintln!("Password cannot be empty.");
            continue;
        }
        let p2 = prompt_tty_secret(&format!("Confirm password for '{name}': "))?;
        if *p1 != *p2 {
            eprintln!("Passwords did not match. Try again.");
            continue;
        }
        return Ok(p1);
    }
}

/// Read a single passphrase line directly from raw fd 0 when `from_stdin` is requested
/// (avoiding `std::io::Stdin`'s unzeroized static 8 KiB `BufReader` while preserving
/// subsequent lines for multi-step scripts), or prompt via TTY otherwise.
fn prompt_passphrase(prompt: &str, from_stdin: bool) -> Result<Zeroizing<String>> {
    if from_stdin {
        const MAX_STDIN_PASS_BYTES: usize = 4096;
        let mut buf = Zeroizing::new(Vec::with_capacity(256));
        let mut byte = Zeroizing::new([0u8; 1]);
        let mut saw_any = false;
        loop {
            let n = unsafe {
                libc::read(
                    libc::STDIN_FILENO,
                    byte.as_mut_ptr() as *mut libc::c_void,
                    1,
                )
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(VaultError::Io(err));
            }
            if n == 0 {
                break;
            }
            saw_any = true;
            if byte[0] == b'\n' {
                break;
            }
            if buf.len() >= MAX_STDIN_PASS_BYTES {
                return Err(VaultError::InvalidFormat(
                    "passphrase from stdin exceeds maximum length".into(),
                ));
            }
            buf.push(byte[0]);
        }
        drop(byte);
        if !saw_any {
            return Err(VaultError::InvalidFormat(
                "unexpected EOF reading passphrase from stdin".into(),
            ));
        }
        while buf.last() == Some(&b'\r') {
            buf.pop();
        }
        let s = String::from_utf8(std::mem::take(&mut *buf)).map_err(|_| {
            VaultError::InvalidFormat("passphrase from stdin is not valid UTF-8".into())
        })?;
        return Ok(Zeroizing::new(s));
    }
    prompt_tty_secret(prompt)
}

fn prompt_new_passphrase(from_stdin: bool) -> Result<Zeroizing<String>> {
    if from_stdin {
        let pw = prompt_passphrase("", true)?;
        if pw.chars().count() < 10 {
            return Err(VaultError::WeakKdfParameters(
                "master passphrase must be at least 10 characters".into(),
            ));
        }
        return Ok(pw);
    }

    loop {
        let p1 = prompt_tty_secret("New master passphrase (min 10 chars): ")?;
        if p1.chars().count() < 10 {
            eprintln!("Master passphrase too short — use at least 10 characters (recommend an 8+ word passphrase).");
            continue;
        }
        let bits = estimate_entropy_bits(&p1);
        eprintln!(
            "Estimated passphrase strength: {:.0} bits ({})",
            bits,
            strength_label(bits)
        );
        let p2 = prompt_tty_secret("Confirm master passphrase: ")?;
        if *p1 != *p2 {
            eprintln!("Passphrases did not match. Try again.");
            continue;
        }
        return Ok(p1);
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::Cli;

    #[test]
    fn verify_cli_flags() {
        Cli::command().debug_assert();
    }
}
