use std::fs::File;
use std::io::{self, BufRead, IsTerminal, Read, Write};
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
    generate_random_master_key, resolve_master_key, validate_slot_label, wrap_master_key_for_slot,
    VaultHeader, MAX_FIDO2_SLOTS, VAULT_VERSION_V1, VAULT_VERSION_V2,
};
use crate::daemon::{default_socket_path, run_daemon, DaemonClient, DEFAULT_IDLE_TIMEOUT_SECS};
use crate::error::{Result, VaultError};
use crate::generator::{
    estimate_entropy_bits, generate_passphrase, generate_password, generated_password_entropy_bits,
    passphrase_entropy_bits, strength_label, PassphraseOptions, PasswordOptions,
};
use crate::hardening::{HardeningStatus, LockedKey};
use crate::totp::TotpConfig;
use crate::tui::{run_tui, TuiConfig};
use crate::vault::audit::run_audit;
use crate::vault::storage::{
    default_vault_path, generate_keyfile, load_vault_from_disk, purge_encrypted_backups,
    read_header_from_disk, save_vault_to_disk,
};
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
    version,
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
        /// Word count for passphrase mode (6..=24, recommend >= 8)
        #[arg(short, long, default_value_t = 8)]
        words: usize,
        /// Exclude symbols in random password mode
        #[arg(long)]
        no_symbols: bool,
        /// Exclude visually ambiguous characters (I, l, 1, O, 0)
        #[arg(long)]
        no_ambiguous: bool,
        /// Copy directly to Wayland secret clipboard instead of printing
        #[arg(short, long)]
        copy: bool,
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
        /// Remove rolling `.bak.*` files encrypted under the previous master key after rekey succeeds
        #[arg(long)]
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
        /// Remove rolling `.bak.*` files that still contain the removed key slot
        #[arg(long)]
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
            } => client.save_vault(vault_path, vault, Some(revision.clone())),
            Self::Standalone {
                vault_path,
                master_key,
                header,
                vault,
            } => save_vault_to_disk(vault_path, master_key, header, vault),
        }
    }
}

pub fn execute(cli: Cli, hardening: HardeningStatus) -> Result<()> {
    let vault_path = cli.vault.clone().unwrap_or_else(default_vault_path);
    let socket_path = cli.socket.clone().unwrap_or_else(default_socket_path);

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
                            slot.label,
                            slot.fido2.require_uv,
                            fp
                        );
                    }
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
                let (_, vault) = load_vault_from_disk(&vault_path, &res.master_key, true)?;
                drop(passphrase);

                wait_for_yubikey_swap(&format!(
                    "Now plug in the NEW YubiKey to enroll as '{label}', then press Enter..."
                ))?;

                let provider = LibFido2Cli;
                let new_meta = provider.enroll(cli.fido2_device.as_deref(), uv)?;
                eprintln!("Touch the NEW YubiKey ('{label}') once more to verify enrollment...");
                let new_secret =
                    provider.get_hmac_secret(&new_meta, cli.fido2_device.as_deref())?;

                if old_header.version == VAULT_VERSION_V2 {
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
                    save_vault_to_disk(&vault_path, &res.master_key, &mut updated_header, &vault)?;
                    let _ = load_vault_from_disk(&vault_path, &res.master_key, true)?;
                    println!(
                        "Enrolled FIDO2 key '{label}' ({}/{} slots). You can now unlock with any enrolled key: {}",
                        updated_header.fido2_slots.len(),
                        MAX_FIDO2_SLOTS,
                        updated_header.fido2_labels().join(", ")
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

                    save_vault_to_disk(&vault_path, &new_master_key, &mut v2_header, &vault)?;
                    let _ = load_vault_from_disk(&vault_path, &new_master_key, true)?;
                    println!(
                        "Upgraded vault to OMAV v2 and enrolled '{label}' ({}/{} slots: {}).",
                        v2_header.fido2_slots.len(),
                        MAX_FIDO2_SLOTS,
                        v2_header.fido2_labels().join(", ")
                    );
                }
                Ok(())
            }

            Fido2Action::Remove {
                label,
                purge_old_backups,
            } => {
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
                let (_, vault) = load_vault_from_disk(&vault_path, &res.master_key, true)?;
                drop(passphrase);

                let mut updated_header = old_header.clone();
                let remaining_slot_clone = old_header.fido2_slots[matched_idx].clone();
                updated_header
                    .fido2_slots
                    .retain(|s| !s.label.eq_ignore_ascii_case(&label));

                let rotated_master = if updated_header.fido2_slots.len() == 1 {
                    // We already hold the sole remaining key's secret in memory — rotate the
                    // vault master key immediately with zero extra touches!
                    let new_mk = generate_random_master_key()?;
                    let remaining_secret = res
                        .matched_fido2_secret
                        .as_ref()
                        .ok_or(VaultError::Fido2Required)?;
                    let rewrapped = wrap_master_key_for_slot(
                        &updated_header,
                        &new_mk,
                        &res.pw_hash,
                        kf_digest.as_deref(),
                        &remaining_slot_clone.label,
                        remaining_slot_clone.fido2,
                        remaining_secret,
                    )?;
                    updated_header.fido2_slots = vec![rewrapped];
                    save_vault_to_disk(&vault_path, &new_mk, &mut updated_header, &vault)?;
                    let _ = load_vault_from_disk(&vault_path, &new_mk, true)?;
                    true
                } else {
                    save_vault_to_disk(
                        &vault_path,
                        &res.master_key,
                        &mut updated_header,
                        &vault,
                    )?;
                    let _ = load_vault_from_disk(&vault_path, &res.master_key, true)?;
                    false
                };

                if purge_old_backups {
                    let removed = purge_encrypted_backups(&vault_path)?;
                    println!(
                        "Removed FIDO2 key '{label}' and purged {removed} old backup file(s). Remaining keys: {}",
                        updated_header.fido2_labels().join(", ")
                    );
                } else {
                    println!(
                        "Removed FIDO2 key '{label}'. Remaining keys: {}",
                        updated_header.fido2_labels().join(", ")
                    );
                }
                if rotated_master {
                    println!("Vault master key was automatically rotated for the remaining key.");
                } else {
                    eprintln!(
                        "Note: If '{label}' was lost or stolen, run `omavault rekey --purge-old-backups` to also rotate the underlying vault master key."
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
            if copy {
                copy_secret(
                    &secret,
                    ClipboardOptions {
                        timeout_secs: timeout,
                        paste_once,
                    },
                )?;
                eprintln!(
                    "Copied generated secret ({bits:.0} bits · {}) to Wayland secret clipboard (clears in {timeout}s).",
                    strength_label(bits)
                );
            } else {
                println!("{}", *secret);
                eprintln!("Entropy: {bits:.0} bits ({})", strength_label(bits));
            }
            Ok(())
        }

        Commands::Daemon { timeout } => {
            eprintln!(
                "omavault daemon listening on '{}' (idle timeout: {}s, {})",
                socket_path.display(),
                timeout,
                hardening.summary()
            );
            run_daemon(&socket_path, timeout, true)
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
            let client = DaemonClient::new(socket_path);
            if client.lock().is_ok() {
                println!("Vault locked (master key wiped from RAM, clipboard cleared).");
            } else {
                println!("Daemon not running; local clipboard cleared.");
            }
            Ok(())
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
            client.unlock(
                &vault_path,
                passphrase,
                cli.keyfile.clone(),
                cli.fido2_device.clone(),
            )?;
            println!("Vault unlocked in daemon.");
            Ok(())
        }

        Commands::Status => {
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
                        header.fido2_labels().join(", ")
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
                    "Daemon status:     {} (mlock: {}, guard-page: {}, idle remaining: {}s)",
                    if st.unlocked { "UNLOCKED" } else { "LOCKED" },
                    st.mlocked,
                    st.guard_protected,
                    st.remaining_secs
                );
                if let Some(reason) = st.last_lock_reason {
                    println!("Last lock reason:  {reason}");
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

            let vault = Vault::new();
            save_vault_to_disk(&vault_path, &master_key, &mut header, &vault)?;

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
            })
        }

        Commands::List { query } => {
            let session = open_session(
                &vault_path,
                &socket_path,
                cli.keyfile.as_deref(),
                cli.fido2_device.as_deref(),
                cli.passphrase_stdin,
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
                        format!(" ({})", e.username)
                    };
                    println!("{}{}{}", e.name, user, totp_tag);
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
                println!("Added '{trimmed_name}' and copied password to Wayland secret clipboard.");
            } else {
                println!("Added '{trimmed_name}' to encrypted vault.");
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
                    "Copied {field:?} for '{name}' (Wayland secret-tagged, clears in {timeout}s)."
                );
            } else if matches!(field, GetField::Password) && !reveal {
                return Err(VaultError::InvalidFormat(
                    "refusing to print password without `--reveal` (use `--copy` for Wayland secret clipboard)".into(),
                ));
            } else if matches!(field, GetField::Notes) && !reveal && io::stdout().is_terminal() {
                return Err(VaultError::InvalidFormat(
                    "refusing to print sensitive notes to terminal without `--reveal` or `--copy`".into(),
                ));
            } else {
                println!("{}", *value);
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
                    "Copied TOTP for '{name}' ({}s remaining, secret-tagged).",
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
                entry.username = u;
            }
            if let Some(u) = url {
                entry.url = u;
            }
            if let Some(n) = new_notes {
                entry.notes = n.to_string();
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
                    println!("Updated '{name}' and copied new password to Wayland secret clipboard.");
                    return Ok(());
                }
            }
            println!("Updated '{name}' and re-encrypted vault.");
            Ok(())
        }

        Commands::Rm { name, yes } => {
            let mut session = open_session(
                &vault_path,
                &socket_path,
                cli.keyfile.as_deref(),
                cli.fido2_device.as_deref(),
                cli.passphrase_stdin,
            )?;
            if session.vault().find_by_name(&name).is_none() {
                return Err(VaultError::EntryNotFound(name));
            }
            if !yes {
                print!("Permanently delete '{name}'? [y/N]: ");
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
            println!("Deleted '{name}'.");
            Ok(())
        }

        Commands::Audit => {
            let session = open_session(
                &vault_path,
                &socket_path,
                cli.keyfile.as_deref(),
                cli.fido2_device.as_deref(),
                cli.passphrase_stdin,
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
                        w.entry_name, w.entropy_bits, w.label, w.length
                    );
                }
            }
            if !report.reused_groups.is_empty() {
                println!("\nReused passwords ({} groups):", report.reused_groups.len());
                for g in &report.reused_groups {
                    println!("  - {}", g.entry_names.join(", "));
                }
            }
            if !report.stale_entries.is_empty() {
                println!("\nPasswords older than 1 year ({}):", report.stale_entries.len());
                for (name, days) in &report.stale_entries {
                    println!("  - {name} ({days} days)");
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
            purge_old_backups,
        } => {
            if enable_fido2 {
                validate_slot_label(&fido2_label)?;
            }

            // Lock daemon BEFORE reading/writing so no concurrent session can revert the rekey.
            let client = DaemonClient::new(socket_path);
            let _ = client.lock();
            clear_clipboard_best_effort();

            let old_header = read_header_from_disk(&vault_path, true)?;
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

            let (_, vault) = load_vault_from_disk(&vault_path, &old_res.master_key, true)?;
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

            let (mut new_header, new_master_key) = if remove_fido2
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
                (hdr, mk)
            } else if enable_fido2 {
                let provider = LibFido2Cli;
                let meta = provider.enroll(cli.fido2_device.as_deref(), fido2_uv)?;
                eprintln!(
                    "Touch your FIDO2 security key ('{fido2_label}') once more to finish re-keying..."
                );
                let sec = provider.get_hmac_secret(&meta, cli.fido2_device.as_deref())?;

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
                (hdr, mk)
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
                (hdr, mk)
            } else {
                // Re-key existing OMAV v2 multi-slot vault: rotate vault_master_key and re-wrap
                // the active YubiKey (reusing its secret) plus any other enrolled YubiKeys.
                let mut hdr = VaultHeader::new_v2_fido2_shell(new_params, new_kf.is_some())?;
                let new_pw_hash =
                    derive_passphrase_hash(new_pass.as_bytes(), &hdr.kdf_salt, new_params, true)?;
                let mk = generate_random_master_key()?;
                let provider = LibFido2Cli;

                for (idx, old_slot) in old_header.fido2_slots.iter().enumerate() {
                    if Some(idx) == old_matched_idx {
                        let sec = old_fido2_secret
                            .as_ref()
                            .ok_or(VaultError::Fido2Required)?;
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
                            eprintln!("Touch YubiKey '{}' to re-wrap its key slot...", old_slot.label);
                            let sec = provider
                                .get_hmac_secret(&old_slot.fido2, cli.fido2_device.as_deref())?;
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
                            eprintln!("Dropped FIDO2 key slot '{}' during rekey.", old_slot.label);
                        }
                    }
                }
                (hdr, mk)
            };
            drop(new_pass);

            save_vault_to_disk(&vault_path, &new_master_key, &mut new_header, &vault)?;
            // Verify new vault decrypts cleanly before optionally purging old-key backups.
            let _ = load_vault_from_disk(&vault_path, &new_master_key, true)?;

            if purge_old_backups {
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
                    "Note: Rolling backups (*.bak.*) encrypted under the old key still exist. Pass --purge-old-backups if rotating due to key compromise."
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
    Ok(VaultSession::Standalone {
        vault_path: vault_path.to_path_buf(),
        master_key: res.master_key,
        header: verified_header,
        vault,
    })
}

fn wait_for_yubikey_swap(prompt: &str) -> Result<()> {
    eprint!("{prompt}");
    io::stderr().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(())
}

fn prompt_rewrap_or_skip(label: &str) -> Result<bool> {
    eprint!(
        "Plug in YubiKey '{label}' and press Enter to re-wrap it (or type 'skip' to drop it): "
    );
    io::stderr().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(!line.trim().eq_ignore_ascii_case("skip"))
}

fn read_totp_input(prompt_flag: bool, file_path: Option<&Path>) -> Result<Option<TotpConfig>> {
    if let Some(path) = file_path {
        let file = File::open(path)?;
        if !file.metadata()?.file_type().is_file() {
            return Err(VaultError::InvalidTotp(
                "TOTP file must be a regular file".into(),
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

/// Read a single passphrase line when `from_stdin` is requested (preserving subsequent lines
/// for multi-step scripts like `rekey --passphrase-stdin`), or prompt via TTY otherwise.
fn prompt_passphrase(prompt: &str, from_stdin: bool) -> Result<Zeroizing<String>> {
    if from_stdin {
        let mut line = Zeroizing::new(String::with_capacity(256));
        let stdin = io::stdin();
        let n = stdin.lock().read_line(&mut line)?;
        if n == 0 {
            return Err(VaultError::InvalidFormat(
                "unexpected EOF reading passphrase from stdin".into(),
            ));
        }
        while line.ends_with(['\r', '\n']) {
            line.pop();
        }
        return Ok(line);
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
