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
    derive_master_key, hash_keyfile, KdfParams, DEFAULT_ARGON2_LANES, DEFAULT_ARGON2_MEM_KIB,
    DEFAULT_ARGON2_TIME,
};
use crate::crypto::VaultHeader;
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
            let passphrase = prompt_passphrase("Master passphrase: ", cli.passphrase_stdin)?;
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
                println!(
                    "Required factors:  Passphrase{}{}",
                    if header.requires_keyfile() { " + Keyfile" } else { "" },
                    if header.requires_fido2() { " + FIDO2" } else { "" },
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

            let (fido2_meta, fido2_secret) = if fido2 {
                let provider = LibFido2Cli;
                let meta = provider.enroll(cli.fido2_device.as_deref(), fido2_uv)?;
                let secret = provider.get_hmac_secret(&meta, cli.fido2_device.as_deref())?;
                (Some(meta), Some(secret))
            } else {
                (None, None)
            };

            let mut header = VaultHeader::new(params, kf_digest.is_some(), fido2_meta)?;
            let master_key = derive_master_key(
                passphrase.as_bytes(),
                &header.kdf_salt,
                params,
                kf_digest.as_deref(),
                fido2_secret.as_deref(),
                true,
            )?;

            let vault = Vault::new();
            save_vault_to_disk(&vault_path, &master_key, &mut header, &vault)?;

            println!("Initialized encrypted omavault at '{}'", vault_path.display());
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
            fido2_uv,
            remove_fido2,
            mem_mib,
            time,
            lanes,
            purge_old_backups,
        } => {
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
            let old_fido2 = if old_header.requires_fido2() {
                let meta = old_header.fido2.as_ref().ok_or(VaultError::Fido2Required)?;
                Some(LibFido2Cli.get_hmac_secret(meta, cli.fido2_device.as_deref())?)
            } else {
                None
            };

            let old_master_key = derive_master_key(
                old_pass.as_bytes(),
                &old_header.kdf_salt,
                old_header.kdf_params,
                old_kf.as_deref(),
                old_fido2.as_deref(),
                true,
            )?;
            drop(old_pass);

            let (_, vault) = load_vault_from_disk(&vault_path, &old_master_key, true)?;
            // Immediately wipe old master key from RAM before prompting for new credentials.
            drop(old_master_key);

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

            let (new_fido2_meta, new_fido2_secret) = if remove_fido2 {
                (None, None)
            } else if enable_fido2 {
                let provider = LibFido2Cli;
                let meta = provider.enroll(cli.fido2_device.as_deref(), fido2_uv)?;
                let sec = provider.get_hmac_secret(&meta, cli.fido2_device.as_deref())?;
                (Some(meta), Some(sec))
            } else {
                (old_header.fido2.clone(), old_fido2)
            };

            let mut new_header =
                VaultHeader::new(new_params, new_kf.is_some(), new_fido2_meta)?;
            let new_master_key = derive_master_key(
                new_pass.as_bytes(),
                &new_header.kdf_salt,
                new_params,
                new_kf.as_deref(),
                new_fido2_secret.as_deref(),
                true,
            )?;
            drop(new_pass);

            save_vault_to_disk(&vault_path, &new_master_key, &mut new_header, &vault)?;
            // Verify new vault decrypts cleanly before optionally purging old-key backups.
            let _ = load_vault_from_disk(&vault_path, &new_master_key, true)?;

            if purge_old_backups {
                let removed = purge_encrypted_backups(&vault_path)?;
                println!(
                    "Vault re-keyed ({} MiB, t={}, p={}) and purged {removed} old-key backup file(s).",
                    new_params.mem_kib / 1024,
                    new_params.time_cost,
                    new_params.parallelism
                );
            } else {
                println!(
                    "Vault re-keyed successfully ({} MiB, t={}, p={}).",
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

    let fido2_secret = if header.requires_fido2() {
        let meta = header.fido2.as_ref().ok_or(VaultError::Fido2Required)?;
        Some(LibFido2Cli.get_hmac_secret(meta, fido2_device)?)
    } else {
        None
    };

    let master_key = derive_master_key(
        passphrase.as_bytes(),
        &header.kdf_salt,
        header.kdf_params,
        kf_digest.as_deref(),
        fido2_secret.as_deref(),
        true,
    )?;

    let (verified_header, vault) = load_vault_from_disk(vault_path, &master_key, true)?;
    Ok(VaultSession::Standalone {
        vault_path: vault_path.to_path_buf(),
        master_key,
        header: verified_header,
        vault,
    })
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
