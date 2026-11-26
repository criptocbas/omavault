use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand, ValueEnum};
use zeroize::Zeroizing;

use crate::clipboard::{
    clear_clipboard_best_effort, copy_secret, run_clipboard_server, ClipboardOptions,
    DEFAULT_CLIPBOARD_TIMEOUT_SECS,
};
use crate::crypto::fido2::{Fido2Provider, LibFido2Cli};
use crate::crypto::kdf::{
    derive_master_key, hash_keyfile, KdfParams, DEFAULT_ARGON2_LANES, DEFAULT_ARGON2_MEM_KIB,
    DEFAULT_ARGON2_TIME,
};
use crate::crypto::VaultHeader;
use crate::daemon::{
    default_socket_path, run_daemon, DaemonClient, DEFAULT_IDLE_TIMEOUT_SECS,
};
use crate::error::{Result, VaultError};
use crate::generator::{
    estimate_entropy_bits, generate_passphrase, generate_password, strength_label,
    PassphraseOptions, PasswordOptions,
};
use crate::hardening::{HardeningStatus, LockedKey};
use crate::totp::TotpConfig;
use crate::tui::{run_tui, TuiConfig};
use crate::vault::audit::run_audit;
use crate::vault::storage::{
    default_vault_path, generate_keyfile, load_vault_from_disk, read_header_from_disk,
    save_vault_to_disk,
};
use crate::vault::{Entry, Vault};

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

    /// Explicit FIDO2 HID device path (auto-detected if omitted)
    #[arg(long, global = true)]
    pub fido2_device: Option<String>,

    /// Path to daemon Unix socket
    #[arg(long, global = true, env = "OMAVAULT_SOCKET")]
    pub socket: Option<PathBuf>,

    /// Read master passphrase from stdin (for non-interactive scripts only)
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
        /// Clipboard auto-clear timeout in seconds
        #[arg(long, default_value_t = DEFAULT_CLIPBOARD_TIMEOUT_SECS)]
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
        /// Argon2id memory cost in MiB (default: 128, minimum: 64)
        #[arg(long, default_value_t = DEFAULT_ARGON2_MEM_KIB / 1024)]
        mem_mib: u32,
        /// Argon2id time cost / iterations (default: 4, minimum: 3)
        #[arg(long, default_value_t = DEFAULT_ARGON2_TIME)]
        time: u32,
        /// Argon2id parallel lanes (default: 4)
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
        #[arg(long, default_value = "")]
        notes: String,
        /// Comma-separated tags
        #[arg(long, default_value = "")]
        tags: String,
        /// TOTP Base32 secret or otpauth://totp/... URI
        #[arg(long)]
        totp: Option<String>,
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
        /// Print password to stdout (required if not copying)
        #[arg(long)]
        reveal: bool,
        /// Clear clipboard immediately after one paste
        #[arg(long)]
        paste_once: bool,
        /// Clipboard auto-clear timeout in seconds
        #[arg(long, default_value_t = DEFAULT_CLIPBOARD_TIMEOUT_SECS)]
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
        #[arg(long, default_value_t = DEFAULT_CLIPBOARD_TIMEOUT_SECS)]
        timeout: u64,
    },

    /// Edit an existing entry
    Edit {
        name: String,
        #[arg(short, long)]
        username: Option<String>,
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        notes: Option<String>,
        /// Set or replace TOTP secret (Base32 or otpauth:// URI)
        #[arg(long)]
        totp: Option<String>,
        /// Prompt for a new password (archives old password in history)
        #[arg(long)]
        rotate_password: bool,
        /// Generate a brand new CSPRNG password (archives old password in history)
        #[arg(short, long)]
        generate: bool,
        #[arg(long, default_value_t = 24)]
        length: usize,
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
        /// Word count for passphrase mode
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
        #[arg(long, default_value_t = DEFAULT_CLIPBOARD_TIMEOUT_SECS)]
        timeout: u64,
    },

    /// Run local password hygiene & security audit (weak, reused, stale, missing 2FA)
    Audit,

    /// Rotate master passphrase, Argon2id parameters, keyfile, or FIDO2 enrollment
    Rekey {
        /// New keyfile path to bind to the vault
        #[arg(long)]
        new_keyfile: Option<PathBuf>,
        /// Remove existing keyfile requirement
        #[arg(long)]
        remove_keyfile: bool,
        /// Enroll a new FIDO2 hardware key
        #[arg(long)]
        enable_fido2: bool,
        /// Require User Verification on the newly enrolled FIDO2 key
        #[arg(long)]
        fido2_uv: bool,
        /// Remove existing FIDO2 requirement
        #[arg(long)]
        remove_fido2: bool,
        #[arg(long, default_value_t = DEFAULT_ARGON2_MEM_KIB / 1024)]
        mem_mib: u32,
        #[arg(long, default_value_t = DEFAULT_ARGON2_TIME)]
        time: u32,
        #[arg(long, default_value_t = DEFAULT_ARGON2_LANES)]
        lanes: u32,
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
        #[arg(long, default_value_t = DEFAULT_CLIPBOARD_TIMEOUT_SECS)]
        timeout: u64,
        #[arg(long)]
        paste_once: bool,
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
            } => client.save_vault(vault_path, vault),
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
        } => run_clipboard_server(timeout, paste_once),

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
                (
                    generate_passphrase(&opts)?,
                    crate::generator::passphrase_entropy_bits(&opts),
                )
            } else {
                let s = generate_password(&PasswordOptions {
                    length,
                    symbols: !no_symbols,
                    exclude_ambiguous: no_ambiguous,
                    ..PasswordOptions::default()
                })?;
                let b = estimate_entropy_bits(&s);
                (s, b)
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
            println!("omavault daemon locked and stopped.");
            Ok(())
        }

        Commands::Lock => {
            let client = DaemonClient::new(socket_path);
            if client.is_available() {
                client.lock()?;
                println!("Vault locked (master key wiped from RAM, clipboard cleared).");
            } else {
                clear_clipboard_best_effort();
                println!("Daemon not running; clipboard cleared.");
            }
            Ok(())
        }

        Commands::Unlock => {
            let client = DaemonClient::new(socket_path);
            if !client.is_available() {
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
            if client.is_available() {
                let st = client.status()?;
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
                if master_key.is_mlocked() { "ACTIVE (mlock + PROT_NONE)" } else { "fallback (check RLIMIT_MEMLOCK)" }
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
            notes,
            tags,
            totp,
            generate,
            length,
            copy,
        } => {
            let mut session = open_session(
                &vault_path,
                &socket_path,
                cli.keyfile.as_deref(),
                cli.fido2_device.as_deref(),
                cli.passphrase_stdin,
            )?;

            let password = if generate {
                generate_password(&PasswordOptions {
                    length,
                    ..PasswordOptions::default()
                })?
            } else {
                prompt_passphrase(&format!("Password for '{name}': "), false)?
            };

            let totp_cfg = match totp {
                Some(raw) => Some(TotpConfig::parse(&raw)?),
                None => None,
            };

            let parsed_tags: Vec<String> = tags
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            let mut entry = Entry::new(name.clone(), username, password.to_string());
            entry.url = url;
            entry.notes = notes;
            entry.tags = parsed_tags;
            entry.totp = totp_cfg;

            session.vault_mut().add_entry(entry)?;
            session.save()?;

            if copy {
                copy_secret(&password, ClipboardOptions::default())?;
                println!("Added '{name}' and copied password to Wayland secret clipboard.");
            } else {
                println!("Added '{name}' to encrypted vault.");
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
                eprintln!(
                    "Refusing to print password to terminal without `--reveal` (use `--copy` for Wayland secret clipboard)."
                );
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
            notes,
            totp,
            rotate_password,
            generate,
            length,
        } => {
            let mut session = open_session(
                &vault_path,
                &socket_path,
                cli.keyfile.as_deref(),
                cli.fido2_device.as_deref(),
                cli.passphrase_stdin,
            )?;

            let new_pw = if generate {
                Some(generate_password(&PasswordOptions {
                    length,
                    ..PasswordOptions::default()
                })?)
            } else if rotate_password {
                Some(prompt_passphrase(&format!("New password for '{name}': "), false)?)
            } else {
                None
            };

            let parsed_totp = match totp {
                Some(raw) => Some(TotpConfig::parse(&raw)?),
                None => None,
            };

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
            if let Some(n) = notes {
                entry.notes = n;
            }
            if let Some(t) = parsed_totp {
                entry.totp = Some(t);
            }
            if let Some(pw) = new_pw {
                entry.set_password(pw.to_string());
            }
            entry.updated_at = chrono::Utc::now();

            session.save()?;
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
            let report = run_audit(session.vault());
            println!("=== omavault Security Audit ===");
            println!("Score:          {}/100", report.overall_score);
            println!("Total entries:  {}", report.total_entries);
            println!(
                "2FA (TOTP):     {}/{}",
                report.totp_enabled_count, report.total_entries
            );
            if !report.weak_passwords.is_empty() {
                println!("\nWeak passwords ({}):", report.weak_passwords.len());
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
        } => {
            // Open existing vault directly (never via cached daemon session).
            let old_header = read_header_from_disk(&vault_path, true)?;
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
            let (_, vault) = load_vault_from_disk(&vault_path, &old_master_key, true)?;

            // Build new key hierarchy with fresh kdf_salt, save_salt, and nonce.
            let new_params = KdfParams {
                mem_kib: mem_mib.saturating_mul(1024),
                time_cost: time,
                parallelism: lanes,
            };
            new_params.validate()?;

            let new_pass = prompt_new_passphrase(false)?;

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

            save_vault_to_disk(&vault_path, &new_master_key, &mut new_header, &vault)?;

            // Lock daemon if running so stale master key is purged immediately.
            let client = DaemonClient::new(socket_path);
            if client.is_available() {
                let _ = client.lock();
            }

            println!("Vault re-keyed successfully with fresh KDF salt, payload subkey, and nonce.");
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
    // 1. Prefer unlocked daemon session if available.
    let client = DaemonClient::new(socket_path.to_path_buf());
    if client.is_available() {
        if let Ok(vault) = client.load_vault(vault_path) {
            return Ok(VaultSession::Daemon {
                client,
                vault_path: vault_path.to_path_buf(),
                vault,
            });
        }
    }

    // 2. Fallback to standalone direct decryption.
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

fn prompt_passphrase(prompt: &str, from_stdin: bool) -> Result<Zeroizing<String>> {
    if from_stdin || !io::stdin().is_terminal() {
        let mut buf = Zeroizing::new(String::new());
        io::stdin().read_to_string(&mut buf)?;
        let trimmed = buf.trim_end_matches(['\r', '\n']).to_string();
        return Ok(Zeroizing::new(trimmed));
    }
    let pw = rpassword::prompt_password(prompt)
        .map_err(|e| VaultError::Io(io::Error::other(format!("passphrase prompt failed: {e}"))))?;
    Ok(Zeroizing::new(pw))
}

fn prompt_new_passphrase(from_stdin: bool) -> Result<Zeroizing<String>> {
    if from_stdin || !io::stdin().is_terminal() {
        let pw = prompt_passphrase("", true)?;
        if pw.chars().count() < 10 {
            return Err(VaultError::WeakKdfParameters(
                "master passphrase must be at least 10 characters".into(),
            ));
        }
        return Ok(pw);
    }

    loop {
        let p1 = prompt_passphrase("New master passphrase (min 10 chars): ", false)?;
        if p1.chars().count() < 10 {
            eprintln!("Master passphrase too short — use at least 10 characters (recommend a 6+ word passphrase).");
            continue;
        }
        let bits = estimate_entropy_bits(&p1);
        eprintln!(
            "Estimated passphrase strength: {:.0} bits ({})",
            bits,
            strength_label(bits)
        );
        let p2 = prompt_passphrase("Confirm master passphrase: ", false)?;
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

