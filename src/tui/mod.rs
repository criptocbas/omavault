pub mod theme;

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Clear, Gauge, List, ListItem, ListState, Paragraph, Wrap,
};
use ratatui::{Frame, Terminal};
use zeroize::{Zeroize, Zeroizing};

use crate::clipboard::{
    clear_clipboard_best_effort, copy_secret, ClipboardOptions, DEFAULT_CLIPBOARD_TIMEOUT_SECS,
};
use crate::crypto::fido2::LibFido2Cli;
use crate::crypto::kdf::hash_keyfile;
use crate::crypto::{header_revision, resolve_master_key, VaultHeader, VAULT_VERSION_V2};
use crate::daemon::{DaemonClient, DEFAULT_IDLE_TIMEOUT_SECS};
use crate::error::{Result, VaultError};
use crate::generator::{
    estimate_entropy_bits, generate_passphrase, generate_password, generated_password_entropy_bits,
    passphrase_entropy_bits, strength_label, PassphraseOptions, PasswordOptions,
};
use crate::hardening::{
    boottime_monotonic_skew_ms, boottime_secs, is_screen_locker_active, sanitize_multiline,
    sanitize_single_line, HardeningStatus, LockedKey,
};
use crate::totp::TotpConfig;
use crate::vault::audit::{run_audit, AuditReport};
use crate::vault::storage::{
    load_vault_from_disk, read_header_from_disk, save_vault_to_disk_checked,
};
use crate::vault::{Entry, Vault};

const SUSPEND_SKEW_THRESHOLD_MS: u64 = 2000;

pub struct TuiConfig {
    pub vault_path: PathBuf,
    pub keyfile_path: Option<PathBuf>,
    pub fido2_device: Option<String>,
    pub socket_path: PathBuf,
    pub idle_timeout_secs: u64,
    pub clipboard_timeout_secs: u64,
    pub paste_once: bool,
    pub hardening: HardeningStatus,
}

#[derive(Clone, Copy)]
enum ToastLevel {
    Ok,
    Warn,
    Error,
}

enum SessionBackend {
    Daemon {
        revision: Option<String>,
        mlocked: bool,
    },
    Standalone {
        master_key: LockedKey<32>,
        header: Box<VaultHeader>,
    },
}

enum UnlockOutcome {
    Daemon {
        vault: Vault,
        revision: String,
        mlocked: bool,
    },
    Standalone {
        master_key: LockedKey<32>,
        header: Box<VaultHeader>,
        vault: Vault,
    },
    Error(String),
}

enum Mode {
    Locked {
        passphrase_input: Zeroizing<String>,
        error_msg: Option<String>,
    },
    Unlocking {
        started_at: Instant,
        requires_fido2: bool,
        rx: mpsc::Receiver<UnlockOutcome>,
    },
    Normal,
    Search,
    Editor(EntryForm),
    Generator(GenModalState),
    Audit(AuditReport),
    ConfirmDelete {
        entry_name: String,
    },
    Help,
}

#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
struct EntryForm {
    editing_original_name: Option<String>,
    original_totp: Option<TotpConfig>,
    #[zeroize(skip)]
    totp_modified: bool,
    #[zeroize(skip)]
    reveal_secrets: bool,
    #[zeroize(skip)]
    active_field: usize,
    name: String,
    username: String,
    password: Zeroizing<String>,
    url: String,
    tags: String,
    totp: Zeroizing<String>,
    notes: Zeroizing<String>,
    error: Option<String>,
}

impl EntryForm {
    fn new_blank() -> Self {
        Self {
            editing_original_name: None,
            original_totp: None,
            totp_modified: false,
            reveal_secrets: false,
            active_field: 0,
            name: String::new(),
            username: String::new(),
            password: Zeroizing::new(String::with_capacity(256)),
            url: String::new(),
            tags: String::new(),
            totp: Zeroizing::new(String::with_capacity(256)),
            notes: Zeroizing::new(String::with_capacity(512)),
            error: None,
        }
    }

    fn from_entry(entry: &Entry) -> Self {
        let mut password = Zeroizing::new(String::with_capacity(entry.password.len().max(256)));
        password.push_str(&entry.password);
        let mut totp = Zeroizing::new(String::with_capacity(256));
        if let Some(t) = &entry.totp {
            totp.push_str(&t.secret_base32);
        }
        let mut notes = Zeroizing::new(String::with_capacity(entry.notes.len().max(512)));
        notes.push_str(&entry.notes);

        Self {
            editing_original_name: Some(entry.name.clone()),
            original_totp: entry.totp.clone(),
            totp_modified: false,
            reveal_secrets: false,
            active_field: 0,
            name: entry.name.clone(),
            username: entry.username.clone(),
            password,
            url: entry.url.clone(),
            tags: entry.tags.join(", "),
            totp,
            notes,
            error: None,
        }
    }

    const FIELD_COUNT: usize = 7;

    fn current_mut(&mut self) -> &mut String {
        if self.active_field == 5 {
            self.totp_modified = true;
        }
        match self.active_field {
            0 => &mut self.name,
            1 => &mut self.username,
            2 => &mut self.password,
            3 => &mut self.url,
            4 => &mut self.tags,
            5 => &mut self.totp,
            _ => &mut self.notes,
        }
    }
}

struct GenModalState {
    passphrase_mode: bool,
    length: usize,
    words: usize,
    symbols: bool,
    preview: Zeroizing<String>,
}

impl GenModalState {
    fn new() -> Self {
        let preview = generate_password(&PasswordOptions::default())
            .unwrap_or_else(|_| Zeroizing::new(String::new()));
        Self {
            passphrase_mode: false,
            length: 24,
            words: 8,
            symbols: true,
            preview,
        }
    }

    fn regenerate(&mut self) {
        self.preview = if self.passphrase_mode {
            generate_passphrase(&PassphraseOptions {
                words: self.words,
                ..PassphraseOptions::default()
            })
            .unwrap_or_else(|_| Zeroizing::new(String::new()))
        } else {
            generate_password(&PasswordOptions {
                length: self.length,
                symbols: self.symbols,
                ..PasswordOptions::default()
            })
            .unwrap_or_else(|_| Zeroizing::new(String::new()))
        };
    }
}

struct App {
    cfg: TuiConfig,
    header_preview: VaultHeader,
    mode: Mode,
    backend: Option<SessionBackend>,
    vault: Option<Vault>,
    search_query: Zeroizing<String>,
    list_state: ListState,
    reveal_password: bool,
    status_toast: Option<(ToastLevel, String, Instant)>,
    last_activity_boot_secs: u64,
    daemon_remaining_secs: Option<u64>,
    last_sleep_skew_ms: Option<u64>,
    last_watchdog_check: Instant,
    my_uid: u32,
    should_quit: bool,
}

fn current_boot_secs() -> u64 {
    boottime_secs().unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    })
}

impl App {
    fn new(cfg: TuiConfig) -> Result<Self> {
        let header_preview = read_header_from_disk(&cfg.vault_path, true)?;
        let my_uid = unsafe { libc::geteuid() };
        let mut app = Self {
            cfg,
            header_preview,
            mode: Mode::Locked {
                passphrase_input: Zeroizing::new(String::with_capacity(256)),
                error_msg: None,
            },
            backend: None,
            vault: None,
            search_query: Zeroizing::new(String::with_capacity(128)),
            list_state: ListState::default(),
            reveal_password: false,
            status_toast: None,
            last_activity_boot_secs: current_boot_secs(),
            daemon_remaining_secs: None,
            last_sleep_skew_ms: boottime_monotonic_skew_ms(),
            last_watchdog_check: Instant::now(),
            my_uid,
            should_quit: false,
        };

        // If the auto-lock daemon is already unlocked for this vault, attach seamlessly
        // and read real mlock telemetry from DaemonStatus.
        let client = DaemonClient::new(app.cfg.socket_path.clone());
        if let Ok(st) = client.status() {
            if st.unlocked {
                if let Ok((vault, rev)) = client.load_vault(&app.cfg.vault_path) {
                    app.backend = Some(SessionBackend::Daemon {
                        revision: Some(rev),
                        mlocked: st.mlocked,
                    });
                    app.daemon_remaining_secs = Some(st.remaining_secs);
                    app.vault = Some(vault);
                    app.mode = Mode::Normal;
                    if app.vault.as_ref().is_some_and(|v| !v.entries.is_empty()) {
                        app.list_state.select(Some(0));
                    }
                    app.set_toast(
                        ToastLevel::Ok,
                        if st.mlocked {
                            "Attached to unlocked omavault daemon (mlock ACTIVE)"
                        } else {
                            "Attached to unlocked omavault daemon (mlock unavailable)"
                        },
                    );
                }
            }
        }

        Ok(app)
    }

    fn set_toast(&mut self, level: ToastLevel, msg: impl Into<String>) {
        self.status_toast = Some((level, msg.into(), Instant::now()));
    }

    /// Lock vault locally (and optionally tell daemon to lock as well).
    fn lock_vault(&mut self, reason: &str, notify_daemon: bool) {
        let mut daemon_warn: Option<String> = None;
        if notify_daemon && matches!(self.backend, Some(SessionBackend::Daemon { .. })) {
            let client = DaemonClient::new(self.cfg.socket_path.clone());
            if let Err(e) = client.lock() {
                daemon_warn = Some(format!(
                    "Local TUI locked ({reason}), WARNING: failed to lock daemon: {e}"
                ));
            }
        }
        // Dropping `vault` and `backend` triggers `ZeroizeOnDrop` on all passwords and
        // volatile-zeroize + munlock + munmap on `LockedKey<32>`.
        self.vault = None;
        self.backend = None;
        self.daemon_remaining_secs = None;
        self.reveal_password = false;
        self.search_query.zeroize();
        self.status_toast = None;
        clear_clipboard_best_effort();
        self.mode = Mode::Locked {
            passphrase_input: Zeroizing::new(String::with_capacity(256)),
            error_msg: Some(daemon_warn.unwrap_or_else(|| format!("Vault locked ({reason})"))),
        };
    }

    fn start_unlock(&mut self, passphrase: Zeroizing<String>) {
        let socket_path = self.cfg.socket_path.clone();
        let vault_path = self.cfg.vault_path.clone();
        let keyfile_path = self.cfg.keyfile_path.clone();
        let fido2_device = self.cfg.fido2_device.clone();
        let requires_fido2 = self.header_preview.requires_fido2();

        let (tx, rx) = mpsc::channel();
        self.mode = Mode::Unlocking {
            started_at: Instant::now(),
            requires_fido2,
            rx,
        };

        thread::spawn(move || {
            let client = DaemonClient::new(socket_path);
            if client.status().is_ok() {
                let outcome = match client.unlock(&vault_path, passphrase, keyfile_path, fido2_device)
                {
                    Ok(()) => {
                        let mlocked = client.status().map(|s| s.mlocked).unwrap_or(false);
                        match client.load_vault(&vault_path) {
                            Ok((vault, revision)) => UnlockOutcome::Daemon {
                                vault,
                                revision,
                                mlocked,
                            },
                            Err(e) => UnlockOutcome::Error(e.to_string()),
                        }
                    }
                    Err(e) => UnlockOutcome::Error(e.to_string()),
                };
                let _ = tx.send(outcome);
                return;
            }

            // Standalone unlock (no daemon running): resolve MasterKey directly into LockedKey<32>.
            let result = (|| -> Result<(LockedKey<32>, VaultHeader, Vault)> {
                let header = read_header_from_disk(&vault_path, true)?;
                let kf_digest = if header.requires_keyfile() {
                    let path = keyfile_path.as_deref().ok_or(VaultError::KeyfileRequired)?;
                    Some(hash_keyfile(path)?)
                } else {
                    None
                };
                let res = resolve_master_key(
                    &header,
                    passphrase.as_bytes(),
                    kf_digest.as_deref(),
                    &LibFido2Cli,
                    fido2_device.as_deref(),
                    true,
                )?;
                let (verified_header, vault) =
                    load_vault_from_disk(&vault_path, &res.master_key, true)?;
                Ok((res.master_key, verified_header, vault))
            })();

            let outcome = match result {
                Ok((master_key, header, vault)) => UnlockOutcome::Standalone {
                    master_key,
                    header: Box::new(header),
                    vault,
                },
                Err(e) => UnlockOutcome::Error(e.to_string()),
            };
            let _ = tx.send(outcome);
        });
    }

    fn finish_unlock(&mut self, outcome: UnlockOutcome) {
        match outcome {
            UnlockOutcome::Daemon {
                vault,
                revision,
                mlocked,
            } => {
                self.backend = Some(SessionBackend::Daemon {
                    revision: Some(revision),
                    mlocked,
                });
                self.vault = Some(vault);
                self.mode = Mode::Normal;
                self.last_activity_boot_secs = current_boot_secs();
                if self.vault.as_ref().is_some_and(|v| !v.entries.is_empty()) {
                    self.list_state.select(Some(0));
                }
                self.set_toast(
                    ToastLevel::Ok,
                    if mlocked {
                        "Unlocked via omavault daemon (mlock ACTIVE)"
                    } else {
                        "Unlocked via omavault daemon (mlock unavailable)"
                    },
                );
            }
            UnlockOutcome::Standalone {
                master_key,
                header,
                vault,
            } => {
                let mlock_msg = if master_key.is_mlocked() {
                    "Unlocked (standalone · mlock ACTIVE)"
                } else {
                    "Unlocked (standalone · mlock unavailable)"
                };
                self.backend = Some(SessionBackend::Standalone { master_key, header });
                self.vault = Some(vault);
                self.mode = Mode::Normal;
                self.last_activity_boot_secs = current_boot_secs();
                if self.vault.as_ref().is_some_and(|v| !v.entries.is_empty()) {
                    self.list_state.select(Some(0));
                }
                self.set_toast(ToastLevel::Ok, mlock_msg);
            }
            UnlockOutcome::Error(err) => {
                self.mode = Mode::Locked {
                    passphrase_input: Zeroizing::new(String::with_capacity(256)),
                    error_msg: Some(err),
                };
            }
        }
    }

    /// Persist a staged vault snapshot cleanly; only commit to `self.vault` if disk/daemon write succeeds.
    fn persist_staged_vault(&mut self, staged: Vault) -> Result<()> {
        match self.backend.as_mut() {
            Some(SessionBackend::Daemon { revision, .. }) => {
                let client = DaemonClient::new(self.cfg.socket_path.clone());
                client.save_vault(&self.cfg.vault_path, &staged, revision.clone())?;
                // Refresh latest revision token after save.
                if let Ok((_, new_rev)) = client.load_vault(&self.cfg.vault_path) {
                    *revision = Some(new_rev);
                }
            }
            Some(SessionBackend::Standalone { master_key, header }) => {
                let expected_rev = header_revision(header);
                save_vault_to_disk_checked(
                    &self.cfg.vault_path,
                    master_key,
                    header,
                    &staged,
                    Some(&expected_rev),
                    true,
                    true,
                )?;
            }
            None => return Err(VaultError::Daemon("vault not unlocked".into())),
        }
        self.vault = Some(staged);
        Ok(())
    }

    fn filtered_indices(&self) -> Vec<usize> {
        let Some(vault) = &self.vault else {
            return Vec::new();
        };
        vault
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.matches_query(&self.search_query))
            .map(|(i, _)| i)
            .collect()
    }

    fn selected_entry(&self) -> Option<&Entry> {
        let vault = self.vault.as_ref()?;
        let indices = self.filtered_indices();
        let sel = self.list_state.selected()?;
        let &real_idx = indices.get(sel)?;
        vault.entries.get(real_idx)
    }

    fn clamp_selection(&mut self) {
        let len = self.filtered_indices().len();
        if len == 0 {
            self.list_state.select(None);
        } else {
            let idx = self.list_state.selected().unwrap_or(0).min(len - 1);
            self.list_state.select(Some(idx));
        }
    }

    fn copy_to_secret_clipboard(&mut self, label: &str, secret: &str) {
        if secret.is_empty() {
            self.set_toast(ToastLevel::Warn, format!("{label} is empty — nothing copied"));
            return;
        }
        let opts = ClipboardOptions {
            timeout_secs: self.cfg.clipboard_timeout_secs,
            paste_once: self.cfg.paste_once,
        };
        match copy_secret(secret, opts) {
            Ok(()) => {
                let mode_str = if opts.paste_once {
                    "paste-once".to_string()
                } else {
                    format!("clears in {}s", opts.timeout_secs)
                };
                self.set_toast(
                    ToastLevel::Ok,
                    format!("Copied {label} (Wayland secret-tagged · {mode_str})"),
                );
            }
            Err(e) => self.set_toast(ToastLevel::Error, format!("Clipboard unavailable: {e}")),
        }
    }

    fn is_mlocked(&self) -> bool {
        match &self.backend {
            Some(SessionBackend::Standalone { master_key, .. }) => master_key.is_mlocked(),
            Some(SessionBackend::Daemon { mlocked, .. }) => *mlocked,
            None => false,
        }
    }

    fn remaining_lock_secs(&self) -> u64 {
        let timeout = self.cfg.idle_timeout_secs.max(10);
        let elapsed = current_boot_secs().saturating_sub(self.last_activity_boot_secs);
        let local = timeout.saturating_sub(elapsed);
        match self.daemon_remaining_secs {
            Some(d) => local.min(d),
            None => local,
        }
    }

    /// Periodic security watchdog executed every tick:
    /// 1. Suspend/lid-close detection (`CLOCK_BOOTTIME - CLOCK_MONOTONIC` skew >= 2s)
    /// 2. Omarchy / Hyprland / Wayland screen-lock detection (active even during `Mode::Unlocking`)
    /// 3. `CLOCK_BOOTTIME` inactivity timeout (counts suspend time!)
    /// 4. Daemon lock synchronization (immediately wipes TUI RAM if `omavaultd` locked!)
    fn on_tick(&mut self) {
        if let Some((_, _, ts)) = &self.status_toast {
            if ts.elapsed() > Duration::from_secs(6) {
                self.status_toast = None;
            }
        }

        if matches!(self.mode, Mode::Unlocking { .. }) {
            // Check suspend & screen lock even while an unlock is in flight so a lid close
            // or lock screen during YubiKey wait cancels the unlock cleanly!
            let current_skew = boottime_monotonic_skew_ms();
            let slept = match (self.last_sleep_skew_ms, current_skew) {
                (Some(prev), Some(curr)) => curr.saturating_sub(prev) >= SUSPEND_SKEW_THRESHOLD_MS,
                _ => false,
            };
            self.last_sleep_skew_ms = current_skew;
            if slept || is_screen_locker_active(self.my_uid) {
                let reason = if slept {
                    "unlock cancelled: system suspend/resume detected"
                } else {
                    "unlock cancelled: screen lock detected"
                };
                let client = DaemonClient::new(self.cfg.socket_path.clone());
                let _ = client.lock();
                self.mode = Mode::Locked {
                    passphrase_input: Zeroizing::new(String::with_capacity(256)),
                    error_msg: Some(reason.into()),
                };
                return;
            }

            if let Mode::Unlocking { rx, .. } = &self.mode {
                match rx.try_recv() {
                    Ok(outcome) => {
                        self.finish_unlock(outcome);
                        return;
                    }
                    Err(mpsc::TryRecvError::Empty) => return,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        self.finish_unlock(UnlockOutcome::Error(
                            "unlock worker exited unexpectedly".into(),
                        ));
                        return;
                    }
                }
            }
        }

        if matches!(self.mode, Mode::Locked { .. }) {
            self.last_sleep_skew_ms = boottime_monotonic_skew_ms();
            return;
        }

        if self.last_watchdog_check.elapsed() < Duration::from_secs(1) {
            return;
        }
        self.last_watchdog_check = Instant::now();

        // 1. Check system suspend/resume skew.
        let current_skew = boottime_monotonic_skew_ms();
        if let (Some(prev), Some(curr)) = (self.last_sleep_skew_ms, current_skew) {
            if curr.saturating_sub(prev) >= SUSPEND_SKEW_THRESHOLD_MS {
                self.last_sleep_skew_ms = current_skew;
                self.lock_vault("system suspend/resume detected", true);
                return;
            }
        }
        self.last_sleep_skew_ms = current_skew;

        // 2. Check active Omarchy / Hyprland / Wayland screen lock (even in standalone mode!).
        if is_screen_locker_active(self.my_uid) {
            self.lock_vault("screen lock detected", true);
            return;
        }

        // 3. Check CLOCK_BOOTTIME inactivity timeout.
        let timeout = self.cfg.idle_timeout_secs.max(10);
        if current_boot_secs().saturating_sub(self.last_activity_boot_secs) >= timeout {
            self.lock_vault("inactivity timeout", true);
            return;
        }

        // 4. Synchronize with omavaultd if running in daemon-backed mode.
        if let Some(SessionBackend::Daemon { mlocked, .. }) = self.backend.as_mut() {
            let client = DaemonClient::new(self.cfg.socket_path.clone());
            match client.status() {
                Ok(st) if st.unlocked => {
                    *mlocked = st.mlocked;
                    self.daemon_remaining_secs = Some(st.remaining_secs);
                }
                Ok(st) => {
                    let reason = st
                        .last_lock_reason
                        .unwrap_or_else(|| "daemon locked".to_string());
                    self.lock_vault(&reason, false);
                }
                Err(_) => {
                    self.lock_vault("daemon disconnected", false);
                }
            }
        }
    }

    fn handle_key(&mut self, key: KeyEvent) {
        self.last_activity_boot_secs = current_boot_secs();

        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.should_quit = true;
            return;
        }

        match &mut self.mode {
            Mode::Locked {
                passphrase_input,
                error_msg,
            } => match key.code {
                KeyCode::Esc => self.should_quit = true,
                KeyCode::Enter => {
                    let entered = std::mem::replace(
                        passphrase_input,
                        Zeroizing::new(String::with_capacity(256)),
                    );
                    *error_msg = None;
                    self.start_unlock(entered);
                }
                KeyCode::Backspace => {
                    passphrase_input.pop();
                }
                KeyCode::Char(c) => {
                    passphrase_input.push(c);
                }
                _ => {}
            },
            Mode::Unlocking { .. } => {
                if key.code == KeyCode::Esc {
                    self.should_quit = true;
                }
            }
            Mode::Search => match key.code {
                KeyCode::Esc => {
                    self.search_query.zeroize();
                    self.clamp_selection();
                    self.mode = Mode::Normal;
                }
                KeyCode::Enter => {
                    self.mode = Mode::Normal;
                }
                KeyCode::Backspace => {
                    self.search_query.pop();
                    self.clamp_selection();
                }
                KeyCode::Char(c) => {
                    self.search_query.push(c);
                    self.clamp_selection();
                }
                _ => {}
            },
            Mode::Help | Mode::Audit(_) => match key.code {
                KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('?') | KeyCode::Enter => {
                    self.mode = Mode::Normal;
                }
                _ => {}
            },
            Mode::ConfirmDelete { entry_name } => {
                let name = entry_name.clone();
                match key.code {
                    KeyCode::Char('y') | KeyCode::Char('Y') => {
                        if let Some(current) = &self.vault {
                            let mut staged = current.clone();
                            match staged.remove_by_name(&name) {
                                Ok(_) => match self.persist_staged_vault(staged) {
                                    Ok(()) => self.set_toast(
                                        ToastLevel::Ok,
                                        format!("Deleted entry '{name}'"),
                                    ),
                                    Err(e) => self.set_toast(
                                        ToastLevel::Error,
                                        format!("Save failed (rolled back): {e}"),
                                    ),
                                },
                                Err(e) => self.set_toast(ToastLevel::Error, e.to_string()),
                            }
                        }
                        self.clamp_selection();
                        self.mode = Mode::Normal;
                    }
                    KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                        self.mode = Mode::Normal;
                    }
                    _ => {}
                }
            }
            Mode::Generator(gen_state) => match key.code {
                KeyCode::Esc | KeyCode::Char('q') => {
                    self.mode = Mode::Normal;
                }
                KeyCode::Char(' ') | KeyCode::Char('r') => {
                    gen_state.regenerate();
                }
                KeyCode::Char('m') => {
                    gen_state.passphrase_mode = !gen_state.passphrase_mode;
                    gen_state.regenerate();
                }
                KeyCode::Char('s') if !gen_state.passphrase_mode => {
                    gen_state.symbols = !gen_state.symbols;
                    gen_state.regenerate();
                }
                KeyCode::Char('+') | KeyCode::Char('=') | KeyCode::Right => {
                    if gen_state.passphrase_mode {
                        gen_state.words = (gen_state.words + 1).min(16);
                    } else {
                        gen_state.length = (gen_state.length + 2).min(64);
                    }
                    gen_state.regenerate();
                }
                KeyCode::Char('-') | KeyCode::Left => {
                    if gen_state.passphrase_mode {
                        gen_state.words = gen_state.words.saturating_sub(1).max(6);
                    } else {
                        gen_state.length = gen_state.length.saturating_sub(2).max(12);
                    }
                    gen_state.regenerate();
                }
                KeyCode::Char('y') | KeyCode::Enter => {
                    let secret = gen_state.preview.clone();
                    self.copy_to_secret_clipboard("generated password", &secret);
                }
                _ => {}
            },
            Mode::Editor(form) => {
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('g') {
                    if let Ok(pw) = generate_password(&PasswordOptions::default()) {
                        form.password = pw;
                        form.error = None;
                    }
                    return;
                }
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('r') {
                    form.reveal_secrets = !form.reveal_secrets;
                    return;
                }
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('s') {
                    self.commit_editor_form();
                    return;
                }
                match key.code {
                    KeyCode::Esc => {
                        self.mode = Mode::Normal;
                    }
                    KeyCode::Tab | KeyCode::Down => {
                        form.active_field = (form.active_field + 1) % EntryForm::FIELD_COUNT;
                    }
                    KeyCode::BackTab | KeyCode::Up => {
                        form.active_field =
                            (form.active_field + EntryForm::FIELD_COUNT - 1) % EntryForm::FIELD_COUNT;
                    }
                    KeyCode::Enter => {
                        if form.active_field + 1 < EntryForm::FIELD_COUNT {
                            form.active_field += 1;
                        } else {
                            self.commit_editor_form();
                        }
                    }
                    KeyCode::Backspace => {
                        form.current_mut().pop();
                    }
                    KeyCode::Char(c) => {
                        form.current_mut().push(c);
                    }
                    _ => {}
                }
            }
            Mode::Normal => self.handle_normal_key(key),
        }
    }

    fn handle_normal_key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('l') {
            self.lock_vault("manual lock", true);
            return;
        }
        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('L') => self.lock_vault("manual lock", true),
            KeyCode::Char('/') => self.mode = Mode::Search,
            KeyCode::Char('?') => self.mode = Mode::Help,
            KeyCode::Char('g') => self.mode = Mode::Generator(GenModalState::new()),
            KeyCode::Char('A') => {
                if let Some(vault) = &self.vault {
                    match run_audit(vault) {
                        Ok(report) => self.mode = Mode::Audit(report),
                        Err(e) => self.set_toast(ToastLevel::Error, format!("Audit failed: {e}")),
                    }
                }
            }
            KeyCode::Char('r') => {
                self.reveal_password = !self.reveal_password;
            }
            KeyCode::Char('j') | KeyCode::Down => {
                let len = self.filtered_indices().len();
                if len > 0 {
                    let next = match self.list_state.selected() {
                        Some(i) => (i + 1) % len,
                        None => 0,
                    };
                    self.list_state.select(Some(next));
                    self.reveal_password = false;
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                let len = self.filtered_indices().len();
                if len > 0 {
                    let prev = match self.list_state.selected() {
                        Some(0) | None => len - 1,
                        Some(i) => i - 1,
                    };
                    self.list_state.select(Some(prev));
                    self.reveal_password = false;
                }
            }
            KeyCode::Char('y') => {
                if let Some(entry) = self.selected_entry().cloned() {
                    self.copy_to_secret_clipboard(
                        &format!("'{}' password", entry.name),
                        &entry.password,
                    );
                }
            }
            KeyCode::Char('u') => {
                if let Some(entry) = self.selected_entry().cloned() {
                    if entry.username.is_empty() {
                        self.set_toast(ToastLevel::Warn, "Entry has no username");
                    } else {
                        self.copy_to_secret_clipboard(
                            &format!("'{}' username", entry.name),
                            &entry.username,
                        );
                    }
                }
            }
            KeyCode::Char('t') => {
                if let Some(entry) = self.selected_entry().cloned() {
                    if let Some(totp) = &entry.totp {
                        match totp.generate_now() {
                            Ok(code) => {
                                self.copy_to_secret_clipboard(
                                    &format!("'{}' TOTP ({}s left)", entry.name, code.remaining_secs),
                                    &code.code,
                                );
                            }
                            Err(e) => self.set_toast(ToastLevel::Error, format!("TOTP error: {e}")),
                        }
                    } else {
                        self.set_toast(ToastLevel::Warn, "Entry has no TOTP configured");
                    }
                }
            }
            KeyCode::Char('a') => {
                self.mode = Mode::Editor(EntryForm::new_blank());
            }
            KeyCode::Char('e') => {
                if let Some(entry) = self.selected_entry().cloned() {
                    self.mode = Mode::Editor(EntryForm::from_entry(&entry));
                }
            }
            KeyCode::Char('d') => {
                if let Some(entry) = self.selected_entry() {
                    self.mode = Mode::ConfirmDelete {
                        entry_name: entry.name.clone(),
                    };
                }
            }
            KeyCode::Esc if !self.search_query.is_empty() => {
                self.search_query.zeroize();
                self.clamp_selection();
            }
            _ => {}
        }
    }

    fn commit_editor_form(&mut self) {
        let Mode::Editor(form) = &mut self.mode else {
            return;
        };

        let name = form.name.trim().to_string();
        if name.is_empty() {
            form.error = Some("Entry name cannot be empty".into());
            return;
        }

        // Preserve original TotpConfig (algorithm, digits, period, issuer) unless modified!
        let totp_cfg = if !form.totp_modified {
            form.original_totp.clone()
        } else if form.totp.trim().is_empty() {
            None
        } else {
            match TotpConfig::parse(form.totp.trim()) {
                Ok(cfg) => Some(cfg),
                Err(e) => {
                    form.error = Some(e.to_string());
                    return;
                }
            }
        };

        let tags: Vec<String> = form
            .tags
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let editing = form.editing_original_name.clone();
        let username = form.username.trim().to_string();
        let password = form.password.clone();
        let url = form.url.trim().to_string();
        let notes = form.notes.clone();

        let Some(current_vault) = &self.vault else {
            return;
        };
        let mut staged = current_vault.clone();

        let mutate_res = if let Some(orig) = editing {
            staged.update_entry(&orig, &name, |entry| {
                entry.set_username(username);
                entry.set_password(password);
                entry.set_url(url);
                entry.tags = tags;
                entry.totp = totp_cfg;
                entry.set_notes(notes);
            })
        } else {
            let mut entry = Entry::new(name.clone(), username, password.to_string());
            entry.set_url(url);
            entry.tags = tags;
            entry.totp = totp_cfg;
            entry.set_notes(notes);
            staged.add_entry(entry)
        };

        if let Err(e) = mutate_res {
            if let Mode::Editor(f) = &mut self.mode {
                f.error = Some(e.to_string());
            }
            return;
        }

        match self.persist_staged_vault(staged) {
            Ok(()) => {
                self.clamp_selection();
                self.mode = Mode::Normal;
                self.set_toast(
                    ToastLevel::Ok,
                    format!("Encrypted & saved '{name}' (fresh key + nonce)"),
                );
            }
            Err(e) => {
                if let Mode::Editor(f) = &mut self.mode {
                    f.error = Some(format!("Failed saving vault: {e}"));
                }
            }
        }
    }
}

/// RAII terminal + clipboard guard guaranteeing panic-safe cleanup on unwind, error, or signal.
struct TuiGuard;

impl Drop for TuiGuard {
    fn drop(&mut self) {
        clear_clipboard_best_effort();
        let _ = disable_raw_mode();
        let mut stdout = io::stdout();
        let _ = execute!(stdout, LeaveAlternateScreen, crossterm::cursor::Show);
    }
}

/// Launch the interactive Omarchy Ratatui password manager.
pub fn run_tui(cfg: TuiConfig) -> Result<()> {
    let mut app = App::new(cfg)?;
    let signal_quit = Arc::new(AtomicBool::new(false));
    let _ = signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&signal_quit));
    let _ = signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&signal_quit));
    let _ = signal_hook::flag::register(signal_hook::consts::SIGHUP, Arc::clone(&signal_quit));

    enable_raw_mode().map_err(VaultError::Io)?;
    let _tui_guard = TuiGuard;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).map_err(VaultError::Io)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(VaultError::Io)?;

    let run_res = (|| -> Result<()> {
        loop {
            terminal.draw(|f| draw_ui(f, &mut app)).map_err(VaultError::Io)?;

            let poll_ms = if matches!(app.mode, Mode::Unlocking { .. }) {
                100
            } else {
                250
            };
            if event::poll(Duration::from_millis(poll_ms)).map_err(VaultError::Io)? {
                if let Event::Key(key) = event::read().map_err(VaultError::Io)? {
                    if key.kind == KeyEventKind::Press {
                        app.handle_key(key);
                    }
                }
            }
            app.on_tick();

            if app.should_quit || signal_quit.load(Ordering::SeqCst) {
                break;
            }
        }
        Ok(())
    })();

    // If the user cancelled/quit while an unlock was still in flight, immediately signal `omavaultd`
    // to bump `lock_epoch` so the background unlock cannot silently leave the daemon unlocked!
    if matches!(app.mode, Mode::Unlocking { .. }) {
        let client = DaemonClient::new(app.cfg.socket_path.clone());
        let _ = client.lock();
    }

    // Overwrite ratatui screen buffer and wipe RAM before TuiGuard restores terminal & clears clipboard.
    let _ = terminal.clear();
    app.vault = None;
    app.backend = None;
    app.search_query.zeroize();

    run_res
}

/// Sanitize untrusted entry strings for single-line TUI display (strips ANSI/OSC/BiDi/zero-width).
fn sanitize_display(s: &str) -> String {
    sanitize_single_line(s)
}

fn draw_ui(f: &mut Frame, app: &mut App) {
    let area = f.area();
    let bg_block = Block::default().style(Style::default().bg(theme::BG_PRIMARY).fg(theme::FG_PRIMARY));
    f.render_widget(bg_block, area);

    match &app.mode {
        Mode::Locked {
            passphrase_input,
            error_msg,
        } => {
            draw_locked_screen(
                f,
                area,
                &app.cfg.vault_path,
                &app.header_preview,
                passphrase_input.chars().count(),
                error_msg.as_deref(),
                None,
                &app.cfg.hardening,
            );
            return;
        }
        Mode::Unlocking {
            started_at,
            requires_fido2,
            ..
        } => {
            draw_locked_screen(
                f,
                area,
                &app.cfg.vault_path,
                &app.header_preview,
                0,
                None,
                Some((*started_at, *requires_fido2)),
                &app.cfg.hardening,
            );
            return;
        }
        _ => {}
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(2),
        ])
        .split(area);

    draw_top_bar(f, chunks[0], app);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(36), Constraint::Percentage(64)])
        .split(chunks[1]);

    draw_entry_list(f, body[0], app);
    draw_entry_detail(f, body[1], app);
    draw_bottom_bar(f, chunks[2], app);

    match &app.mode {
        Mode::Editor(form) => draw_editor_modal(f, area, form),
        Mode::Generator(gen) => draw_generator_modal(f, area, gen),
        Mode::Audit(report) => draw_audit_modal(f, area, report),
        Mode::ConfirmDelete { entry_name } => draw_confirm_delete(f, area, entry_name),
        Mode::Help => draw_help_modal(f, area),
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn draw_locked_screen(
    f: &mut Frame,
    area: Rect,
    vault_path: &Path,
    header: &VaultHeader,
    input_len: usize,
    error_msg: Option<&str>,
    unlocking: Option<(Instant, bool)>,
    hardening: &HardeningStatus,
) {
    let box_area = centered_rect(64, 52, area);
    f.render_widget(Clear, box_area);

    let mut factors: Vec<String> = vec!["Passphrase".to_string()];
    if header.requires_keyfile() {
        factors.push("Keyfile".to_string());
    }
    if header.version == VAULT_VERSION_V2 && !header.fido2_slots.is_empty() {
        let count = header.fido2_slots.len();
        let noun = if count == 1 { "key" } else { "keys" };
        factors.push(format!(
            "FIDO2 ({count} {noun}: {})",
            header.fido2_labels().join(", ")
        ));
    } else if header.requires_fido2() {
        factors.push("FIDO2 Hardware Touch".to_string());
    }

    let masked = if input_len == 0 {
        String::new()
    } else {
        "•".repeat(input_len.min(32))
    };
    let mut lines = vec![
        Line::from(Span::styled(
            "  OMAVAULT  ·  HARDENED PASSWORD VAULT",
            theme::title_style(),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Vault:   ", theme::muted_style()),
            Span::raw(sanitize_display(&vault_path.display().to_string())),
        ]),
        Line::from(vec![
            Span::styled("  Crypto:  ", theme::muted_style()),
            Span::styled(
                format!(
                    "OMAV v{} · Argon2id ({} MiB, t={}, p={}) + HKDF-SHA512 + XChaCha20-Poly1305",
                    header.version,
                    header.kdf_params.mem_kib / 1024,
                    header.kdf_params.time_cost,
                    header.kdf_params.parallelism
                ),
                Style::default().fg(theme::ACCENT_GREEN),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Factors: ", theme::muted_style()),
            Span::styled(
                factors.join(" + "),
                Style::default().fg(theme::ACCENT_MAGENTA),
            ),
        ]),
        Line::from(vec![
            Span::styled("  OS Lock: ", theme::muted_style()),
            Span::styled(hardening.summary(), theme::muted_style()),
        ]),
        Line::from(""),
    ];

    if let Some((started_at, requires_fido2)) = unlocking {
        const SPINNER: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        let frame = ((started_at.elapsed().as_millis() / 100) as usize) % SPINNER.len();
        let spin = SPINNER[frame];
        let msg = if requires_fido2 {
            format!("  {spin} Waiting for YubiKey touch… (plug in & tap when it blinks)")
        } else {
            format!("  {spin} Unlocking vault (Argon2id)…")
        };
        lines.push(Line::from(Span::styled(
            msg,
            Style::default()
                .fg(theme::ACCENT_CYAN)
                .add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  [Esc] Cancel & Quit",
            theme::muted_style(),
        )));
    } else {
        lines.push(Line::from(Span::styled(
            "  Master Passphrase:",
            Style::default()
                .fg(theme::ACCENT_CYAN)
                .add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(Span::styled(
            format!("  > {masked}_"),
            Style::default()
                .fg(theme::FG_PRIMARY)
                .add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(""));

        if let Some(err) = error_msg {
            lines.push(Line::from(Span::styled(
                format!("  ! {}", sanitize_display(err)),
                theme::danger_style(),
            )));
        } else {
            lines.push(Line::from(Span::styled(
                "  [Enter] Unlock   [Esc] Quit",
                theme::muted_style(),
            )));
        }
    }

    let widget = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme::border_style(true))
                .style(Style::default().bg(theme::BG_PRIMARY))
                .title(Span::styled(" 🔒 VAULT LOCKED ", theme::title_style())),
        )
        .wrap(Wrap { trim: false });

    f.render_widget(widget, box_area);
}

fn draw_top_bar(f: &mut Frame, area: Rect, app: &App) {
    let search_active = matches!(app.mode, Mode::Search);
    let count = app.vault.as_ref().map(|v| v.entries.len()).unwrap_or(0);
    let rem = app.remaining_lock_secs();
    let mlock_badge = if app.is_mlocked() {
        Span::styled(" mlock:ON ", theme::ok_style())
    } else {
        Span::styled(" mlock:OFF ", theme::warn_style())
    };
    let search_text = if app.search_query.is_empty() && !search_active {
        "Press / to search...".to_string()
    } else if search_active {
        format!("{}_", sanitize_display(&app.search_query))
    } else {
        sanitize_display(&app.search_query)
    };

    let line = Line::from(vec![
        Span::styled(" OMAVAULT ", theme::title_style()),
        Span::styled("│ ", theme::muted_style()),
        Span::styled(
            format!("Search: {search_text}  "),
            if search_active {
                Style::default().fg(theme::ACCENT_CYAN).add_modifier(Modifier::BOLD)
            } else {
                theme::muted_style()
            },
        ),
        Span::styled("│ ", theme::muted_style()),
        Span::raw(format!("{count} entries  ")),
        mlock_badge,
        Span::styled(
            format!(" │ auto-lock:{:02}:{:02}", rem / 60, rem % 60),
            theme::muted_style(),
        ),
    ]);

    let bar = Paragraph::new(line).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(theme::border_style(search_active)),
    );
    f.render_widget(bar, area);
}

fn draw_entry_list(f: &mut Frame, area: Rect, app: &mut App) {
    let indices = app.filtered_indices();
    let items: Vec<ListItem> = match &app.vault {
        Some(vault) => indices
            .iter()
            .map(|&idx| {
                let entry = &vault.entries[idx];
                let mut spans = vec![Span::raw(format!(" {}", sanitize_display(&entry.name)))];
                if entry.totp.is_some() {
                    spans.push(Span::styled(" [2FA]", Style::default().fg(theme::ACCENT_GREEN)));
                }
                if entry.password.is_empty() || estimate_entropy_bits(&entry.password) < 60.0 {
                    spans.push(Span::styled(" [!]", theme::warn_style()));
                }
                ListItem::new(Line::from(spans))
            })
            .collect(),
        None => Vec::new(),
    };

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme::border_style(matches!(app.mode, Mode::Normal)))
                .title(Span::styled(" Entries ", theme::title_style())),
        )
        .highlight_style(theme::selected_style())
        .highlight_symbol("▸");

    f.render_stateful_widget(list, area, &mut app.list_state);
}

fn draw_entry_detail(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::border_style(false))
        .title(Span::styled(" Inspector ", theme::title_style()));

    let Some(entry) = app.selected_entry() else {
        let empty = Paragraph::new("\n  No entry selected.\n  Press [a] to add your first secret.")
            .style(theme::muted_style())
            .block(block);
        f.render_widget(empty, area);
        return;
    };

    let inner = block.inner(area);
    f.render_widget(block, area);

    let sections = if entry.totp.is_some() {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(9), Constraint::Length(5)])
            .split(inner)
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(9), Constraint::Length(0)])
            .split(inner)
    };

    let bits = estimate_entropy_bits(&entry.password);
    let label = strength_label(bits);
    let pw_display = if app.reveal_password {
        sanitize_display(&entry.password)
    } else if entry.password.is_empty() {
        "(empty)".to_string()
    } else {
        "•".repeat(entry.password.chars().count().min(32))
    };

    let strength_style = if bits < 60.0 {
        theme::danger_style()
    } else if bits < 80.0 {
        theme::warn_style()
    } else {
        theme::ok_style()
    };

    let mut lines = vec![
        Line::from(vec![
            Span::styled(" Name:     ", theme::muted_style()),
            Span::styled(
                sanitize_display(&entry.name),
                Style::default().fg(theme::ACCENT_CYAN).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled(" Username: ", theme::muted_style()),
            Span::raw(if entry.username.is_empty() {
                "-".to_string()
            } else {
                sanitize_display(&entry.username)
            }),
        ]),
        Line::from(vec![
            Span::styled(" Password: ", theme::muted_style()),
            Span::styled(pw_display, Style::default().fg(theme::FG_PRIMARY)),
            Span::raw("  "),
            Span::styled(format!("[{bits:.0} bits · {label}]"), strength_style),
        ]),
        Line::from(vec![
            Span::styled(" URL:      ", theme::muted_style()),
            Span::styled(
                if entry.url.is_empty() {
                    "-".to_string()
                } else {
                    sanitize_display(&entry.url)
                },
                Style::default().fg(theme::ACCENT_BLUE),
            ),
        ]),
        Line::from(vec![
            Span::styled(" Tags:     ", theme::muted_style()),
            Span::styled(
                if entry.tags.is_empty() {
                    "-".to_string()
                } else {
                    sanitize_display(&entry.tags.join(", "))
                },
                Style::default().fg(theme::ACCENT_MAGENTA),
            ),
        ]),
        Line::from(vec![
            Span::styled(" Updated:  ", theme::muted_style()),
            Span::raw(entry.updated_at.format("%Y-%m-%d %H:%M UTC").to_string()),
            Span::styled(
                format!("  (history: {})", entry.password_history.len()),
                theme::muted_style(),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(" Notes:", theme::muted_style())),
        Line::from(format!(
            " {}",
            if entry.notes.is_empty() {
                "(none)".to_string()
            } else if app.reveal_password {
                sanitize_multiline(&entry.notes)
            } else {
                "•••••••••••• (press [r] to reveal)".to_string()
            }
        )),
    ];

    if !entry.custom_fields.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(" Custom Fields:", theme::muted_style())));
        for cf in &entry.custom_fields {
            let val = if cf.secret && !app.reveal_password {
                "••••••••".to_string()
            } else {
                sanitize_display(&cf.value)
            };
            lines.push(Line::from(format!(
                "  {}: {}",
                sanitize_display(&cf.label),
                val
            )));
        }
    }

    let details = Paragraph::new(lines).wrap(Wrap { trim: false });
    f.render_widget(details, sections[0]);

    if let Some(totp) = &entry.totp {
        if let Ok(code) = totp.generate_now() {
            let formatted = if code.code.len() == 6 {
                format!("{} {}", &code.code[..3], &code.code[3..])
            } else {
                code.code.clone()
            };
            let ratio = (code.remaining_secs as f64 / code.period.max(1) as f64).clamp(0.0, 1.0);
            let gauge_color = if code.remaining_secs <= 5 {
                theme::ACCENT_RED
            } else {
                theme::ACCENT_GREEN
            };
            let gauge = Gauge::default()
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(gauge_color))
                        .title(Span::styled(
                            format!(" 2FA TOTP ({}) — press [t] to copy ", totp.algorithm),
                            Style::default().fg(gauge_color).add_modifier(Modifier::BOLD),
                        )),
                )
                .gauge_style(Style::default().fg(gauge_color).bg(theme::BG_ELEVATED))
                .ratio(ratio)
                .label(format!("{formatted}   ({}s remaining)", code.remaining_secs));
            f.render_widget(gauge, sections[1]);
        }
    }
}

fn draw_bottom_bar(f: &mut Frame, area: Rect, app: &App) {
    let text = if let Some((level, msg, _)) = &app.status_toast {
        let (prefix, style) = match level {
            ToastLevel::Ok => (" ✓ ", theme::ok_style()),
            ToastLevel::Warn => (" ! ", theme::warn_style()),
            ToastLevel::Error => (" ✗ ", theme::danger_style()),
        };
        Line::from(Span::styled(
            format!("{prefix}{}", sanitize_display(msg)),
            style,
        ))
    } else {
        Line::from(Span::styled(
            " [j/k] Nav  [/] Search  [y] Copy Pass  [u] User  [t] TOTP  [r] Reveal  [a] Add  [e] Edit  [d] Del  [g] Gen  [A] Audit  [L] Lock  [?] Help  [q] Quit",
            theme::muted_style(),
        ))
    };
    let bar = Paragraph::new(text).alignment(Alignment::Left);
    f.render_widget(bar, area);
}

fn draw_editor_modal(f: &mut Frame, area: Rect, form: &EntryForm) {
    let modal = centered_rect(76, 74, area);
    f.render_widget(Clear, modal);

    let title = if form.editing_original_name.is_some() {
        " Edit Entry (Tab: next · Ctrl+G: gen · Ctrl+R: reveal · Ctrl+S: save · Esc: cancel) "
    } else {
        " New Entry (Tab: next · Ctrl+G: gen · Ctrl+R: reveal · Ctrl+S: save · Esc: cancel) "
    };

    let masked_pw = if form.reveal_secrets {
        sanitize_display(&form.password)
    } else {
        "•".repeat(form.password.chars().count().min(32))
    };
    let masked_totp = if form.reveal_secrets || form.totp.is_empty() {
        sanitize_display(&form.totp)
    } else {
        "•".repeat(form.totp.chars().count().min(32))
    };

    let masked_notes = if form.reveal_secrets || form.notes.is_empty() {
        sanitize_display(&form.notes)
    } else {
        "•".repeat(form.notes.chars().count().min(32))
    };

    let fields: [(&str, String); EntryForm::FIELD_COUNT] = [
        ("Name", sanitize_display(&form.name)),
        ("Username", sanitize_display(&form.username)),
        ("Password", masked_pw),
        ("URL", sanitize_display(&form.url)),
        ("Tags (comma)", sanitize_display(&form.tags)),
        ("TOTP (Base32 / otpauth://)", masked_totp),
        ("Notes", masked_notes),
    ];

    let mut lines = Vec::new();
    for (idx, (label, val)) in fields.iter().enumerate() {
        let active = idx == form.active_field;
        let prefix = if active { "▸ " } else { "  " };
        let style = if active {
            Style::default().fg(theme::ACCENT_CYAN).add_modifier(Modifier::BOLD)
        } else {
            theme::muted_style()
        };
        let cursor = if active { "_" } else { "" };
        lines.push(Line::from(vec![
            Span::styled(format!("{prefix}{label}: "), style),
            Span::raw(format!("{val}{cursor}")),
        ]));
        lines.push(Line::from(""));
    }

    if let Some(err) = &form.error {
        lines.push(Line::from(Span::styled(
            format!("  ! {}", sanitize_display(err)),
            theme::danger_style(),
        )));
    }

    let p = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme::border_style(true))
                .style(Style::default().bg(theme::BG_PRIMARY))
                .title(Span::styled(title, theme::title_style())),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(p, modal);
}

fn draw_generator_modal(f: &mut Frame, area: Rect, gen: &GenModalState) {
    let modal = centered_rect(68, 42, area);
    f.render_widget(Clear, modal);

    let bits = if gen.passphrase_mode {
        passphrase_entropy_bits(&PassphraseOptions {
            words: gen.words,
            ..PassphraseOptions::default()
        })
    } else {
        generated_password_entropy_bits(&PasswordOptions {
            length: gen.length,
            symbols: gen.symbols,
            ..PasswordOptions::default()
        })
    };
    let mode_label = if gen.passphrase_mode {
        format!("Diceware Passphrase ({} words)", gen.words)
    } else {
        format!(
            "CSPRNG Password ({} chars · symbols:{})",
            gen.length,
            if gen.symbols { "ON" } else { "OFF" }
        )
    };

    let lines = vec![
        Line::from(vec![
            Span::styled("  Mode:     ", theme::muted_style()),
            Span::styled(mode_label, Style::default().fg(theme::ACCENT_MAGENTA)),
        ]),
        Line::from(vec![
            Span::styled("  Entropy:  ", theme::muted_style()),
            Span::styled(
                format!("{bits:.0} bits · {}", strength_label(bits)),
                theme::ok_style(),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            format!("  {}", *gen.preview),
            Style::default().fg(theme::ACCENT_CYAN).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  [Space] Regenerate  [m] Switch Mode  [+/-] Size  [s] Symbols  [y] Secret Copy  [Esc] Close",
            theme::muted_style(),
        )),
    ];

    let p = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme::border_style(true))
                .style(Style::default().bg(theme::BG_PRIMARY))
                .title(Span::styled(" CSPRNG Password Generator ", theme::title_style())),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(p, modal);
}

fn draw_audit_modal(f: &mut Frame, area: Rect, report: &AuditReport) {
    let modal = centered_rect(72, 68, area);
    f.render_widget(Clear, modal);

    let mut lines = vec![
        Line::from(vec![
            Span::styled("  Security Hygiene Score: ", theme::muted_style()),
            Span::styled(
                format!("{}/100", report.overall_score),
                if report.overall_score >= 85 {
                    theme::ok_style()
                } else if report.overall_score >= 60 {
                    theme::warn_style()
                } else {
                    theme::danger_style()
                },
            ),
        ]),
        Line::from(format!(
            "  Total entries: {}  ·  2FA (TOTP): {}/{}  ·  Missing 2FA: {}",
            report.total_entries,
            report.totp_enabled_count,
            report.total_entries,
            report.missing_totp.len()
        )),
        Line::from(""),
    ];

    if report.weak_passwords.is_empty() {
        lines.push(Line::from(Span::styled(
            "  ✓ No weak or empty passwords detected",
            theme::ok_style(),
        )));
    } else {
        lines.push(Line::from(Span::styled(
            format!("  ! Weak / empty passwords ({}):", report.weak_passwords.len()),
            theme::danger_style(),
        )));
        for w in report.weak_passwords.iter().take(6) {
            lines.push(Line::from(format!(
                "    - {} ({:.0} bits · {} · len {})",
                sanitize_display(&w.entry_name),
                w.entropy_bits,
                w.label,
                w.length
            )));
        }
        if report.weak_passwords.len() > 6 {
            lines.push(Line::from(Span::styled(
                format!("    ...and {} more (run `omavault audit` for full list)", report.weak_passwords.len() - 6),
                theme::muted_style(),
            )));
        }
    }

    if report.reused_groups.is_empty() {
        lines.push(Line::from(Span::styled(
            "  ✓ No reused passwords detected",
            theme::ok_style(),
        )));
    } else {
        lines.push(Line::from(Span::styled(
            format!("  ! Reused password groups ({}):", report.reused_groups.len()),
            theme::danger_style(),
        )));
        for g in report.reused_groups.iter().take(5) {
            lines.push(Line::from(format!(
                "    - {}",
                sanitize_display(&g.entry_names.join(", "))
            )));
        }
        if report.reused_groups.len() > 5 {
            lines.push(Line::from(Span::styled(
                format!("    ...and {} more groups", report.reused_groups.len() - 5),
                theme::muted_style(),
            )));
        }
    }

    if !report.stale_entries.is_empty() {
        lines.push(Line::from(Span::styled(
            format!("  ! Older than 1 year ({}):", report.stale_entries.len()),
            theme::warn_style(),
        )));
        for (name, days) in report.stale_entries.iter().take(4) {
            lines.push(Line::from(format!(
                "    - {} ({days} days old)",
                sanitize_display(name)
            )));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Press [Esc] or [Enter] to close",
        theme::muted_style(),
    )));

    let p = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme::border_style(true))
                .style(Style::default().bg(theme::BG_PRIMARY))
                .title(Span::styled(" Vault Security Audit ", theme::title_style())),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(p, modal);
}

fn draw_confirm_delete(f: &mut Frame, area: Rect, name: &str) {
    let modal = centered_rect(52, 24, area);
    f.render_widget(Clear, modal);
    let p = Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled(
            format!("  Permanently delete entry '{}'?", sanitize_display(name)),
            theme::danger_style(),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  [y] Yes, delete    [n/Esc] Cancel",
            theme::muted_style(),
        )),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(theme::danger_style())
            .style(Style::default().bg(theme::BG_PRIMARY))
            .title(Span::styled(" Confirm Delete ", theme::danger_style())),
    );
    f.render_widget(p, modal);
}

fn draw_help_modal(f: &mut Frame, area: Rect) {
    let modal = centered_rect(68, 64, area);
    f.render_widget(Clear, modal);
    let lines = vec![
        Line::from(Span::styled("  Navigation & Search", theme::title_style())),
        Line::from("   j / k / ↑ / ↓   Move selection"),
        Line::from("   /               Filter entries (Esc clears)"),
        Line::from(""),
        Line::from(Span::styled("  Secrets & Wayland Clipboard", theme::title_style())),
        Line::from("   y               Copy password (x-kde-passwordManagerHint secret-tagged)"),
        Line::from("   u               Copy username (secret-tagged)"),
        Line::from("   t               Copy live 2FA TOTP code (secret-tagged)"),
        Line::from("   r               Toggle password reveal"),
        Line::from(""),
        Line::from(Span::styled("  Vault Management", theme::title_style())),
        Line::from("   a / e / d       Add / Edit / Delete entry (Ctrl+R reveals inside editor)"),
        Line::from("   g               CSPRNG Password & Diceware Generator"),
        Line::from("   A               Run local Password Security Audit"),
        Line::from("   L / Ctrl+L      Lock vault & wipe keys from RAM immediately"),
        Line::from("   q / Ctrl+C      Quit & clear clipboard"),
    ];
    let p = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme::border_style(true))
                .style(Style::default().bg(theme::BG_PRIMARY))
                .title(Span::styled(" Keybindings ", theme::title_style())),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(p, modal);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let vert = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vert[1])[1]
}

impl Default for TuiConfig {
    fn default() -> Self {
        Self {
            vault_path: crate::vault::storage::default_vault_path(),
            keyfile_path: None,
            fido2_device: None,
            socket_path: crate::daemon::default_socket_path(),
            idle_timeout_secs: DEFAULT_IDLE_TIMEOUT_SECS,
            clipboard_timeout_secs: DEFAULT_CLIPBOARD_TIMEOUT_SECS,
            paste_once: false,
            hardening: HardeningStatus::default(),
        }
    }
}
