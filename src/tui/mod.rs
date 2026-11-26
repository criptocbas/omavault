pub mod theme;

use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
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
use zeroize::Zeroizing;

use crate::clipboard::{
    clear_clipboard_best_effort, copy_secret, ClipboardOptions, DEFAULT_CLIPBOARD_TIMEOUT_SECS,
};
use crate::crypto::fido2::{Fido2Provider, LibFido2Cli};
use crate::crypto::kdf::{derive_master_key, hash_keyfile};
use crate::crypto::VaultHeader;
use crate::daemon::{DaemonClient, DEFAULT_IDLE_TIMEOUT_SECS};
use crate::error::{Result, VaultError};
use crate::generator::{
    estimate_entropy_bits, generate_passphrase, generate_password, strength_label,
    PassphraseOptions, PasswordOptions,
};
use crate::hardening::{HardeningStatus, LockedKey};
use crate::totp::TotpConfig;
use crate::vault::audit::{run_audit, AuditReport};
use crate::vault::storage::{load_vault_from_disk, read_header_from_disk, save_vault_to_disk};
use crate::vault::{Entry, Vault};

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

enum SessionBackend {
    Daemon,
    Standalone {
        master_key: LockedKey<32>,
        header: Box<VaultHeader>,
    },
}

enum Mode {
    Locked {
        passphrase_input: Zeroizing<String>,
        error_msg: Option<String>,
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

struct EntryForm {
    editing_original_name: Option<String>,
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
            active_field: 0,
            name: String::new(),
            username: String::new(),
            password: Zeroizing::new(String::new()),
            url: String::new(),
            tags: String::new(),
            totp: Zeroizing::new(String::new()),
            notes: Zeroizing::new(String::new()),
            error: None,
        }
    }

    fn from_entry(entry: &Entry) -> Self {
        Self {
            editing_original_name: Some(entry.name.clone()),
            active_field: 0,
            name: entry.name.clone(),
            username: entry.username.clone(),
            password: Zeroizing::new(entry.password.clone()),
            url: entry.url.clone(),
            tags: entry.tags.join(", "),
            totp: Zeroizing::new(
                entry
                    .totp
                    .as_ref()
                    .map(|t| t.secret_base32.clone())
                    .unwrap_or_default(),
            ),
            notes: Zeroizing::new(entry.notes.clone()),
            error: None,
        }
    }

    const FIELD_COUNT: usize = 7;

    fn current_mut(&mut self) -> &mut String {
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
    search_query: String,
    list_state: ListState,
    reveal_password: bool,
    status_toast: Option<(String, Instant)>,
    last_activity: Instant,
    should_quit: bool,
}

impl App {
    fn new(cfg: TuiConfig) -> Result<Self> {
        let header_preview = read_header_from_disk(&cfg.vault_path, true)?;
        let mut app = Self {
            cfg,
            header_preview,
            mode: Mode::Locked {
                passphrase_input: Zeroizing::new(String::new()),
                error_msg: None,
            },
            backend: None,
            vault: None,
            search_query: String::new(),
            list_state: ListState::default(),
            reveal_password: false,
            status_toast: None,
            last_activity: Instant::now(),
            should_quit: false,
        };

        // If the auto-lock daemon is already unlocked for this vault, attach seamlessly!
        let client = DaemonClient::new(app.cfg.socket_path.clone());
        if let Ok(vault) = client.load_vault(&app.cfg.vault_path) {
            app.backend = Some(SessionBackend::Daemon);
            app.vault = Some(vault);
            app.mode = Mode::Normal;
            if app.vault.as_ref().is_some_and(|v| !v.entries.is_empty()) {
                app.list_state.select(Some(0));
            }
            app.set_toast("Attached to unlocked omavault daemon");
        }

        Ok(app)
    }

    fn set_toast(&mut self, msg: impl Into<String>) {
        self.status_toast = Some((msg.into(), Instant::now()));
    }

    fn lock_vault(&mut self, reason: &str) {
        if let Some(SessionBackend::Daemon) = self.backend {
            let client = DaemonClient::new(self.cfg.socket_path.clone());
            let _ = client.lock();
        }
        // Dropping `vault` and `backend` triggers `ZeroizeOnDrop` on all passwords and
        // volatile-zeroize + munlock + munmap on `LockedKey<32>`.
        self.vault = None;
        self.backend = None;
        self.reveal_password = false;
        self.search_query.clear();
        clear_clipboard_best_effort();
        self.mode = Mode::Locked {
            passphrase_input: Zeroizing::new(String::new()),
            error_msg: Some(format!("Vault locked ({reason})")),
        };
    }

    fn attempt_unlock(&mut self, passphrase: Zeroizing<String>) {
        let client = DaemonClient::new(self.cfg.socket_path.clone());
        if client.is_available() {
            match client.unlock(
                &self.cfg.vault_path,
                passphrase,
                self.cfg.keyfile_path.clone(),
                self.cfg.fido2_device.clone(),
            ) {
                Ok(()) => match client.load_vault(&self.cfg.vault_path) {
                    Ok(vault) => {
                        self.backend = Some(SessionBackend::Daemon);
                        self.vault = Some(vault);
                        self.mode = Mode::Normal;
                        self.last_activity = Instant::now();
                        if self.vault.as_ref().is_some_and(|v| !v.entries.is_empty()) {
                            self.list_state.select(Some(0));
                        }
                        self.set_toast("Unlocked via omavault daemon (mlock active)");
                        return;
                    }
                    Err(e) => {
                        self.mode = Mode::Locked {
                            passphrase_input: Zeroizing::new(String::new()),
                            error_msg: Some(e.to_string()),
                        };
                        return;
                    }
                },
                Err(e) => {
                    self.mode = Mode::Locked {
                        passphrase_input: Zeroizing::new(String::new()),
                        error_msg: Some(e.to_string()),
                    };
                    return;
                }
            }
        }

        // Standalone unlock (no daemon running): derive MasterKey directly into LockedKey<32>.
        let result = (|| -> Result<(LockedKey<32>, VaultHeader, Vault)> {
            let header = read_header_from_disk(&self.cfg.vault_path, true)?;
            let kf_digest = if header.requires_keyfile() {
                let path = self
                    .cfg
                    .keyfile_path
                    .as_ref()
                    .ok_or(VaultError::KeyfileRequired)?;
                Some(hash_keyfile(path)?)
            } else {
                None
            };
            let fido2_secret = if header.requires_fido2() {
                let meta = header.fido2.as_ref().ok_or(VaultError::Fido2Required)?;
                let provider = LibFido2Cli;
                Some(provider.get_hmac_secret(meta, self.cfg.fido2_device.as_deref())?)
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
            let (verified_header, vault) =
                load_vault_from_disk(&self.cfg.vault_path, &master_key, true)?;
            Ok((master_key, verified_header, vault))
        })();

        match result {
            Ok((master_key, header, vault)) => {
                let mlock_msg = if master_key.is_mlocked() {
                    "Unlocked (standalone · mlock ACTIVE)"
                } else {
                    "Unlocked (standalone · mlock unavailable)"
                };
                self.backend = Some(SessionBackend::Standalone {
                    master_key,
                    header: Box::new(header),
                });
                self.vault = Some(vault);
                self.mode = Mode::Normal;
                self.last_activity = Instant::now();
                if self.vault.as_ref().is_some_and(|v| !v.entries.is_empty()) {
                    self.list_state.select(Some(0));
                }
                self.set_toast(mlock_msg);
            }
            Err(e) => {
                self.mode = Mode::Locked {
                    passphrase_input: Zeroizing::new(String::new()),
                    error_msg: Some(e.to_string()),
                };
            }
        }
    }

    fn persist_vault(&mut self) -> Result<()> {
        let vault = self
            .vault
            .as_ref()
            .ok_or_else(|| VaultError::Daemon("vault not unlocked".into()))?;
        match self.backend.as_mut() {
            Some(SessionBackend::Daemon) => {
                let client = DaemonClient::new(self.cfg.socket_path.clone());
                client.save_vault(&self.cfg.vault_path, vault)
            }
            Some(SessionBackend::Standalone { master_key, header }) => {
                save_vault_to_disk(&self.cfg.vault_path, master_key, header, vault)
            }
            None => Err(VaultError::Daemon("vault not unlocked".into())),
        }
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
                self.set_toast(format!(
                    "Copied {label} (Wayland secret-tagged · {mode_str})"
                ));
            }
            Err(e) => self.set_toast(format!("Clipboard unavailable: {e}")),
        }
    }

    fn is_mlocked(&self) -> bool {
        match &self.backend {
            Some(SessionBackend::Standalone { master_key, .. }) => master_key.is_mlocked(),
            Some(SessionBackend::Daemon) => true,
            None => false,
        }
    }

    fn remaining_lock_secs(&self) -> u64 {
        let timeout = Duration::from_secs(self.cfg.idle_timeout_secs.max(10));
        timeout.saturating_sub(self.last_activity.elapsed()).as_secs()
    }

    fn on_tick(&mut self) {
        if !matches!(self.mode, Mode::Locked { .. }) {
            let timeout = Duration::from_secs(self.cfg.idle_timeout_secs.max(10));
            if self.last_activity.elapsed() >= timeout {
                self.lock_vault("inactivity timeout");
            }
        }
        if let Some((_, ts)) = &self.status_toast {
            if ts.elapsed() > Duration::from_secs(6) {
                self.status_toast = None;
            }
        }
    }

    fn handle_key(&mut self, key: KeyEvent) {
        self.last_activity = Instant::now();

        // Global Ctrl+C exits cleanly and wipes memory.
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.should_quit = true;
            return;
        }

        // Handle mode-specific keys.
        match &mut self.mode {
            Mode::Locked {
                passphrase_input,
                error_msg,
            } => match key.code {
                KeyCode::Esc => self.should_quit = true,
                KeyCode::Enter => {
                    let entered = std::mem::replace(
                        passphrase_input,
                        Zeroizing::new(String::new()),
                    );
                    *error_msg = None;
                    self.attempt_unlock(entered);
                }
                KeyCode::Backspace => {
                    passphrase_input.pop();
                }
                KeyCode::Char(c) => {
                    passphrase_input.push(c);
                }
                _ => {}
            },
            Mode::Search => match key.code {
                KeyCode::Esc => {
                    self.search_query.clear();
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
                        if let Some(vault) = self.vault.as_mut() {
                            if vault.remove_by_name(&name).is_ok() {
                                if let Err(e) = self.persist_vault() {
                                    self.set_toast(format!("Save failed: {e}"));
                                } else {
                                    self.set_toast(format!("Deleted entry '{name}'"));
                                }
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
                        gen_state.words = gen_state.words.saturating_sub(1).max(4);
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
            self.lock_vault("manual lock");
            return;
        }
        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('L') => self.lock_vault("manual lock"),
            KeyCode::Char('/') => self.mode = Mode::Search,
            KeyCode::Char('?') => self.mode = Mode::Help,
            KeyCode::Char('g') => self.mode = Mode::Generator(GenModalState::new()),
            KeyCode::Char('A') => {
                if let Some(vault) = &self.vault {
                    self.mode = Mode::Audit(run_audit(vault));
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
                    self.copy_to_secret_clipboard(&format!("'{}' password", entry.name), &entry.password);
                }
            }
            KeyCode::Char('u') => {
                if let Some(entry) = self.selected_entry().cloned() {
                    if entry.username.is_empty() {
                        self.set_toast("Entry has no username");
                    } else {
                        self.copy_to_secret_clipboard(&format!("'{}' username", entry.name), &entry.username);
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
                            Err(e) => self.set_toast(format!("TOTP error: {e}")),
                        }
                    } else {
                        self.set_toast("Entry has no TOTP configured");
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
                self.search_query.clear();
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

        let totp_cfg = if form.totp.trim().is_empty() {
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
        let password = form.password.to_string();
        let url = form.url.trim().to_string();
        let notes = form.notes.to_string();

        if let Some(vault) = self.vault.as_mut() {
            if let Some(orig) = editing {
                if let Some(entry) = vault.find_by_name_mut(&orig) {
                    entry.name = name.clone();
                    entry.username = username;
                    entry.set_password(password);
                    entry.url = url;
                    entry.tags = tags;
                    entry.totp = totp_cfg;
                    entry.notes = notes;
                    entry.updated_at = chrono::Utc::now();
                }
            } else {
                let mut entry = Entry::new(name.clone(), username, password);
                entry.url = url;
                entry.tags = tags;
                entry.totp = totp_cfg;
                entry.notes = notes;
                if let Err(e) = vault.add_entry(entry) {
                    if let Mode::Editor(f) = &mut self.mode {
                        f.error = Some(e.to_string());
                    }
                    return;
                }
            }
        }

        match self.persist_vault() {
            Ok(()) => {
                self.clamp_selection();
                self.mode = Mode::Normal;
                self.set_toast(format!("Encrypted & saved '{name}' (fresh key + nonce)"));
            }
            Err(e) => {
                if let Mode::Editor(f) = &mut self.mode {
                    f.error = Some(format!("Failed saving vault: {e}"));
                }
            }
        }
    }
}

/// Launch the interactive Omarchy Ratatui password manager.
pub fn run_tui(cfg: TuiConfig) -> Result<()> {
    let mut app = App::new(cfg)?;

    enable_raw_mode().map_err(VaultError::Io)?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).map_err(VaultError::Io)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(VaultError::Io)?;

    let run_res = (|| -> Result<()> {
        loop {
            terminal.draw(|f| draw_ui(f, &mut app)).map_err(VaultError::Io)?;

            if event::poll(Duration::from_millis(250)).map_err(VaultError::Io)? {
                if let Event::Key(key) = event::read().map_err(VaultError::Io)? {
                    app.handle_key(key);
                }
            }
            app.on_tick();

            if app.should_quit {
                break;
            }
        }
        Ok(())
    })();

    // Always restore terminal state cleanly even on error.
    let _ = disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let _ = terminal.show_cursor();

    run_res
}

fn draw_ui(f: &mut Frame, app: &mut App) {
    let area = f.area();
    let bg_block = Block::default().style(Style::default().bg(theme::BG_PRIMARY).fg(theme::FG_PRIMARY));
    f.render_widget(bg_block, area);

    if let Mode::Locked {
        passphrase_input,
        error_msg,
    } = &app.mode
    {
        draw_locked_screen(
            f,
            area,
            &app.cfg.vault_path,
            &app.header_preview,
            passphrase_input.chars().count(),
            error_msg.as_deref(),
            &app.cfg.hardening,
        );
        return;
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

fn draw_locked_screen(
    f: &mut Frame,
    area: Rect,
    vault_path: &Path,
    header: &VaultHeader,
    input_len: usize,
    error_msg: Option<&str>,
    hardening: &HardeningStatus,
) {
    let box_area = centered_rect(64, 52, area);
    f.render_widget(Clear, box_area);

    let mut factors = vec!["Passphrase"];
    if header.requires_keyfile() {
        factors.push("Keyfile");
    }
    if header.requires_fido2() {
        factors.push("FIDO2 Hardware Touch");
    }

    let masked = "•".repeat(input_len);
    let mut lines = vec![
        Line::from(Span::styled(
            "  OMAVAULT  ·  HARDENED PASSWORD VAULT",
            theme::title_style(),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Vault:   ", theme::muted_style()),
            Span::raw(vault_path.display().to_string()),
        ]),
        Line::from(vec![
            Span::styled("  Crypto:  ", theme::muted_style()),
            Span::styled(
                format!(
                    "Argon2id ({} MiB, t={}, p={}) + HKDF-SHA512 + XChaCha20-Poly1305",
                    header.kdf_params.mem_kib / 1024,
                    header.kdf_params.time_cost,
                    header.kdf_params.parallelism
                ),
                Style::default().fg(theme::ACCENT_GREEN),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Factors: ", theme::muted_style()),
            Span::styled(factors.join(" + "), Style::default().fg(theme::ACCENT_MAGENTA)),
        ]),
        Line::from(vec![
            Span::styled("  OS Lock: ", theme::muted_style()),
            Span::styled(hardening.summary(), theme::muted_style()),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  Master Passphrase:",
            Style::default().fg(theme::ACCENT_CYAN).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            format!("  > {masked}_"),
            Style::default().fg(theme::FG_PRIMARY).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];

    if let Some(err) = error_msg {
        lines.push(Line::from(Span::styled(
            format!("  ! {err}"),
            theme::danger_style(),
        )));
    } else {
        lines.push(Line::from(Span::styled(
            "  [Enter] Unlock   [Esc] Quit",
            theme::muted_style(),
        )));
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
        format!("{}_", app.search_query)
    } else {
        app.search_query.clone()
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
                let mut spans = vec![Span::raw(format!(" {}", entry.name))];
                if entry.totp.is_some() {
                    spans.push(Span::styled(" [2FA]", Style::default().fg(theme::ACCENT_GREEN)));
                }
                if estimate_entropy_bits(&entry.password) < 60.0 && !entry.password.is_empty() {
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
        entry.password.clone()
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
                &entry.name,
                Style::default().fg(theme::ACCENT_CYAN).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled(" Username: ", theme::muted_style()),
            Span::raw(if entry.username.is_empty() { "-" } else { &entry.username }),
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
                if entry.url.is_empty() { "-" } else { &entry.url },
                Style::default().fg(theme::ACCENT_BLUE),
            ),
        ]),
        Line::from(vec![
            Span::styled(" Tags:     ", theme::muted_style()),
            Span::styled(
                if entry.tags.is_empty() {
                    "-".to_string()
                } else {
                    entry.tags.join(", ")
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
            if entry.notes.is_empty() { "(none)" } else { &entry.notes }
        )),
    ];

    if !entry.custom_fields.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(" Custom Fields:", theme::muted_style())));
        for cf in &entry.custom_fields {
            let val = if cf.secret && !app.reveal_password {
                "••••••••"
            } else {
                &cf.value
            };
            lines.push(Line::from(format!("  {}: {}", cf.label, val)));
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
    let text = if let Some((msg, _)) = &app.status_toast {
        Line::from(Span::styled(format!(" ✓ {msg}"), theme::ok_style()))
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
    let modal = centered_rect(72, 72, area);
    f.render_widget(Clear, modal);

    let title = if form.editing_original_name.is_some() {
        " Edit Entry (Tab: next · Ctrl+G: generate password · Ctrl+S: save · Esc: cancel) "
    } else {
        " New Entry (Tab: next · Ctrl+G: generate password · Ctrl+S: save · Esc: cancel) "
    };

    let fields: [(&str, &str); EntryForm::FIELD_COUNT] = [
        ("Name", &form.name),
        ("Username", &form.username),
        ("Password", &form.password),
        ("URL", &form.url),
        ("Tags (comma)", &form.tags),
        ("TOTP (Base32 / otpauth://)", &form.totp),
        ("Notes", &form.notes),
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
        lines.push(Line::from(Span::styled(format!("  ! {err}"), theme::danger_style())));
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
        crate::generator::passphrase_entropy_bits(&PassphraseOptions {
            words: gen.words,
            ..PassphraseOptions::default()
        })
    } else {
        estimate_entropy_bits(&gen.preview)
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
    let modal = centered_rect(70, 62, area);
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
            "  Total entries: {}  ·  2FA (TOTP) enabled: {}/{}",
            report.total_entries, report.totp_enabled_count, report.total_entries
        )),
        Line::from(""),
    ];

    if report.weak_passwords.is_empty() {
        lines.push(Line::from(Span::styled(
            "  ✓ No weak passwords detected",
            theme::ok_style(),
        )));
    } else {
        lines.push(Line::from(Span::styled(
            format!("  ! Weak passwords ({}):", report.weak_passwords.len()),
            theme::danger_style(),
        )));
        for w in report.weak_passwords.iter().take(6) {
            lines.push(Line::from(format!(
                "    - {} ({:.0} bits, len {})",
                w.entry_name, w.entropy_bits, w.length
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
            lines.push(Line::from(format!("    - {}", g.entry_names.join(", "))));
        }
    }

    if !report.stale_entries.is_empty() {
        lines.push(Line::from(Span::styled(
            format!("  ! Older than 1 year ({}):", report.stale_entries.len()),
            theme::warn_style(),
        )));
        for (name, days) in report.stale_entries.iter().take(5) {
            lines.push(Line::from(format!("    - {name} ({days} days old)")));
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
            format!("  Permanently delete entry '{name}'?"),
            theme::danger_style(),
        )),
        Line::from(""),
        Line::from(Span::styled("  [y] Yes, delete    [n/Esc] Cancel", theme::muted_style())),
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
    let modal = centered_rect(66, 62, area);
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
        Line::from("   a / e / d       Add / Edit / Delete entry"),
        Line::from("   g               CSPRNG Password & Diceware Generator"),
        Line::from("   A               Run local Password Security Audit"),
        Line::from("   L / Ctrl+L      Lock vault & wipe keys from RAM immediately"),
        Line::from("   q / Ctrl+C      Quit"),
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
