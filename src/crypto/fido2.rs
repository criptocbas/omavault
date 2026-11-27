use std::cell::RefCell;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use data_encoding::BASE64;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::Fido2KeySlot;
use crate::error::{Result, VaultError};
use crate::hardening::fill_random;

pub const DEFAULT_RP_ID: &str = "omavault.local";
const USER_NAME: &str = "omavault";
/// Hard timeout for FIDO2 authenticator subprocesses so headless calls cannot hang forever.
const FIDO2_CMD_TIMEOUT: Duration = Duration::from_secs(45);

/// Trusted system binary search prefixes (in priority order).
const TRUSTED_BIN_DIRS: &[&str] = &["/usr/bin", "/usr/local/bin", "/bin"];

/// Non-secret FIDO2 metadata stored inside the AAD-authenticated vault header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fido2Metadata {
    /// Relying Party ID (must be `omavault.local`).
    pub rp_id: String,
    /// Base64-encoded non-resident credential ID returned during enrollment.
    pub credential_id_b64: String,
    /// Base64-encoded 32-byte random HMAC challenge salt.
    pub hmac_salt_b64: String,
    /// Whether User Verification (PIN / biometric) is required on the authenticator.
    #[serde(default)]
    pub require_uv: bool,
}

impl Fido2Metadata {
    /// Strictly validate FIDO2 metadata before trusting it prior to AEAD verification.
    pub fn validate(&self) -> Result<()> {
        if self.rp_id != DEFAULT_RP_ID {
            return Err(VaultError::Fido2Error(
                "unexpected FIDO2 relying party ID in vault header".into(),
            ));
        }
        if self.rp_id.contains(['\n', '\r', '\0'])
            || self.credential_id_b64.contains(['\n', '\r', '\0'])
            || self.hmac_salt_b64.contains(['\n', '\r', '\0'])
        {
            return Err(VaultError::Fido2Error(
                "invalid control characters in FIDO2 metadata".into(),
            ));
        }
        let cred = BASE64
            .decode(self.credential_id_b64.as_bytes())
            .map_err(|_| VaultError::Fido2Error("invalid Base64 FIDO2 credential ID".into()))?;
        if cred.is_empty() || cred.len() > 1024 {
            return Err(VaultError::Fido2Error(
                "invalid FIDO2 credential ID length".into(),
            ));
        }
        let salt = BASE64
            .decode(self.hmac_salt_b64.as_bytes())
            .map_err(|_| VaultError::Fido2Error("invalid Base64 FIDO2 HMAC salt".into()))?;
        if salt.len() != 32 {
            return Err(VaultError::Fido2Error(
                "FIDO2 HMAC salt must be exactly 32 bytes".into(),
            ));
        }
        Ok(())
    }
}

/// Trait abstracting FIDO2 `hmac-secret` hardware tokens so both real YubiKeys
/// (via `libfido2` tools) and deterministic unit tests are first-class citizens.
pub trait Fido2Provider {
    /// Enroll a new non-resident `hmac-secret` credential on a connected FIDO2 token.
    fn enroll(&self, device: Option<&str>, require_uv: bool) -> Result<Fido2Metadata>;

    /// Perform an assertion with the `hmac-secret` extension and return the 32-byte
    /// hardware-bound secret in a `Zeroizing` buffer.
    fn get_hmac_secret(
        &self,
        meta: &Fido2Metadata,
        device: Option<&str>,
    ) -> Result<Zeroizing<[u8; 32]>>;

    /// Match a connected FIDO2 token against a list of `OMAV` v2 key slots, returning
    /// `(slot_index, hmac_secret)` for the first slot owned by a plugged-in authenticator.
    fn assert_matching_slot(
        &self,
        slots: &[Fido2KeySlot],
        device: Option<&str>,
    ) -> Result<(usize, Zeroizing<[u8; 32]>)> {
        if slots.is_empty() {
            return Err(VaultError::Fido2Required);
        }
        let mut last_err = VaultError::Fido2NoMatchingCredential;
        for idx in slot_probe_order(slots) {
            match self.get_hmac_secret(&slots[idx].fido2, device) {
                Ok(secret) => return Ok((idx, secret)),
                Err(VaultError::Fido2NoMatchingCredential) => continue,
                Err(e) => {
                    last_err = e;
                    break;
                }
            }
        }
        Err(last_err)
    }
}

/// Cancel token for one in-flight FIDO2 operation.
///
/// Installed on the calling thread with [`with_cancel`]. The provider trait stays
/// unchanged, so existing `&LibFido2Cli` call sites do not grow a new argument.
#[derive(Clone, Debug)]
pub struct Fido2Cancel(Arc<AtomicBool>);

impl Default for Fido2Cancel {
    fn default() -> Self {
        Self::new()
    }
}

impl Fido2Cancel {
    pub fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    /// Share a flag that already exists (the TUI's unlock-cancel `Arc`).
    pub fn from_flag(flag: Arc<AtomicBool>) -> Self {
        Self(flag)
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    /// `true` when both handles point at the same flag, including after `clone`.
    pub fn same_token(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

thread_local! {
    static CURRENT_CANCEL: RefCell<Option<Fido2Cancel>> = const { RefCell::new(None) };
}

const FIDO2_CANCELLED_MSG: &str = "FIDO2 operation cancelled";

fn cancelled_error() -> VaultError {
    VaultError::Fido2Error(FIDO2_CANCELLED_MSG.into())
}

fn is_cancelled_error(err: &VaultError) -> bool {
    matches!(err, VaultError::Fido2Error(msg) if msg == FIDO2_CANCELLED_MSG)
}

fn cancel_requested() -> bool {
    CURRENT_CANCEL.with(|slot| {
        slot.borrow()
            .as_ref()
            .is_some_and(|cancel| cancel.is_cancelled())
    })
}

/// Run `f` with `cancel` visible to FIDO2 waits on this thread.
///
/// Restores the previous token on return and on unwind. Daemon and TUI threads are reused.
pub fn with_cancel<R>(cancel: &Fido2Cancel, f: impl FnOnce() -> R) -> R {
    struct Restore(Option<Fido2Cancel>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let previous = self.0.take();
            CURRENT_CANCEL.with(|slot| {
                *slot.borrow_mut() = previous;
            });
        }
    }

    let previous = CURRENT_CANCEL.with(|slot| slot.borrow_mut().replace(cancel.clone()));
    let _restore = Restore(previous);
    f()
}

/// Production FIDO2 provider backed by Arch/Omarchy's `libfido2` CLI tools
/// (`fido2-token`, `fido2-cred`, `fido2-assert`).
///
/// Security hardening:
/// - Resolves binaries from trusted root-owned system directories (`/usr/bin/...`), never
///   from untrusted `PATH` entries.
/// - Validates device paths as canonicalized `/dev/` character devices and passes `--`
///   before positional arguments to eliminate `getopt(3)` option injection.
/// - Reaps child processes on all error paths and enforces a bounded 45s timeout.
/// - Wraps stdout in `Zeroizing` immediately, verifies challenge echo, `rp_id`, and
///   authenticator data `UP`/`UV` flags before accepting the 32-byte HMAC secret.
#[derive(Debug, Default, Clone, Copy)]
pub struct LibFido2Cli;

impl LibFido2Cli {
    /// Resolve a trusted root-owned non-writable `libfido2` binary path.
    fn resolve_tool(name: &str) -> Result<PathBuf> {
        for dir in TRUSTED_BIN_DIRS {
            let candidate = Path::new(dir).join(name);
            if let Ok(meta) = fs::metadata(&candidate) {
                let mode = meta.permissions().mode();
                if meta.file_type().is_file()
                    && meta.uid() == 0
                    && (mode & 0o022) == 0
                    && (mode & 0o111) != 0
                {
                    return Ok(candidate);
                }
            }
        }
        Err(VaultError::Fido2Error(format!(
            "trusted root-owned `{name}` not found in /usr/bin (install `libfido2`: `sudo pacman -S libfido2`)"
        )))
    }

    /// Validate that a caller-supplied or discovered HID path is a real `/dev/` character device
    /// and cannot be interpreted as a CLI option flag.
    pub fn validate_device_path(raw: &str) -> Result<String> {
        let trimmed = raw.trim();
        if trimmed.is_empty()
            || trimmed.starts_with('-')
            || trimmed.contains(['\0', '\n', '\r'])
            || trimmed.contains("..")
        {
            return Err(VaultError::Fido2Error(
                "invalid FIDO2 device path (must be a canonical /dev/* character device)".into(),
            ));
        }
        let canonical = fs::canonicalize(trimmed).map_err(|_| {
            VaultError::Fido2Error("FIDO2 device path does not exist or cannot be resolved".into())
        })?;
        if !canonical.starts_with("/dev/") {
            return Err(VaultError::Fido2Error(
                "FIDO2 device path must reside under /dev/".into(),
            ));
        }
        let meta = fs::metadata(&canonical)
            .map_err(|_| VaultError::Fido2Error("cannot stat FIDO2 device node".into()))?;
        if !meta.file_type().is_char_device() {
            return Err(VaultError::Fido2Error(
                "FIDO2 device path must be a character device".into(),
            ));
        }
        let canonical_str = canonical
            .to_str()
            .ok_or_else(|| VaultError::Fido2Error("FIDO2 device path is not valid UTF-8".into()))?;
        let is_hidraw = canonical_str
            .strip_prefix("/dev/hidraw")
            .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()));
        if !is_hidraw {
            return Err(VaultError::Fido2Error(
                "FIDO2 device path must canonicalize to a /dev/hidraw<N> HID character device"
                    .into(),
            ));
        }
        Ok(canonical_str.to_string())
    }

    /// Auto-detect all connected FIDO2 HID devices via `fido2-token -L`.
    pub fn discover_devices() -> Result<Vec<String>> {
        if cancel_requested() {
            return Err(cancelled_error());
        }
        let bin = Self::resolve_tool("fido2-token")?;
        let mut cmd = Command::new(bin);
        cmd.arg("-L")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let child = spawn_grouped(&mut cmd)
            .map_err(|e| VaultError::Fido2Error(format!("failed to execute `fido2-token`: {e}")))?;

        let output = wait_with_timeout(child, Duration::from_secs(10), "fido2-token")?;
        if !output.status.success() {
            return Err(VaultError::Fido2Error(format!(
                "`fido2-token -L` exited with {}",
                output.status
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut devices = Vec::new();
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some((dev, _)) = trimmed.split_once(':') {
                if let Ok(valid) = Self::validate_device_path(dev) {
                    if !devices.contains(&valid) {
                        devices.push(valid);
                    }
                }
            }
        }

        if devices.is_empty() {
            return Err(VaultError::Fido2Error(
                "no FIDO2 hardware authenticator detected (plug in your YubiKey / FIDO2 token)"
                    .into(),
            ));
        }

        Ok(devices)
    }

    /// Auto-detect the first connected FIDO2 HID device via `fido2-token -L`.
    pub fn discover_device() -> Result<String> {
        Self::discover_devices()?.into_iter().next().ok_or_else(|| {
            VaultError::Fido2Error(
                "no FIDO2 hardware authenticator detected (plug in your YubiKey / FIDO2 token)"
                    .into(),
            )
        })
    }

    fn resolve_device(device: Option<&str>) -> Result<String> {
        match device {
            Some(d) if !d.trim().is_empty() => Self::validate_device_path(d),
            _ => Self::discover_device(),
        }
    }

    fn resolve_devices(device: Option<&str>) -> Result<Vec<String>> {
        match device {
            Some(d) if !d.trim().is_empty() => Ok(vec![Self::validate_device_path(d)?]),
            _ => Self::discover_devices(),
        }
    }

    /// Assert `meta` on one device path that already passed [`Self::validate_device_path`].
    ///
    /// Callers receive a [`VaultError`]. Slot probing uses the classified helper so it can
    /// tell a missing credential from a PIN failure.
    pub fn assert_on_device(
        &self,
        meta: &Fido2Metadata,
        dev: &str,
        print_prompt: bool,
    ) -> Result<Zeroizing<[u8; 32]>> {
        self.assert_on_device_classified(meta, dev, print_prompt)
            .map_err(|(_, err)| err)
    }

    /// Like [`Self::assert_on_device`], but the slot loop can branch on the failure kind.
    ///
    /// A UV slot tries `-t pin=true` first. Only `SlotNeedsOtherUv` (no PIN, or the option
    /// is rejected) retries once with `-t uv=true`. Both attempts still require the UV flag.
    fn assert_on_device_classified(
        &self,
        meta: &Fido2Metadata,
        dev: &str,
        print_prompt: bool,
    ) -> AssertOutcome {
        if !meta.require_uv {
            return self.assert_once(meta, dev, print_prompt, AssertUvMode::None);
        }
        match self.assert_once(meta, dev, print_prompt, AssertUvMode::Pin) {
            Err((kind, _)) if should_retry_with_uv(kind) => {
                self.assert_once(meta, dev, false, AssertUvMode::Biometric)
            }
            other => other,
        }
    }

    fn assert_once(
        &self,
        meta: &Fido2Metadata,
        dev: &str,
        print_prompt: bool,
        uv_mode: AssertUvMode,
    ) -> AssertOutcome {
        meta.validate()?;
        if cancel_requested() {
            return Err(cancelled_error().into());
        }
        let bin = Self::resolve_tool("fido2-assert")?;

        let mut client_data_hash = [0u8; 32];
        fill_random(&mut client_data_hash)?;
        let expected_cdh_b64 = BASE64.encode(&client_data_hash);

        let stdin_payload = Zeroizing::new(format!(
            "{}\n{}\n{}\n{}\n",
            expected_cdh_b64, meta.rp_id, meta.credential_id_b64, meta.hmac_salt_b64,
        ));

        let mut cmd = Command::new(bin);
        cmd.arg("-G").arg("-h").arg("-t").arg("up=true");
        match uv_mode {
            AssertUvMode::None => {}
            AssertUvMode::Pin => {
                // PIN-based tokens (YubiKey 5). Biometric tokens retry with `uv=true`.
                cmd.arg("-t").arg("pin=true");
            }
            AssertUvMode::Biometric => {
                cmd.arg("-t").arg("uv=true");
            }
        }
        cmd.arg("--")
            .arg(dev)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        if print_prompt {
            eprintln!(
                "Touch your FIDO2 security key to unlock omavault (RP: {}, UV: {})...",
                meta.rp_id, meta.require_uv
            );
        }

        let mut child = spawn_grouped(&mut cmd)
            .map_err(|e| VaultError::Fido2Error(format!("failed to launch `fido2-assert`: {e}")))?;

        write_stdin_or_reap(&mut child, stdin_payload.as_bytes(), "fido2-assert")?;
        let output = wait_with_timeout(child, FIDO2_CMD_TIMEOUT, "fido2-assert")?;
        // stdout is already wrapped in Zeroizing BEFORE inspecting status.
        let stdout_bytes = output.stdout;

        if !output.status.success() {
            return Err(failure_from_stderr(
                "fido2-assert",
                &output.stderr,
                output.status,
            ));
        }

        let stdout_str = std::str::from_utf8(&stdout_bytes)
            .map_err(|_| VaultError::Fido2Error("non-UTF8 output from `fido2-assert`".into()))?;
        let lines: Vec<&str> = stdout_str.lines().collect();

        // Per fido2-assert(1) for non-resident + -h:
        // 0: client data hash, 1: rp id, 2: authdata, 3: signature, 4: hmac secret (32B)
        if lines.len() != 5 {
            return Err(VaultError::Fido2Error(
                "unexpected `fido2-assert` output line count".into(),
            )
            .into());
        }

        if lines[0].trim() != expected_cdh_b64 || lines[1].trim() != meta.rp_id {
            return Err(VaultError::Fido2Error(
                "FIDO2 assertion failed challenge/RP verification".into(),
            )
            .into());
        }
        verify_authdata_flags(lines[2].trim(), &meta.rp_id, meta.require_uv, false, true)?;

        let decoded = Zeroizing::new(
            BASE64
                .decode(lines[4].trim().as_bytes())
                .map_err(|_| VaultError::Fido2Error("invalid Base64 HMAC secret".into()))?,
        );
        if decoded.len() != 32 {
            return Err(VaultError::Fido2Error(format!(
                "expected 32-byte HMAC secret from authenticator, got {} bytes",
                decoded.len()
            ))
            .into());
        }

        let mut secret = Zeroizing::new([0u8; 32]);
        secret.copy_from_slice(&decoded);
        Ok(secret)
    }

    /// Probe all connected FIDO2 devices (or an explicit device) for a specific credential.
    ///
    /// Stops on a PIN/UV failure or cancellation. Other failures are remembered and the next
    /// device is tried, so one key's transport error does not hide another key.
    pub fn assert_on_any_device(
        &self,
        meta: &Fido2Metadata,
        device: Option<&str>,
    ) -> Result<Zeroizing<[u8; 32]>> {
        if cancel_requested() {
            return Err(cancelled_error());
        }
        let devices = Self::resolve_devices(device)?;
        let mut remembered: Option<(AssertFailureKind, VaultError)> = None;
        for dev in &devices {
            if cancel_requested() {
                return Err(cancelled_error());
            }
            match self.assert_on_device_classified(meta, dev, false) {
                Ok(secret) => return Ok(secret),
                Err((kind, err)) => {
                    if is_cancelled_error(&err) || kind == AssertFailureKind::StopPinProblem {
                        return Err(err);
                    }
                    remembered = Some(prefer_failure(remembered, (kind, err)));
                }
            }
        }
        Err(remembered
            .map(|(_, err)| err)
            .unwrap_or(VaultError::Fido2NoMatchingCredential))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AssertFailureKind {
    NoCredential,
    SlotNeedsOtherUv,
    StopPinProblem,
    Device,
}

struct AssertFailureCode {
    kind: AssertFailureKind,
    /// Symbolic libfido2 name, compared as one underscore-preserving token.
    name: &'static str,
    /// Standalone hex token. `0x35` must not match `0x350`.
    hex: &'static str,
}

/// libfido2 1.17 codes from `/usr/include/fido/err.h`.
const ASSERT_FAILURE_CODES: &[AssertFailureCode] = &[
    AssertFailureCode {
        kind: AssertFailureKind::NoCredential,
        name: "fido_err_no_credentials",
        hex: "0x2e",
    },
    // This key cannot perform UV for the slot.
    AssertFailureCode {
        kind: AssertFailureKind::SlotNeedsOtherUv,
        name: "fido_err_pin_not_set",
        hex: "0x35",
    },
    AssertFailureCode {
        kind: AssertFailureKind::SlotNeedsOtherUv,
        name: "fido_err_unsupported_option",
        hex: "0x2b",
    },
    AssertFailureCode {
        kind: AssertFailureKind::SlotNeedsOtherUv,
        name: "fido_err_invalid_option",
        hex: "0x2c",
    },
    // Wrong PIN, blocked PIN, or a refused touch. Do not open another prompt.
    AssertFailureCode {
        kind: AssertFailureKind::StopPinProblem,
        name: "fido_err_pin_invalid",
        hex: "0x31",
    },
    AssertFailureCode {
        kind: AssertFailureKind::StopPinProblem,
        name: "fido_err_pin_blocked",
        hex: "0x32",
    },
    AssertFailureCode {
        kind: AssertFailureKind::StopPinProblem,
        name: "fido_err_pin_auth_invalid",
        hex: "0x33",
    },
    AssertFailureCode {
        kind: AssertFailureKind::StopPinProblem,
        name: "fido_err_pin_auth_blocked",
        hex: "0x34",
    },
    AssertFailureCode {
        kind: AssertFailureKind::StopPinProblem,
        name: "fido_err_pin_required",
        hex: "0x36",
    },
    AssertFailureCode {
        kind: AssertFailureKind::StopPinProblem,
        name: "fido_err_uv_blocked",
        hex: "0x3c",
    },
    AssertFailureCode {
        kind: AssertFailureKind::StopPinProblem,
        name: "fido_err_uv_invalid",
        hex: "0x3f",
    },
    AssertFailureCode {
        kind: AssertFailureKind::StopPinProblem,
        name: "fido_err_operation_denied",
        hex: "0x27",
    },
];

type AssertOutcome = std::result::Result<Zeroizing<[u8; 32]>, (AssertFailureKind, VaultError)>;

enum AssertUvMode {
    None,
    Pin,
    Biometric,
}

fn kind_rank(kind: AssertFailureKind) -> u8 {
    match kind {
        AssertFailureKind::StopPinProblem => 3,
        AssertFailureKind::SlotNeedsOtherUv => 2,
        AssertFailureKind::Device => 1,
        AssertFailureKind::NoCredential => 0,
    }
}

fn prefer_failure(
    remembered: Option<(AssertFailureKind, VaultError)>,
    next: (AssertFailureKind, VaultError),
) -> (AssertFailureKind, VaultError) {
    match remembered {
        Some((kind, err)) if kind_rank(kind) >= kind_rank(next.0) => (kind, err),
        _ => next,
    }
}

/// Retry PIN-mode UV exactly once, and only when the key cannot do PIN UV.
fn should_retry_with_uv(kind: AssertFailureKind) -> bool {
    matches!(kind, AssertFailureKind::SlotNeedsOtherUv)
}

fn classify_assert_stderr(stderr: &str) -> AssertFailureKind {
    let lower = stderr.to_ascii_lowercase();
    let mut best: Option<AssertFailureKind> = None;
    if is_no_credentials_stderr(&lower) {
        best = Some(AssertFailureKind::NoCredential);
    }
    // Keep '_' inside symbolic names. Hex tokens still split on '_', matching
    // `is_no_credentials_stderr`, so `0x2e` is never a prefix of `0x2e8a`.
    let name_tokens: Vec<&str> = lower
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|token| !token.is_empty())
        .collect();
    let hex_tokens: Vec<&str> = lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .collect();
    for code in ASSERT_FAILURE_CODES {
        let hit = name_tokens.contains(&code.name) || hex_tokens.contains(&code.hex);
        if hit {
            best = Some(match best {
                Some(prev) if kind_rank(prev) >= kind_rank(code.kind) => prev,
                _ => code.kind,
            });
        }
    }
    best.unwrap_or(AssertFailureKind::Device)
}

impl From<VaultError> for (AssertFailureKind, VaultError) {
    fn from(err: VaultError) -> Self {
        (AssertFailureKind::Device, err)
    }
}

fn failure_from_stderr(
    tool: &str,
    stderr: &[u8],
    status: ExitStatus,
) -> (AssertFailureKind, VaultError) {
    let stderr_text = String::from_utf8_lossy(stderr);
    let kind = classify_assert_stderr(&stderr_text);
    let err = if kind == AssertFailureKind::NoCredential {
        VaultError::Fido2NoMatchingCredential
    } else {
        let detail = sanitize_stderr_snippet(&stderr_text);
        let msg = if detail.is_empty() {
            format!("`{tool}` failed with status {status}")
        } else {
            format!("`{tool}` failed: {detail}")
        };
        VaultError::Fido2Error(msg)
    };
    (kind, err)
}

/// Non-UV slots first, then UV slots. Indices are the original positions in `slots`.
fn slot_probe_order(slots: &[Fido2KeySlot]) -> Vec<usize> {
    let mut order = Vec::with_capacity(slots.len());
    order.extend(
        slots
            .iter()
            .enumerate()
            .filter(|(_, slot)| !slot.fido2.require_uv)
            .map(|(idx, _)| idx),
    );
    order.extend(
        slots
            .iter()
            .enumerate()
            .filter(|(_, slot)| slot.fido2.require_uv)
            .map(|(idx, _)| idx),
    );
    order
}

/// `attempt(device_idx, slot_idx)` performs one assertion.
fn probe_slots<F>(
    n_devices: usize,
    slots: &[Fido2KeySlot],
    mut attempt: F,
) -> Result<(usize, Zeroizing<[u8; 32]>)>
where
    F: FnMut(usize, usize) -> AssertOutcome,
{
    if cancel_requested() {
        return Err(cancelled_error());
    }
    let order = slot_probe_order(slots);
    let mut remembered: Option<(AssertFailureKind, VaultError)> = None;
    for device_idx in 0..n_devices {
        if cancel_requested() {
            return Err(cancelled_error());
        }
        for &slot_idx in &order {
            if cancel_requested() {
                return Err(cancelled_error());
            }
            match attempt(device_idx, slot_idx) {
                Ok(secret) => return Ok((slot_idx, secret)),
                Err((kind, err)) => {
                    if is_cancelled_error(&err) {
                        return Err(err);
                    }
                    match kind {
                        AssertFailureKind::NoCredential | AssertFailureKind::SlotNeedsOtherUv => {
                            remembered = Some(prefer_failure(remembered, (kind, err)));
                        }
                        AssertFailureKind::Device => {
                            remembered = Some(prefer_failure(remembered, (kind, err)));
                            break;
                        }
                        AssertFailureKind::StopPinProblem => return Err(err),
                    }
                }
            }
        }
    }
    Err(remembered
        .map(|(_, err)| err)
        .unwrap_or(VaultError::Fido2NoMatchingCredential))
}

fn is_no_credentials_stderr(stderr: &str) -> bool {
    let lower = stderr.to_ascii_lowercase();
    if lower.contains("fido_err_no_credentials") || lower.contains("no credentials") {
        return true;
    }
    // Match `0x2e` only as a standalone hex token (never prefixes like `0x2e8a`).
    lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|tok| tok == "0x2e")
}

fn sanitize_stderr_snippet(stderr: &str) -> String {
    stderr
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(" | ")
        .chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect()
}

impl Fido2Provider for LibFido2Cli {
    fn enroll(&self, device: Option<&str>, require_uv: bool) -> Result<Fido2Metadata> {
        let dev = Self::resolve_device(device)?;
        let bin = Self::resolve_tool("fido2-cred")?;

        let mut client_data_hash = [0u8; 32];
        let mut user_id = [0u8; 32];
        let mut hmac_salt = [0u8; 32];
        fill_random(&mut client_data_hash)?;
        fill_random(&mut user_id)?;
        fill_random(&mut hmac_salt)?;

        let expected_cdh_b64 = BASE64.encode(&client_data_hash);
        let stdin_payload = Zeroizing::new(format!(
            "{}\n{}\n{}\n{}\n",
            expected_cdh_b64,
            DEFAULT_RP_ID,
            USER_NAME,
            BASE64.encode(&user_id),
        ));

        let mut cmd = Command::new(bin);
        cmd.arg("-M").arg("-h");
        if require_uv {
            cmd.arg("-v");
        }
        cmd.arg("--")
            .arg(&dev)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        if cancel_requested() {
            return Err(cancelled_error());
        }

        eprintln!(
            "Touch your FIDO2 security key to enroll it with omavault (RP: {DEFAULT_RP_ID}, UV: {require_uv})..."
        );

        let mut child = spawn_grouped(&mut cmd)
            .map_err(|e| VaultError::Fido2Error(format!("failed to launch `fido2-cred`: {e}")))?;

        write_stdin_or_reap(&mut child, stdin_payload.as_bytes(), "fido2-cred")?;
        let output = wait_with_timeout(child, FIDO2_CMD_TIMEOUT, "fido2-cred")?;
        let stdout_bytes = output.stdout;

        if !output.status.success() {
            return Err(VaultError::Fido2Error(format!(
                "`fido2-cred` failed with status {}",
                output.status
            )));
        }

        // Per fido2-cred(1):
        // 0: client data hash, 1: rp id, 2: cred format, 3: authdata, 4: credential id
        let stdout = std::str::from_utf8(&stdout_bytes)
            .map_err(|_| VaultError::Fido2Error("non-UTF8 output from `fido2-cred`".into()))?;
        let lines: Vec<&str> = stdout.lines().collect();
        if lines.len() < 5 {
            return Err(VaultError::Fido2Error(
                "unexpected `fido2-cred` output format".into(),
            ));
        }

        if lines[0].trim() != expected_cdh_b64 || lines[1].trim() != DEFAULT_RP_ID {
            return Err(VaultError::Fido2Error(
                "FIDO2 enrollment response failed challenge/RP verification".into(),
            ));
        }
        verify_authdata_flags(lines[3].trim(), DEFAULT_RP_ID, require_uv, true, true)?;

        let cred_id_b64 = lines[4].trim().to_string();
        let meta = Fido2Metadata {
            rp_id: DEFAULT_RP_ID.to_string(),
            credential_id_b64: cred_id_b64,
            hmac_salt_b64: BASE64.encode(&hmac_salt),
            require_uv,
        };
        meta.validate()?;
        Ok(meta)
    }

    fn get_hmac_secret(
        &self,
        meta: &Fido2Metadata,
        device: Option<&str>,
    ) -> Result<Zeroizing<[u8; 32]>> {
        self.assert_on_any_device(meta, device)
    }

    fn assert_matching_slot(
        &self,
        slots: &[Fido2KeySlot],
        device: Option<&str>,
    ) -> Result<(usize, Zeroizing<[u8; 32]>)> {
        if slots.is_empty() {
            return Err(VaultError::Fido2Required);
        }
        if cancel_requested() {
            return Err(cancelled_error());
        }
        let devices = Self::resolve_devices(device)?;
        probe_slots(devices.len(), slots, |device_idx, slot_idx| {
            self.assert_on_device_classified(&slots[slot_idx].fido2, &devices[device_idx], false)
        })
    }
}

/// Strictly verify CBOR-encoded CTAP2 authenticator data:
/// - Must be valid CBOR major-type-2 byte string (fail closed, no raw fallback)
/// - `authdata[0..32]` must equal `SHA-256(expected_rp_id)`
/// - `UP` (0x01) required; `UV` (0x04), `AT` (0x40), `ED` (0x80) verified as requested.
fn verify_authdata_flags(
    authdata_b64: &str,
    expected_rp_id: &str,
    require_uv: bool,
    require_at: bool,
    require_ed: bool,
) -> Result<()> {
    let raw = BASE64
        .decode(authdata_b64.as_bytes())
        .map_err(|_| VaultError::Fido2Error("invalid Base64 FIDO2 authdata".into()))?;
    let authdata = unwrap_cbor_bstr(&raw).ok_or_else(|| {
        VaultError::Fido2Error("FIDO2 authdata is not a valid CBOR byte string".into())
    })?;
    if authdata.len() < 37 {
        return Err(VaultError::Fido2Error(
            "FIDO2 authdata truncated (expected >= 37 bytes)".into(),
        ));
    }
    let expected_rp_hash = Sha256::digest(expected_rp_id.as_bytes());
    if authdata[0..32] != expected_rp_hash[..] {
        return Err(VaultError::Fido2Error(
            "FIDO2 authdata rpIdHash does not match expected relying party".into(),
        ));
    }
    let flags = authdata[32];
    let up = (flags & 0x01) != 0;
    let uv = (flags & 0x04) != 0;
    let at = (flags & 0x40) != 0;
    let ed = (flags & 0x80) != 0;
    if !up {
        return Err(VaultError::Fido2Error(
            "FIDO2 authenticator did not confirm User Presence (UP)".into(),
        ));
    }
    if require_uv && !uv {
        return Err(VaultError::Fido2Error(
            "FIDO2 authenticator did not confirm User Verification (UV)".into(),
        ));
    }
    if require_at && !at {
        return Err(VaultError::Fido2Error(
            "FIDO2 enrollment authdata missing Attested Credential Data (AT) flag".into(),
        ));
    }
    if require_ed && !ed {
        return Err(VaultError::Fido2Error(
            "FIDO2 authdata missing Extension Data (ED) flag for hmac-secret".into(),
        ));
    }
    Ok(())
}

fn apply_pdeathsig(cmd: &mut Command) {
    #[cfg(target_os = "linux")]
    unsafe {
        let parent = libc::getpid();
        cmd.pre_exec(move || {
            let _ = libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM, 0, 0, 0);
            if libc::getppid() != parent {
                return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
            }
            Ok(())
        });
    }
    #[cfg(not(target_os = "linux"))]
    let _ = cmd;
}

/// Owns a `fido2-*` child that lives in its own process group.
///
/// `spawn` can return before the child finishes `setpgid(0, 0)`, so a group-only
/// signal can miss. Drop kills the group and the pid, and refuses `pgid <= 0`
/// (`kill(-0)` would signal the caller).
struct ChildGuard {
    child: Child,
    pgid: i32,
    done: bool,
}

impl ChildGuard {
    fn kill_group(&mut self) {
        if self.done {
            return;
        }
        if self.pgid > 0 {
            unsafe {
                libc::kill(-self.pgid, libc::SIGKILL);
                libc::kill(self.pgid, libc::SIGKILL);
            }
        }
        let _ = self.child.wait();
        self.done = true;
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !self.done {
            self.kill_group();
        }
    }
}

fn spawn_grouped(cmd: &mut Command) -> std::io::Result<ChildGuard> {
    apply_pdeathsig(cmd);
    let mut child = cmd.process_group(0).spawn()?;
    let pgid = i32::try_from(child.id()).unwrap_or(-1);
    if pgid <= 0 {
        let _ = child.kill();
        let _ = child.wait();
        return Err(std::io::Error::other(
            "refusing to track a FIDO2 child with a non-positive process group",
        ));
    }
    Ok(ChildGuard {
        child,
        pgid,
        done: false,
    })
}

struct BoundedOutput {
    status: ExitStatus,
    stdout: Zeroizing<Vec<u8>>,
    stderr: Vec<u8>,
}

const MAX_FIDO2_STDOUT_BYTES: u64 = 64 * 1024;
const MAX_FIDO2_STDERR_BYTES: u64 = 8 * 1024;

/// Decode a CBOR major-type-2 byte string wrapper if present.
fn unwrap_cbor_bstr(data: &[u8]) -> Option<&[u8]> {
    let first = *data.first()?;
    if (first >> 5) != 2 {
        return None;
    }
    let ai = first & 0x1f;
    let (hdr_len, bstr_len) = match ai {
        0..=23 => (1usize, ai as usize),
        24 => (2, *data.get(1)? as usize),
        25 => (
            3,
            u16::from_be_bytes([*data.get(1)?, *data.get(2)?]) as usize,
        ),
        26 => (
            5,
            u32::from_be_bytes([*data.get(1)?, *data.get(2)?, *data.get(3)?, *data.get(4)?])
                as usize,
        ),
        _ => return None,
    };
    let end = hdr_len.checked_add(bstr_len)?;
    if end == data.len() {
        Some(&data[hdr_len..end])
    } else {
        None
    }
}

fn write_stdin_or_reap(guard: &mut ChildGuard, data: &[u8], tool: &str) -> Result<()> {
    if let Some(mut stdin) = guard.child.stdin.take() {
        if let Err(e) = stdin.write_all(data) {
            if e.kind() != std::io::ErrorKind::BrokenPipe {
                guard.kill_group();
                return Err(VaultError::Fido2Error(format!(
                    "failed writing to `{tool}`: {e}"
                )));
            }
        }
    }
    Ok(())
}

fn join_drained(
    stdout_handle: Option<thread::JoinHandle<Zeroizing<Vec<u8>>>>,
    stderr_handle: Option<thread::JoinHandle<Vec<u8>>>,
) -> (Zeroizing<Vec<u8>>, Vec<u8>) {
    let stdout = stdout_handle
        .and_then(|handle| handle.join().ok())
        .unwrap_or_else(|| Zeroizing::new(Vec::new()));
    let stderr = stderr_handle
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default();
    (stdout, stderr)
}

fn wait_with_timeout(
    mut guard: ChildGuard,
    timeout: Duration,
    tool: &str,
) -> Result<BoundedOutput> {
    // Drain piped stdout/stderr concurrently on bounded reader threads so >64 KiB child output
    // can never deadlock the pipe while we poll `try_wait()`.
    let stdout_handle = guard.child.stdout.take().map(|out| {
        thread::spawn(move || {
            // Pre-size so the hmac-secret output never goes through growth reallocations.
            let mut buf = Zeroizing::new(Vec::with_capacity(MAX_FIDO2_STDOUT_BYTES as usize + 1));
            let _ = out.take(MAX_FIDO2_STDOUT_BYTES).read_to_end(&mut buf);
            buf
        })
    });
    let stderr_handle = guard.child.stderr.take().map(|err| {
        thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = err.take(MAX_FIDO2_STDERR_BYTES).read_to_end(&mut buf);
            buf
        })
    });

    let deadline = Instant::now() + timeout;
    let status = loop {
        if cancel_requested() {
            guard.kill_group();
            join_drained(stdout_handle, stderr_handle);
            return Err(cancelled_error());
        }
        match guard.child.try_wait() {
            Ok(Some(status)) => {
                // Already reaped. Drop must not wait again.
                guard.done = true;
                break status;
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    guard.kill_group();
                    join_drained(stdout_handle, stderr_handle);
                    return Err(VaultError::Fido2Error(format!(
                        "`{tool}` timed out after {}s",
                        timeout.as_secs()
                    )));
                }
                thread::sleep(Duration::from_millis(25));
            }
            Err(e) => {
                guard.kill_group();
                join_drained(stdout_handle, stderr_handle);
                return Err(VaultError::Fido2Error(format!(
                    "failed waiting on `{tool}`: {e}"
                )));
            }
        }
    };

    let (stdout, stderr) = join_drained(stdout_handle, stderr_handle);
    Ok(BoundedOutput {
        status,
        stdout,
        stderr,
    })
}

/// Deterministic software mock FIDO2 authenticator compiled ONLY for tests (`test-utils`).
#[cfg(any(test, feature = "test-utils"))]
#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct MockFido2Provider {
    pub token_secret: [u8; 32],
}

#[cfg(any(test, feature = "test-utils"))]
impl std::fmt::Debug for MockFido2Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockFido2Provider")
            .field("token_secret", &"[REDACTED]")
            .finish()
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl Fido2Provider for MockFido2Provider {
    fn enroll(&self, _device: Option<&str>, require_uv: bool) -> Result<Fido2Metadata> {
        let mut cred_id = [0u8; 32];
        let mut hmac_salt = [0u8; 32];
        fill_random(&mut cred_id)?;
        fill_random(&mut hmac_salt)?;
        Ok(Fido2Metadata {
            rp_id: DEFAULT_RP_ID.to_string(),
            credential_id_b64: BASE64.encode(&cred_id),
            hmac_salt_b64: BASE64.encode(&hmac_salt),
            require_uv,
        })
    }

    fn get_hmac_secret(
        &self,
        meta: &Fido2Metadata,
        _device: Option<&str>,
    ) -> Result<Zeroizing<[u8; 32]>> {
        meta.validate()?;
        let mut hasher = blake3::Hasher::new_keyed(&self.token_secret);
        hasher.update(&(meta.rp_id.len() as u32).to_le_bytes());
        hasher.update(meta.rp_id.as_bytes());
        hasher.update(&(meta.credential_id_b64.len() as u32).to_le_bytes());
        hasher.update(meta.credential_id_b64.as_bytes());
        hasher.update(&(meta.hmac_salt_b64.len() as u32).to_le_bytes());
        hasher.update(meta.hmac_salt_b64.as_bytes());
        let hash = hasher.finalize();
        Ok(Zeroizing::new(*hash.as_bytes()))
    }
}

/// Credential-aware mock FIDO2 hardware key for testing multi-YubiKey slot matching (`test-utils`).
///
/// Faithfully simulates CTAP2 behavior: returns `VaultError::Fido2NoMatchingCredential` for
/// credentials enrolled on a different token, and computes a deterministic HMAC secret for its own.
#[cfg(any(test, feature = "test-utils"))]
pub struct MockTrackedFido2Key {
    token_secret: Zeroizing<[u8; 32]>,
    owned_credentials: std::sync::Mutex<Vec<String>>,
}

#[cfg(any(test, feature = "test-utils"))]
impl MockTrackedFido2Key {
    pub fn new(token_secret: [u8; 32]) -> Self {
        Self {
            token_secret: Zeroizing::new(token_secret),
            owned_credentials: std::sync::Mutex::new(Vec::new()),
        }
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl Fido2Provider for MockTrackedFido2Key {
    fn enroll(&self, _device: Option<&str>, require_uv: bool) -> Result<Fido2Metadata> {
        let mut cred_id = [0u8; 32];
        let mut hmac_salt = [0u8; 32];
        fill_random(&mut cred_id)?;
        fill_random(&mut hmac_salt)?;
        let cred_b64 = BASE64.encode(&cred_id);
        self.owned_credentials
            .lock()
            .unwrap()
            .push(cred_b64.clone());
        Ok(Fido2Metadata {
            rp_id: DEFAULT_RP_ID.to_string(),
            credential_id_b64: cred_b64,
            hmac_salt_b64: BASE64.encode(&hmac_salt),
            require_uv,
        })
    }

    fn get_hmac_secret(
        &self,
        meta: &Fido2Metadata,
        _device: Option<&str>,
    ) -> Result<Zeroizing<[u8; 32]>> {
        meta.validate()?;
        let owns = self
            .owned_credentials
            .lock()
            .unwrap()
            .iter()
            .any(|c| c == &meta.credential_id_b64);
        if !owns {
            return Err(VaultError::Fido2NoMatchingCredential);
        }
        let mut hasher = blake3::Hasher::new_keyed(&self.token_secret);
        hasher.update(&(meta.rp_id.len() as u32).to_le_bytes());
        hasher.update(meta.rp_id.as_bytes());
        hasher.update(&(meta.credential_id_b64.len() as u32).to_le_bytes());
        hasher.update(meta.credential_id_b64.as_bytes());
        hasher.update(&(meta.hmac_salt_b64.len() as u32).to_le_bytes());
        hasher.update(meta.hmac_salt_b64.as_bytes());
        let hash = hasher.finalize();
        Ok(Zeroizing::new(*hash.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_flag_injection_and_non_dev_fido2_paths() {
        assert!(LibFido2Cli::validate_device_path("-o/tmp/pwn").is_err());
        assert!(LibFido2Cli::validate_device_path("--help").is_err());
        assert!(LibFido2Cli::validate_device_path("/etc/passwd").is_err());
        assert!(LibFido2Cli::validate_device_path("/dev/../etc/passwd").is_err());
    }

    #[test]
    fn validates_fido2_metadata_strictly() {
        let good = Fido2Metadata {
            rp_id: DEFAULT_RP_ID.into(),
            credential_id_b64: BASE64.encode(&[1u8; 32]),
            hmac_salt_b64: BASE64.encode(&[2u8; 32]),
            require_uv: true,
        };
        assert!(good.validate().is_ok());

        let bad_rp = Fido2Metadata {
            rp_id: "evil.example.com".into(),
            ..good.clone()
        };
        assert!(bad_rp.validate().is_err());

        let bad_salt = Fido2Metadata {
            hmac_salt_b64: BASE64.encode(&[2u8; 16]),
            ..good
        };
        assert!(bad_salt.validate().is_err());
    }

    #[test]
    fn verifies_cbor_authdata_up_and_uv_flags() {
        let rp_hash = Sha256::digest(DEFAULT_RP_ID.as_bytes());
        // Construct valid CBOR byte string (0x58 0x25 = 37 bytes) with rpIdHash + flags + signCount.
        let mut raw = vec![0x58, 37];
        raw.extend_from_slice(&rp_hash);
        raw.push(0x01 | 0x04 | 0x40 | 0x80); // UP | UV | AT | ED
        raw.extend_from_slice(&[0u8; 4]); // signCount
        assert!(
            verify_authdata_flags(&BASE64.encode(&raw), DEFAULT_RP_ID, true, true, true).is_ok()
        );

        // Clear UV bit: passes when require_uv=false, fails when require_uv=true.
        raw[2 + 32] = 0x01 | 0x80; // UP | ED
        assert!(
            verify_authdata_flags(&BASE64.encode(&raw), DEFAULT_RP_ID, false, false, true).is_ok()
        );
        assert!(
            verify_authdata_flags(&BASE64.encode(&raw), DEFAULT_RP_ID, true, false, true).is_err()
        );

        // Missing AT on enrollment fails; missing ED fails.
        assert!(
            verify_authdata_flags(&BASE64.encode(&raw), DEFAULT_RP_ID, false, true, true).is_err()
        );
        raw[2 + 32] = 0x01; // UP only, missing ED
        assert!(
            verify_authdata_flags(&BASE64.encode(&raw), DEFAULT_RP_ID, false, false, true).is_err()
        );

        // Wrong rpIdHash fails.
        raw[2 + 32] = 0x01 | 0x80;
        assert!(
            verify_authdata_flags(&BASE64.encode(&raw), "other.local", false, false, true).is_err()
        );

        // Non-CBOR raw authdata (without major type 2 header) MUST fail closed.
        assert!(verify_authdata_flags(
            &BASE64.encode(&raw[2..]),
            DEFAULT_RP_ID,
            false,
            false,
            true
        )
        .is_err());
    }

    fn test_slot(label: &str, require_uv: bool) -> Fido2KeySlot {
        Fido2KeySlot {
            label: label.into(),
            fido2: Fido2Metadata {
                rp_id: DEFAULT_RP_ID.into(),
                credential_id_b64: BASE64.encode(label.as_bytes()),
                hmac_salt_b64: BASE64.encode(&[0u8; 32]),
                require_uv,
            },
            wrap_nonce_b64: String::new(),
            wrapped_key_b64: String::new(),
        }
    }

    fn assert_pid_gone(pid: i32) {
        assert!(pid > 0, "refusing to signal a non-positive pid");
        let started = Instant::now();
        loop {
            let rc = unsafe { libc::kill(pid, 0) };
            if rc == -1 {
                let err = std::io::Error::last_os_error().raw_os_error();
                assert_eq!(err, Some(libc::ESRCH), "kill({pid}, 0) errno {err:?}");
                return;
            }
            if started.elapsed() > Duration::from_secs(1) {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
                panic!("pid {pid} still alive after 1s");
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn assert_on_device_rejects_bad_metadata_before_spawn() {
        let meta = Fido2Metadata {
            rp_id: "evil.example".into(),
            credential_id_b64: BASE64.encode(&[1u8; 32]),
            hmac_salt_b64: BASE64.encode(&[2u8; 32]),
            require_uv: false,
        };
        let err = match LibFido2Cli.assert_on_device(&meta, "/dev/hidraw0", false) {
            Err(err) => err,
            Ok(_) => panic!("bad metadata was accepted"),
        };
        assert!(matches!(err, VaultError::Fido2Error(_)));
    }

    #[test]
    fn classifies_assert_stderr_by_code() {
        let cases = [
            ("FIDO_ERR_NO_CREDENTIALS", AssertFailureKind::NoCredential),
            ("fido_err_no_credentials", AssertFailureKind::NoCredential),
            ("0x2e", AssertFailureKind::NoCredential),
            ("no credentials", AssertFailureKind::NoCredential),
            ("FIDO_ERR_PIN_NOT_SET", AssertFailureKind::SlotNeedsOtherUv),
            ("0x35", AssertFailureKind::SlotNeedsOtherUv),
            (
                "FIDO_ERR_UNSUPPORTED_OPTION",
                AssertFailureKind::SlotNeedsOtherUv,
            ),
            ("0x2b", AssertFailureKind::SlotNeedsOtherUv),
            (
                "FIDO_ERR_INVALID_OPTION",
                AssertFailureKind::SlotNeedsOtherUv,
            ),
            ("0x2c", AssertFailureKind::SlotNeedsOtherUv),
            ("FIDO_ERR_PIN_INVALID", AssertFailureKind::StopPinProblem),
            ("0x31", AssertFailureKind::StopPinProblem),
            ("FIDO_ERR_PIN_BLOCKED", AssertFailureKind::StopPinProblem),
            ("0x32", AssertFailureKind::StopPinProblem),
            (
                "FIDO_ERR_PIN_AUTH_INVALID",
                AssertFailureKind::StopPinProblem,
            ),
            ("0x33", AssertFailureKind::StopPinProblem),
            (
                "FIDO_ERR_PIN_AUTH_BLOCKED",
                AssertFailureKind::StopPinProblem,
            ),
            ("0x34", AssertFailureKind::StopPinProblem),
            ("FIDO_ERR_PIN_REQUIRED", AssertFailureKind::StopPinProblem),
            ("0x36", AssertFailureKind::StopPinProblem),
            ("FIDO_ERR_UV_BLOCKED", AssertFailureKind::StopPinProblem),
            ("0x3c", AssertFailureKind::StopPinProblem),
            ("0x3C", AssertFailureKind::StopPinProblem),
            ("FIDO_ERR_UV_INVALID", AssertFailureKind::StopPinProblem),
            ("0x3f", AssertFailureKind::StopPinProblem),
            (
                "FIDO_ERR_OPERATION_DENIED",
                AssertFailureKind::StopPinProblem,
            ),
            ("0x27", AssertFailureKind::StopPinProblem),
            ("something else entirely", AssertFailureKind::Device),
            ("0x350", AssertFailureKind::Device),
            ("0x2e8a", AssertFailureKind::Device),
            ("code 0x350", AssertFailureKind::Device),
        ];
        for (input, expected) in cases {
            assert_eq!(classify_assert_stderr(input), expected, "{input}");
        }
    }

    #[test]
    fn uv_retry_only_when_slot_needs_other_uv() {
        assert!(should_retry_with_uv(AssertFailureKind::SlotNeedsOtherUv));
        assert!(!should_retry_with_uv(AssertFailureKind::StopPinProblem));
        assert!(!should_retry_with_uv(AssertFailureKind::NoCredential));
        assert!(!should_retry_with_uv(AssertFailureKind::Device));
    }

    #[test]
    fn probe_slots_matches_non_uv_slot_after_uv_option_failure() {
        // Stored UV-first. A PIN/option failure on A must not hide non-UV slot B (M-7).
        let slots = vec![test_slot("A", true), test_slot("B", false)];
        let (idx, secret) = probe_slots(1, &slots, |_dev, slot_idx| {
            if slots[slot_idx].fido2.require_uv {
                Err((
                    AssertFailureKind::SlotNeedsOtherUv,
                    VaultError::Fido2Error("FIDO_ERR_PIN_NOT_SET".into()),
                ))
            } else {
                Ok(Zeroizing::new([9u8; 32]))
            }
        })
        .expect("non-UV slot matches");
        assert_eq!(idx, 1);
        assert_eq!(secret.as_slice(), &[9u8; 32]);
    }

    #[test]
    fn probe_slots_continues_to_the_next_slot_after_other_uv() {
        // Non-UV misses, the first UV slot cannot do PIN, a later UV slot still matches.
        let slots = vec![
            test_slot("A", true),
            test_slot("B", false),
            test_slot("C", true),
        ];
        let (idx, secret) = probe_slots(1, &slots, |_dev, slot_idx| {
            match slots[slot_idx].label.as_str() {
                "B" => Err((
                    AssertFailureKind::NoCredential,
                    VaultError::Fido2NoMatchingCredential,
                )),
                "A" => Err((
                    AssertFailureKind::SlotNeedsOtherUv,
                    VaultError::Fido2Error("FIDO_ERR_PIN_NOT_SET".into()),
                )),
                "C" => Ok(Zeroizing::new([3u8; 32])),
                other => panic!("unexpected slot {other}"),
            }
        })
        .expect("later UV slot matches");
        assert_eq!(idx, 2);
        assert_eq!(secret.as_slice(), &[3u8; 32]);
    }

    #[test]
    fn probe_slots_stops_on_pin_problem_without_another_uv_attempt() {
        let slots = vec![
            test_slot("A", true),
            test_slot("B", false),
            test_slot("C", true),
        ];
        let mut uv_calls = 0;
        let mut devices = Vec::new();
        let err = probe_slots(2, &slots, |dev, slot_idx| {
            devices.push(dev);
            if slots[slot_idx].fido2.require_uv {
                uv_calls += 1;
                Err((
                    AssertFailureKind::StopPinProblem,
                    VaultError::Fido2Error("FIDO_ERR_PIN_INVALID".into()),
                ))
            } else {
                Err((
                    AssertFailureKind::NoCredential,
                    VaultError::Fido2NoMatchingCredential,
                ))
            }
        })
        .expect_err("pin failure stops the probe");
        assert!(matches!(err, VaultError::Fido2Error(msg) if msg == "FIDO_ERR_PIN_INVALID"));
        assert_eq!(uv_calls, 1);
        assert!(devices.iter().all(|dev| *dev == 0));
    }

    #[test]
    fn probe_slots_continues_on_the_next_device_after_a_device_error() {
        let slots = vec![test_slot("B", false)];
        let mut seen = Vec::new();
        let (idx, secret) = probe_slots(2, &slots, |dev, _slot_idx| {
            seen.push(dev);
            if dev == 0 {
                Err((
                    AssertFailureKind::Device,
                    VaultError::Fido2Error("io error".into()),
                ))
            } else {
                Ok(Zeroizing::new([4u8; 32]))
            }
        })
        .expect("device 1 matches");
        assert_eq!(idx, 0);
        assert_eq!(seen, vec![0, 1]);
        assert_eq!(secret.as_slice(), &[4u8; 32]);
    }

    #[test]
    fn probe_slots_tries_non_uv_before_uv_on_each_device() {
        let slots = vec![
            test_slot("A", true),
            test_slot("B", false),
            test_slot("C", true),
        ];
        let mut order = Vec::new();
        let err = probe_slots(2, &slots, |dev, slot_idx| {
            order.push((dev, slot_idx));
            Err((
                AssertFailureKind::NoCredential,
                VaultError::Fido2NoMatchingCredential,
            ))
        })
        .expect_err("nothing matches");
        assert!(matches!(err, VaultError::Fido2NoMatchingCredential));
        assert_eq!(order, vec![(0, 1), (0, 0), (0, 2), (1, 1), (1, 0), (1, 2)]);
    }

    #[test]
    fn probe_slots_prefers_the_most_informative_remembered_error() {
        let slots = vec![test_slot("B", false)];
        let err = probe_slots(2, &slots, |dev, _slot_idx| {
            if dev == 0 {
                Err((
                    AssertFailureKind::SlotNeedsOtherUv,
                    VaultError::Fido2Error("no pin".into()),
                ))
            } else {
                Err((
                    AssertFailureKind::Device,
                    VaultError::Fido2Error("io error".into()),
                ))
            }
        })
        .expect_err("no match");
        assert!(matches!(err, VaultError::Fido2Error(msg) if msg == "no pin"));
    }

    #[test]
    fn probe_slots_does_not_treat_cancel_as_a_device_error() {
        let slots = vec![test_slot("B", false)];
        let mut calls = 0;
        let err = probe_slots(2, &slots, |_dev, _slot_idx| {
            calls += 1;
            Err((AssertFailureKind::Device, cancelled_error()))
        })
        .expect_err("cancel stops the probe");
        assert_eq!(calls, 1);
        assert!(is_cancelled_error(&err));

        let cancel = Fido2Cancel::new();
        cancel.cancel();
        let err = with_cancel(&cancel, || {
            probe_slots(1, &slots, |_dev, _slot_idx| {
                panic!("must not attempt an assertion after cancel");
            })
        })
        .expect_err("already cancelled");
        assert!(is_cancelled_error(&err));
    }

    #[test]
    fn child_guard_kills_process_group_on_drop() {
        let mut cmd = Command::new("sleep");
        cmd.arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let guard = spawn_grouped(&mut cmd).expect("spawn sleep");
        let pid = guard.pgid;
        drop(guard);
        assert_pid_gone(pid);
    }

    #[test]
    fn child_guard_kills_process_group_on_unwind() {
        let mut cmd = Command::new("sleep");
        cmd.arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let pid = std::sync::atomic::AtomicI32::new(0);
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let guard = spawn_grouped(&mut cmd).expect("spawn sleep");
            pid.store(guard.pgid, Ordering::SeqCst);
            panic!("unwind with a live fido child");
        }));
        assert!(panicked.is_err());
        let pid = pid.load(Ordering::SeqCst);
        assert_pid_gone(pid);
    }

    #[test]
    fn cancel_stops_wait_and_reaps_the_child() {
        let mut cmd = Command::new("sleep");
        cmd.arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let guard = spawn_grouped(&mut cmd).expect("spawn sleep");
        let pid = guard.pgid;
        let cancel = Fido2Cancel::new();
        let cancel_thread = cancel.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            cancel_thread.cancel();
        });
        let started = Instant::now();
        let err = match with_cancel(&cancel, || {
            wait_with_timeout(guard, Duration::from_secs(45), "sleep")
        }) {
            Err(err) => err,
            Ok(_) => panic!("cancelled wait returned success"),
        };
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "elapsed {:?}",
            started.elapsed()
        );
        match err {
            VaultError::Fido2Error(msg) => assert_eq!(msg, "FIDO2 operation cancelled"),
            other => panic!("unexpected {other:?}"),
        }
        assert_pid_gone(pid);
    }

    struct IndexPastEnd;

    impl Fido2Provider for IndexPastEnd {
        fn enroll(&self, _device: Option<&str>, _require_uv: bool) -> Result<Fido2Metadata> {
            Err(VaultError::Fido2Error("enroll unused".into()))
        }

        fn get_hmac_secret(
            &self,
            _meta: &Fido2Metadata,
            _device: Option<&str>,
        ) -> Result<Zeroizing<[u8; 32]>> {
            Err(VaultError::Fido2Error("hmac unused".into()))
        }

        fn assert_matching_slot(
            &self,
            _slots: &[Fido2KeySlot],
            _device: Option<&str>,
        ) -> Result<(usize, Zeroizing<[u8; 32]>)> {
            Ok((1, Zeroizing::new([0x5a; 32])))
        }
    }

    #[test]
    fn resolve_master_key_out_of_range_slot_does_not_panic() {
        let params = crate::crypto::kdf::KdfParams {
            mem_kib: 32,
            time_cost: 1,
            parallelism: 1,
        };
        let mut header =
            crate::crypto::VaultHeader::new_v2_fido2_shell(params, false).expect("v2 shell");
        header.fido2_slots.push(test_slot("only", false));
        let err = match crate::crypto::resolve_master_key(
            &header,
            b"pw",
            None,
            &IndexPastEnd,
            None,
            false,
        ) {
            Err(err) => err,
            Ok(_) => panic!("out-of-range slot unlocked"),
        };
        assert!(matches!(err, VaultError::Fido2NoMatchingCredential));
    }

    #[test]
    fn to_bytes_rejects_mem_kib_above_the_ceiling() {
        let params = crate::crypto::kdf::KdfParams {
            mem_kib: crate::crypto::kdf::MAX_ARGON2_MEM_KIB + 1,
            time_cost: 1,
            parallelism: 1,
        };
        let header = crate::crypto::VaultHeader::new_v2_fido2_shell(params, false).expect("shell");
        let err = header.to_bytes().expect_err("absurd mem_kib");
        assert!(matches!(err, VaultError::WeakKdfParameters(_)));
    }
}
