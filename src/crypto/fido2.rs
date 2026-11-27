use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
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
        for (idx, slot) in slots.iter().enumerate() {
            match self.get_hmac_secret(&slot.fido2, device) {
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
        let canonical_str = canonical.to_str().ok_or_else(|| {
            VaultError::Fido2Error("FIDO2 device path is not valid UTF-8".into())
        })?;
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
        let bin = Self::resolve_tool("fido2-token")?;
        let mut cmd = Command::new(bin);
        cmd.arg("-L")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        apply_pdeathsig(&mut cmd);
        let child = cmd.spawn().map_err(|e| {
            VaultError::Fido2Error(format!("failed to execute `fido2-token`: {e}"))
        })?;

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
        Self::discover_devices()?
            .into_iter()
            .next()
            .ok_or_else(|| {
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

    fn assert_on_device(
        &self,
        meta: &Fido2Metadata,
        dev: &str,
        print_prompt: bool,
    ) -> Result<Zeroizing<[u8; 32]>> {
        meta.validate()?;
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
        if meta.require_uv {
            // `-t pin=true` prompts for PIN & requests user verification on PIN-based tokens
            // (e.g., YubiKey 5 Series), matching `fido2-cred -v` behavior consistently.
            cmd.arg("-t").arg("pin=true");
        }
        cmd.arg("--")
            .arg(dev)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        apply_pdeathsig(&mut cmd);

        if print_prompt {
            eprintln!(
                "Touch your FIDO2 security key to unlock omavault (RP: {}, UV: {})...",
                meta.rp_id, meta.require_uv
            );
        }

        let mut child = cmd
            .spawn()
            .map_err(|e| VaultError::Fido2Error(format!("failed to launch `fido2-assert`: {e}")))?;

        write_stdin_or_reap(&mut child, stdin_payload.as_bytes(), "fido2-assert")?;
        let output = wait_with_timeout(child, FIDO2_CMD_TIMEOUT, "fido2-assert")?;
        // stdout is already wrapped in Zeroizing BEFORE inspecting status.
        let stdout_bytes = output.stdout;

        if !output.status.success() {
            let stderr_text = String::from_utf8_lossy(&output.stderr);
            if is_no_credentials_stderr(&stderr_text) {
                return Err(VaultError::Fido2NoMatchingCredential);
            }
            let detail = sanitize_stderr_snippet(&stderr_text);
            let msg = if detail.is_empty() {
                format!("`fido2-assert` failed with status {}", output.status)
            } else {
                format!("`fido2-assert` failed: {detail}")
            };
            return Err(VaultError::Fido2Error(msg));
        }

        let stdout_str = std::str::from_utf8(&stdout_bytes)
            .map_err(|_| VaultError::Fido2Error("non-UTF8 output from `fido2-assert`".into()))?;
        let lines: Vec<&str> = stdout_str.lines().collect();

        // Per fido2-assert(1) for non-resident + -h:
        // 0: client data hash, 1: rp id, 2: authdata, 3: signature, 4: hmac secret (32B)
        if lines.len() != 5 {
            return Err(VaultError::Fido2Error(
                "unexpected `fido2-assert` output line count".into(),
            ));
        }

        if lines[0].trim() != expected_cdh_b64 || lines[1].trim() != meta.rp_id {
            return Err(VaultError::Fido2Error(
                "FIDO2 assertion failed challenge/RP verification".into(),
            ));
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
            )));
        }

        let mut secret = Zeroizing::new([0u8; 32]);
        secret.copy_from_slice(&decoded);
        Ok(secret)
    }
    /// Probe all connected FIDO2 devices (or an explicit device) for a specific credential.
    pub fn assert_on_any_device(
        &self,
        meta: &Fido2Metadata,
        device: Option<&str>,
    ) -> Result<Zeroizing<[u8; 32]>> {
        let devices = Self::resolve_devices(device)?;
        let mut last_err = VaultError::Fido2NoMatchingCredential;
        for dev in &devices {
            match self.assert_on_device(meta, dev, false) {
                Ok(secret) => return Ok(secret),
                Err(VaultError::Fido2NoMatchingCredential) => continue,
                Err(e) => {
                    last_err = e;
                }
            }
        }
        Err(last_err)
    }
}

fn is_no_credentials_stderr(stderr: &str) -> bool {
    let lower = stderr.to_ascii_lowercase();
    if lower.contains("fido_err_no_credentials") || lower.contains("no credentials") {
        return true;
    }
    // Match `0x2e` only as a standalone hex token (never prefixes like `0x2e8a`).
    lower.split(|c: char| !c.is_ascii_alphanumeric()).any(|tok| tok == "0x2e")
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
        apply_pdeathsig(&mut cmd);

        eprintln!(
            "Touch your FIDO2 security key to enroll it with omavault (RP: {DEFAULT_RP_ID}, UV: {require_uv})..."
        );

        let mut child = cmd
            .spawn()
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
        let dev = Self::resolve_device(device)?;
        self.assert_on_device(meta, &dev, false)
    }

    fn assert_matching_slot(
        &self,
        slots: &[Fido2KeySlot],
        device: Option<&str>,
    ) -> Result<(usize, Zeroizing<[u8; 32]>)> {
        if slots.is_empty() {
            return Err(VaultError::Fido2Required);
        }
        let devices = Self::resolve_devices(device)?;
        let mut last_err = VaultError::Fido2NoMatchingCredential;
        for dev in &devices {
            for (idx, slot) in slots.iter().enumerate() {
                match self.assert_on_device(&slot.fido2, dev, false) {
                    Ok(secret) => return Ok((idx, secret)),
                    Err(VaultError::Fido2NoMatchingCredential) => continue,
                    Err(e) => {
                        // Record non-matching error for this device and keep probing remaining
                        // connected devices rather than aborting multi-device fallback prematurely.
                        last_err = e;
                        break;
                    }
                }
            }
        }
        Err(last_err)
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
        cmd.pre_exec(|| {
            let _ = libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM, 0, 0, 0);
            Ok(())
        });
    }
    #[cfg(not(target_os = "linux"))]
    let _ = cmd;
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
        25 => (3, u16::from_be_bytes([*data.get(1)?, *data.get(2)?]) as usize),
        26 => (
            5,
            u32::from_be_bytes([
                *data.get(1)?,
                *data.get(2)?,
                *data.get(3)?,
                *data.get(4)?,
            ]) as usize,
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

fn write_stdin_or_reap(child: &mut Child, data: &[u8], tool: &str) -> Result<()> {
    if let Some(mut stdin) = child.stdin.take() {
        if let Err(e) = stdin.write_all(data) {
            if e.kind() != std::io::ErrorKind::BrokenPipe {
                let _ = child.kill();
                let _ = child.wait();
                return Err(VaultError::Fido2Error(format!(
                    "failed writing to `{tool}`: {e}"
                )));
            }
        }
    }
    Ok(())
}

fn wait_with_timeout(mut child: Child, timeout: Duration, tool: &str) -> Result<BoundedOutput> {
    // Drain piped stdout/stderr concurrently on bounded reader threads so >64 KiB child output
    // can never deadlock the pipe while we poll `try_wait()`.
    let stdout_handle = child.stdout.take().map(|out| {
        thread::spawn(move || {
            let mut buf = Zeroizing::new(Vec::new());
            let _ = out.take(MAX_FIDO2_STDOUT_BYTES).read_to_end(&mut buf);
            buf
        })
    });
    let stderr_handle = child.stderr.take().map(|err| {
        thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = err.take(MAX_FIDO2_STDERR_BYTES).read_to_end(&mut buf);
            buf
        })
    });

    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    if let Some(h) = stdout_handle {
                        let _ = h.join();
                    }
                    if let Some(h) = stderr_handle {
                        let _ = h.join();
                    }
                    return Err(VaultError::Fido2Error(format!(
                        "`{tool}` timed out after {}s",
                        timeout.as_secs()
                    )));
                }
                thread::sleep(Duration::from_millis(25));
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                if let Some(h) = stdout_handle {
                    let _ = h.join();
                }
                if let Some(h) = stderr_handle {
                    let _ = h.join();
                }
                return Err(VaultError::Fido2Error(format!(
                    "failed waiting on `{tool}`: {e}"
                )));
            }
        }
    };

    let stdout = stdout_handle
        .and_then(|h| h.join().ok())
        .unwrap_or_else(|| Zeroizing::new(Vec::new()));
    let stderr = stderr_handle
        .and_then(|h| h.join().ok())
        .unwrap_or_default();

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
        assert!(verify_authdata_flags(&BASE64.encode(&raw), DEFAULT_RP_ID, true, true, true).is_ok());

        // Clear UV bit: passes when require_uv=false, fails when require_uv=true.
        raw[2 + 32] = 0x01 | 0x80; // UP | ED
        assert!(verify_authdata_flags(&BASE64.encode(&raw), DEFAULT_RP_ID, false, false, true).is_ok());
        assert!(verify_authdata_flags(&BASE64.encode(&raw), DEFAULT_RP_ID, true, false, true).is_err());

        // Missing AT on enrollment fails; missing ED fails.
        assert!(verify_authdata_flags(&BASE64.encode(&raw), DEFAULT_RP_ID, false, true, true).is_err());
        raw[2 + 32] = 0x01; // UP only, missing ED
        assert!(verify_authdata_flags(&BASE64.encode(&raw), DEFAULT_RP_ID, false, false, true).is_err());

        // Wrong rpIdHash fails.
        raw[2 + 32] = 0x01 | 0x80;
        assert!(verify_authdata_flags(&BASE64.encode(&raw), "other.local", false, false, true).is_err());

        // Non-CBOR raw authdata (without major type 2 header) MUST fail closed.
        assert!(verify_authdata_flags(&BASE64.encode(&raw[2..]), DEFAULT_RP_ID, false, false, true).is_err());
    }
}
