use std::io::Write;
use std::process::{Command, Stdio};

use data_encoding::BASE64;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Result, VaultError};
use crate::hardening::fill_random;

pub const DEFAULT_RP_ID: &str = "omavault.local";
const USER_NAME: &str = "omavault";

/// Non-secret FIDO2 metadata stored inside the AAD-authenticated vault header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fido2Metadata {
    /// Relying Party ID (e.g. `omavault.local`).
    pub rp_id: String,
    /// Base64-encoded non-resident credential ID returned during enrollment.
    pub credential_id_b64: String,
    /// Base64-encoded 32-byte random HMAC challenge salt.
    pub hmac_salt_b64: String,
    /// Whether User Verification (PIN / biometric) was requested on the authenticator.
    #[serde(default)]
    pub require_uv: bool,
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
}

/// Production FIDO2 provider backed by Arch/Omarchy's `libfido2` CLI tools
/// (`fido2-token`, `fido2-cred`, `fido2-assert`).
///
/// Uses direct `Command::new` execution (no shell), passes parameters via stdin,
/// and immediately zeroizes raw stdout buffers containing the HMAC secret.
#[derive(Debug, Default, Clone, Copy)]
pub struct LibFido2Cli;

impl LibFido2Cli {
    /// Auto-detect the first connected FIDO2 HID device via `fido2-token -L`.
    pub fn discover_device() -> Result<String> {
        let output = Command::new("fido2-token")
            .arg("-L")
            .output()
            .map_err(|e| {
                VaultError::Fido2Error(format!(
                    "failed to execute `fido2-token` (install `libfido2` on Arch/Omarchy: `sudo pacman -S libfido2`): {e}"
                ))
            })?;

        if !output.status.success() {
            return Err(VaultError::Fido2Error(format!(
                "`fido2-token -L` exited with {}",
                output.status
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            // Output format: `/dev/hidraw3: vendor=0x1050, product=0x0407 (Yubico ...)`
            if let Some((dev, _)) = trimmed.split_once(':') {
                let dev = dev.trim();
                if dev.starts_with('/') {
                    return Ok(dev.to_string());
                }
            }
        }

        Err(VaultError::Fido2Error(
            "no FIDO2 hardware authenticator detected (plug in your YubiKey / FIDO2 token)".into(),
        ))
    }

    fn resolve_device(device: Option<&str>) -> Result<String> {
        match device {
            Some(d) if !d.trim().is_empty() => Ok(d.trim().to_string()),
            _ => Self::discover_device(),
        }
    }
}

impl Fido2Provider for LibFido2Cli {
    fn enroll(&self, device: Option<&str>, require_uv: bool) -> Result<Fido2Metadata> {
        let dev = Self::resolve_device(device)?;

        let mut client_data_hash = [0u8; 32];
        let mut user_id = [0u8; 32];
        let mut hmac_salt = [0u8; 32];
        fill_random(&mut client_data_hash)?;
        fill_random(&mut user_id)?;
        fill_random(&mut hmac_salt)?;

        let stdin_payload = format!(
            "{}\n{}\n{}\n{}\n",
            BASE64.encode(&client_data_hash),
            DEFAULT_RP_ID,
            USER_NAME,
            BASE64.encode(&user_id),
        );

        let mut cmd = Command::new("fido2-cred");
        cmd.arg("-M").arg("-h");
        if require_uv {
            cmd.arg("-v");
        }
        cmd.arg(&dev)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        eprintln!("Touch your FIDO2 security key to enroll it with omavault...");

        let mut child = cmd.spawn().map_err(|e| {
            VaultError::Fido2Error(format!(
                "failed to launch `fido2-cred` (install `libfido2`): {e}"
            ))
        })?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(stdin_payload.as_bytes()).map_err(|e| {
                VaultError::Fido2Error(format!("failed writing to `fido2-cred`: {e}"))
            })?;
        }

        let output = child.wait_with_output().map_err(|e| {
            VaultError::Fido2Error(format!("`fido2-cred` failed: {e}"))
        })?;

        if !output.status.success() {
            return Err(VaultError::Fido2Error(format!(
                "`fido2-cred` failed with status {}",
                output.status
            )));
        }

        // Per fido2-cred(1):
        // line 0: client data hash
        // line 1: rp id
        // line 2: cred format
        // line 3: authdata
        // line 4: credential id (base64)
        let stdout = String::from_utf8(output.stdout)
            .map_err(|_| VaultError::Fido2Error("non-UTF8 output from `fido2-cred`".into()))?;
        let lines: Vec<&str> = stdout.lines().collect();
        if lines.len() < 5 {
            return Err(VaultError::Fido2Error(format!(
                "unexpected `fido2-cred` output ({} lines, expected >= 5)",
                lines.len()
            )));
        }

        let cred_id_b64 = lines[4].trim().to_string();
        if cred_id_b64.is_empty() || BASE64.decode(cred_id_b64.as_bytes()).is_err() {
            return Err(VaultError::Fido2Error(
                "invalid credential ID returned by `fido2-cred`".into(),
            ));
        }

        Ok(Fido2Metadata {
            rp_id: DEFAULT_RP_ID.to_string(),
            credential_id_b64: cred_id_b64,
            hmac_salt_b64: BASE64.encode(&hmac_salt),
            require_uv,
        })
    }

    fn get_hmac_secret(
        &self,
        meta: &Fido2Metadata,
        device: Option<&str>,
    ) -> Result<Zeroizing<[u8; 32]>> {
        // Validate fields contain no newline/NUL injection before piping to fido2-assert.
        if meta.rp_id.contains(['\n', '\r', '\0'])
            || meta.credential_id_b64.contains(['\n', '\r', '\0'])
            || meta.hmac_salt_b64.contains(['\n', '\r', '\0'])
        {
            return Err(VaultError::Fido2Error(
                "invalid control characters in FIDO2 metadata".into(),
            ));
        }

        let dev = Self::resolve_device(device)?;

        let mut client_data_hash = [0u8; 32];
        fill_random(&mut client_data_hash)?;

        // Per fido2-assert(1) for non-resident credential with -h (hmac-secret):
        // line 0: client data hash (base64)
        // line 1: rp id
        // line 2: credential id (base64)
        // line 3: hmac salt (base64)
        let stdin_payload = format!(
            "{}\n{}\n{}\n{}\n",
            BASE64.encode(&client_data_hash),
            meta.rp_id,
            meta.credential_id_b64,
            meta.hmac_salt_b64,
        );

        let mut cmd = Command::new("fido2-assert");
        cmd.arg("-G").arg("-h");
        if meta.require_uv {
            cmd.arg("-t").arg("uv=true");
        }
        cmd.arg(&dev)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        eprintln!("Touch your FIDO2 security key to unlock omavault...");

        let mut child = cmd.spawn().map_err(|e| {
            VaultError::Fido2Error(format!(
                "failed to launch `fido2-assert` (install `libfido2`): {e}"
            ))
        })?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(stdin_payload.as_bytes()).map_err(|e| {
                VaultError::Fido2Error(format!("failed writing to `fido2-assert`: {e}"))
            })?;
        }

        let output = child.wait_with_output().map_err(|e| {
            VaultError::Fido2Error(format!("`fido2-assert` failed: {e}"))
        })?;

        if !output.status.success() {
            return Err(VaultError::Fido2Error(format!(
                "`fido2-assert` failed with status {}",
                output.status
            )));
        }

        // Wrap stdout bytes in Zeroizing so raw base64 secret is wiped on drop.
        let stdout_bytes = Zeroizing::new(output.stdout);
        let stdout_str = std::str::from_utf8(&stdout_bytes)
            .map_err(|_| VaultError::Fido2Error("non-UTF8 output from `fido2-assert`".into()))?;
        let lines: Vec<&str> = stdout_str.lines().collect();

        // Per fido2-assert(1) for non-resident + -h:
        // line 0: client data hash
        // line 1: rp id
        // line 2: authdata
        // line 3: assertion signature
        // line 4: hmac secret (base64, 32 bytes)
        if lines.len() < 5 {
            return Err(VaultError::Fido2Error(format!(
                "unexpected `fido2-assert` output ({} lines, expected >= 5)",
                lines.len()
            )));
        }

        let decoded = Zeroizing::new(
            BASE64
                .decode(lines[4].trim().as_bytes())
                .map_err(|_| VaultError::Fido2Error("invalid base64 HMAC secret".into()))?,
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
}

/// Deterministic software mock FIDO2 authenticator for unit & integration tests.
/// Computes `BLAKE3(token_secret || credential_id || hmac_salt)` to simulate
/// a hardware authenticator's `hmac-secret` output.
#[derive(Debug, Clone)]
pub struct MockFido2Provider {
    pub token_secret: [u8; 32],
}

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
        let mut hasher = blake3::Hasher::new_keyed(&self.token_secret);
        hasher.update(meta.rp_id.as_bytes());
        hasher.update(meta.credential_id_b64.as_bytes());
        hasher.update(meta.hmac_salt_b64.as_bytes());
        let hash = hasher.finalize();
        Ok(Zeroizing::new(*hash.as_bytes()))
    }
}
