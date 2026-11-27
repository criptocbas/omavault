use std::collections::HashSet;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{Result, VaultError};

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

const MIN_TOTP_SECRET_BYTES: usize = 10; // 80-bit minimum (RFC 4226 floor)

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum TotpAlgorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

impl fmt::Display for TotpAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sha1 => write!(f, "SHA1"),
            Self::Sha256 => write!(f, "SHA256"),
            Self::Sha512 => write!(f, "SHA512"),
        }
    }
}

/// RFC 6238 TOTP configuration stored encrypted inside a vault entry.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct TotpConfig {
    /// Base32-encoded shared secret (uppercase, stripped of spaces/trailing padding).
    pub secret_base32: String,
    #[zeroize(skip)]
    #[serde(default)]
    pub algorithm: TotpAlgorithm,
    #[zeroize(skip)]
    #[serde(default = "default_digits")]
    pub digits: u32,
    #[zeroize(skip)]
    #[serde(default = "default_period")]
    pub period: u64,
    #[serde(default)]
    pub issuer: Option<String>,
}

fn default_digits() -> u32 {
    6
}

fn default_period() -> u64 {
    30
}

impl fmt::Debug for TotpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpConfig")
            .field("secret_base32", &"[REDACTED]")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("issuer", &self.issuer)
            .finish()
    }
}

/// Generated TOTP code plus countdown metadata.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct TotpCode {
    pub code: String,
    #[zeroize(skip)]
    pub remaining_secs: u64,
    #[zeroize(skip)]
    pub period: u64,
}

impl fmt::Debug for TotpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpCode")
            .field("code", &"[REDACTED]")
            .field("remaining_secs", &self.remaining_secs)
            .field("period", &self.period)
            .finish()
    }
}

impl TotpConfig {
    /// Validate invariants consistently across parsed and deserialized configs.
    pub fn validate(&self) -> Result<()> {
        if self.digits != 6 && self.digits != 8 {
            return Err(VaultError::InvalidTotp("TOTP digits must be 6 or 8".into()));
        }
        if self.period == 0 || self.period > 300 {
            return Err(VaultError::InvalidTotp(
                "TOTP period must be between 1 and 300 seconds".into(),
            ));
        }
        let decoded = decode_base32(&self.secret_base32)?;
        if decoded.len() < MIN_TOTP_SECRET_BYTES {
            return Err(VaultError::InvalidTotp(
                "TOTP secret too short (minimum 10 bytes / 80 bits)".into(),
            ));
        }
        Ok(())
    }

    /// Parse either an `otpauth://totp/...` URI (case-insensitive scheme) or a raw Base32 secret.
    ///
    /// Never echoes raw input substrings in error messages so malformed URIs cannot leak seeds.
    pub fn parse(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(VaultError::InvalidTotp("TOTP secret cannot be empty".into()));
        }
        let cfg = if trimmed
            .as_bytes()
            .get(..10)
            .is_some_and(|p| p.eq_ignore_ascii_case(b"otpauth://"))
        {
            Self::parse_otpauth_uri(trimmed)?
        } else {
            let normalized = normalize_base32(trimmed)?;
            Self {
                secret_base32: normalized.to_string(),
                algorithm: TotpAlgorithm::Sha1,
                digits: 6,
                period: 30,
                issuer: None,
            }
        };
        cfg.validate()?;
        Ok(cfg)
    }

    fn parse_otpauth_uri(uri: &str) -> Result<Self> {
        let rest = &uri[10..]; // after case-insensitive "otpauth://"
        let (kind, after_kind) = rest
            .split_once('/')
            .ok_or_else(|| VaultError::InvalidTotp("missing otpauth path".into()))?;
        if !kind.eq_ignore_ascii_case("totp") {
            return Err(VaultError::InvalidTotp(
                "unsupported otpauth type (only 'totp' is supported)".into(),
            ));
        }

        // Strip URI #fragment before parsing query parameters.
        let without_fragment = after_kind.split('#').next().unwrap_or(after_kind);
        let (_label, query) = without_fragment.split_once('?').ok_or_else(|| {
            VaultError::InvalidTotp("missing query parameters in otpauth URI".into())
        })?;

        let mut seen_keys: HashSet<String> = HashSet::new();
        let mut secret: Option<Zeroizing<String>> = None;
        let mut algorithm = TotpAlgorithm::Sha1;
        let mut digits: u32 = 6;
        let mut period: u64 = 30;
        let mut issuer: Option<String> = None;

        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let key_lower = k.to_ascii_lowercase();
            let val = percent_decode(v);

            match key_lower.as_str() {
                "secret" => {
                    if !seen_keys.insert(key_lower) {
                        return Err(VaultError::InvalidTotp(
                            "duplicate 'secret' parameter in otpauth URI".into(),
                        ));
                    }
                    secret = Some(normalize_base32(&val)?);
                }
                "algorithm" => {
                    if !seen_keys.insert(key_lower) {
                        return Err(VaultError::InvalidTotp(
                            "duplicate 'algorithm' parameter in otpauth URI".into(),
                        ));
                    }
                    algorithm = match val.to_ascii_uppercase().as_str() {
                        "SHA1" => TotpAlgorithm::Sha1,
                        "SHA256" => TotpAlgorithm::Sha256,
                        "SHA512" => TotpAlgorithm::Sha512,
                        _ => {
                            return Err(VaultError::InvalidTotp(
                                "unsupported TOTP algorithm (expected SHA1, SHA256, or SHA512)"
                                    .into(),
                            ));
                        }
                    };
                }
                "digits" => {
                    if !seen_keys.insert(key_lower) {
                        return Err(VaultError::InvalidTotp(
                            "duplicate 'digits' parameter in otpauth URI".into(),
                        ));
                    }
                    digits = val
                        .parse::<u32>()
                        .map_err(|_| VaultError::InvalidTotp("invalid digits value".into()))?;
                    if digits != 6 && digits != 8 {
                        return Err(VaultError::InvalidTotp("TOTP digits must be 6 or 8".into()));
                    }
                }
                "period" => {
                    if !seen_keys.insert(key_lower) {
                        return Err(VaultError::InvalidTotp(
                            "duplicate 'period' parameter in otpauth URI".into(),
                        ));
                    }
                    period = val
                        .parse::<u64>()
                        .map_err(|_| VaultError::InvalidTotp("invalid period value".into()))?;
                    if period == 0 || period > 300 {
                        return Err(VaultError::InvalidTotp(
                            "TOTP period must be between 1 and 300 seconds".into(),
                        ));
                    }
                }
                "issuer" if !val.is_empty() => {
                    if !seen_keys.insert(key_lower) {
                        return Err(VaultError::InvalidTotp(
                            "duplicate 'issuer' parameter in otpauth URI".into(),
                        ));
                    }
                    issuer = Some(val.to_string());
                }
                _ => {}
            }
        }

        let secret_base32 = secret.ok_or_else(|| {
            VaultError::InvalidTotp("otpauth URI missing 'secret' parameter".into())
        })?;

        Ok(Self {
            secret_base32: secret_base32.to_string(),
            algorithm,
            digits,
            period,
            issuer,
        })
    }

    /// Generate the current TOTP code using system wall-clock UTC time.
    pub fn generate_now(&self) -> Result<TotpCode> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| VaultError::InvalidTotp(format!("system clock error: {e}")))?
            .as_secs();
        self.generate_at(now)
    }

    /// Generate a TOTP code for a specific UNIX timestamp (deterministic, RFC 6238 compliant).
    pub fn generate_at(&self, unix_secs: u64) -> Result<TotpCode> {
        self.validate()?;

        let key = decode_base32(&self.secret_base32)?;
        let counter = unix_secs / self.period;
        let remaining_secs = self.period - (unix_secs % self.period);

        let code = hotp_raw(&key, counter, self.algorithm, self.digits)?;
        Ok(TotpCode {
            code: code.to_string(),
            remaining_secs,
            period: self.period,
        })
    }
}

/// Core RFC 4226 HOTP / RFC 6238 dynamic truncation implementation.
///
/// Validates `digits` in `6..=8` and non-empty `key` to eliminate integer overflow and
/// release-mode division-by-zero aborts.
pub fn hotp_raw(
    key: &[u8],
    counter: u64,
    algorithm: TotpAlgorithm,
    digits: u32,
) -> Result<Zeroizing<String>> {
    if key.is_empty() {
        return Err(VaultError::InvalidTotp("HOTP key cannot be empty".into()));
    }
    if !(6..=8).contains(&digits) {
        return Err(VaultError::InvalidTotp(
            "HOTP digits must be between 6 and 8".into(),
        ));
    }

    let counter_be = counter.to_be_bytes();

    let digest: Zeroizing<Vec<u8>> = match algorithm {
        TotpAlgorithm::Sha1 => {
            let mut mac = HmacSha1::new_from_slice(key)
                .map_err(|_| VaultError::InvalidTotp("HMAC-SHA1 initialization failed".into()))?;
            mac.update(&counter_be);
            let mut raw = mac.finalize().into_bytes();
            let out = Zeroizing::new(raw.to_vec());
            raw.as_mut_slice().zeroize();
            out
        }
        TotpAlgorithm::Sha256 => {
            let mut mac = HmacSha256::new_from_slice(key)
                .map_err(|_| VaultError::InvalidTotp("HMAC-SHA256 initialization failed".into()))?;
            mac.update(&counter_be);
            let mut raw = mac.finalize().into_bytes();
            let out = Zeroizing::new(raw.to_vec());
            raw.as_mut_slice().zeroize();
            out
        }
        TotpAlgorithm::Sha512 => {
            let mut mac = HmacSha512::new_from_slice(key)
                .map_err(|_| VaultError::InvalidTotp("HMAC-SHA512 initialization failed".into()))?;
            mac.update(&counter_be);
            let mut raw = mac.finalize().into_bytes();
            let out = Zeroizing::new(raw.to_vec());
            raw.as_mut_slice().zeroize();
            out
        }
    };

    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = ((u32::from(digest[offset]) & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);

    let modulo = 10u32
        .checked_pow(digits)
        .ok_or_else(|| VaultError::InvalidTotp("TOTP digits overflow".into()))?;
    let otp = binary % modulo;
    Ok(Zeroizing::new(format!(
        "{:0width$}",
        otp,
        width = digits as usize
    )))
}

fn normalize_base32(input: &str) -> Result<Zeroizing<String>> {
    // Strip whitespace and hyphens, uppercase, then strip ONLY trailing RFC 4648 '=' padding.
    // Built in ONE pre-sized buffer (`.filter().collect()` loses the size hint and reallocates,
    // leaving partial copies of the seed in freed heap).
    let mut cleaned: Zeroizing<String> = Zeroizing::new(String::with_capacity(input.len()));
    for c in input.chars() {
        if !c.is_whitespace() && c != '-' {
            cleaned.push(c.to_ascii_uppercase());
        }
    }
    while cleaned.ends_with('=') {
        cleaned.pop();
    }
    if cleaned.is_empty() || cleaned.contains('=') {
        return Err(VaultError::InvalidTotp("invalid Base32 TOTP secret".into()));
    }
    let decoded = decode_base32(&cleaned)?;
    if decoded.len() < MIN_TOTP_SECRET_BYTES {
        return Err(VaultError::InvalidTotp(
            "TOTP secret too short (minimum 10 bytes / 80 bits)".into(),
        ));
    }
    Ok(cleaned)
}

fn decode_base32(cleaned: &str) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = BASE32_NOPAD
        .decode(cleaned.as_bytes())
        .map_err(|_| VaultError::InvalidTotp("invalid Base32 TOTP secret".into()))?;
    Ok(Zeroizing::new(bytes))
}

fn percent_decode(s: &str) -> Zeroizing<String> {
    let bytes = s.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            if let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(val) = u8::from_str_radix(hex, 16) {
                    out.push(val);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    Zeroizing::new(String::from_utf8_lossy(&out).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 Appendix B official test vectors.
    #[test]
    fn rfc6238_official_test_vectors() {
        let seed_sha1 = b"12345678901234567890";
        let seed_sha256 = b"12345678901234567890123456789012";
        let seed_sha512 =
            b"1234567890123456789012345678901234567890123456789012345678901234";

        let vectors: &[(u64, &str, &str, &str)] = &[
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
        ];

        for &(ts, exp1, exp256, exp512) in vectors {
            let c1 = hotp_raw(seed_sha1, ts / 30, TotpAlgorithm::Sha1, 8).unwrap();
            let c256 = hotp_raw(seed_sha256, ts / 30, TotpAlgorithm::Sha256, 8).unwrap();
            let c512 = hotp_raw(seed_sha512, ts / 30, TotpAlgorithm::Sha512, 8).unwrap();
            assert_eq!(&*c1, exp1, "SHA1 mismatch at ts={ts}");
            assert_eq!(&*c256, exp256, "SHA256 mismatch at ts={ts}");
            assert_eq!(&*c512, exp512, "SHA512 mismatch at ts={ts}");
        }
    }

    #[test]
    fn parses_otpauth_uri_and_rejects_malformed_edge_cases() {
        let uri = "OTPAUTH://totp/GitHub:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA256&digits=6&period=30#frag";
        let cfg = TotpConfig::parse(uri).expect("parse otpauth");
        assert_eq!(cfg.algorithm, TotpAlgorithm::Sha256);
        assert_eq!(cfg.digits, 6);
        assert_eq!(cfg.period, 30);
        assert_eq!(cfg.issuer.as_deref(), Some("GitHub"));
        let code = cfg.generate_at(1_700_000_000).expect("generate totp");
        assert_eq!(code.code.len(), 6);

        // Duplicate secret rejected.
        assert!(TotpConfig::parse(
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&secret=JBSWY3DPEHPK3PXP"
        )
        .is_err());

        // Interior '=' rejected.
        assert!(TotpConfig::parse("JBSW====Y3DPEHPK3PXP").is_err());

        // percent_decode does not treat %+a as hex.
        assert_eq!(&*percent_decode("%+a"), "%+a");

        // Error messages must never echo secret substrings.
        let err = TotpConfig::parse(
            "otpauth://totp/x?algorithm=SHA1secret=MYSECRETSEED123456&secret=JBSWY3DPEHPK3PXP",
        )
        .unwrap_err();
        assert!(!err.to_string().contains("MYSECRETSEED"));
    }

    #[test]
    fn hotp_raw_rejects_overflow_and_zero_digits() {
        let key = b"12345678901234567890";
        assert!(hotp_raw(key, 1, TotpAlgorithm::Sha1, 0).is_err());
        assert!(hotp_raw(key, 1, TotpAlgorithm::Sha1, 10).is_err());
        assert!(hotp_raw(key, 1, TotpAlgorithm::Sha1, 32).is_err());
        assert!(hotp_raw(&[], 1, TotpAlgorithm::Sha1, 6).is_err());
    }
}
