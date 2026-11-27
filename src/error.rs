use thiserror::Error;

/// Top-level error type for omavault.
///
/// SECURITY INVARIANT: Never embed secret material (passphrases, keys, plaintext
/// entries, TOTP seeds, or FIDO2 HMAC secrets) inside error messages.
#[derive(Debug, Error)]
pub enum VaultError {
    #[error("vault not found at {0}")]
    VaultNotFound(String),

    #[error("vault already exists at {0}")]
    VaultAlreadyExists(String),

    #[error("invalid vault format: {0}")]
    InvalidFormat(String),

    #[error("unsupported vault version {0} (supported: 1, 2)")]
    UnsupportedVersion(u16),

    #[error("KDF parameters violate security policy: {0}")]
    WeakKdfParameters(String),

    #[error("authentication failed: wrong master passphrase, keyfile, hardware key, or tampered vault")]
    AuthenticationFailed,

    #[error("keyfile required to unlock this vault (pass --keyfile <path>)")]
    KeyfileRequired,

    #[error("FIDO2 hardware key required to unlock this vault")]
    Fido2Required,

    #[error("connected FIDO2 hardware key does not match any enrolled key slot for this vault")]
    Fido2NoMatchingCredential,

    #[error("FIDO2 hardware key error: {0}")]
    Fido2Error(String),

    #[error("crypto operation failed: {0}")]
    Crypto(String),

    #[error("memory hardening error: {0}")]
    Hardening(String),

    #[error("clipboard error: {0}")]
    Clipboard(String),

    #[error("daemon error: {0}")]
    Daemon(String),

    #[error("entry not found: {0}")]
    EntryNotFound(String),

    #[error("duplicate entry name: {0}")]
    DuplicateEntry(String),

    #[error("invalid TOTP configuration: {0}")]
    InvalidTotp(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(String),
}

pub type Result<T> = std::result::Result<T, VaultError>;
