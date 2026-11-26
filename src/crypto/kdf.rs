use std::fs::File;
use std::io::Read;
use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::error::{Result, VaultError};
use crate::hardening::LockedKey;

/// Default Argon2id parameters (OWASP high-security interactive recommendation):
/// 128 MiB RAM, 4 iterations, 4 parallel lanes.
pub const DEFAULT_ARGON2_MEM_KIB: u32 = 131_072; // 128 MiB
pub const DEFAULT_ARGON2_TIME: u32 = 4;
pub const DEFAULT_ARGON2_LANES: u32 = 4;

/// Hard minimum KDF floors enforced when opening production vaults
/// to block header downgrade attacks.
pub const MIN_ARGON2_MEM_KIB: u32 = 65_536; // 64 MiB
pub const MIN_ARGON2_TIME: u32 = 3;
pub const MIN_ARGON2_LANES: u32 = 1;

/// Hard upper bounds to prevent OOM/CPU DoS from maliciously crafted files.
pub const MAX_ARGON2_MEM_KIB: u32 = 4_194_304; // 4 GiB
pub const MAX_ARGON2_TIME: u32 = 64;
pub const MAX_ARGON2_LANES: u32 = 64;

const HKDF_MASTER_INFO: &[u8] = b"omavault-v1-master-key-combiner";
const HKDF_PAYLOAD_INFO: &[u8] = b"omavault-v1-payload-xchacha20poly1305";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub mem_kib: u32,
    pub time_cost: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            mem_kib: DEFAULT_ARGON2_MEM_KIB,
            time_cost: DEFAULT_ARGON2_TIME,
            parallelism: DEFAULT_ARGON2_LANES,
        }
    }
}

impl KdfParams {
    /// Enforce production minimum and maximum security bounds.
    pub fn validate(&self) -> Result<()> {
        if self.mem_kib < MIN_ARGON2_MEM_KIB {
            return Err(VaultError::WeakKdfParameters(format!(
                "Argon2id memory {} KiB is below minimum {} KiB",
                self.mem_kib, MIN_ARGON2_MEM_KIB
            )));
        }
        if self.mem_kib > MAX_ARGON2_MEM_KIB {
            return Err(VaultError::WeakKdfParameters(format!(
                "Argon2id memory {} KiB exceeds maximum {} KiB",
                self.mem_kib, MAX_ARGON2_MEM_KIB
            )));
        }
        if self.time_cost < MIN_ARGON2_TIME || self.time_cost > MAX_ARGON2_TIME {
            return Err(VaultError::WeakKdfParameters(format!(
                "Argon2id time cost {} outside allowed range {}..={}",
                self.time_cost, MIN_ARGON2_TIME, MAX_ARGON2_TIME
            )));
        }
        if self.parallelism < MIN_ARGON2_LANES || self.parallelism > MAX_ARGON2_LANES {
            return Err(VaultError::WeakKdfParameters(format!(
                "Argon2id parallelism {} outside allowed range {}..={}",
                self.parallelism, MIN_ARGON2_LANES, MAX_ARGON2_LANES
            )));
        }
        Ok(())
    }

    /// Lighter KDF parameters strictly for automated tests (never used for user vaults).
    #[cfg(test)]
    pub fn fast_for_tests() -> Self {
        Self {
            mem_kib: 8 * 1024,
            time_cost: 1,
            parallelism: 1,
        }
    }
}

/// Hash an arbitrary keyfile using streaming BLAKE3 into a 32-byte digest.
///
/// Keyfiles of any size are supported without loading the entire file into RAM at once.
pub fn hash_keyfile(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let mut file = File::open(path).map_err(|e| {
        VaultError::Io(std::io::Error::new(
            e.kind(),
            format!("failed to open keyfile '{}': {e}", path.display()),
        ))
    })?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = Zeroizing::new([0u8; 8192]);
    let mut total_bytes = 0u64;
    loop {
        let n = file.read(&mut *buf)?;
        if n == 0 {
            break;
        }
        total_bytes += n as u64;
        hasher.update(&buf[..n]);
    }
    if total_bytes == 0 {
        return Err(VaultError::InvalidFormat("keyfile is empty".into()));
    }
    let digest = hasher.finalize();
    Ok(Zeroizing::new(*digest.as_bytes()))
}

/// Derive the 32-byte hardened `MasterKey` stored in `mlock`ed `PROT_NONE` memory.
///
/// Pipeline:
/// 1. `pw_hash = Argon2id(passphrase, kdf_salt, params)` (32 bytes)
/// 2. Domain-separated IKM construction:
///    `b"PW" || pw_hash`
///    `|| (if keyfile: b"KF" || blake3(keyfile))`
///    `|| (if fido2:   b"F2" || fido2_hmac_secret)`
/// 3. `master_key = HKDF-SHA512(salt = kdf_salt, ikm = tagged_ikm, info = "omavault-v1-master-key-combiner")`
pub fn derive_master_key(
    passphrase: &[u8],
    kdf_salt: &[u8; 32],
    params: KdfParams,
    keyfile_digest: Option<&[u8; 32]>,
    fido2_secret: Option<&[u8; 32]>,
    enforce_policy: bool,
) -> Result<LockedKey<32>> {
    if enforce_policy {
        params.validate()?;
    }

    let argon2_params = Params::new(params.mem_kib, params.time_cost, params.parallelism, Some(32))
        .map_err(|e| VaultError::Crypto(format!("invalid Argon2id params: {e}")))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
    let mut pw_hash = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(passphrase, kdf_salt, &mut *pw_hash)
        .map_err(|e| VaultError::Crypto(format!("Argon2id derivation failed: {e}")))?;

    // Construct domain-separated input key material.
    let mut ikm = Zeroizing::new(Vec::with_capacity(34 * 3));
    ikm.extend_from_slice(b"PW");
    ikm.extend_from_slice(&*pw_hash);

    if let Some(kf) = keyfile_digest {
        ikm.extend_from_slice(b"KF");
        ikm.extend_from_slice(kf);
    }
    if let Some(f2) = fido2_secret {
        ikm.extend_from_slice(b"F2");
        ikm.extend_from_slice(f2);
    }

    let hk = Hkdf::<Sha512>::new(Some(kdf_salt), &ikm);
    let mut master_raw = [0u8; 32];
    hk.expand(HKDF_MASTER_INFO, &mut master_raw)
        .map_err(|_| VaultError::Crypto("HKDF-SHA512 master key expand failed".into()))?;

    // LockedKey::new copies bytes into mlocked PROT_NONE memory and zeroizes `master_raw`.
    LockedKey::new(&mut master_raw)
}

/// Derive a fresh per-save 256-bit AEAD encryption key from `master_key` and `save_salt`.
///
/// Because every save generates a fresh 32-byte `save_salt` AND a fresh 24-byte `nonce`,
/// no AEAD key or nonce is ever reused across saves.
pub fn derive_payload_key(
    master_key: &LockedKey<32>,
    save_salt: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    master_key.expose(|mk| {
        let hk = Hkdf::<Sha512>::new(Some(save_salt), mk);
        let mut enc_key = Zeroizing::new([0u8; 32]);
        hk.expand(HKDF_PAYLOAD_INFO, &mut *enc_key)
            .map_err(|_| VaultError::Crypto("HKDF-SHA512 payload key expand failed".into()))?;
        Ok(enc_key)
    })
}
