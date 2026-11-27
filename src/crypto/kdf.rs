use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::{Zeroize, Zeroizing};

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

/// Tight upper bounds to prevent pre-authentication OOM/CPU DoS from crafted vault headers.
pub const MAX_ARGON2_MEM_KIB: u32 = 1_048_576; // 1 GiB
pub const MAX_ARGON2_TIME: u32 = 16;
pub const MAX_ARGON2_LANES: u32 = 16;
/// Combined memory * iterations ceiling (8 GiB-iterations).
pub const MAX_ARGON2_WORK_KIB_ITERS: u64 = 8 * 1_048_576;

/// Maximum keyfile size read by `hash_keyfile` (64 MiB).
const MAX_KEYFILE_BYTES: u64 = 64 * 1024 * 1024;

const HKDF_MASTER_INFO: &[u8] = b"omavault-v1-master-key-combiner";
const HKDF_SLOT_KEK_INFO: &[u8] = b"omavault-v2-fido2-slot-kek";
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
    /// Always-enforced upper DoS bounds and RFC 9106 structural invariants.
    pub fn validate_upper_bounds(&self) -> Result<()> {
        if self.mem_kib == 0 || self.mem_kib > MAX_ARGON2_MEM_KIB {
            return Err(VaultError::WeakKdfParameters(format!(
                "Argon2id memory {} KiB exceeds allowed ceiling {} KiB",
                self.mem_kib, MAX_ARGON2_MEM_KIB
            )));
        }
        if self.time_cost == 0 || self.time_cost > MAX_ARGON2_TIME {
            return Err(VaultError::WeakKdfParameters(format!(
                "Argon2id time cost {} outside allowed ceiling 1..={}",
                self.time_cost, MAX_ARGON2_TIME
            )));
        }
        if self.parallelism == 0 || self.parallelism > MAX_ARGON2_LANES {
            return Err(VaultError::WeakKdfParameters(format!(
                "Argon2id parallelism {} outside allowed ceiling 1..={}",
                self.parallelism, MAX_ARGON2_LANES
            )));
        }
        let work = (self.mem_kib as u64).saturating_mul(self.time_cost as u64);
        if work > MAX_ARGON2_WORK_KIB_ITERS {
            return Err(VaultError::WeakKdfParameters(format!(
                "Argon2id combined work {work} KiB-iters exceeds maximum {MAX_ARGON2_WORK_KIB_ITERS}"
            )));
        }
        // RFC 9106 requires m >= 8 * p.
        if (self.mem_kib as u64) < (self.parallelism as u64).saturating_mul(8) {
            return Err(VaultError::WeakKdfParameters(format!(
                "Argon2id memory {} KiB must be >= 8 * parallelism ({})",
                self.mem_kib, self.parallelism
            )));
        }
        Params::new(self.mem_kib, self.time_cost, self.parallelism, Some(32))
            .map_err(|e| VaultError::WeakKdfParameters(format!("invalid Argon2id params: {e}")))?;
        Ok(())
    }

    /// Enforce both production minimum floors (anti-downgrade) and upper DoS ceilings.
    pub fn validate(&self) -> Result<()> {
        self.validate_upper_bounds()?;
        if self.mem_kib < MIN_ARGON2_MEM_KIB {
            return Err(VaultError::WeakKdfParameters(format!(
                "Argon2id memory {} KiB is below minimum {} KiB",
                self.mem_kib, MIN_ARGON2_MEM_KIB
            )));
        }
        if self.time_cost < MIN_ARGON2_TIME {
            return Err(VaultError::WeakKdfParameters(format!(
                "Argon2id time cost {} is below minimum {}",
                self.time_cost, MIN_ARGON2_TIME
            )));
        }
        if self.parallelism < MIN_ARGON2_LANES {
            return Err(VaultError::WeakKdfParameters(format!(
                "Argon2id parallelism {} is below minimum {}",
                self.parallelism, MIN_ARGON2_LANES
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

/// Hash a regular keyfile using streaming BLAKE3 into a 32-byte digest.
///
/// Opens with `O_NONBLOCK | O_NOFOLLOW` so FIFOs never hang and symlinks are rejected,
/// verifies regular file + owner-only permissions (`0600`), caps reads at 64 MiB, and
/// wraps `blake3::Hasher` in `Zeroizing` so I/O errors still wipe internal state.
pub fn hash_keyfile(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| {
            VaultError::Io(std::io::Error::new(
                e.kind(),
                format!("failed to open keyfile '{}': {e}", path.display()),
            ))
        })?;
    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        return Err(VaultError::InvalidFormat(
            "keyfile path must be a regular file (special files/FIFOs/devices are rejected)".into(),
        ));
    }
    if meta.uid() != unsafe { libc::geteuid() } {
        return Err(VaultError::Hardening(format!(
            "keyfile '{}' is not owned by the current user",
            path.display()
        )));
    }
    if (meta.mode() & 0o077) != 0 {
        return Err(VaultError::Hardening(format!(
            "keyfile '{}' has unsafe permissions {:04o} (must be owner-only 0600)",
            path.display(),
            meta.mode() & 0o7777
        )));
    }
    if meta.len() > MAX_KEYFILE_BYTES {
        return Err(VaultError::InvalidFormat(format!(
            "keyfile exceeds maximum allowed size ({MAX_KEYFILE_BYTES} bytes)"
        )));
    }

    let mut reader = file.take(MAX_KEYFILE_BYTES.saturating_add(1));
    let mut hasher = Zeroizing::new(blake3::Hasher::new());
    let mut buf = Zeroizing::new([0u8; 8192]);
    let mut total_bytes = 0u64;
    loop {
        let n = match reader.read(&mut *buf) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(VaultError::Io(e)),
        };
        if n == 0 {
            break;
        }
        total_bytes = total_bytes.saturating_add(n as u64);
        if total_bytes > MAX_KEYFILE_BYTES {
            return Err(VaultError::InvalidFormat(format!(
                "keyfile exceeds maximum allowed size ({MAX_KEYFILE_BYTES} bytes)"
            )));
        }
        hasher.update(&buf[..n]);
    }
    if total_bytes == 0 {
        return Err(VaultError::InvalidFormat("keyfile is empty".into()));
    }
    let mut digest = hasher.finalize();
    let out = Zeroizing::new(*digest.as_bytes());
    digest.zeroize();
    Ok(out)
}

/// Compute the raw 32-byte Argon2id passphrase hash (`RFC 9106 v0x13`).
///
/// Exposed separately so `OMAV` v2 multi-slot vaults run Argon2id once per unlock/enroll
/// instead of repeating expensive memory-hard hashing per slot.
pub fn derive_passphrase_hash(
    passphrase: &[u8],
    kdf_salt: &[u8; 32],
    params: KdfParams,
    enforce_policy: bool,
) -> Result<Zeroizing<[u8; 32]>> {
    if enforce_policy {
        params.validate()?;
    } else {
        params.validate_upper_bounds()?;
    }

    let argon2_params = Params::new(
        params.mem_kib,
        params.time_cost,
        params.parallelism,
        Some(32),
    )
    .map_err(|e| VaultError::Crypto(format!("invalid Argon2id params: {e}")))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
    let mut pw_hash = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(passphrase, kdf_salt, &mut *pw_hash)
        .map_err(|e| VaultError::Crypto(format!("Argon2id derivation failed: {e}")))?;
    Ok(pw_hash)
}

/// Derive a 32-byte `OMAV` v1 hardened `MasterKey` directly from a pre-computed Argon2id `pw_hash`.
pub fn derive_master_key_from_pw_hash(
    pw_hash: &[u8; 32],
    kdf_salt: &[u8; 32],
    keyfile_digest: Option<&[u8; 32]>,
    fido2_secret: Option<&[u8; 32]>,
) -> Result<LockedKey<32>> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(34 * 3));
    ikm.extend_from_slice(b"PW");
    ikm.extend_from_slice(pw_hash);

    if let Some(kf) = keyfile_digest {
        ikm.extend_from_slice(b"KF");
        ikm.extend_from_slice(kf);
    }
    if let Some(f2) = fido2_secret {
        ikm.extend_from_slice(b"F2");
        ikm.extend_from_slice(f2);
    }

    let mut master_raw = [0u8; 32];
    hkdf_sha512(kdf_salt, &ikm, HKDF_MASTER_INFO, &mut master_raw)
        .map_err(|_| VaultError::Crypto("HKDF-SHA512 master key expand failed".into()))?;

    LockedKey::new(&mut master_raw)
}

/// Derive a 32-byte Key-Encryption-Key (KEK) for wrapping/unwrapping an `OMAV` v2 FIDO2 key slot.
///
/// Combines the Argon2id passphrase hash, optional 512-bit keyfile BLAKE3 digest, and the
/// hardware-bound 32-byte FIDO2 `hmac-secret` under domain separation `"omavault-v2-fido2-slot-kek"`.
pub fn derive_slot_kek(
    pw_hash: &[u8; 32],
    kdf_salt: &[u8; 32],
    keyfile_digest: Option<&[u8; 32]>,
    fido2_secret: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(34 * 3));
    ikm.extend_from_slice(b"PW");
    ikm.extend_from_slice(pw_hash);

    if let Some(kf) = keyfile_digest {
        ikm.extend_from_slice(b"KF");
        ikm.extend_from_slice(kf);
    }
    ikm.extend_from_slice(b"F2");
    ikm.extend_from_slice(fido2_secret);

    let mut kek = Zeroizing::new([0u8; 32]);
    hkdf_sha512(kdf_salt, &ikm, HKDF_SLOT_KEK_INFO, &mut *kek)
        .map_err(|_| VaultError::Crypto("HKDF-SHA512 slot KEK expand failed".into()))?;
    Ok(kek)
}

/// Derive the 32-byte hardened `MasterKey` stored in `mlock`ed `PROT_NONE` memory (`OMAV` v1).
///
/// Pipeline:
/// 1. `pw_hash = Argon2id(passphrase, kdf_salt, params)` (32 bytes, zeroized matrix)
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
    let pw_hash = derive_passphrase_hash(passphrase, kdf_salt, params, enforce_policy)?;
    derive_master_key_from_pw_hash(&pw_hash, kdf_salt, keyfile_digest, fido2_secret)
}

/// Derive a fresh per-save 256-bit AEAD encryption key from `master_key` and `save_salt`.
pub fn derive_payload_key(
    master_key: &LockedKey<32>,
    save_salt: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    master_key.expose(|mk| {
        let mut enc_key = Zeroizing::new([0u8; 32]);
        hkdf_sha512(save_salt, mk, HKDF_PAYLOAD_INFO, &mut *enc_key)
            .map_err(|_| VaultError::Crypto("HKDF-SHA512 payload key expand failed".into()))?;
        Ok(enc_key)
    })?
}

/// HKDF-SHA512 (extract + expand) with stack hygiene.
///
/// `hkdf`/`hmac` 0.12 do not zeroize their internal state (the PRK and HMAC pads — equivalent to
/// key material). The computation runs in a dedicated non-inlined frame, and the stack region it
/// used is scrubbed immediately after it returns.
fn hkdf_sha512(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> std::result::Result<(), ()> {
    let result = hkdf_sha512_frame(salt, ikm, info, out);
    crate::hardening::scrub_stack();
    result
}

#[inline(never)]
fn hkdf_sha512_frame(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> std::result::Result<(), ()> {
    let hk = Hkdf::<Sha512>::new(Some(salt), ikm);
    hk.expand(info, out).map_err(|_| ())
}
