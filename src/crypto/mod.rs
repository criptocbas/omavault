pub mod fido2;
pub mod kdf;

use std::collections::HashSet;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use data_encoding::BASE64;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::fido2::{Fido2Metadata, Fido2Provider};
use crate::crypto::kdf::{
    derive_master_key_from_pw_hash, derive_passphrase_hash, derive_payload_key, derive_slot_kek,
    KdfParams,
};
use crate::error::{Result, VaultError};
use crate::hardening::{fill_random, LockedKey};

/// Binary magic header for omavault files (`OMAV`).
pub const VAULT_MAGIC: &[u8; 4] = b"OMAV";
/// Legacy direct-KDF vault format (passphrase, optional keyfile, optional single FIDO2 key).
pub const VAULT_VERSION_V1: u16 = 1;
/// Envelope-encrypted multi-key FIDO2 slot format (random master key wrapped per YubiKey slot).
pub const VAULT_VERSION_V2: u16 = 2;
/// Backwards-compatible alias for `VAULT_VERSION_V1`.
pub const VAULT_VERSION: u16 = VAULT_VERSION_V1;

pub const FLAG_KEYFILE: u16 = 1 << 0;
pub const FLAG_FIDO2: u16 = 1 << 1;
const KNOWN_FLAGS_MASK: u16 = FLAG_KEYFILE | FLAG_FIDO2;

/// Maximum number of enrolled FIDO2 hardware key slots in a single `OMAV` v2 vault.
pub const MAX_FIDO2_SLOTS: usize = 8;

/// Fixed prefix size before optional `fido2_meta` bytes.
const FIXED_HEADER_LEN: usize = 4 + 2 + 2 + 4 + 4 + 4 + 32 + 32 + 24 + 2; // 110 bytes
const MAX_FIDO2_META_LEN_V1: usize = 4096;
const MAX_FIDO2_META_LEN_V2: usize = 16384;
/// Length-hiding padding block size (4 KiB).
const PADDING_BLOCK_SIZE: usize = 4096;
const AEAD_TAG_LEN: usize = 16;
const SLOT_WRAP_NONCE_LEN: usize = 24;
const SLOT_WRAPPED_KEY_LEN: usize = 32 + AEAD_TAG_LEN;
const SLOT_AAD_DOMAIN: &[u8] = b"omavault-v2-slot-aad";

/// Upper bound on decrypted payload size (64 MiB) to guard against malformed inputs.
pub const MAX_PAYLOAD_SIZE: usize = 64 * 1024 * 1024;
/// Maximum legal ciphertext size corresponding to `MAX_PAYLOAD_SIZE` padded + Poly1305 tag.
pub const MAX_CIPHERTEXT_SIZE: usize =
    (MAX_PAYLOAD_SIZE + 4).div_ceil(PADDING_BLOCK_SIZE) * PADDING_BLOCK_SIZE + AEAD_TAG_LEN;
/// Maximum legal full vault file size (header + ciphertext).
pub const MAX_VAULT_FILE_BYTES: u64 =
    (FIXED_HEADER_LEN + MAX_FIDO2_META_LEN_V2 + MAX_CIPHERTEXT_SIZE) as u64;

/// Validate a NEW human-friendly FIDO2 slot label: 1..=64 bytes, no outer whitespace, no control
/// characters, and no BiDi overrides / zero-width / tag characters that could spoof terminal output.
pub fn validate_slot_label(label: &str) -> Result<()> {
    validate_slot_label_lenient(label)?;
    if label
        .chars()
        .any(crate::hardening::is_dangerous_display_char)
    {
        return Err(VaultError::Fido2Error(
            "FIDO2 key label cannot contain BiDi control, zero-width, or other invisible characters"
                .into(),
        ));
    }
    Ok(())
}

/// Parse-time label validation (kept lenient so vaults created by earlier versions still open;
/// labels are additionally sanitized whenever they are displayed).
fn validate_slot_label_lenient(label: &str) -> Result<()> {
    if label.is_empty() || label.len() > 64 {
        return Err(VaultError::Fido2Error(
            "FIDO2 key label must be between 1 and 64 bytes".into(),
        ));
    }
    if label.trim() != label || label.chars().any(|c| c.is_control()) {
        return Err(VaultError::Fido2Error(
            "FIDO2 key label cannot contain control characters or leading/trailing whitespace"
                .into(),
        ));
    }
    Ok(())
}

/// Authenticated key-wrapping slot for one enrolled FIDO2 hardware key in an `OMAV` v2 vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fido2KeySlot {
    /// Human-friendly unique label (e.g. `"primary"`, `"backup"`).
    pub label: String,
    /// Non-secret FIDO2 enrollment metadata (`rp_id`, `credential_id_b64`, `hmac_salt_b64`, `require_uv`).
    pub fido2: Fido2Metadata,
    /// Base64-encoded 24-byte random XChaCha20-Poly1305 nonce used to wrap the vault master key.
    pub wrap_nonce_b64: String,
    /// Base64-encoded 48-byte XChaCha20-Poly1305 ciphertext (32B wrapped master key + 16B tag).
    pub wrapped_key_b64: String,
}

impl Fido2KeySlot {
    pub fn validate(&self) -> Result<()> {
        validate_slot_label_lenient(&self.label)?;
        self.fido2.validate()?;
        let nonce = BASE64.decode(self.wrap_nonce_b64.as_bytes()).map_err(|_| {
            VaultError::InvalidFormat("invalid Base64 FIDO2 slot wrap nonce".into())
        })?;
        if nonce.len() != SLOT_WRAP_NONCE_LEN {
            return Err(VaultError::InvalidFormat(
                "FIDO2 slot wrap nonce must be 24 bytes".into(),
            ));
        }
        let wrapped = BASE64
            .decode(self.wrapped_key_b64.as_bytes())
            .map_err(|_| VaultError::InvalidFormat("invalid Base64 FIDO2 wrapped key".into()))?;
        if wrapped.len() != SLOT_WRAPPED_KEY_LEN {
            return Err(VaultError::InvalidFormat(
                "FIDO2 slot wrapped key must be 48 bytes".into(),
            ));
        }
        Ok(())
    }
}

/// Serialized JSON payload stored in the `fido2_meta` region of `OMAV` v2 headers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fido2SlotBundle {
    pub slots: Vec<Fido2KeySlot>,
}

impl Fido2SlotBundle {
    pub fn validate(&self) -> Result<()> {
        if self.slots.is_empty() || self.slots.len() > MAX_FIDO2_SLOTS {
            return Err(VaultError::InvalidFormat(format!(
                "OMAV v2 vault must have between 1 and {MAX_FIDO2_SLOTS} FIDO2 key slots"
            )));
        }
        let mut labels = HashSet::with_capacity(self.slots.len());
        let mut creds = HashSet::with_capacity(self.slots.len());
        for slot in &self.slots {
            slot.validate()?;
            if !labels.insert(slot.label.to_ascii_lowercase()) {
                return Err(VaultError::InvalidFormat(format!(
                    "duplicate FIDO2 key slot label '{}'",
                    slot.label
                )));
            }
            if !creds.insert(slot.fido2.credential_id_b64.as_str()) {
                return Err(VaultError::InvalidFormat(
                    "duplicate FIDO2 credential ID across key slots".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Authenticated header of an `OMAV` v1 or v2 encrypted vault file.
///
/// Every byte of this serialized header is passed as Associated Data (AAD) to
/// `XChaCha20-Poly1305`, ensuring any modification to version, flags, KDF params,
/// salts, nonce, or FIDO2 metadata/slots causes immediate MAC verification failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultHeader {
    pub version: u16,
    pub flags: u16,
    pub kdf_params: KdfParams,
    pub kdf_salt: [u8; 32],
    pub save_salt: [u8; 32],
    pub nonce: [u8; 24],
    /// Legacy single FIDO2 enrollment metadata (`OMAV` v1 only).
    pub fido2: Option<Fido2Metadata>,
    /// Multi-key envelope-wrapped FIDO2 key slots (`OMAV` v2 only).
    pub fido2_slots: Vec<Fido2KeySlot>,
}

impl VaultHeader {
    /// Construct a new `OMAV` v1 header (passphrase, optional keyfile, optional single FIDO2 key).
    pub fn new(
        kdf_params: KdfParams,
        use_keyfile: bool,
        fido2: Option<Fido2Metadata>,
    ) -> Result<Self> {
        if let Some(meta) = &fido2 {
            meta.validate()?;
        }
        let mut kdf_salt = [0u8; 32];
        let mut save_salt = [0u8; 32];
        let mut nonce = [0u8; 24];
        fill_random(&mut kdf_salt)?;
        fill_random(&mut save_salt)?;
        fill_random(&mut nonce)?;

        let mut flags = 0u16;
        if use_keyfile {
            flags |= FLAG_KEYFILE;
        }
        if fido2.is_some() {
            flags |= FLAG_FIDO2;
        }

        Ok(Self {
            version: VAULT_VERSION_V1,
            flags,
            kdf_params,
            kdf_salt,
            save_salt,
            nonce,
            fido2,
            fido2_slots: Vec::new(),
        })
    }

    /// Construct a fresh `OMAV` v2 header shell with `FLAG_FIDO2` set and fresh CSPRNG salts/nonce.
    ///
    /// Callers wrap the random `vault_master_key` into one or more `Fido2KeySlot`s using
    /// `wrap_master_key_for_slot` and push them onto `header.fido2_slots` before sealing.
    pub fn new_v2_fido2_shell(kdf_params: KdfParams, use_keyfile: bool) -> Result<Self> {
        let mut kdf_salt = [0u8; 32];
        let mut save_salt = [0u8; 32];
        let mut nonce = [0u8; 24];
        fill_random(&mut kdf_salt)?;
        fill_random(&mut save_salt)?;
        fill_random(&mut nonce)?;

        let mut flags = FLAG_FIDO2;
        if use_keyfile {
            flags |= FLAG_KEYFILE;
        }

        Ok(Self {
            version: VAULT_VERSION_V2,
            flags,
            kdf_params,
            kdf_salt,
            save_salt,
            nonce,
            fido2: None,
            fido2_slots: Vec::new(),
        })
    }

    pub fn requires_keyfile(&self) -> bool {
        (self.flags & FLAG_KEYFILE) != 0
    }

    pub fn requires_fido2(&self) -> bool {
        (self.flags & FLAG_FIDO2) != 0
    }

    pub fn fido2_labels(&self) -> Vec<&str> {
        if self.version == VAULT_VERSION_V2 {
            self.fido2_slots.iter().map(|s| s.label.as_str()).collect()
        } else if self.fido2.is_some() {
            vec!["legacy-v1"]
        } else {
            Vec::new()
        }
    }

    pub fn has_fido2_label(&self, label: &str) -> bool {
        self.fido2_slots
            .iter()
            .any(|s| s.label.eq_ignore_ascii_case(label))
    }

    /// Generate fresh `save_salt` and `nonce` for every new save operation.
    pub fn rotate_save_material(&mut self) -> Result<()> {
        fill_random(&mut self.save_salt)?;
        fill_random(&mut self.nonce)?;
        Ok(())
    }

    /// Serialize header bytes (which also serve verbatim as AEAD AAD).
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.kdf_params.validate_upper_bounds()?;
        if (self.flags & !KNOWN_FLAGS_MASK) != 0 {
            return Err(VaultError::InvalidFormat(format!(
                "unknown vault header flags: 0x{:04x}",
                self.flags
            )));
        }

        let (fido2_bytes, max_meta_len) = match self.version {
            VAULT_VERSION_V1 => {
                if !self.fido2_slots.is_empty() {
                    return Err(VaultError::InvalidFormat(
                        "OMAV v1 header cannot contain v2 FIDO2 key slots".into(),
                    ));
                }
                if self.requires_fido2() != self.fido2.is_some() {
                    return Err(VaultError::InvalidFormat(
                        "header FIDO2 flag does not match FIDO2 metadata presence".into(),
                    ));
                }
                let bytes = match &self.fido2 {
                    Some(meta) => {
                        meta.validate()?;
                        serde_json::to_vec(meta)
                            .map_err(|e| VaultError::Serialization(e.to_string()))?
                    }
                    None => Vec::new(),
                };
                (bytes, MAX_FIDO2_META_LEN_V1)
            }
            VAULT_VERSION_V2 => {
                if !self.requires_fido2() || self.fido2.is_some() {
                    return Err(VaultError::InvalidFormat(
                        "OMAV v2 header requires FLAG_FIDO2 and v2 slot bundle".into(),
                    ));
                }
                let bundle = Fido2SlotBundle {
                    slots: self.fido2_slots.clone(),
                };
                bundle.validate()?;
                let bytes = serde_json::to_vec(&bundle)
                    .map_err(|e| VaultError::Serialization(e.to_string()))?;
                (bytes, MAX_FIDO2_META_LEN_V2)
            }
            other => return Err(VaultError::UnsupportedVersion(other)),
        };

        if fido2_bytes.len() > max_meta_len {
            return Err(VaultError::InvalidFormat(
                "FIDO2 metadata exceeds maximum allowed size".into(),
            ));
        }

        let mut out = Vec::with_capacity(FIXED_HEADER_LEN + fido2_bytes.len());
        out.extend_from_slice(VAULT_MAGIC);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.flags.to_le_bytes());
        out.extend_from_slice(&self.kdf_params.mem_kib.to_le_bytes());
        out.extend_from_slice(&self.kdf_params.time_cost.to_le_bytes());
        out.extend_from_slice(&self.kdf_params.parallelism.to_le_bytes());
        out.extend_from_slice(&self.kdf_salt);
        out.extend_from_slice(&self.save_salt);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&(fido2_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&fido2_bytes);
        Ok(out)
    }

    /// Parse header from a full vault blob and return `(header, header_byte_len)`.
    ///
    /// Enforces pre-authentication size bounds and validates FIDO2 metadata/slots before
    /// any expensive KDF or hardware authenticator interaction runs.
    pub fn parse(data: &[u8], enforce_kdf_policy: bool) -> Result<(Self, usize)> {
        if data.len() < FIXED_HEADER_LEN + PADDING_BLOCK_SIZE + AEAD_TAG_LEN {
            return Err(VaultError::InvalidFormat(
                "vault file truncated or too small".into(),
            ));
        }
        if &data[0..4] != VAULT_MAGIC {
            return Err(VaultError::InvalidFormat(
                "invalid vault magic (not an omavault file)".into(),
            ));
        }

        let version = u16::from_le_bytes([data[4], data[5]]);
        let max_meta_len = match version {
            VAULT_VERSION_V1 => MAX_FIDO2_META_LEN_V1,
            VAULT_VERSION_V2 => MAX_FIDO2_META_LEN_V2,
            other => return Err(VaultError::UnsupportedVersion(other)),
        };

        let flags = u16::from_le_bytes([data[6], data[7]]);
        if (flags & !KNOWN_FLAGS_MASK) != 0 {
            return Err(VaultError::InvalidFormat(format!(
                "unknown vault header flags: 0x{flags:04x}"
            )));
        }

        let kdf_params = KdfParams {
            mem_kib: u32::from_le_bytes(data[8..12].try_into().unwrap()),
            time_cost: u32::from_le_bytes(data[12..16].try_into().unwrap()),
            parallelism: u32::from_le_bytes(data[16..20].try_into().unwrap()),
        };
        if enforce_kdf_policy {
            kdf_params.validate()?;
        } else {
            kdf_params.validate_upper_bounds()?;
        }

        let mut kdf_salt = [0u8; 32];
        kdf_salt.copy_from_slice(&data[20..52]);
        let mut save_salt = [0u8; 32];
        save_salt.copy_from_slice(&data[52..84]);
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&data[84..108]);

        let fido2_len = u16::from_le_bytes([data[108], data[109]]) as usize;
        if fido2_len > max_meta_len {
            return Err(VaultError::InvalidFormat(
                "FIDO2 metadata length exceeds limit".into(),
            ));
        }

        let header_len = FIXED_HEADER_LEN + fido2_len;
        if data.len() < header_len + PADDING_BLOCK_SIZE + AEAD_TAG_LEN {
            return Err(VaultError::InvalidFormat(
                "vault file truncated inside header/ciphertext".into(),
            ));
        }
        let ct_len = data.len() - header_len;
        if ct_len > MAX_CIPHERTEXT_SIZE
            || !(ct_len - AEAD_TAG_LEN).is_multiple_of(PADDING_BLOCK_SIZE)
        {
            return Err(VaultError::InvalidFormat(
                "invalid vault ciphertext length or alignment".into(),
            ));
        }

        let has_fido2_flag = (flags & FLAG_FIDO2) != 0;
        let (fido2, fido2_slots) = match version {
            VAULT_VERSION_V1 => {
                if has_fido2_flag {
                    if fido2_len == 0 {
                        return Err(VaultError::InvalidFormat(
                            "FIDO2 flag set but metadata missing".into(),
                        ));
                    }
                    let meta: Fido2Metadata = serde_json::from_slice(
                        &data[FIXED_HEADER_LEN..header_len],
                    )
                    .map_err(|_| VaultError::InvalidFormat("corrupt FIDO2 metadata".into()))?;
                    meta.validate()?;
                    (Some(meta), Vec::new())
                } else {
                    if fido2_len != 0 {
                        return Err(VaultError::InvalidFormat(
                            "unexpected FIDO2 metadata without FIDO2 flag".into(),
                        ));
                    }
                    (None, Vec::new())
                }
            }
            VAULT_VERSION_V2 => {
                if !has_fido2_flag || fido2_len == 0 {
                    return Err(VaultError::InvalidFormat(
                        "OMAV v2 vault requires FIDO2 flag and slot bundle".into(),
                    ));
                }
                let bundle: Fido2SlotBundle =
                    serde_json::from_slice(&data[FIXED_HEADER_LEN..header_len]).map_err(|_| {
                        VaultError::InvalidFormat("corrupt OMAV v2 FIDO2 slot bundle".into())
                    })?;
                bundle.validate()?;
                (None, bundle.slots)
            }
            _ => unreachable!(),
        };

        Ok((
            Self {
                version,
                flags,
                kdf_params,
                kdf_salt,
                save_salt,
                nonce,
                fido2,
                fido2_slots,
            },
            header_len,
        ))
    }
}

/// Compute the opaque revision token for a vault header.
///
/// It is a domain-separated BLAKE3 hash of the COMPLETE serialized header (version, flags, KDF
/// params, `kdf_salt`, per-save `save_salt` + nonce, and every key slot), so ANY on-disk header
/// edit — not just a `save_salt` change — is detected as a concurrent modification. (Hashing only
/// `save_salt` let a tampered header that kept `save_salt` pass the check.)
pub fn header_revision(header: &VaultHeader) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"omavault-header-revision-v1\0");
    match header.to_bytes() {
        Ok(bytes) => {
            hasher.update(&bytes);
        }
        // Unreachable for parsed/constructed headers (they are validated); still never collide
        // with a real revision.
        Err(_) => {
            hasher.update(b"\xffinvalid-header");
            hasher.update(&header.save_salt);
        }
    }
    hasher.finalize().to_hex().to_string()
}

/// Generate a fresh CSPRNG 256-bit vault master key inside `mlock`ed `PROT_NONE` memory.
pub fn generate_random_master_key() -> Result<LockedKey<32>> {
    let mut raw = [0u8; 32];
    fill_random(&mut raw)?;
    LockedKey::new(&mut raw)
}

fn build_slot_aad(header: &VaultHeader, label: &str, fido2: &Fido2Metadata) -> Vec<u8> {
    let mut aad = Vec::with_capacity(256);
    aad.extend_from_slice(SLOT_AAD_DOMAIN);
    aad.extend_from_slice(&header.version.to_le_bytes());
    aad.extend_from_slice(&header.flags.to_le_bytes());
    aad.extend_from_slice(&header.kdf_params.mem_kib.to_le_bytes());
    aad.extend_from_slice(&header.kdf_params.time_cost.to_le_bytes());
    aad.extend_from_slice(&header.kdf_params.parallelism.to_le_bytes());
    aad.extend_from_slice(&header.kdf_salt);
    for field in [
        label.as_bytes(),
        fido2.rp_id.as_bytes(),
        fido2.credential_id_b64.as_bytes(),
        fido2.hmac_salt_b64.as_bytes(),
    ] {
        aad.extend_from_slice(&(field.len() as u32).to_le_bytes());
        aad.extend_from_slice(field);
    }
    aad.push(u8::from(fido2.require_uv));
    aad
}

/// XChaCha20-Poly1305 in a frame that returns before the stack is scrubbed.
///
/// `chacha20` 0.9.1 copies the key into `hchacha`'s stack state and does not zeroize it.
/// The cipher call is `#[inline(never)]`. `scrub_stack` runs in this function immediately
/// after that frame returns, on both success and failure, so the next call reuses those
/// addresses. This does not prove a particular stack byte was wiped.
fn aead_seal(
    key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    msg: &[u8],
) -> std::result::Result<Vec<u8>, ()> {
    let result = aead_seal_frame(key, nonce, aad, msg);
    crate::hardening::scrub_stack();
    result
}

#[inline(never)]
fn aead_seal_frame(
    key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    msg: &[u8],
) -> std::result::Result<Vec<u8>, ()> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(XNonce::from_slice(nonce), Payload { msg, aad })
        .map_err(|_| ())
}

fn aead_open(
    key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> std::result::Result<Vec<u8>, ()> {
    let result = aead_open_frame(key, nonce, aad, ciphertext);
    crate::hardening::scrub_stack();
    result
}

#[inline(never)]
fn aead_open_frame(
    key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> std::result::Result<Vec<u8>, ()> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| ())
}

/// Wrap `master_key` into an authenticated `OMAV` v2 `Fido2KeySlot` bound to `(passphrase, [keyfile], YubiKey)`.
pub fn wrap_master_key_for_slot(
    header: &VaultHeader,
    master_key: &LockedKey<32>,
    pw_hash: &[u8; 32],
    keyfile_digest: Option<&[u8; 32]>,
    label: &str,
    fido2: Fido2Metadata,
    fido2_secret: &[u8; 32],
) -> Result<Fido2KeySlot> {
    if header.version != VAULT_VERSION_V2 || !header.requires_fido2() {
        return Err(VaultError::InvalidFormat(
            "key-slot wrapping requires an OMAV v2 FIDO2 header".into(),
        ));
    }
    if header.requires_keyfile() != keyfile_digest.is_some() {
        return Err(VaultError::InvalidFormat(
            "keyfile presence does not match vault header FLAG_KEYFILE".into(),
        ));
    }
    validate_slot_label(label)?;
    fido2.validate()?;

    let kek = derive_slot_kek(pw_hash, &header.kdf_salt, keyfile_digest, fido2_secret)?;
    let mut wrap_nonce = [0u8; SLOT_WRAP_NONCE_LEN];
    fill_random(&mut wrap_nonce)?;
    let aad = build_slot_aad(header, label, &fido2);

    let wrapped = master_key.expose(|mk| {
        aead_seal(&kek, &wrap_nonce, &aad, mk.as_slice())
            .map_err(|_| VaultError::Crypto("FIDO2 key-slot wrap encryption failed".into()))
    })??;

    let slot = Fido2KeySlot {
        label: label.to_string(),
        fido2,
        wrap_nonce_b64: BASE64.encode(&wrap_nonce),
        wrapped_key_b64: BASE64.encode(&wrapped),
    };
    slot.validate()?;
    Ok(slot)
}

/// Unwrap the 256-bit `vault_master_key` from an `OMAV` v2 `Fido2KeySlot` into `LockedKey<32>`.
pub fn unwrap_master_key_from_slot(
    header: &VaultHeader,
    slot: &Fido2KeySlot,
    pw_hash: &[u8; 32],
    keyfile_digest: Option<&[u8; 32]>,
    fido2_secret: &[u8; 32],
) -> Result<LockedKey<32>> {
    if header.version != VAULT_VERSION_V2 || !header.requires_fido2() {
        return Err(VaultError::InvalidFormat(
            "key-slot unwrapping requires an OMAV v2 FIDO2 header".into(),
        ));
    }
    if header.requires_keyfile() != keyfile_digest.is_some() {
        return Err(VaultError::InvalidFormat(
            "keyfile presence does not match vault header FLAG_KEYFILE".into(),
        ));
    }
    slot.validate()?;

    let kek = derive_slot_kek(pw_hash, &header.kdf_salt, keyfile_digest, fido2_secret)?;
    let wrap_nonce = BASE64
        .decode(slot.wrap_nonce_b64.as_bytes())
        .map_err(|_| VaultError::InvalidFormat("invalid Base64 slot wrap nonce".into()))?;
    let wrapped = BASE64
        .decode(slot.wrapped_key_b64.as_bytes())
        .map_err(|_| VaultError::InvalidFormat("invalid Base64 slot wrapped key".into()))?;
    let aad = build_slot_aad(header, &slot.label, &slot.fido2);

    let plain = Zeroizing::new(
        aead_open(&kek, &wrap_nonce, &aad, &wrapped)
            .map_err(|_| VaultError::AuthenticationFailed)?,
    );
    if plain.len() != 32 {
        return Err(VaultError::AuthenticationFailed);
    }

    let mut raw = [0u8; 32];
    raw.copy_from_slice(&plain);
    LockedKey::new(&mut raw)
}

/// Outcome of unlocking any `OMAV` v1 or v2 vault header.
pub struct UnlockResolution {
    pub master_key: LockedKey<32>,
    pub matched_slot_index: Option<usize>,
    pub matched_fido2_secret: Option<Zeroizing<[u8; 32]>>,
    pub pw_hash: Zeroizing<[u8; 32]>,
}

/// Unified unlock routine for both `OMAV` v1 (direct KDF) and `OMAV` v2 (multi-YubiKey slots).
///
/// Runs Argon2id exactly once per unlock attempt, matches the plugged-in YubiKey against
/// enrolled slots (for v2), and returns the hardened `LockedKey<32>`.
pub fn resolve_master_key<P: Fido2Provider>(
    header: &VaultHeader,
    passphrase: &[u8],
    keyfile_digest: Option<&[u8; 32]>,
    fido2_provider: &P,
    fido2_device: Option<&str>,
    enforce_policy: bool,
) -> Result<UnlockResolution> {
    if header.requires_keyfile() && keyfile_digest.is_none() {
        return Err(VaultError::KeyfileRequired);
    }
    if !header.requires_keyfile() && keyfile_digest.is_some() {
        return Err(VaultError::InvalidFormat(
            "keyfile supplied for a vault that does not use a keyfile".into(),
        ));
    }

    let pw_hash = derive_passphrase_hash(
        passphrase,
        &header.kdf_salt,
        header.kdf_params,
        enforce_policy,
    )?;

    match header.version {
        VAULT_VERSION_V1 => {
            let fido2_secret = if header.requires_fido2() {
                let meta = header.fido2.as_ref().ok_or(VaultError::Fido2Required)?;
                Some(fido2_provider.get_hmac_secret(meta, fido2_device)?)
            } else {
                None
            };
            let master_key = derive_master_key_from_pw_hash(
                &pw_hash,
                &header.kdf_salt,
                keyfile_digest,
                fido2_secret.as_deref(),
            )?;
            Ok(UnlockResolution {
                master_key,
                matched_slot_index: None,
                matched_fido2_secret: fido2_secret,
                pw_hash,
            })
        }
        VAULT_VERSION_V2 => {
            if !header.requires_fido2() || header.fido2_slots.is_empty() {
                return Err(VaultError::Fido2Required);
            }
            let (slot_idx, fido2_secret) =
                fido2_provider.assert_matching_slot(&header.fido2_slots, fido2_device)?;
            let slot = header
                .fido2_slots
                .get(slot_idx)
                .ok_or(VaultError::Fido2NoMatchingCredential)?;
            let master_key =
                unwrap_master_key_from_slot(header, slot, &pw_hash, keyfile_digest, &fido2_secret)?;
            Ok(UnlockResolution {
                master_key,
                matched_slot_index: Some(slot_idx),
                matched_fido2_secret: Some(fido2_secret),
                pw_hash,
            })
        }
        other => Err(VaultError::UnsupportedVersion(other)),
    }
}

/// Encrypt plaintext bytes into a complete, length-padded, AAD-authenticated `OMAV` blob.
///
/// Automatically rotates `header.save_salt` and `header.nonce` so every single write
/// uses a brand-new 256-bit HKDF subkey and 192-bit XChaCha20-Poly1305 nonce.
pub fn seal_vault(
    master_key: &LockedKey<32>,
    header: &mut VaultHeader,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    if plaintext.len() > MAX_PAYLOAD_SIZE {
        return Err(VaultError::InvalidFormat(
            "vault payload exceeds 64 MiB safety limit".into(),
        ));
    }

    header.rotate_save_material()?;
    let aad = header.to_bytes()?;

    let min_frame = 4 + plaintext.len();
    let padded_len = min_frame.div_ceil(PADDING_BLOCK_SIZE) * PADDING_BLOCK_SIZE;
    let mut frame = Zeroizing::new(vec![0u8; padded_len]);
    frame[0..4].copy_from_slice(&(plaintext.len() as u32).to_le_bytes());
    frame[4..4 + plaintext.len()].copy_from_slice(plaintext);
    if padded_len > min_frame {
        fill_random(&mut frame[min_frame..])?;
    }

    let enc_key = derive_payload_key(master_key, &header.save_salt)?;
    let ciphertext = aead_seal(&enc_key, &header.nonce, &aad, &frame)
        .map_err(|_| VaultError::Crypto("XChaCha20-Poly1305 encryption failed".into()))?;

    let mut blob = Vec::with_capacity(aad.len() + ciphertext.len());
    blob.extend_from_slice(&aad);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Decrypt and authenticate a complete `OMAV` v1 or v2 blob, returning `(header, Zeroizing<plaintext>)`.
pub fn open_vault(
    master_key: &LockedKey<32>,
    blob: &[u8],
    enforce_kdf_policy: bool,
) -> Result<(VaultHeader, Zeroizing<Vec<u8>>)> {
    let (header, header_len) = VaultHeader::parse(blob, enforce_kdf_policy)?;
    let aad = &blob[..header_len];
    let ciphertext = &blob[header_len..];

    let enc_key = derive_payload_key(master_key, &header.save_salt)?;
    let frame = Zeroizing::new(
        aead_open(&enc_key, &header.nonce, aad, ciphertext)
            .map_err(|_| VaultError::AuthenticationFailed)?,
    );

    if frame.len() < 4 || !frame.len().is_multiple_of(PADDING_BLOCK_SIZE) {
        return Err(VaultError::InvalidFormat(
            "decrypted frame invalid alignment".into(),
        ));
    }
    let payload_len = u32::from_le_bytes(frame[0..4].try_into().unwrap()) as usize;
    if payload_len > MAX_PAYLOAD_SIZE || 4 + payload_len > frame.len() {
        return Err(VaultError::InvalidFormat(
            "invalid decrypted frame payload length".into(),
        ));
    }
    let padding_len = frame.len() - (4 + payload_len);
    if padding_len >= PADDING_BLOCK_SIZE {
        return Err(VaultError::InvalidFormat(
            "invalid decrypted frame padding length".into(),
        ));
    }

    let plaintext = Zeroizing::new(frame[4..4 + payload_len].to_vec());
    Ok((header, plaintext))
}

#[cfg(test)]
mod aead_scrub_tests {
    use super::*;

    #[test]
    fn aead_helpers_round_trip_and_reject_tampering() {
        // Both the Ok and Err returns run scrub_stack before leaving the helper.
        // Safe Rust cannot show that a particular stack byte was wiped.
        let key = [7u8; 32];
        let nonce = [9u8; 24];
        let aad = b"header-aad";
        let msg = b"secret-payload";
        let ct = aead_seal(&key, &nonce, aad, msg).expect("seal");
        let pt = aead_open(&key, &nonce, aad, &ct).expect("open");
        assert_eq!(pt, msg);

        let mut flipped = ct.clone();
        flipped[0] ^= 1;
        assert!(aead_open(&key, &nonce, aad, &flipped).is_err());
        assert!(aead_open(&key, &nonce, b"other-aad", &ct).is_err());
    }
}
