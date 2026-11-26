pub mod fido2;
pub mod kdf;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::crypto::fido2::Fido2Metadata;
use crate::crypto::kdf::{derive_payload_key, KdfParams};
use crate::error::{Result, VaultError};
use crate::hardening::{fill_random, LockedKey};

/// Binary magic header for omavault files (`OMAV`).
pub const VAULT_MAGIC: &[u8; 4] = b"OMAV";
pub const VAULT_VERSION: u16 = 1;

pub const FLAG_KEYFILE: u16 = 1 << 0;
pub const FLAG_FIDO2: u16 = 1 << 1;
const KNOWN_FLAGS_MASK: u16 = FLAG_KEYFILE | FLAG_FIDO2;

/// Fixed prefix size before optional `fido2_meta` bytes.
const FIXED_HEADER_LEN: usize = 4 + 2 + 2 + 4 + 4 + 4 + 32 + 32 + 24 + 2; // 110 bytes
const MAX_FIDO2_META_LEN: usize = 4096;
/// Length-hiding padding block size (4 KiB).
const PADDING_BLOCK_SIZE: usize = 4096;
const AEAD_TAG_LEN: usize = 16;
/// Upper bound on decrypted payload size (64 MiB) to guard against malformed inputs.
pub const MAX_PAYLOAD_SIZE: usize = 64 * 1024 * 1024;
/// Maximum legal ciphertext size corresponding to `MAX_PAYLOAD_SIZE` padded + Poly1305 tag.
pub const MAX_CIPHERTEXT_SIZE: usize =
    (MAX_PAYLOAD_SIZE + 4).div_ceil(PADDING_BLOCK_SIZE) * PADDING_BLOCK_SIZE + AEAD_TAG_LEN;
/// Maximum legal full vault file size (header + ciphertext).
pub const MAX_VAULT_FILE_BYTES: u64 =
    (FIXED_HEADER_LEN + MAX_FIDO2_META_LEN + MAX_CIPHERTEXT_SIZE) as u64;

/// Authenticated header of an `OMAV` v1 encrypted vault file.
///
/// Every byte of this serialized header is passed as Associated Data (AAD) to
/// `XChaCha20-Poly1305`, ensuring any modification to version, flags, KDF params,
/// salts, nonce, or FIDO2 metadata causes immediate MAC verification failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultHeader {
    pub version: u16,
    pub flags: u16,
    pub kdf_params: KdfParams,
    pub kdf_salt: [u8; 32],
    pub save_salt: [u8; 32],
    pub nonce: [u8; 24],
    pub fido2: Option<Fido2Metadata>,
}

impl VaultHeader {
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
            version: VAULT_VERSION,
            flags,
            kdf_params,
            kdf_salt,
            save_salt,
            nonce,
            fido2,
        })
    }

    pub fn requires_keyfile(&self) -> bool {
        (self.flags & FLAG_KEYFILE) != 0
    }

    pub fn requires_fido2(&self) -> bool {
        (self.flags & FLAG_FIDO2) != 0
    }

    /// Generate fresh `save_salt` and `nonce` for every new save operation.
    pub fn rotate_save_material(&mut self) -> Result<()> {
        fill_random(&mut self.save_salt)?;
        fill_random(&mut self.nonce)?;
        Ok(())
    }

    /// Serialize header bytes (which also serve verbatim as AEAD AAD).
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        if self.version != VAULT_VERSION {
            return Err(VaultError::UnsupportedVersion(self.version));
        }
        if (self.flags & !KNOWN_FLAGS_MASK) != 0 {
            return Err(VaultError::InvalidFormat(format!(
                "unknown vault header flags: 0x{:04x}",
                self.flags
            )));
        }
        if self.requires_fido2() != self.fido2.is_some() {
            return Err(VaultError::InvalidFormat(
                "header FIDO2 flag does not match FIDO2 metadata presence".into(),
            ));
        }

        let fido2_bytes = match &self.fido2 {
            Some(meta) => {
                meta.validate()?;
                serde_json::to_vec(meta)
                    .map_err(|e| VaultError::Serialization(e.to_string()))?
            }
            None => Vec::new(),
        };
        if fido2_bytes.len() > MAX_FIDO2_META_LEN {
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
    /// Enforces pre-authentication size bounds and validates FIDO2 metadata before
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
        if version != VAULT_VERSION {
            return Err(VaultError::UnsupportedVersion(version));
        }

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
        if fido2_len > MAX_FIDO2_META_LEN {
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
        if ct_len > MAX_CIPHERTEXT_SIZE || (ct_len - AEAD_TAG_LEN) % PADDING_BLOCK_SIZE != 0 {
            return Err(VaultError::InvalidFormat(
                "invalid vault ciphertext length or alignment".into(),
            ));
        }

        let has_fido2_flag = (flags & FLAG_FIDO2) != 0;
        let fido2 = if has_fido2_flag {
            if fido2_len == 0 {
                return Err(VaultError::InvalidFormat(
                    "FIDO2 flag set but metadata missing".into(),
                ));
            }
            let meta: Fido2Metadata = serde_json::from_slice(&data[FIXED_HEADER_LEN..header_len])
                .map_err(|_| VaultError::InvalidFormat("corrupt FIDO2 metadata".into()))?;
            meta.validate()?;
            Some(meta)
        } else {
            if fido2_len != 0 {
                return Err(VaultError::InvalidFormat(
                    "unexpected FIDO2 metadata without FIDO2 flag".into(),
                ));
            }
            None
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
            },
            header_len,
        ))
    }
}

/// Encrypt plaintext bytes into a complete, length-padded, AAD-authenticated `OMAV` v1 blob.
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
    let cipher = XChaCha20Poly1305::new((&*enc_key).into());
    let nonce = XNonce::from_slice(&header.nonce);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &frame,
                aad: &aad,
            },
        )
        .map_err(|_| VaultError::Crypto("XChaCha20-Poly1305 encryption failed".into()))?;

    let mut blob = Vec::with_capacity(aad.len() + ciphertext.len());
    blob.extend_from_slice(&aad);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Decrypt and authenticate a complete `OMAV` v1 blob, returning `(header, Zeroizing<plaintext>)`.
pub fn open_vault(
    master_key: &LockedKey<32>,
    blob: &[u8],
    enforce_kdf_policy: bool,
) -> Result<(VaultHeader, Zeroizing<Vec<u8>>)> {
    let (header, header_len) = VaultHeader::parse(blob, enforce_kdf_policy)?;
    let aad = &blob[..header_len];
    let ciphertext = &blob[header_len..];

    let enc_key = derive_payload_key(master_key, &header.save_salt)?;
    let cipher = XChaCha20Poly1305::new((&*enc_key).into());
    let nonce = XNonce::from_slice(&header.nonce);

    let frame = Zeroizing::new(
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| VaultError::AuthenticationFailed)?,
    );

    if frame.len() < 4 || frame.len() % PADDING_BLOCK_SIZE != 0 {
        return Err(VaultError::InvalidFormat("decrypted frame invalid alignment".into()));
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
