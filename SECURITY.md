# Security Architecture & Cryptographic Specification

`omavault` uses **zero custom cryptographic primitives**. All cryptography is delegated to audited, widely-reviewed pure-Rust implementations from the RustCrypto and BLAKE3 ecosystems.

## 1. Binary Vault Format (`OMAV` v1 & v2)

```text
Offset   Size   Field            Notes
------   ----   --------------   ------------------------------------------------
0        4      magic            ASCII "OMAV"
4        2      version          u16 LE (1 = direct KDF, 2 = multi-YubiKey FIDO2 key slots)
6        2      flags            u16 LE (bit 0 = keyfile, bit 1 = FIDO2)
8        4      argon2_mem_kib   u32 LE (default 131072 = 128 MiB, floor 65536)
12       4      argon2_time      u32 LE (default 4, floor 3, max 64)
16       4      argon2_lanes     u32 LE (default 4, floor 1, max 64)
20       32     kdf_salt         OS CSPRNG (rotated on init & rekey)
52       32     save_salt        OS CSPRNG (freshly rotated on EVERY save)
84       24     nonce            OS CSPRNG 192-bit XChaCha20-Poly1305 nonce (fresh per save)
108      2      fido2_meta_len   u16 LE (0..=4096 in v1; 1..=16384 in v2)
110      L      fido2_meta       UTF-8 JSON (v1: single Fido2Metadata; v2: 1..=8 wrapped Fido2KeySlots)
110+L    ...    ciphertext       XChaCha20-Poly1305(enc_key, nonce, AAD = bytes[0..110+L])
```

### Inner Length-Hiding Plaintext Frame (encrypted inside AEAD)

```text
[0..4]               payload_len  u32 LE
[4..4+payload_len]   json         UTF-8 serialized Vault
[4+payload_len..N]   padding      OS CSPRNG random bytes; N = ceil((4 + payload_len) / 4096) * 4096
```

## 2. Key Hierarchy

1. **Master Key Derivation**:
   - `pw_hash = Argon2id(passphrase, kdf_salt, m, t, p)` (32 bytes, RFC 9106 v0x13)
   - **`OMAV` v1** (passphrase / optional keyfile / legacy single FIDO2):
     - `ikm = b"PW" || pw_hash [|| b"KF" || BLAKE3(keyfile)] [|| b"F2" || FIDO2_hmac_secret]`
     - `master_key = HKDF-SHA512(salt = kdf_salt, ikm = ikm, info = "omavault-v1-master-key-combiner")` (32 bytes)
   - **`OMAV` v2** (multi-YubiKey FIDO2 key slots, `1..=8` keys):
     - `master_key` is a fresh 256-bit OS CSPRNG key (`getrandom(2)`).
     - Each enrolled YubiKey slot derives `kek_i = HKDF-SHA512(salt = kdf_salt, ikm = b"PW" || pw_hash [|| b"KF" || BLAKE3(keyfile)] || b"F2" || FIDO2_i_hmac_secret, info = "omavault-v2-fido2-slot-kek")` and wraps `master_key` with `XChaCha20-Poly1305(kek_i, wrap_nonce_i, master_key, AAD = slot_aad)`.
   - `master_key` is copied immediately into a dedicated `LockedKey<32>` page (`mmap` + `mlock` + `MADV_DONTDUMP` + `MADV_WIPEONFORK` + `mprotect(PROT_NONE)`), and all intermediate buffers are volatile-zeroized.
2. **Per-Save Payload Subkey** (`derive_payload_key`):
   - On every save, fresh 32-byte `save_salt` and 24-byte `nonce` are drawn from `getrandom(2)`.
   - `enc_key = HKDF-SHA512(salt = save_salt, ikm = master_key, info = "omavault-v1-payload-xchacha20poly1305")`
   - Ciphertext is authenticated with `XChaCha20-Poly1305` using the complete header as AAD.

## 3. Threat Model (Honest Boundaries)

### Defended Against
- **Offline vault theft / cold disk extraction**: Protected by 128 MiB Argon2id + optional 512-bit keyfile + hardware-bound FIDO2 `hmac-secret` + XChaCha20-Poly1305.
- **Header tampering & KDF downgrade attacks**: Full-header AAD rejects any 1-bit modification; hard KDF floors (`>= 64 MiB`, `>= 3` iterations) reject weak files before KDF execution.
- **Omarchy clipboard history leaks (`Super + Ctrl + V`)**: Native Wayland `x-kde-passwordManagerHint` (`sensitive`) tagging prevents Walker/cliphist/Stash from recording copied secrets, combined with `--paste-once` and safe timed auto-clear.
- **Swap & core dump leakage**: `mlock`, `MADV_DONTDUMP`, `MADV_WIPEONFORK`, `RLIMIT_CORE=0`, and `PROT_NONE` guard pages prevent secret material from reaching swap or crash dumps.
- **Same-UID non-root process snooping**: `prctl(PR_SET_DUMPABLE, 0)` blocks non-root `ptrace` attachment; daemon Unix socket verifies `SO_PEERCRED` UID and lives on `0700` tmpfs (`$XDG_RUNTIME_DIR`).
- **Unattended laptop / lid close / screen lock**: Redundant auto-lock mechanisms (inactivity timer, zero-subprocess Hyprland `ext-session-lock` IPC detector for Omarchy 4.5's `omarchy-shell`, `/proc` `hyprlock`/`swaylock` detector, `CLOCK_BOOTTIME - CLOCK_MONOTONIC` suspend skew detector, and optional legacy `hypridle` hooks).
- **Screen sharing / accidental screenshots**: Hyprland `no_screen_share on` window rule hides the floating TUI window from portals and screen captures.

### Out of Scope (Inherent OS Trust Boundary)
- A malicious `root` user or compromised Linux kernel can always read physical memory, inject keystrokes, or instrument Wayland compositors while the vault is unlocked. Keep your Omarchy Arch system updated, keep full-disk encryption (LUKS2) enabled, and lock the vault (`Super + Ctrl + Shift + L`) whenever stepping away.
