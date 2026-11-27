# Security Architecture & Cryptographic Specification

`omavault` uses **zero custom cryptographic primitives**. All cryptography is delegated to audited, widely-reviewed pure-Rust implementations from the RustCrypto and BLAKE3 ecosystems.

## 1. Binary Vault Format (`OMAV` v1 & v2)

```text
Offset   Size   Field            Notes
------   ----   --------------   ------------------------------------------------
0        4      magic            ASCII "OMAV"
4        2      version          u16 LE (1 = direct KDF, 2 = multi-YubiKey FIDO2 key slots)
6        2      flags            u16 LE (bit 0 = keyfile, bit 1 = FIDO2)
8        4      argon2_mem_kib   u32 LE (default 131072 = 128 MiB, floor 65536, max 1048576)
12       4      argon2_time      u32 LE (default 4, floor 3, max 16)
16       4      argon2_lanes     u32 LE (default 4, floor 1, max 16; work cap 8 GiB-iters)
20       32     kdf_salt         OS CSPRNG (rotated on init, rekey, and FIDO2 key revocation)
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
   - `pw_hash = Argon2id(passphrase, kdf_salt, m, t, p)` (32 bytes, RFC 9106 v0x13, computed once per unlock)
   - **`OMAV` v1** (passphrase / optional keyfile / legacy single FIDO2):
     - `ikm = b"PW" || pw_hash [|| b"KF" || BLAKE3(keyfile)] [|| b"F2" || FIDO2_hmac_secret]`
     - `master_key = HKDF-SHA512(salt = kdf_salt, ikm = ikm, info = "omavault-v1-master-key-combiner")` (32 bytes)
   - **`OMAV` v2** (multi-YubiKey FIDO2 key slots, `1..=8` unique slots):
     - `master_key` is a fresh 256-bit OS CSPRNG key (`getrandom(2)`).
     - Each enrolled YubiKey slot derives:
       - `kek_i = HKDF-SHA512(salt = kdf_salt, ikm = b"PW" || pw_hash [|| b"KF" || BLAKE3(keyfile)] || b"F2" || FIDO2_i_hmac_secret, info = "omavault-v2-fido2-slot-kek")`
     - `master_key` is wrapped with `XChaCha20-Poly1305(kek_i, wrap_nonce_i, master_key, AAD = slot_aad)` where:
       - `slot_aad = b"omavault-v2-slot-aad" || version || flags || kdf_params || kdf_salt || len+label || len+rp_id || len+credential_id_b64 || len+hmac_salt_b64 || require_uv`
       - Binding every slot to `kdf_salt`, `kdf_params`, and slot metadata prevents cross-vault slot transplantation or downgrade attacks.
     - Revoking a key (`omavault fido2 remove <label>`) rotates **both** `master_key` and `kdf_salt`, re-wraps all remaining keys, verifies decryption of the new vault, and purges rolling `.bak.*` files by default.
   - `master_key` is copied immediately into a dedicated `LockedKey<32>` page (`mmap` + `mlock` + `MADV_DONTDUMP` + `MADV_WIPEONFORK` + `mprotect(PROT_NONE)`), and all intermediate buffers are volatile-zeroized.
2. **Per-Save Payload Subkey** (`derive_payload_key`):
   - On every save, fresh 32-byte `save_salt` and 24-byte `nonce` are drawn from `getrandom(2)`.
   - `enc_key = HKDF-SHA512(salt = save_salt, ikm = master_key, info = "omavault-v1-payload-xchacha20poly1305")`
   - Ciphertext is authenticated with `XChaCha20-Poly1305` using the complete serialized header (`bytes[0..110+L]`) as AAD.

## 3. FIDO2 / YubiKey Verification Model

- `libfido2` tools (`fido2-token`, `fido2-cred`, `fido2-assert`) are resolved exclusively from root-owned non-group/world-writable system directories (`/usr/bin`, `/usr/local/bin`, `/bin`) with `--` option terminators, strict `/dev/hidraw<N>` canonical device validation, `PR_SET_PDEATHSIG(SIGTERM)`, and concurrent bounded stdout/stderr draining.
- Every enrollment and assertion response is verified for:
  - Exact `clientDataHash` echo and `rp_id == "omavault.local"`
  - Valid CBOR major-type-2 byte-string `authdata` (fail-closed, no raw fallback)
  - `authdata[0..32] == SHA-256(rp_id)` (`rpIdHash`)
  - CTAP2 flags: `UP` (`0x01`) always required, `ED` (`0x80`) required for `hmac-secret`, `AT` (`0x40`) required on enrollment, and `UV` (`0x04`) required when `require_uv == true`.

## 4. Threat Model (Honest Boundaries)

### Defended Against
- **Offline vault theft / cold disk extraction**: Protected by 128 MiB Argon2id + optional 512-bit owner-only keyfile + hardware-bound FIDO2 `hmac-secret` + XChaCha20-Poly1305.
- **Header tampering & KDF downgrade / DoS attacks**: Full-header AAD and per-slot AAD reject any 1-bit modification; hard KDF floors (`>= 64 MiB`, `>= 3` iterations) and ceilings (`<= 1 GiB`, `<= 16` iterations, `<= 8 GiB-iters`) are enforced before KDF execution.
- **Omarchy clipboard history & selection leaks (`Super + Ctrl + V`)**: Native Wayland `x-kde-passwordManagerHint` (`sensitive(true)`) tagging excludes secrets from Omarchy 4.5's `omarchy.clipboard`, combined with `--paste-once`, fail-closed timed auto-clear, `SIGTERM`-triggered helper self-clear (even when `omavaultd` lacks `WAYLAND_DISPLAY`), and `foot` primary-selection/OSC-52 disabling.
- **Swap, core dump & heap residue leakage**: `mlock`, `MADV_DONTDUMP`, `MADV_WIPEONFORK`, `RLIMIT_CORE=0`, `PROT_NONE` guard pages (with VMA-split-safe `Drop` zeroization), and two-pass exact-size `Zeroizing` serialization prevent secret material from reaching swap, crash dumps, or freed `Vec` reallocations.
- **Same-UID non-root process snooping & IPC races**: `prctl(PR_SET_DUMPABLE, 0)` blocks non-root `ptrace`; `omavaultd.service` applies `systemd` `SystemCallFilter` seccomp and `MemoryDenyWriteExecute`; Unix socket verifies mutual `SO_PEERCRED` UID on `0700` tmpfs (`$XDG_RUNTIME_DIR`); monotonic `lock_epoch` + priority control worker slots prevent unlock-cancel races and emergency lock starvation; revision-checked `flock` prevents lost updates.
- **Unattended laptop / lid close / suspend / hibernate / screen lock**: Redundant auto-lock mechanisms: inactivity timer (`CLOCK_BOOTTIME`), pre-sleep/hibernate `systemd-logind` `PrepareForSleep` monitor, non-blocking Hyprland `ext-session-lock` IPC detector for Omarchy 4.5's `omarchy-shell`, `/proc` `hyprlock`/`swaylock` detector, post-wake `CLOCK_BOOTTIME - CLOCK_MONOTONIC` skew detector, `SIGUSR1`, and `Super + Ctrl + Shift + L`.
- **Screen sharing, accidental screenshots & terminal spoofing**: Hyprland `no_screen_share = true` hides the floating TUI window from portals and screen captures; `foot` disables scrollback, primary selection, and OSC-52; ANSI/OSC/Unicode BiDi sanitizers strip control sequences from CLI/TUI display; sensitive notes stay masked behind `[r]`/`--reveal`.

### Out of Scope & Operational Recommendations
- **Root / kernel compromise**: A malicious `root` user or compromised Linux kernel can always read physical memory, inject keystrokes, or instrument Wayland compositors while the vault is unlocked. Keep your Omarchy Arch system updated, keep full-disk encryption (LUKS2) enabled, and lock the vault (`Super + Ctrl + Shift + L`) whenever stepping away.
- **Same-user binary tampering**: Installing via `omarchy/PKGBUILD` (`makepkg -si`) places the binary at root-owned `/usr/bin/omavault` instead of user-writable `~/.local/bin/omavault`, closing same-UID binary shadowing.
- **Disaster recovery**: Keep an offline/offsite backup of `~/.local/share/omavault/vault.omav` alongside your backup YubiKey so hardware failure of either the laptop or one YubiKey never causes data loss.
