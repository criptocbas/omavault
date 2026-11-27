# omavault

A bulletproof, memory-hardened, keyboard-first password manager crafted in Rust specifically for **Omarchy Linux** (Arch + Hyprland + Wayland).

## Security Architecture at a Glance

| Layer | Technology | Protection |
|---|---|---|
| **Password KDF** | **Argon2id** (`128 MiB` RAM, `t=4`, `p=4`, enforced `64 MiB`/`t=3` floor, `1 GiB`/`t=16` ceiling) | Resists GPU/ASIC brute-force & blocks header downgrade / DoS attacks |
| **Multi-Key Hardware 2FA** | **`OMAV` v2 Key Slots (`1..=8` YubiKeys)** via `libfido2` `hmac-secret` + HKDF-SHA512 + XChaCha20-Poly1305 | Every unlock requires **both** master passphrase + physical YubiKey touch; add backup keys (`fido2 add`), revoke lost keys with automatic `master_key` + `kdf_salt` rotation (`fido2 remove`), and strict CBOR `rpIdHash` + `UP`/`UV`/`AT`/`ED` verification |
| **Per-Save Key Rotation** | **HKDF-SHA512** (`master_key`, fresh 32-byte `save_salt`) | Every single save uses a brand-new 256-bit encryption subkey |
| **Authenticated Encryption** | **XChaCha20-Poly1305** (256-bit key, fresh 192-bit nonce, full-header AAD) | Constant-time software AEAD with zero nonce-collision risk; any 1-bit tamper fails MAC |
| **Traffic / Size Privacy** | **4 KiB CSPRNG random padding** inside AEAD ciphertext | Hides entry lengths and minor edit sizes |
| **RAM Hardening** | `mmap` + `mlock` + `MADV_DONTDUMP` + `MADV_WIPEONFORK` + `mprotect(PROT_NONE)` for the master key; a **zeroizing global allocator** (`explicit_bzero` on every free/realloc); stack scrubbing after HKDF | Master key never swaps to disk, never dumps, wipes on fork, stays `PROT_NONE` when idle; freed heap never retains secret copies; `omavault status` warns if swap could page decrypted entries to disk |
| **Process & Sandbox Hardening** | `prctl(PR_SET_DUMPABLE, 0)`, `RLIMIT_CORE=0`, `umask(0o077)`, `overflow-checks = true`, `systemd` `SystemCallFilter` seccomp + `MemoryDenyWriteExecute` | Blocks non-root `ptrace`, core dumps, W^X JIT, and disallowed syscalls from line 1 of `main()` |
| **Omarchy Clipboard Shield** | Native Wayland **`wl-clipboard-rs` `sensitive(true)`** (`x-kde-passwordManagerHint`) | Excludes copied secrets from Omarchy 4.5's `omarchy.clipboard` (`Super + Ctrl + V`), supports `--paste-once`, and fail-closed auto-clears after 15s or on lock |
| **Auto-Lock Daemon** | `omavaultd` over `0600` `$XDG_RUNTIME_DIR` socket with mutual `SO_PEERCRED` UID verification & priority control lane | Locks & wipes RAM automatically on inactivity timeout, **Omarchy/Hyprland `ext-session-lock` IPC**, **pre-sleep/hibernate (`systemd-logind` `PrepareForSleep`)**, **post-wake `CLOCK_BOOTTIME` skew**, `SIGUSR1`, or `Super + Ctrl + Shift + L` |
| **Hyprland & Terminal Privacy** | `no_screen_share = true`, `stay_focused = true`, `foot` with `scrollback.lines=0`, `main.selection-target=none`, `security.osc52=disabled` | Blocks screenshots & screen-sharing portals from capturing the TUI and prevents secrets from leaking into scrollback, primary selection, or OSC-52 |
| **Disk Durability** | `0700` dir / `0600` temp file + `O_NOFOLLOW | O_NONBLOCK` + revision-checked `flock` + `fsync` + atomic `rename` + encrypted `.bak.1..5` | Crash-safe, concurrency-safe writes; old-key backups are automatically purged on `rekey` and `fido2 remove` |

---

## Quick Installation on Omarchy

Make sure Rust is installed (`sudo pacman -S rust`), then clone and install:

```bash
git clone https://github.com/criptocbas/omavault.git
cd omavault
chmod +x omarchy/install.sh
./omarchy/install.sh
```

Or — **recommended for maximum hardening** — build and install as a root-owned Arch package (`/usr/bin/omavault` and `/usr/lib/systemd/user/omavaultd.service`) so unprivileged same-user processes cannot modify the binary:

```bash
cd omarchy
makepkg -si
```

### Omarchy 4.5+ (Lua Hyprland config)

Add this single line to `~/.config/hypr/hyprland.lua`:

```lua
require("hypr.omavault")
```

Then validate with `hyprctl reload && hyprctl configerrors`. The Lua module:
- Launches `omavault tui` in `foot` with scrollback, primary selection, and OSC-52 clipboard writes all disabled (falling back cleanly to hardened `ghostty` / `alacritty`).
- Applies `float = true`, `center = true`, `stay_focused = true`, and `no_screen_share = true` to `^org\.omarchy\.omavault$`.
- Rebinds **`Super + Shift + /`** (`SUPER + SHIFT + SLASH`, replacing Omarchy's default 1Password shortcut) to open `omavault`, and binds **`Super + Ctrl + Shift + L`** to lock immediately.
- `omavaultd` automatically detects Omarchy's `omarchy-shell` lock screen over Hyprland IPC and pre-sleep events via `systemd-logind`.

### Legacy Hyprland (`.conf`)

Add this single line to `~/.config/hypr/hyprland.conf`:

```ini
source = ~/.config/hypr/omavault.conf
```

Optionally, add the lock hooks from `omarchy/hypridle-hook.conf` to `~/.config/hypr/hypridle.conf`.

For **YubiKey / FIDO2 hardware 2FA**, ensure `libfido2` is installed:

```bash
sudo pacman -S libfido2
```

UV/PIN-required keys cannot be unlocked through the `omavaultd` service (`fido2-assert` reads the PIN from `/dev/tty`). Stop the daemon (`systemctl --user stop omavaultd`) and use the standalone CLI or TUI for those keys.

---

## Quick Usage

### 1. Initialize your encrypted vault

```bash
# Master passphrase only (Argon2id 128 MiB + XChaCha20-Poly1305)
omavault init

# Master passphrase + 512-bit keyfile
omavault keyfile generate ~/.config/omavault-backup.key
omavault init --keyfile ~/.config/omavault-backup.key

# Master passphrase + YubiKey / FIDO2 hardware touch (OMAV v2 multi-key slots)
omavault init --fido2 --fido2-label primary

# Add a second backup YubiKey (unlock with either key!)
omavault fido2 add --label backup
omavault fido2 list

# Revoke a lost/stolen YubiKey using your remaining key
# (rotates vault_master_key + kdf_salt and purges old-key backups by default)
omavault fido2 remove backup

# Maximum paranoia: Triple-factor (Passphrase + Keyfile + YubiKey FIDO2)
omavault init --keyfile /run/media/$USER/USB/omavault.key --fido2 --fido2-label primary
```

> **Backup tip:** Enrolling 2 YubiKeys protects against losing a YubiKey. Back up `~/.local/share/omavault/vault.omav` offline or to cloud storage to also protect against laptop loss/SSD failure — the file is authenticated XChaCha20-Poly1305 + Argon2id + YubiKey-bound ciphertext.

### 2. Launch the Omarchy TUI

Press **`Super + Shift + /`** anywhere in Hyprland (on Omarchy 4.5+), or run:

```bash
omavault
```

**TUI Keybindings:**
- `j` / `k` / `↑` / `↓` — navigate entries
- `/` — fuzzy search across name, username, URL, tags
- `y` — copy password to Wayland secret clipboard (invisible to Omarchy clipboard history, clears in 15s)
- `u` — copy username (secret-tagged)
- `t` — copy live 2FA TOTP code (secret-tagged)
- `r` — toggle password & sensitive notes visibility in inspector (`Ctrl+R` inside editor)
- `a` / `e` / `d` — add / edit / delete entry (`Ctrl+G` inside editor generates a 24-char CSPRNG password)
- `g` — CSPRNG password & Diceware passphrase generator
- `A` — local password security audit (weak, reused, stale, missing 2FA)
- `L` / `Ctrl+L` — instant lock (wipes RAM & clipboard)
- `?` — help overlay

### 3. Scriptable CLI

```bash
# Add an entry with generated 28-char password + hidden 2FA TOTP prompt (never leaks to shell history)
omavault add github.com -u octocat --url https://github.com --totp --generate --length 28 --copy

# Copy password with paste-once mode (auto-wipes after 1 paste!)
omavault get github.com --copy --paste-once

# Get live TOTP code
omavault totp github.com --copy

# Generate a 12-word Diceware passphrase (105.6 bits entropy; min 10 words).
# On a terminal it goes to the secret clipboard by default; add --print to print it instead.
omavault gen --passphrase --words 12

# Restored an older vault backup on purpose? omavault refuses older copies by default:
omavault --allow-rollback list

# Run local security audit
omavault audit

# Rotate master passphrase / upgrade Argon2id memory to 256 MiB / enroll FIDO2
# (automatically purges old-key backups after verifying the new vault; pass --keep-old-backups to retain them)
omavault rekey --mem-mib 256 --enable-fido2

# Check process & daemon hardening, crypto parameters, enrolled YubiKeys, and daemon status
omavault status

# Lock immediately (exits non-zero if a running daemon fails to lock)
omavault lock
```

See [SECURITY.md](SECURITY.md) for the complete binary specification, key hierarchy, FIDO2 verification model, and threat model.

---

## Security Status & Contributing

`omavault` uses zero custom cryptography (relying exclusively on audited RustCrypto and BLAKE3 crates) and has undergone extensive internal security review and automated regression testing. However, it is an early open-source project and has **not yet undergone a formal independent third-party cryptographic audit**.

Security researchers, Rust developers, and Omarchy users are warmly invited to inspect the code, try to break it, open issues, or submit pull requests.

Licensed under the [MIT License](LICENSE).
