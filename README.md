# omavault

A bulletproof, memory-hardened, keyboard-first password manager crafted in Rust specifically for **Omarchy Linux** (Arch + Hyprland + Wayland).

## Security Architecture at a Glance

| Layer | Technology | Protection |
|---|---|---|
| **Password KDF** | **Argon2id** (`128 MiB` RAM, `t=4`, `p=4`, enforced `64 MiB`/`t=3` floor) | Resists GPU/ASIC brute-force & blocks header downgrade attacks |
| **Multi-Factor Combiner** | **HKDF-SHA512** (domain-separated `PW` + `KF` + `F2`) | Combines master passphrase + optional 512-bit keyfile + optional FIDO2/YubiKey `hmac-secret` |
| **Per-Save Key Rotation** | **HKDF-SHA512** (`master_key`, fresh 32-byte `save_salt`) | Every single save uses a brand-new 256-bit encryption subkey |
| **Authenticated Encryption** | **XChaCha20-Poly1305** (256-bit key, fresh 192-bit nonce, full-header AAD) | Constant-time software AEAD with zero nonce-collision risk; any 1-bit tamper fails MAC |
| **Traffic / Size Privacy** | **4 KiB CSPRNG random padding** inside AEAD ciphertext | Hides entry lengths and minor edit sizes |
| **RAM Hardening** | `mmap` + `mlock` + `MADV_DONTDUMP` + `MADV_WIPEONFORK` + `mprotect(PROT_NONE)` + `zeroize` | Master key never swaps to disk, never dumps, wipes on fork, and stays unreadable (`PROT_NONE`) when idle |
| **Process Hardening** | `prctl(PR_SET_DUMPABLE, 0)`, `RLIMIT_CORE=0`, `umask(0o077)` | Blocks non-root `ptrace` attachment and core dumps from line 1 of `main()` |
| **Omarchy Clipboard Shield** | Native Wayland **`wl-clipboard-rs` `sensitive(true)`** (`x-kde-passwordManagerHint`) | Excludes copied passwords from Omarchy's universal clipboard history (`Super + Ctrl + V`), supports `--paste-once`, and safely auto-clears after 15s |
| **Auto-Lock Daemon** | `omavaultd` over `0600` `$XDG_RUNTIME_DIR` socket with `SO_PEERCRED` UID verification | Locks & wipes RAM automatically on inactivity timeout, **`hyprlock` detection**, **lid-close/suspend** (`CLOCK_BOOTTIME - CLOCK_MONOTONIC` skew), or `Super + Ctrl + Shift + L` |
| **Hyprland Screen Privacy** | `windowrule = no_screen_share on` | Blocks screen-sharing portals & screenshots from capturing the floating TUI window |
| **Disk Durability** | `0700` dir / `0600` temp file + `fsync` + atomic `rename` + encrypted `.bak.1..5` | Crash-safe writes; vault is never world-readable or half-written |

---

## Quick Installation on Omarchy

```bash
cd omavault
chmod +x omarchy/install.sh
./omarchy/install.sh
```

Or build an Arch package with `makepkg -si` inside `omarchy/`.

Then add this single line to `~/.config/hypr/hyprland.conf`:

```ini
source = ~/.config/hypr/omavault.conf
```

Optionally, add the lock hooks from `omarchy/hypridle-hook.conf` to `~/.config/hypr/hypridle.conf` for instantaneous pre-sleep locking.

For **YubiKey / FIDO2 hardware 2FA**, install `libfido2`:

```bash
sudo pacman -S libfido2
```

---

## Quick Usage

### 1. Initialize your encrypted vault

```bash
# Master passphrase only (Argon2id 128 MiB + XChaCha20-Poly1305)
omavault init

# Master passphrase + 512-bit keyfile
omavault keyfile generate ~/.config/omavault-backup.key
omavault init --keyfile ~/.config/omavault-backup.key

# Master passphrase + YubiKey / FIDO2 hardware touch (hmac-secret)
omavault init --fido2 --fido2-uv

# Maximum paranoia: Triple-factor (Passphrase + Keyfile + YubiKey FIDO2)
omavault init --keyfile /run/media/$USER/USB/omavault.key --fido2 --fido2-uv
```

### 2. Launch the Omarchy TUI

Press **`Super + Shift + P`** anywhere in Hyprland, or run:

```bash
omavault
```

**TUI Keybindings:**
- `j` / `k` / `↑` / `↓` — navigate entries
- `/` — fuzzy search across name, username, URL, tags
- `y` — copy password to Wayland secret clipboard (invisible to Omarchy clipboard history, clears in 15s)
- `u` — copy username (secret-tagged)
- `t` — copy live 2FA TOTP code (secret-tagged)
- `r` — toggle password visibility in inspector
- `a` / `e` / `d` — add / edit / delete entry (`Ctrl+G` inside editor generates a 24-char CSPRNG password)
- `g` — CSPRNG password & Diceware passphrase generator
- `A` — local password security audit (weak, reused, stale, missing 2FA)
- `L` / `Ctrl+L` — instant lock (wipes RAM & clipboard)
- `?` — help overlay

### 3. Scriptable CLI

```bash
# Add an entry with generated 28-char password + 2FA TOTP
omavault add github.com -u octocat --url https://github.com --totp "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP" --generate --length 28 --copy

# Copy password with paste-once mode (auto-wipes after 1 paste!)
omavault get github.com --copy --paste-once

# Get live TOTP code
omavault totp github.com --copy

# Generate a 10-word Diceware passphrase
omavault gen --passphrase --words 10 --copy

# Run local security audit
omavault audit

# Rotate master passphrase / upgrade Argon2id memory to 256 MiB / enroll FIDO2
omavault rekey --mem-mib 256 --enable-fido2

# Check hardening, crypto parameters, and daemon status
omavault status

# Lock immediately
omavault lock
```

See [SECURITY.md](SECURITY.md) for the complete binary specification, key hierarchy, and threat model.
