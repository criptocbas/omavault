# Changelog

## v0.4.0 — 2026-11-27

### Phase 1: data-loss hotfix

Phase 1 shipped as **v0.3.1** (see below). Header-changing saves (`rekey`, `fido2 add`, `fido2 remove`) persist the new header and verify it from disk before old-key backups are purged. `init` cannot overwrite a vault created concurrently.

### Phase 2: reliable locking

- **Pre-sleep/hibernate lock never worked** for the unprivileged daemon (`busctl monitor`
  requires root; stderr was discarded; it also matched `boolean true` while busctl prints
  `BOOLEAN true`). Replaced with a native unprivileged D-Bus subscription to logind
  `PrepareForSleep` (pinned to logind's unique bus name) that holds a logind **delay
  inhibitor**, so suspend/hibernate waits until keys are wiped. State is shown in
  `omavault status`. The standalone TUI uses the same monitor. New dependency: `dbus`.
- **IPC polling could keep the vault unlocked forever**: new absolute session lifetime
  (`omavault daemon --max-session`, default 3600 s, 60..=86400) that activity cannot extend.
- **Emergency lock could be starved** by idle connections (the documented reserved control
  slots did not exist): 8 real reserved slots that accept only `Lock`/`Status`/`Shutdown`,
  1 s first-frame header deadline, non-blocking busy replies, an overall write deadline, and
  incremental receive-buffer growth. `omavault lock` retries briefly on "busy" and then falls back
  to a verified `SIGUSR1` to the daemon PID (published in `daemon.lock`); `SIGUSR1` is now
  handled immediately instead of once per second.
- **Lock hotkey ignored standalone TUIs**: TUIs register in the runtime dir and lock on `SIGUSR1`;
  `omavault lock` signals all of them. Daemon-not-running detection is now a typed error instead
  of English `strerror` matching.
- **`SystemCallFilter=` deny-list was silently ignored** (mixed `~` tokens on one line); split into
  allow/deny lines and added `IPAddressDeny=any` (`systemd-analyze security`: 5.6 → 5.3).
  *Correction:* an earlier commit also added `ProtectSystem=full`, `ProtectKernel*`,
  `ProtectControlGroups`, `ProtectClock`, `ProtectHostname` and `PrivateIPC`. In a user unit each
  implies `PrivateUsers=yes`, under which root-owned files appear owned by uid 65534, so the daemon
  refused to run `/usr/bin/fido2-*` ("trusted root-owned fido2-token not found") and FIDO2 unlock
  via the daemon failed. Those options were removed; the unit now documents why.
- Daemon races: `LoadVault` re-checks the lock epoch before releasing plaintext; the screen-locker
  probe no longer runs under the state mutex; session switches bump the epoch; `SaveVault`
  re-verifies the session and returns the new revision (`Saved { revision }`), removing the TUI's
  plaintext reload after every save.
- TUI unlock-cancel race: a shared cancel flag (set before the TUI's own `Lock`) makes the worker
  re-lock the daemon if its unlock lands after the user cancelled or quit.
- Client connect helper retries `EAGAIN` (full backlog) and `EINTR` within its deadline.
- Hyprland `.conf` and hypridle snippets prefer root-owned `/usr/bin/omavault` over `~/.local/bin`.

### Phase 3: integrity & output safety

- **Rollback / file-swap protection**: authenticated `vault_id` + monotonic `generation` inside the
  encrypted payload; a per-path record in `~/.local/state/omavault/seen/` refuses older copies,
  different vaults at the same path, and pre-v0.4 copies of a versioned vault. Enforced by the
  CLI, TUI, and daemon (unlock and every load); new global `--allow-rollback`. Vaults written by
  older versions open normally and get an ID on their next save.
- **Full-header revision token** (BLAKE3 of the serialized header) instead of `save_salt` only,
  so a tampered header can no longer be "laundered" by the next save.
- **Terminal-escape injection**: stdout fields are sanitized even when piped (new global `--raw`
  to opt out); `get --reveal` on a terminal strips control sequences from notes and refuses
  passwords containing them; error messages are always sanitized; FIDO2 labels are sanitized
  and `fido2 list` notes that it reads the unauthenticated header. Entries with control, BiDi, or
  zero-width characters in any field are rejected on add/edit (all front-ends); CRLF in notes is
  normalized. New FIDO2 labels reject BiDi/zero-width characters.
- **Filesystem trust on every read**: vault file must be owned by you, not group/world-writable,
  not hard-linked, in a directory you own that is not group/world-writable. Existing
  group/world-writable directories are refused instead of silently `chmod`ed; hard-linked lock
  files are refused; `purge` also removes orphaned `.tmp.` files and fsyncs the directory;
  keyfiles must be owned by you (and `EINTR` is retried while hashing).
- **`omavault gen`** copies to the secret clipboard by default on a terminal (use `--print` to
  print). `--totp-file` must be owned by you, `0600`, and at most 4 KiB.
- TUI: Diceware generator defaults to 12 words within 10..=24 and shows errors instead of a blank
  "STRONG" secret; editing an entry no longer resets custom TOTP parameters unless the secret
  actually changed; multi-line notes render as separate lines.
- Background warnings (pre-sleep monitor, rollback store) no longer write to stderr while the
  TUI owns the terminal, so they cannot corrupt the full-screen display.
- **API**: `save_vault_to_disk*` / `create_new_vault_on_disk` take `&mut Vault` (they stamp the
  generation; restored on failure). `DaemonRequest::Unlock` gained `allow_rollback` (defaults to
  `false`).

### Phase 4: memory hygiene

- **Zeroizing global allocator** (`src/alloc.rs`, registered in the binary): every heap block is
  wiped with `explicit_bzero(3)` before it is freed, and on every reallocation. Closes the
  red-team findings where secrets survived in freed heap: `serde_json`'s escape scratch buffer
  (multi-line notes; master passphrases with `"`/`\` on daemon unlock), per-frame TUI sanitizing
  copies, `get --reveal` / stdout buffers, and growth reallocations (Gemini M-5, M-6, L-9). No
  measurable unlock slowdown (~285 ms before and after on a 64 MiB vault).
- FIDO2 tool output, Base32 TOTP normalization, stdin passphrase and `--totp-file` buffers are
  also pre-sized so they never reallocate, independent of the allocator.
- HKDF-SHA512 runs in a dedicated non-inlined frame and the stack region is scrubbed afterwards
  (`hkdf`/`hmac` 0.12 do not zeroize their PRK/HMAC state).
- `omavault status` shows **swap exposure** (none / zram only / encrypted / unencrypted /
  unverified) from `/proc/swaps` + sysfs (dm-crypt detection follows LVM-on-LUKS stacks); the TUI
  warns at unlock if swap is unencrypted. SECURITY.md no longer claims decrypted entries cannot
  reach swap (only the master key is `mlock`ed; `mlockall` is not viable under the default
  8 MiB `RLIMIT_MEMLOCK`).
- Tests: `tests/heap_residue_tests.rs` installs a probing allocator that checks every freed block
  for a secret marker before and after the wipe (serde escapes, unlock request, sanitizers,
  reallocations); mutation-checked (disabling the wipe makes it fail). Swap classifier unit tests.

### Phase 5: clipboard races

- **H-3:** `copy_secret` holds `clip.lock` across spawn, readiness, state publish, and the signal
  to the previous helper. The new generation is written to `clip.state` before the old helper is
  signalled, and a helper globally clears the clipboard only when that lock still shows its own
  generation (or the state file is missing). A fast second copy is no longer wiped by the helper
  it replaced, and a failed copy leaves the previous secret in place.
- **M-9:** reads, writes, and unlinks of `clip.state` happen under the same owner-only `flock`,
  so a helper exiting cannot delete a newer helper's state and leave that helper untracked
  across lock.
- **L-11:** the helper registers `SIGTERM`/`SIGINT` before it claims the Wayland selection and
  before it prints `OK`.
- The parent waits at most 2 s for the helper's readiness line (the lock is held while it waits)
  and kills the helper if it does not become ready. This is enforced at compile time to stay
  below the 3 s lock wait, so neither a superseded helper nor an emergency clear can time out on
  the lock and clear a copy that is still being set up.
- Tests: `may_clear` truth table, state round-trip, `clip.lock` mode/symlink/hard-link refusal,
  bounded lock timeout, and stress regressions for H-3 and M-9.

### Phase 6: FIDO2 robustness

- **M-7:** slot probing tries non-UV slots before UV slots on each device, and continues after
  "no credentials" or "this key cannot do UV". A PIN slot no longer hides a valid non-UV slot
  on the same key. A wrong PIN, a blocked PIN, or a refused touch stops the probe immediately
  and does not burn further PIN retries.
- **L-4:** every `fido2-*` child runs in its own process group. The parent sets
  `PR_SET_PDEATHSIG(SIGTERM)` and aborts the exec if it died before the child installed the
  signal. A guard kills the group on timeout, cancellation, panic, or any early return.
- Cancelling an unlock (TUI Esc / lock hotkey, `omavault lock`, sleep, screen lock, `SIGUSR1`)
  stops a pending `fido2-assert` instead of leaving the key blinking until touch or the 45 s
  timeout.
- **L-5:** legacy v1 vaults try every connected key, not only the first.
- **L-6:** a UV slot tries `-t pin=true` and, only when the key has no PIN or rejects that
  option, retries once with `-t uv=true`. Both attempts still require the authenticator-data
  UV flag.
- **L-8:** an out-of-range slot index returns `Fido2NoMatchingCredential` instead of panicking,
  and `to_bytes` rejects KDF parameters above the ceiling.
- **Limit:** UV/PIN slots still cannot be unlocked through `omavaultd`. `fido2-assert -t pin=true`
  reads the PIN from `/dev/tty`, which the service does not have. Those slots work in the
  standalone CLI/TUI (`systemctl --user stop omavaultd`, or no daemon).

### Phase 7: packaging, supply chain, and docs

- `ratatui` 0.30 and `crossterm` 0.29. MSRV is Rust 1.88. `chrono` stays; `RUSTSEC-2026-0543` (unmaintained) is the only accepted advisory, because `DateTime<Utc>` is part of the serialized vault.
- `cargo deny` allows only the licenses in this lockfile (including MPL-2.0 via `option-ext`) and crates.io. CI checks fmt, clippy `-D warnings`, `cargo test --locked`, the 1.88 MSRV, `cargo audit`, `cargo deny`, and `systemd-analyze verify` on the user unit. Namespace `Protect*` options stay off that unit: in a user service they imply `PrivateUsers=yes` and break FIDO2.
- cargo-fuzz targets for `VaultHeader::parse`, `TotpConfig::parse`, and vault JSON. A weekly nightly workflow runs each for 60 seconds.
- The local PKGBUILD fetches with `--locked` and builds with `--frozen`. `omarchy/PKGBUILD.aur` is a signed-tag stub; the PGP fingerprint is still a placeholder. `install.sh` warns when a user unit or `~/.local/bin/omavault` would shadow the packaged files.
- Alacritty launchers disable OSC-52 and `selection.save_to_clipboard`. Ghostty 1.4 renamed `--scrollback-limit` to `--scrollback-limit-bytes`; the launcher sets both the byte and line limits to 0 and `--copy-on-select=none`. `--clipboard-write=deny` is unchanged.
- `omavault init` checks the destination directory before it asks for a passphrase or a YubiKey touch.
- SECURITY.md and the README state the limits the code actually has (same-UID daemon access, swap, rollback history, UV/PIN slots, root and hibernation).

### Also

- The build version (`<crate version> (<git commit>)`) is shown on the TUI unlock screen, the
  TUI top bar, the help screen, `omavault --version`, and `omavault status`, so unreleased builds
  from `main` can be told apart. Embedded by a small `build.rs` (falls back to the plain version
  without git; override with `OMAVAULT_GIT_COMMIT`).

### Tests

- `tests/integrity_output_tests.rs`: revision vs. header tampering, generation stamping, rollback
  store (restore / swap / downgrade / allow), end-to-end rollback refusal, piped-output and
  real-pty `--reveal` sanitizing, input validation, filesystem trust, hard-linked lock file,
  orphaned temp purge. Each fix was mutation-checked (reverting it makes its test fail).
- `tests/daemon_lock_tests.rs`: max-session vs. a polling attacker, sustained connection flood
  against the real daemon binary, control-slot refusal of heavy requests, `Saved` revision, typed
  `DaemonUnavailable`. `tests/daemon_sigusr1_test.rs`: SIGUSR1 lock latency < 500 ms.

## v0.3.1 — Critical data-loss fix

> [!CAUTION]
> **If you used v0.3.0 `omavault rekey`, `omavault fido2 remove`, or `omavault fido2 add`:**
> - `rekey` and `fido2 remove` (default, with key rotation) left the vault **unopenable** and,
>   unless `--keep-old-backups` was passed, deleted the rolling `.bak.*` backups. Restore from an
>   external/offline backup of `vault.omav`.
> - `fido2 remove --no-rotate` reported success but **left the removed key enrolled**. Re-run it
>   on v0.3.1.
> - `fido2 add` on an OMAV v2 vault reported success but **did not save the new key**. Re-run it
>   on v0.3.1 before relying on your backup YubiKey.
>
> Normal unlock, add/edit/delete, copy, TOTP and lock were not affected.

### Fixed

- `save_vault_to_disk_checked` no longer replaces the caller's header with the on-disk header
  after the revision check. Header-changing commands (`rekey`, `fido2 add`, `fido2 remove`) now
  actually persist their new KDF salt, key slots and version.
- Post-save verification is now independent: before purging old-key backups, `rekey`,
  `fido2 add` and `fido2 remove` re-read the on-disk header, require it to be byte-identical to
  the header just written, re-run Argon2id against the on-disk salt, re-derive/unwrap the master
  key from the on-disk key slot, and decrypt the vault with it. Previously the check reused the
  in-memory key and could not detect a mismatched header.
- Header-changing saves always write a rolling backup first; backups are purged only after
  verification succeeds.
- The caller's in-memory header is updated only after the new file is durably written, so a
  failed write (e.g. disk full) no longer desyncs a long-running TUI session from disk.
- `fido2 add` on a legacy OMAV v1 vault (v1 → v2 upgrade) now uses the revision-checked save.
- `omavault init` can no longer overwrite a vault created concurrently: the existence check
  happens under the vault lock and the file is published with `link(2)` (atomic, no-replace).

### Tests

- New `tests/header_mutation_tests.rs`: rekey, `fido2 add`, `fido2 remove` (rotating and
  `--no-rotate`) re-opened from scratch with only passphrase + mock YubiKey; verification
  negative cases; failed-write header consistency; no-overwrite init; and an end-to-end test
  driving the real binary through `init → add → rekey → get`.

### Build

- Dev/test builds compile `argon2`/`blake2` with `opt-level = 3` so production-floor KDF tests
  run quickly. Release builds are unchanged.
