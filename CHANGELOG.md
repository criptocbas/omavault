# Changelog

## Unreleased (v0.4.0) — Phase 2: reliable locking

### Fixed
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
  allow/deny lines. Added `ProtectSystem=full`, `ProtectKernel{Tunables,Modules,Logs}`,
  `ProtectControlGroups`, `ProtectClock`, `ProtectHostname`, `PrivateIPC`, `IPAddressDeny=any`
  (`systemd-analyze security`: 5.6 → 3.8).
- Daemon races: `LoadVault` re-checks the lock epoch before releasing plaintext; the screen-locker
  probe no longer runs under the state mutex; session switches bump the epoch; `SaveVault`
  re-verifies the session and returns the new revision (`Saved { revision }`), removing the TUI's
  plaintext reload after every save.
- TUI unlock-cancel race: a shared cancel flag (set before the TUI's own `Lock`) makes the worker
  re-lock the daemon if its unlock lands after the user cancelled or quit.
- Client connect helper retries `EAGAIN` (full backlog) and `EINTR` within its deadline.
- Hyprland `.conf` and hypridle snippets prefer root-owned `/usr/bin/omavault` over `~/.local/bin`.

### Tests
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
