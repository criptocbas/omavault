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

### Added
- The build version (`<crate version> (<git commit>)`) is shown on the TUI unlock screen, the
  TUI top bar, the help screen, `omavault --version`, and `omavault status`, so unreleased builds
  from `main` can be told apart. Embedded by a small `build.rs` (falls back to the plain version
  without git; override with `OMAVAULT_GIT_COMMIT`).

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
