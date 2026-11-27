# Changelog

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
