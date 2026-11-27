#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Public, side-effect-free header parser. `false` skips the production
    // KDF floor so the fuzzer can reach the structural checks.
    let _ = omavault::crypto::VaultHeader::parse(data, false);
});
