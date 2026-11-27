use clap::Parser;

use omavault::alloc::ZeroizingAlloc;
use omavault::cli::{execute, Cli};

/// Wipe every heap block before it is freed (see `omavault::alloc`).
#[global_allocator]
static GLOBAL: ZeroizingAlloc = ZeroizingAlloc::system();
use omavault::hardening::{harden_process, sanitize_single_line};

fn main() {
    // SECURITY: Apply OS-level hardening (umask 0077, PR_SET_DUMPABLE=0, RLIMIT_CORE=0)
    // before parsing arguments or touching any secrets.
    let hardening = harden_process();
    #[cfg(target_os = "linux")]
    if !hardening.dumpable_disabled || !hardening.core_dumps_disabled {
        eprintln!(
            "omavault security warning: incomplete OS hardening ({})",
            hardening.summary()
        );
    }

    let cli = Cli::parse();
    if let Err(err) = execute(cli, hardening) {
        // Always sanitize: stderr redirected to a log can still be `cat`/`less -R`'d later.
        eprintln!("omavault error: {}", sanitize_single_line(&err.to_string()));
        std::process::exit(1);
    }
}
