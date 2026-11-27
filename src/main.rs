use clap::Parser;

use omavault::cli::{execute, Cli};
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
