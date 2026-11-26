use clap::Parser;

use omavault::cli::{execute, Cli};
use omavault::hardening::harden_process;

fn main() {
    // SECURITY: Apply OS-level hardening (umask 0077, PR_SET_DUMPABLE=0, RLIMIT_CORE=0)
    // before parsing arguments or touching any secrets.
    let hardening = harden_process();

    let cli = Cli::parse();
    if let Err(err) = execute(cli, hardening) {
        eprintln!("omavault error: {err}");
        std::process::exit(1);
    }
}
