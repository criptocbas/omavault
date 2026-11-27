/// Build version shown by `--version`, `status`, and the TUI: `<crate version> (<git commit>)`.
pub const VERSION: &str = env!("OMAVAULT_VERSION");

pub mod alloc;
pub mod cli;
pub mod clipboard;
pub mod crypto;
pub mod daemon;
pub mod error;
pub mod generator;
pub mod hardening;
pub mod procsig;
pub mod sleep;
pub mod totp;
pub mod tui;
pub mod vault;
