//! Embeds a human-readable build version: `<crate version> (<short git commit>)`.
//!
//! Unreleased builds from `main` share the last released crate version, so the commit hash is
//! the only way to tell which code is actually installed. Falls back to the plain crate version
//! when git or `.git` is unavailable (e.g. building from a source tarball); it never fails the build.

use std::path::Path;
use std::process::Command;

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());
    let git_dir = Path::new(&manifest_dir).join(".git");
    for p in ["HEAD", "refs/heads", "packed-refs"] {
        println!("cargo:rerun-if-changed={}", git_dir.join(p).display());
    }
    println!("cargo:rerun-if-env-changed=OMAVAULT_GIT_COMMIT");

    let commit = std::env::var("OMAVAULT_GIT_COMMIT")
        .ok()
        .or_else(|| {
            Command::new("git")
                .args(["-C", &manifest_dir, "rev-parse", "--short=8", "HEAD"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .and_then(|o| String::from_utf8(o.stdout).ok())
        })
        .map(|s| s.trim().to_string())
        // Only ever embed a plain hex hash (never arbitrary command/env output).
        .filter(|s| !s.is_empty() && s.len() <= 40 && s.bytes().all(|b| b.is_ascii_hexdigit()));

    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "unknown".into());
    let full = match commit {
        Some(c) => format!("{version} ({c})"),
        None => version,
    };
    println!("cargo:rustc-env=OMAVAULT_VERSION={full}");
}
