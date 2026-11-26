use std::collections::HashMap;

use chrono::{Duration, Utc};
use zeroize::{Zeroize, Zeroizing};

use crate::error::Result;
use crate::generator::{estimate_entropy_bits, strength_label};
use crate::vault::Vault;

#[derive(Debug, Clone)]
pub struct WeakPasswordFinding {
    pub entry_name: String,
    pub entropy_bits: f64,
    pub label: &'static str,
    pub length: usize,
}

#[derive(Debug, Clone)]
pub struct ReusedPasswordGroup {
    pub entry_names: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AuditReport {
    pub total_entries: usize,
    pub totp_enabled_count: usize,
    pub weak_passwords: Vec<WeakPasswordFinding>,
    pub reused_groups: Vec<ReusedPasswordGroup>,
    pub stale_entries: Vec<(String, i64)>,
    pub missing_totp: Vec<String>,
    pub overall_score: u8,
}

#[derive(PartialEq, Eq, Hash, Zeroize, zeroize::ZeroizeOnDrop)]
struct DigestKey([u8; 32]);

/// Perform a local, zero-network security audit of all entries in the vault.
///
/// Uses keyed BLAKE3 hashing with a CSPRNG ephemeral key (propagating CSPRNG failures
/// and zeroizing both the ephemeral key and every digest key on drop).
pub fn run_audit(vault: &Vault) -> Result<AuditReport> {
    let mut ephemeral_key = Zeroizing::new([0u8; 32]);
    crate::hardening::fill_random(&mut *ephemeral_key)?;

    let mut pw_groups: HashMap<DigestKey, Vec<String>> = HashMap::new();
    let mut weak_passwords = Vec::new();
    let mut stale_entries = Vec::new();
    let mut missing_totp = Vec::new();
    let mut totp_enabled_count = 0usize;

    let now = Utc::now();
    let stale_threshold = Duration::days(365);

    for entry in &vault.entries {
        if entry.totp.is_some() {
            totp_enabled_count += 1;
        } else {
            missing_totp.push(entry.name.clone());
        }

        if entry.password.is_empty() {
            weak_passwords.push(WeakPasswordFinding {
                entry_name: entry.name.clone(),
                entropy_bits: 0.0,
                label: "EMPTY",
                length: 0,
            });
        } else {
            let bits = estimate_entropy_bits(&entry.password);
            if bits < 60.0 || entry.password.chars().count() < 12 {
                weak_passwords.push(WeakPasswordFinding {
                    entry_name: entry.name.clone(),
                    entropy_bits: bits,
                    label: strength_label(bits),
                    length: entry.password.chars().count(),
                });
            }

            let mut digest = blake3::keyed_hash(&ephemeral_key, entry.password.as_bytes());
            let key_bytes = DigestKey(*digest.as_bytes());
            digest.zeroize();
            pw_groups
                .entry(key_bytes)
                .or_default()
                .push(entry.name.clone());
        }

        // Fall back to `created_at` (not `updated_at`) so editing non-password metadata
        // never resets staleness age.
        let last_rotated = entry.password_updated_at.unwrap_or(entry.created_at);
        let age = now.signed_duration_since(last_rotated);
        if age > stale_threshold {
            stale_entries.push((entry.name.clone(), age.num_days()));
        }
    }

    let mut reused_groups: Vec<ReusedPasswordGroup> = pw_groups
        .into_values()
        .filter(|names| names.len() > 1)
        .map(|entry_names| ReusedPasswordGroup { entry_names })
        .collect();
    reused_groups.sort_by_key(|a| std::cmp::Reverse(a.entry_names.len()));

    let mut score: i32 = 100;
    score -= (weak_passwords.len() as i32) * 15;
    score -= (reused_groups.len() as i32) * 20;
    score -= (stale_entries.len() as i32) * 3;
    let overall_score = score.clamp(0, 100) as u8;

    Ok(AuditReport {
        total_entries: vault.entries.len(),
        totp_enabled_count,
        weak_passwords,
        reused_groups,
        stale_entries,
        missing_totp,
        overall_score,
    })
}
