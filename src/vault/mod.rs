pub mod audit;
pub mod storage;

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{Result, VaultError};
use crate::totp::TotpConfig;

/// Historical password record retained when an entry's password is rotated.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PasswordHistoryItem {
    pub password: String,
    #[zeroize(skip)]
    pub replaced_at: DateTime<Utc>,
}

impl fmt::Debug for PasswordHistoryItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordHistoryItem")
            .field("password", &"[REDACTED]")
            .field("replaced_at", &self.replaced_at)
            .finish()
    }
}

/// Optional custom key-value field on a vault entry.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct CustomField {
    pub label: String,
    pub value: String,
    #[zeroize(skip)]
    pub secret: bool,
}

impl fmt::Debug for CustomField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CustomField")
            .field("label", &self.label)
            .field("value", if self.secret { &"[REDACTED]" } else { &self.value })
            .field("secret", &self.secret)
            .finish()
    }
}

/// A single credential / secret entry stored inside the encrypted vault.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Entry {
    #[zeroize(skip)]
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub totp: Option<TotpConfig>,
    #[serde(default)]
    pub custom_fields: Vec<CustomField>,
    #[serde(default)]
    pub password_history: Vec<PasswordHistoryItem>,
    #[zeroize(skip)]
    pub created_at: DateTime<Utc>,
    #[zeroize(skip)]
    pub updated_at: DateTime<Utc>,
    #[zeroize(skip)]
    #[serde(default)]
    pub password_updated_at: Option<DateTime<Utc>>,
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("url", &self.url)
            .field("notes", &"[REDACTED]")
            .field("tags", &self.tags)
            .field("has_totp", &self.totp.is_some())
            .finish()
    }
}

impl Entry {
    pub fn new(name: String, username: String, password: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name: name.trim().to_string(),
            username,
            password,
            url: String::new(),
            notes: String::new(),
            tags: Vec::new(),
            totp: None,
            custom_fields: Vec::new(),
            password_history: Vec::new(),
            created_at: now,
            updated_at: now,
            password_updated_at: Some(now),
        }
    }

    /// Update the entry's password while preserving up to 10 previous passwords in history.
    ///
    /// Accepts `Zeroizing<String>` so even when the password is unchanged, the input buffer
    /// is always zeroized on drop.
    pub fn set_password(&mut self, mut new_password: Zeroizing<String>) {
        if self.password != *new_password {
            let owned = std::mem::take(&mut *new_password);
            if !self.password.is_empty() {
                let old = std::mem::replace(&mut self.password, owned);
                self.password_history.insert(
                    0,
                    PasswordHistoryItem {
                        password: old,
                        replaced_at: Utc::now(),
                    },
                );
                self.password_history.truncate(10);
            } else {
                self.password = owned;
            }
            let now = Utc::now();
            self.updated_at = now;
            self.password_updated_at = Some(now);
        }
        // When unchanged, `new_password` (Zeroizing<String>) is automatically zeroized on drop.
    }

    /// Case-insensitive fuzzy/substring match across name, username, URL, and tags.
    pub fn matches_query(&self, query: &str) -> bool {
        let q = query.trim().to_ascii_lowercase();
        if q.is_empty() {
            return true;
        }
        self.name.to_ascii_lowercase().contains(&q)
            || self.username.to_ascii_lowercase().contains(&q)
            || self.url.to_ascii_lowercase().contains(&q)
            || self
                .tags
                .iter()
                .any(|t| t.to_ascii_lowercase().contains(&q))
    }
}

/// Top-level decrypted vault structure. Automatically zeroizes all secrets on Drop.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Vault {
    #[zeroize(skip)]
    pub schema_version: u32,
    #[zeroize(skip)]
    pub created_at: DateTime<Utc>,
    #[zeroize(skip)]
    pub updated_at: DateTime<Utc>,
    pub entries: Vec<Entry>,
}

impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vault")
            .field("schema_version", &self.schema_version)
            .field("entries_count", &self.entries.len())
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

impl Default for Vault {
    fn default() -> Self {
        Self::new()
    }
}

impl Vault {
    pub fn new() -> Self {
        let now = Utc::now();
        Self {
            schema_version: 1,
            created_at: now,
            updated_at: now,
            entries: Vec::new(),
        }
    }

    pub fn add_entry(&mut self, mut entry: Entry) -> Result<()> {
        entry.name = entry.name.trim().to_string();
        if entry.name.is_empty() {
            return Err(VaultError::InvalidFormat(
                "entry name cannot be empty".into(),
            ));
        }
        if self
            .entries
            .iter()
            .any(|e| e.name.eq_ignore_ascii_case(&entry.name))
        {
            return Err(VaultError::DuplicateEntry(entry.name.clone()));
        }
        self.entries.push(entry);
        self.entries
            .sort_by_key(|a| a.name.to_ascii_lowercase());
        self.updated_at = Utc::now();
        Ok(())
    }

    /// Update an existing entry by original name, enforcing case-insensitive uniqueness
    /// on rename, re-sorting entries, and bumping `vault.updated_at`.
    pub fn update_entry<F>(&mut self, orig_name: &str, new_name: &str, apply: F) -> Result<()>
    where
        F: FnOnce(&mut Entry),
    {
        let trimmed_new = new_name.trim();
        if trimmed_new.is_empty() {
            return Err(VaultError::InvalidFormat(
                "entry name cannot be empty".into(),
            ));
        }
        let target_idx = self
            .entries
            .iter()
            .position(|e| e.name.eq_ignore_ascii_case(orig_name))
            .ok_or_else(|| VaultError::EntryNotFound(orig_name.to_string()))?;

        // Check for case-insensitive collision with any OTHER entry.
        let collides = self
            .entries
            .iter()
            .enumerate()
            .any(|(i, e)| i != target_idx && e.name.eq_ignore_ascii_case(trimmed_new));
        if collides {
            return Err(VaultError::DuplicateEntry(trimmed_new.to_string()));
        }

        let entry = &mut self.entries[target_idx];
        entry.name = trimmed_new.to_string();
        apply(entry);
        entry.updated_at = Utc::now();

        self.entries
            .sort_by_key(|a| a.name.to_ascii_lowercase());
        self.updated_at = Utc::now();
        Ok(())
    }

    pub fn find_by_name(&self, name: &str) -> Option<&Entry> {
        self.entries
            .iter()
            .find(|e| e.name.eq_ignore_ascii_case(name))
    }

    pub fn find_by_name_mut(&mut self, name: &str) -> Option<&mut Entry> {
        self.entries
            .iter_mut()
            .find(|e| e.name.eq_ignore_ascii_case(name))
    }

    pub fn remove_by_name(&mut self, name: &str) -> Result<Entry> {
        let pos = self
            .entries
            .iter()
            .position(|e| e.name.eq_ignore_ascii_case(name))
            .ok_or_else(|| VaultError::EntryNotFound(name.to_string()))?;
        let removed = self.entries.remove(pos);
        self.updated_at = Utc::now();
        Ok(removed)
    }

    pub fn search(&self, query: &str) -> Vec<&Entry> {
        self.entries
            .iter()
            .filter(|e| e.matches_query(query))
            .collect()
    }
}
