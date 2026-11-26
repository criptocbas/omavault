use std::fmt;
use std::ptr;
use std::slice;

use zeroize::Zeroize;

use crate::error::{Result, VaultError};

/// Summary of OS-level security mitigations applied to the current process.
#[derive(Debug, Clone, Copy, Default)]
pub struct HardeningStatus {
    /// `prctl(PR_SET_DUMPABLE, 0)` succeeded (blocks non-root ptrace & core dumps).
    pub dumpable_disabled: bool,
    /// `setrlimit(RLIMIT_CORE, 0)` succeeded.
    pub core_dumps_disabled: bool,
    /// `umask(0o077)` applied so newly created files default to owner-only.
    pub umask_restricted: bool,
}

impl HardeningStatus {
    pub fn summary(&self) -> String {
        format!(
            "ptrace-block:{} core-dump-off:{} umask-077:{}",
            if self.dumpable_disabled { "ON" } else { "OFF" },
            if self.core_dumps_disabled { "ON" } else { "OFF" },
            if self.umask_restricted { "ON" } else { "OFF" },
        )
    }
}

/// Apply OS-level process hardening as early as possible in `main()`.
///
/// 1. `umask(0o077)` — ensures no newly created file or socket is ever group/world readable.
/// 2. `prctl(PR_SET_DUMPABLE, 0)` — prevents non-root `ptrace` attachment (including
///    other processes running under the same UID) and prevents core dumps.
/// 3. `setrlimit(RLIMIT_CORE, 0)` — belt-and-suspenders prohibition on core dumps.
pub fn harden_process() -> HardeningStatus {
    let mut status = HardeningStatus::default();

    unsafe {
        // Restrict file creation mask to owner-only (0700 dirs / 0600 files).
        libc::umask(0o077);
        status.umask_restricted = true;

        // Disable ptrace attachment and core dumps for this process.
        #[cfg(target_os = "linux")]
        {
            if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0 {
                status.dumpable_disabled = true;
            }
        }

        // Set RLIMIT_CORE to 0.
        let zero_limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &zero_limit) == 0 {
            status.core_dumps_disabled = true;
        }
    }

    status
}

/// Page-aligned, memory-hardened container for fixed-size cryptographic keys.
///
/// Security properties on Linux:
/// - Allocated via `mmap(MAP_PRIVATE | MAP_ANONYMOUS)` on dedicated pages.
/// - `mlock()` prevents the kernel from swapping secret pages to disk/swap.
/// - `madvise(MADV_DONTDUMP)` excludes pages from core dumps even if re-enabled.
/// - `madvise(MADV_WIPEONFORK)` instructs the kernel to zero pages in any forked child.
/// - Guarded with `mprotect(PROT_NONE)` whenever idle; only made readable during
///   the tight scope of [`LockedKey::expose`].
/// - Explicitly volatile-wiped (`zeroize`), `munlock`ed, and `munmap`ped on `Drop`.
pub struct LockedKey<const N: usize> {
    ptr: *mut u8,
    map_len: usize,
    mlocked: bool,
    protected: bool,
}

// SAFETY: `LockedKey` owns its private anonymous `mmap` region exclusively.
unsafe impl<const N: usize> Send for LockedKey<N> {}
unsafe impl<const N: usize> Sync for LockedKey<N> {}

impl<const N: usize> LockedKey<N> {
    /// Allocate a hardened page-aligned key buffer, copy `bytes` into it,
    /// zeroize the caller's slice, and immediately mark the page `PROT_NONE`.
    pub fn new(bytes: &mut [u8; N]) -> Result<Self> {
        let page_size = page_size();
        let map_len = N.max(1).div_ceil(page_size) * page_size;

        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                map_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        if ptr == libc::MAP_FAILED || ptr.is_null() {
            bytes.zeroize();
            return Err(VaultError::Hardening("mmap failed for LockedKey".into()));
        }

        let ptr = ptr as *mut u8;

        // Lock memory to prevent swapping to disk. Track whether mlock succeeded
        // so we can report accurate security telemetry without crashing on low RLIMIT_MEMLOCK.
        let mlocked = unsafe { libc::mlock(ptr as *const libc::c_void, map_len) == 0 };

        #[cfg(target_os = "linux")]
        unsafe {
            let _ = libc::madvise(ptr as *mut libc::c_void, map_len, libc::MADV_DONTDUMP);
            let _ = libc::madvise(ptr as *mut libc::c_void, map_len, libc::MADV_WIPEONFORK);
        }

        // Copy secret bytes into hardened page and immediately wipe caller's buffer.
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, N);
        }
        bytes.zeroize();

        // Seal page with PROT_NONE until explicitly exposed.
        let protected = unsafe {
            libc::mprotect(ptr as *mut libc::c_void, map_len, libc::PROT_NONE) == 0
        };

        Ok(Self {
            ptr,
            map_len,
            mlocked,
            protected,
        })
    }

    /// Returns true if the underlying memory page is locked in RAM via `mlock`.
    pub fn is_mlocked(&self) -> bool {
        self.mlocked
    }

    /// Returns true if the page is actively sealed with `PROT_NONE` while idle.
    pub fn is_guard_protected(&self) -> bool {
        self.protected
    }

    /// Temporarily mark the page read-only (`PROT_READ`), run `f` with a reference
    /// to the key bytes, and immediately re-seal with `PROT_NONE` (even on panic via RAII guard).
    pub fn expose<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&[u8; N]) -> R,
    {
        struct ReSealGuard {
            ptr: *mut u8,
            map_len: usize,
            active: bool,
        }
        impl Drop for ReSealGuard {
            fn drop(&mut self) {
                if self.active {
                    unsafe {
                        let _ = libc::mprotect(
                            self.ptr as *mut libc::c_void,
                            self.map_len,
                            libc::PROT_NONE,
                        );
                    }
                }
            }
        }

        if self.protected {
            unsafe {
                let rc = libc::mprotect(
                    self.ptr as *mut libc::c_void,
                    self.map_len,
                    libc::PROT_READ,
                );
                assert_eq!(rc, 0, "mprotect(PROT_READ) failed on LockedKey");
            }
        }

        let _guard = ReSealGuard {
            ptr: self.ptr,
            map_len: self.map_len,
            active: self.protected,
        };

        let slice = unsafe { slice::from_raw_parts(self.ptr, N) };
        let array: &[u8; N] = slice.try_into().expect("LockedKey length invariant");
        f(array)
    }

    /// Create an independent hardened copy of this key (e.g., for session handoff).
    pub fn try_clone(&self) -> Result<Self> {
        self.expose(|bytes| {
            let mut copy = *bytes;
            Self::new(&mut copy)
        })
    }
}

impl<const N: usize> Drop for LockedKey<N> {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                // Make writable again so we can volatile-zeroize the full mapping.
                let _ = libc::mprotect(
                    self.ptr as *mut libc::c_void,
                    self.map_len,
                    libc::PROT_READ | libc::PROT_WRITE,
                );
                let slice = slice::from_raw_parts_mut(self.ptr, self.map_len);
                slice.zeroize();
                if self.mlocked {
                    let _ = libc::munlock(self.ptr as *const libc::c_void, self.map_len);
                }
                let _ = libc::munmap(self.ptr as *mut libc::c_void, self.map_len);
            }
            self.ptr = ptr::null_mut();
        }
    }
}

impl<const N: usize> fmt::Debug for LockedKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LockedKey")
            .field("len", &N)
            .field("mlocked", &self.mlocked)
            .field("protected", &self.protected)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

fn page_size() -> usize {
    let ps = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if ps > 0 {
        ps as usize
    } else {
        4096
    }
}

/// Fill a byte slice with cryptographically secure randomness from the OS CSPRNG.
pub fn fill_random(dest: &mut [u8]) -> Result<()> {
    getrandom::getrandom(dest)
        .map_err(|e| VaultError::Crypto(format!("OS CSPRNG failure: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_key_zeroes_source_and_exposes_value() {
        let mut raw = [0xA5u8; 32];
        let key = LockedKey::new(&mut raw).expect("allocate LockedKey");
        // Caller buffer must be wiped immediately.
        assert_eq!(raw, [0u8; 32]);
        // Debug output must never leak bytes.
        assert!(format!("{key:?}").contains("[REDACTED]"));
        // Scoped expose returns exact secret.
        key.expose(|b| assert_eq!(b, &[0xA5u8; 32]));
        // Clone works cleanly.
        let cloned = key.try_clone().expect("clone LockedKey");
        cloned.expose(|b| assert_eq!(b, &[0xA5u8; 32]));
    }
}
