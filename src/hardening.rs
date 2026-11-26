use std::fmt;
use std::fs;
use std::ptr;
use std::slice;
use std::sync::Mutex;

use zeroize::Zeroize;

use crate::error::{Result, VaultError};

/// Process names recognized as Wayland/X11 screen lockers (including 15-byte comm truncations).
const SCREEN_LOCKERS: &[&str] = &[
    "hyprlock",
    "swaylock",
    "swaylock-effect",
    "gtklock",
    "waylock",
    "i3lock",
];

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
        libc::umask(0o077);
        status.umask_restricted = true;

        #[cfg(target_os = "linux")]
        {
            if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0 {
                status.dumpable_disabled = true;
            }
        }

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

/// Page-aligned, guard-paged, memory-hardened container for fixed-size cryptographic keys.
///
/// Security properties on Linux:
/// - Allocated via `mmap(MAP_PRIVATE | MAP_ANONYMOUS)` with flanking `PROT_NONE` guard pages
///   before and after the secret page(s).
/// - `mlock()` prevents the kernel from swapping secret pages to disk/swap.
/// - `madvise(MADV_DONTDUMP)` excludes pages from core dumps even if re-enabled.
/// - `madvise(MADV_WIPEONFORK)` instructs the kernel to zero pages in any forked child.
/// - Sealed with `mprotect(PROT_NONE)` whenever idle; thread-safe and re-entrancy-safe
///   reference counting (`Mutex<usize>`) keeps pages `PROT_READ` only while actively exposed.
/// - Explicitly volatile-wiped (`zeroize`), `munlock`ed, and `munmap`ped on `Drop`.
pub struct LockedKey<const N: usize> {
    /// Base pointer of the entire 3-segment mmap: `[guard_before][secret_pages][guard_after]`.
    base_ptr: *mut u8,
    /// Pointer to the secret page(s) (`base_ptr + page_size`).
    secret_ptr: *mut u8,
    /// Byte length of the secret region (page-aligned).
    secret_len: usize,
    /// Total byte length of the mmap including both guard pages.
    total_len: usize,
    mlocked: bool,
    dontdump: bool,
    wipeonfork: bool,
    /// Active concurrent/re-entrant exposures protecting `mprotect(PROT_READ/PROT_NONE)`.
    exposure_count: Mutex<usize>,
}

// SAFETY: `LockedKey` exclusively owns its private anonymous `mmap` region and synchronizes
// all `mprotect` transitions via `exposure_count: Mutex<usize>`.
unsafe impl<const N: usize> Send for LockedKey<N> {}
unsafe impl<const N: usize> Sync for LockedKey<N> {}

impl<const N: usize> LockedKey<N> {
    /// Allocate a hardened guard-paged key buffer, copy `bytes` into it,
    /// zeroize the caller's slice, and immediately seal the secret page with `PROT_NONE`.
    pub fn new(bytes: &mut [u8; N]) -> Result<Self> {
        let alloc = Self::allocate_writable();
        let (base_ptr, secret_ptr, secret_len, total_len, mlocked, dontdump, wipeonfork) =
            match alloc {
                Ok(v) => v,
                Err(e) => {
                    bytes.zeroize();
                    return Err(e);
                }
            };

        // Copy secret bytes into hardened page and immediately wipe caller's buffer.
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), secret_ptr, N);
        }
        bytes.zeroize();

        // Fail closed if we cannot seal the secret page to PROT_NONE.
        let rc = unsafe {
            libc::mprotect(
                secret_ptr as *mut libc::c_void,
                secret_len,
                libc::PROT_NONE,
            )
        };
        if rc != 0 {
            unsafe {
                let slice = slice::from_raw_parts_mut(secret_ptr, secret_len);
                slice.zeroize();
                if mlocked {
                    let _ = libc::munlock(secret_ptr as *const libc::c_void, secret_len);
                }
                let _ = libc::munmap(base_ptr as *mut libc::c_void, total_len);
            }
            return Err(VaultError::Hardening(
                "mprotect(PROT_NONE) failed on LockedKey".into(),
            ));
        }

        Ok(Self {
            base_ptr,
            secret_ptr,
            secret_len,
            total_len,
            mlocked,
            dontdump,
            wipeonfork,
            exposure_count: Mutex::new(0),
        })
    }

    #[allow(clippy::type_complexity)]
    fn allocate_writable() -> Result<(*mut u8, *mut u8, usize, usize, bool, bool, bool)> {
        let ps = page_size();
        let pages = N.max(1).div_ceil(ps);
        let secret_len = pages
            .checked_mul(ps)
            .ok_or_else(|| VaultError::Hardening("LockedKey size overflow".into()))?;
        let guard_pair = ps
            .checked_mul(2)
            .ok_or_else(|| VaultError::Hardening("LockedKey guard size overflow".into()))?;
        let total_len = secret_len
            .checked_add(guard_pair)
            .ok_or_else(|| VaultError::Hardening("LockedKey total size overflow".into()))?;

        // Map entire [guard][secret][guard] region as PROT_NONE initially.
        let base = unsafe {
            libc::mmap(
                ptr::null_mut(),
                total_len,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        if base == libc::MAP_FAILED || base.is_null() {
            return Err(VaultError::Hardening("mmap failed for LockedKey".into()));
        }

        let base_ptr = base as *mut u8;
        let secret_ptr = unsafe { base_ptr.add(ps) };

        // Make only the inner secret page(s) readable/writable for initialization.
        let rc = unsafe {
            libc::mprotect(
                secret_ptr as *mut libc::c_void,
                secret_len,
                libc::PROT_READ | libc::PROT_WRITE,
            )
        };
        if rc != 0 {
            unsafe {
                let _ = libc::munmap(base_ptr as *mut libc::c_void, total_len);
            }
            return Err(VaultError::Hardening(
                "mprotect(PROT_READ|PROT_WRITE) failed during LockedKey init".into(),
            ));
        }

        let mlocked = unsafe { libc::mlock(secret_ptr as *const libc::c_void, secret_len) == 0 };

        #[cfg(target_os = "linux")]
        let (dontdump, wipeonfork) = unsafe {
            let dd = libc::madvise(
                secret_ptr as *mut libc::c_void,
                secret_len,
                libc::MADV_DONTDUMP,
            ) == 0;
            let wof = libc::madvise(
                secret_ptr as *mut libc::c_void,
                secret_len,
                libc::MADV_WIPEONFORK,
            ) == 0;
            (dd, wof)
        };

        #[cfg(not(target_os = "linux"))]
        let (dontdump, wipeonfork) = (false, false);

        Ok((
            base_ptr, secret_ptr, secret_len, total_len, mlocked, dontdump, wipeonfork,
        ))
    }

    /// Returns true if the underlying secret memory page is locked in RAM via `mlock`.
    pub fn is_mlocked(&self) -> bool {
        self.mlocked
    }

    /// Returns true if the page is sealed with `PROT_NONE` + flanking guard pages while idle.
    pub fn is_guard_protected(&self) -> bool {
        true
    }

    /// Returns true if `MADV_DONTDUMP` and `MADV_WIPEONFORK` succeeded.
    pub fn is_kernel_hardened(&self) -> bool {
        self.dontdump && self.wipeonfork
    }

    /// Temporarily mark the page read-only (`PROT_READ`), run `f` with a reference
    /// to the key bytes, and re-seal with `PROT_NONE` once the last active exposure exits.
    ///
    /// Safe under both concurrent multi-threaded (`Sync`) calls and nested re-entrant calls.
    pub fn expose<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&[u8; N]) -> R,
    {
        struct ReSealGuard<'a, const M: usize> {
            key: &'a LockedKey<M>,
        }
        impl<const M: usize> Drop for ReSealGuard<'_, M> {
            fn drop(&mut self) {
                let mut count = self
                    .key
                    .exposure_count
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                *count = count.saturating_sub(1);
                if *count == 0 {
                    unsafe {
                        let _ = libc::mprotect(
                            self.key.secret_ptr as *mut libc::c_void,
                            self.key.secret_len,
                            libc::PROT_NONE,
                        );
                    }
                }
            }
        }

        {
            let mut count = self
                .exposure_count
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if *count == 0 {
                let rc = unsafe {
                    libc::mprotect(
                        self.secret_ptr as *mut libc::c_void,
                        self.secret_len,
                        libc::PROT_READ,
                    )
                };
                if rc != 0 {
                    return Err(VaultError::Hardening(
                        "mprotect(PROT_READ) failed on LockedKey".into(),
                    ));
                }
            }
            *count = count
                .checked_add(1)
                .ok_or_else(|| VaultError::Hardening("LockedKey exposure count overflow".into()))?;
        }

        let _guard = ReSealGuard { key: self };

        let slice = unsafe { slice::from_raw_parts(self.secret_ptr, N) };
        let array: &[u8; N] = slice.try_into().expect("LockedKey length invariant");
        Ok(f(array))
    }

    /// Create an independent hardened copy directly page-to-page without touching the stack.
    pub fn try_clone(&self) -> Result<Self> {
        let (base_ptr, secret_ptr, secret_len, total_len, mlocked, dontdump, wipeonfork) =
            Self::allocate_writable()?;

        let copy_res = self.expose(|src| unsafe {
            ptr::copy_nonoverlapping(src.as_ptr(), secret_ptr, N);
        });

        if let Err(e) = copy_res {
            unsafe {
                let slice = slice::from_raw_parts_mut(secret_ptr, secret_len);
                slice.zeroize();
                if mlocked {
                    let _ = libc::munlock(secret_ptr as *const libc::c_void, secret_len);
                }
                let _ = libc::munmap(base_ptr as *mut libc::c_void, total_len);
            }
            return Err(e);
        }

        let rc = unsafe {
            libc::mprotect(
                secret_ptr as *mut libc::c_void,
                secret_len,
                libc::PROT_NONE,
            )
        };
        if rc != 0 {
            unsafe {
                let slice = slice::from_raw_parts_mut(secret_ptr, secret_len);
                slice.zeroize();
                if mlocked {
                    let _ = libc::munlock(secret_ptr as *const libc::c_void, secret_len);
                }
                let _ = libc::munmap(base_ptr as *mut libc::c_void, total_len);
            }
            return Err(VaultError::Hardening(
                "mprotect(PROT_NONE) failed on cloned LockedKey".into(),
            ));
        }

        Ok(Self {
            base_ptr,
            secret_ptr,
            secret_len,
            total_len,
            mlocked,
            dontdump,
            wipeonfork,
            exposure_count: Mutex::new(0),
        })
    }
}

impl<const N: usize> Drop for LockedKey<N> {
    fn drop(&mut self) {
        if !self.base_ptr.is_null() {
            unsafe {
                // Only write/zeroize if mprotect(PROT_READ|PROT_WRITE) succeeds;
                // never trigger UB/SIGSEGV on a PROT_NONE page.
                let writable = libc::mprotect(
                    self.secret_ptr as *mut libc::c_void,
                    self.secret_len,
                    libc::PROT_READ | libc::PROT_WRITE,
                ) == 0;
                if writable {
                    let slice = slice::from_raw_parts_mut(self.secret_ptr, self.secret_len);
                    slice.zeroize();
                }
                if self.mlocked {
                    let _ = libc::munlock(self.secret_ptr as *const libc::c_void, self.secret_len);
                }
                let _ = libc::munmap(self.base_ptr as *mut libc::c_void, self.total_len);
            }
            self.base_ptr = ptr::null_mut();
            self.secret_ptr = ptr::null_mut();
        }
    }
}

impl<const N: usize> fmt::Debug for LockedKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LockedKey")
            .field("len", &N)
            .field("mlocked", &self.mlocked)
            .field("dontdump", &self.dontdump)
            .field("wipeonfork", &self.wipeonfork)
            .field("guard_pages", &true)
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

/// Read `CLOCK_BOOTTIME` in whole seconds (advances during system suspend, unlike `Instant`).
#[cfg(target_os = "linux")]
pub fn boottime_secs() -> Option<u64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
    if rc == 0 && ts.tv_sec >= 0 {
        Some(ts.tv_sec as u64)
    } else {
        None
    }
}

#[cfg(not(target_os = "linux"))]
pub fn boottime_secs() -> Option<u64> {
    None
}

/// Measure `CLOCK_BOOTTIME - CLOCK_MONOTONIC` in milliseconds.
///
/// On Linux, `CLOCK_BOOTTIME` includes suspend time while `CLOCK_MONOTONIC` pauses during
/// suspend. Any jump `>= 2000 ms` immediately detects laptop lid-close / sleep.
#[cfg(target_os = "linux")]
pub fn boottime_monotonic_skew_ms() -> Option<u64> {
    let mut mono = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let mut boot = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        if libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut mono) != 0 {
            return None;
        }
        if libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut boot) != 0 {
            return None;
        }
    }
    let mono_ms = (mono.tv_sec as i128) * 1000 + (mono.tv_nsec as i128) / 1_000_000;
    let boot_ms = (boot.tv_sec as i128) * 1000 + (boot.tv_nsec as i128) / 1_000_000;
    let diff = boot_ms - mono_ms;
    Some(diff.max(0) as u64)
}

#[cfg(not(target_os = "linux"))]
pub fn boottime_monotonic_skew_ms() -> Option<u64> {
    None
}

/// Inspect `/proc/<pid>/status` atomically (zero subprocesses) to detect active Wayland/X11
/// screen lockers owned by `target_uid`.
///
/// Parsing `Uid:` from `/proc/<pid>/status` works even when a hardened screen locker sets
/// `PR_SET_DUMPABLE=0` (which changes `/proc/<pid>` directory ownership to root UID 0),
/// and ignores zombie (`Z`) / dead (`X`) processes.
#[cfg(target_os = "linux")]
pub fn is_screen_locker_active(target_uid: u32) -> bool {
    let Ok(entries) = fs::read_dir("/proc") else {
        return false;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if !name_str.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(status) = fs::read_to_string(entry.path().join("status")) else {
            continue;
        };
        if status_matches_active_locker(&status, target_uid) {
            return true;
        }
    }
    false
}

#[cfg(not(target_os = "linux"))]
pub fn is_screen_locker_active(_target_uid: u32) -> bool {
    false
}

/// Pure parser for `/proc/<pid>/status` so locker detection is unit-testable.
pub(crate) fn status_matches_active_locker(status: &str, target_uid: u32) -> bool {
    let mut proc_name: Option<&str> = None;
    let mut is_alive = true;
    let mut real_uid: Option<u32> = None;

    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Name:") {
            proc_name = Some(rest.trim());
        } else if let Some(rest) = line.strip_prefix("State:") {
            let st = rest.trim();
            if st.starts_with('Z') || st.starts_with('X') || st.starts_with('x') {
                is_alive = false;
            }
        } else if let Some(rest) = line.strip_prefix("Uid:") {
            if let Some(first) = rest.split_whitespace().next() {
                real_uid = first.parse::<u32>().ok();
            }
        }
    }

    is_alive
        && real_uid == Some(target_uid)
        && proc_name.is_some_and(|n| SCREEN_LOCKERS.contains(&n))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread;

    use super::*;

    #[test]
    fn locked_key_zeroes_source_and_exposes_value() {
        let mut raw = [0xA5u8; 32];
        let key = LockedKey::new(&mut raw).expect("allocate LockedKey");
        assert_eq!(raw, [0u8; 32]);
        assert!(format!("{key:?}").contains("[REDACTED]"));
        key.expose(|b| assert_eq!(b, &[0xA5u8; 32])).unwrap();
        let cloned = key.try_clone().expect("clone LockedKey");
        cloned.expose(|b| assert_eq!(b, &[0xA5u8; 32])).unwrap();
    }

    #[test]
    fn locked_key_is_sound_under_concurrent_and_reentrant_expose() {
        let mut raw = [0x5Au8; 32];
        let key = Arc::new(LockedKey::new(&mut raw).expect("allocate LockedKey"));

        // Re-entrant exposure on same thread must not unmap/re-seal outer reference.
        key.expose(|outer| {
            key.expose(|inner| {
                assert_eq!(inner, &[0x5Au8; 32]);
            })
            .unwrap();
            // Outer reference MUST remain readable after inner guard dropped!
            assert_eq!(outer, &[0x5Au8; 32]);
        })
        .unwrap();

        // Concurrent multi-threaded exposures across 8 threads.
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let k = Arc::clone(&key);
                thread::spawn(move || {
                    for _ in 0..200 {
                        k.expose(|b| assert_eq!(b, &[0x5Au8; 32])).unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("worker thread panicked");
        }
    }

    #[test]
    fn proc_status_parser_handles_dumpable_zero_and_zombies() {
        let active_hyprlock = "Name:\thyprlock\nState:\tS (sleeping)\nUid:\t1000\t1000\t1000\t1000\n";
        assert!(status_matches_active_locker(active_hyprlock, 1000));
        assert!(!status_matches_active_locker(active_hyprlock, 1001));

        let zombie_hyprlock = "Name:\thyprlock\nState:\tZ (zombie)\nUid:\t1000\t1000\t1000\t1000\n";
        assert!(!status_matches_active_locker(zombie_hyprlock, 1000));

        let truncated_swaylock = "Name:\tswaylock-effect\nState:\tS (sleeping)\nUid:\t1000\t1000\t1000\t1000\n";
        assert!(status_matches_active_locker(truncated_swaylock, 1000));
    }
}
