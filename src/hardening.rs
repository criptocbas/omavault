use std::fmt;
use std::fs;
use std::io;
use std::ptr;
use std::slice;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use zeroize::Zeroize;

use crate::error::{Result, VaultError};

/// Zero-allocation `io::Write` counter used to compute exact serialized JSON byte lengths
/// before allocating a single fixed-capacity `Zeroizing<Vec<u8>>` (eliminating unzeroized `realloc` copies).
#[derive(Default)]
pub struct CountingWriter {
    pub bytes: usize,
}

impl io::Write for CountingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(buf.len())
            .ok_or_else(|| io::Error::other("serialized payload size overflow"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// How exposed decrypted secrets are to being paged out to disk.
///
/// Only the 32-byte master key lives in `mlock`ed memory. Decrypted entries in the TUI/CLI are
/// ordinary heap: `mlockall` is not viable because the default `RLIMIT_MEMLOCK` (8 MiB) is far
/// below Argon2id's 128 MiB+ working set. Whether swap can leak them depends on the swap setup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwapExposure {
    /// No active swap.
    None,
    /// Only zram (compressed RAM): nothing is written to disk.
    ZramOnly,
    /// All disk-backed swap sits on dm-crypt (LUKS), possibly alongside zram.
    Encrypted,
    /// At least one swap area is on a plain, unencrypted block device.
    Unencrypted(Vec<String>),
    /// Swap whose backing could not be classified (e.g. a swap file on btrfs/zfs).
    Unknown(Vec<String>),
}

impl SwapExposure {
    pub fn describe(&self) -> String {
        match self {
            Self::None => "none".into(),
            Self::ZramOnly => "zram only (RAM-backed; nothing is paged to disk)".into(),
            Self::Encrypted => "encrypted (dm-crypt/LUKS)".into(),
            Self::Unencrypted(devs) => format!(
                "WARNING: UNENCRYPTED swap on {} — decrypted entries could be paged to disk (use zram or LUKS-encrypted swap)",
                devs.join(", ")
            ),
            Self::Unknown(devs) => format!(
                "unverified ({}) — make sure it is on an encrypted filesystem/device",
                devs.join(", ")
            ),
        }
    }

    pub fn is_unencrypted(&self) -> bool {
        matches!(self, Self::Unencrypted(_))
    }
}

/// Classify active swap from `/proc/swaps` and sysfs (no subprocesses).
#[cfg(target_os = "linux")]
pub fn swap_exposure() -> SwapExposure {
    let Ok(swaps) = fs::read_to_string("/proc/swaps") else {
        return SwapExposure::Unknown(vec!["/proc/swaps unreadable".into()]);
    };
    classify_swaps(
        &swaps,
        &|name| block_device_is_crypt(name),
        &|path| file_backing_block_name(path),
        &zram_backing_dev,
    )
}

#[cfg(not(target_os = "linux"))]
pub fn swap_exposure() -> SwapExposure {
    SwapExposure::Unknown(vec!["unsupported platform".into()])
}

/// How a `/dev/zramN` swap should be counted, from its `backing_dev` text.
enum ZramBacking {
    /// Sysfs entry absent, empty, or `none`: compressed RAM, not a disk.
    Ram,
    /// Basename of the writeback device (`sda2`, `dm-0`).
    Block(String),
    /// A backing device was named, but not as a single block name.
    Unreadable,
}

/// `raw` is the contents of `/sys/block/zramN/backing_dev`, or `None` if that file is absent.
fn interpret_zram_backing(raw: Option<String>) -> ZramBacking {
    let Some(raw) = raw else {
        return ZramBacking::Ram;
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("none") {
        return ZramBacking::Ram;
    }
    match std::path::Path::new(trimmed)
        .file_name()
        .and_then(|name| name.to_str())
    {
        Some(block)
            if !block.is_empty()
                && !block.contains('/')
                && !block.contains("..")
                && !block.eq_ignore_ascii_case("none") =>
        {
            ZramBacking::Block(block.to_string())
        }
        _ => ZramBacking::Unreadable,
    }
}

/// Pure classifier (unit-testable). `is_crypt(block_name)` reports whether a block device such as
/// `dm-3` is (or sits on) dm-crypt; `file_block(path)` maps a swap FILE to its backing block name.
/// `zram_backing(zramN)` returns the `backing_dev` text for that zram device, or `None` if absent.
fn classify_swaps(
    proc_swaps: &str,
    is_crypt: &dyn Fn(&str) -> Option<bool>,
    file_block: &dyn Fn(&str) -> Option<String>,
    zram_backing: &dyn Fn(&str) -> Option<String>,
) -> SwapExposure {
    let mut any = false;
    let mut disk_backed = false;
    let mut unencrypted = Vec::new();
    let mut unknown = Vec::new();
    for line in proc_swaps.lines().skip(1) {
        let mut cols = line.split_whitespace();
        let (Some(name), Some(kind)) = (cols.next(), cols.next()) else {
            continue;
        };
        // /proc/swaps escapes spaces in paths as \040.
        let name = name.replace("\\040", " ");
        any = true;
        if name.starts_with("/dev/zram") {
            let Some(zram) = std::path::Path::new(&name)
                .file_name()
                .and_then(|file| file.to_str())
                .filter(|file| file.starts_with("zram") && !file.contains(".."))
            else {
                unknown.push(name);
                continue;
            };
            match interpret_zram_backing(zram_backing(zram)) {
                ZramBacking::Ram => continue,
                ZramBacking::Unreadable => unknown.push(name),
                ZramBacking::Block(block) => {
                    disk_backed = true;
                    match is_crypt(&block) {
                        Some(true) => {}
                        Some(false) => unencrypted.push(name),
                        None => unknown.push(name),
                    }
                }
            }
            continue;
        }
        disk_backed = true;
        let block = if kind == "file" {
            file_block(&name)
        } else {
            std::path::Path::new(&name)
                .canonicalize()
                .ok()
                .and_then(|p| p.file_name().map(|f| f.to_string_lossy().into_owned()))
        };
        match block.as_deref().map(|b| (b, is_crypt(b))) {
            Some((_, Some(true))) => {}
            Some((_, Some(false))) => unencrypted.push(name),
            _ => unknown.push(name),
        }
    }
    if !any {
        SwapExposure::None
    } else if !unencrypted.is_empty() {
        SwapExposure::Unencrypted(unencrypted)
    } else if !unknown.is_empty() {
        SwapExposure::Unknown(unknown)
    } else if disk_backed {
        SwapExposure::Encrypted
    } else {
        SwapExposure::ZramOnly
    }
}

/// Is block device `name` (e.g. `dm-2`, `nvme0n1p3`) dm-crypt, or stacked on dm-crypt
/// (e.g. LVM on LUKS)? `Some(false)` = definitely plain; `None` = cannot tell.
#[cfg(target_os = "linux")]
fn block_device_is_crypt(name: &str) -> Option<bool> {
    fn walk(name: &str, depth: u8) -> Option<bool> {
        if depth > 6 || name.contains('/') || name.contains("..") {
            return None;
        }
        let sys = std::path::Path::new("/sys/class/block").join(name);
        if !sys.exists() {
            return None;
        }
        if let Ok(uuid) = fs::read_to_string(sys.join("dm/uuid")) {
            if uuid.trim_start().starts_with("CRYPT-") {
                return Some(true);
            }
        }
        // Device-mapper / md devices: encrypted iff some underlying device is.
        if let Ok(slaves) = fs::read_dir(sys.join("slaves")) {
            let mut saw_slave = false;
            for s in slaves.flatten() {
                saw_slave = true;
                if walk(&s.file_name().to_string_lossy(), depth + 1) == Some(true) {
                    return Some(true);
                }
            }
            if saw_slave {
                return Some(false);
            }
        }
        Some(false)
    }
    walk(name, 0)
}

/// Contents of `/sys/block/zramN/backing_dev`, or `None` when the file is absent.
#[cfg(target_os = "linux")]
fn zram_backing_dev(zram_name: &str) -> Option<String> {
    if !zram_name.starts_with("zram") || zram_name.contains('/') || zram_name.contains("..") {
        return None;
    }
    fs::read_to_string(format!("/sys/block/{zram_name}/backing_dev")).ok()
}

/// Map a swap file to the block device holding it (via `st_dev` → `/sys/dev/block/MAJ:MIN`).
#[cfg(target_os = "linux")]
fn file_backing_block_name(path: &str) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let dev = fs::metadata(path).ok()?.dev();
    let (major, minor) = (libc::major(dev), libc::minor(dev));
    if major == 0 {
        return None; // anonymous device (btrfs subvolume, overlay, ...): cannot tell
    }
    let link = fs::read_link(format!("/sys/dev/block/{major}:{minor}")).ok()?;
    Some(link.file_name()?.to_string_lossy().into_owned())
}

/// Overwrite a 16 KiB region of the stack just below the caller's frame.
///
/// Call it right after a non-inlined function that handled key material on its stack (e.g.
/// `hkdf`/`hmac` 0.12, which do not zeroize their internal state): this frame reuses the same
/// addresses and wipes whatever the callee left behind. Best-effort defence in depth.
#[inline(never)]
pub fn scrub_stack() {
    let mut buf = [0u8; 16 * 1024];
    // SAFETY: `buf` is a live, writable local of exactly this size.
    unsafe { crate::alloc::wipe(buf.as_mut_ptr(), buf.len()) };
    std::hint::black_box(&buf);
}

/// True for characters that can alter terminal state or visually spoof text: C0/C1 controls
/// (ANSI/OSC/CSI escapes), DEL, Unicode BiDi overrides/isolates, zero-width and tag characters.
pub fn is_dangerous_display_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061C}'
                | '\u{200B}'..='\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{2060}'..='\u{2069}'
                | '\u{FEFF}'
                | '\u{E0000}'..='\u{E007F}'
        )
}

/// Sanitize untrusted text for single-line terminal/TUI display:
/// strips C0/C1 control characters (ANSI/OSC/CSI escapes), Unicode BiDi overrides/isolates,
/// zero-width/tag characters, and normalizes newlines/tabs to spaces.
pub fn sanitize_single_line(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c == '\n' || c == '\r' || c == '\t' {
            out.push(' ');
        } else if !is_dangerous_display_char(c) {
            out.push(c);
        }
    }
    out
}

/// Sanitize untrusted text for multi-line terminal/TUI display:
/// strips C0/C1 controls (except `\n`), Unicode BiDi overrides/isolates, zero-width/tag chars,
/// and Unicode line/paragraph separators.
pub fn sanitize_multiline(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c == '\n' {
            out.push('\n');
        } else if c == '\t' {
            out.push_str("    ");
        } else if !is_dangerous_display_char(c) {
            out.push(c);
        }
    }
    out
}

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
            if self.core_dumps_disabled {
                "ON"
            } else {
                "OFF"
            },
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
    /// Tracks whether the secret page is actually sealed (`PROT_NONE`) when idle.
    sealed: AtomicBool,
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
        let rc =
            unsafe { libc::mprotect(secret_ptr as *mut libc::c_void, secret_len, libc::PROT_NONE) };
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
            sealed: AtomicBool::new(true),
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

    /// Returns true if the page is currently sealed with `PROT_NONE` + flanking guard pages.
    pub fn is_guard_protected(&self) -> bool {
        self.sealed.load(Ordering::Acquire)
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
                    let rc = unsafe {
                        libc::mprotect(
                            self.key.secret_ptr as *mut libc::c_void,
                            self.key.secret_len,
                            libc::PROT_NONE,
                        )
                    };
                    if rc == 0 {
                        self.key.sealed.store(true, Ordering::Release);
                    } else {
                        self.key.sealed.store(false, Ordering::Release);
                        eprintln!("omavault security warning: mprotect(PROT_NONE) re-seal failed");
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
                self.sealed.store(false, Ordering::Release);
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

        let rc =
            unsafe { libc::mprotect(secret_ptr as *mut libc::c_void, secret_len, libc::PROT_NONE) };
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
            sealed: AtomicBool::new(true),
            exposure_count: Mutex::new(0),
        })
    }
}

impl<const N: usize> Drop for LockedKey<N> {
    fn drop(&mut self) {
        if !self.base_ptr.is_null() {
            unsafe {
                // Attempt targeted unseal first; if VMA splitting fails (e.g. vm.max_map_count),
                // fall back to unsealing the entire 3-segment mmap so volatile zeroize STILL runs.
                let writable = libc::mprotect(
                    self.secret_ptr as *mut libc::c_void,
                    self.secret_len,
                    libc::PROT_READ | libc::PROT_WRITE,
                ) == 0
                    || libc::mprotect(
                        self.base_ptr as *mut libc::c_void,
                        self.total_len,
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
    getrandom::getrandom(dest).map_err(|e| VaultError::Crypto(format!("OS CSPRNG failure: {e}")))
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
/// screen lockers owned by `target_uid`, and query Hyprland's IPC socket directly over `AF_UNIX`
/// to detect Wayland `ext-session-lock` screen locks (such as Omarchy 4.5's `omarchy-shell` lock).
///
/// Parsing `Uid:` from `/proc/<pid>/status` works even when a hardened screen locker sets
/// `PR_SET_DUMPABLE=0` (which changes `/proc/<pid>` directory ownership to root UID 0),
/// and ignores zombie (`Z`) / dead (`X`) processes.
#[cfg(target_os = "linux")]
pub fn is_screen_locker_active(target_uid: u32) -> bool {
    if is_proc_screen_locker_active(target_uid) {
        return true;
    }
    is_hyprland_session_locked(target_uid)
}

#[cfg(target_os = "linux")]
fn is_proc_screen_locker_active(target_uid: u32) -> bool {
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

/// Query Hyprland's `j/monitors` IPC endpoint directly over `AF_UNIX` (zero subprocesses)
/// to detect an active `ext-session-lock` (reported as `"LOCK"` in `solitaryBlockedBy`).
#[cfg(target_os = "linux")]
fn is_hyprland_session_locked(target_uid: u32) -> bool {
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime};

    const MAX_IPC_RESPONSE_BYTES: u64 = 256 * 1024;
    const IPC_TIMEOUT: Duration = Duration::from_millis(250);

    let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("/run/user/{target_uid}"));
    let hypr_base = PathBuf::from(runtime_dir).join("hypr");

    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(sig) = std::env::var("HYPRLAND_INSTANCE_SIGNATURE") {
        if !sig.is_empty() && !sig.contains('/') && !sig.contains("..") {
            candidates.push(hypr_base.join(sig).join(".socket.sock"));
        }
    }

    if let Ok(entries) = fs::read_dir(&hypr_base) {
        let mut discovered: Vec<(SystemTime, PathBuf)> = entries
            .flatten()
            .filter_map(|entry| {
                let sock = entry.path().join(".socket.sock");
                let meta = fs::symlink_metadata(&sock).ok()?;
                if meta.uid() != target_uid || !meta.file_type().is_socket() {
                    return None;
                }
                let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                Some((modified, sock))
            })
            .collect();
        discovered.sort_by_key(|entry| std::cmp::Reverse(entry.0));
        for (_, sock) in discovered.into_iter().take(4) {
            if !candidates.contains(&sock) {
                candidates.push(sock);
            }
        }
    }

    let query_socket = |sock_path: &Path| -> Option<bool> {
        let meta = fs::symlink_metadata(sock_path).ok()?;
        if meta.uid() != target_uid || !meta.file_type().is_socket() {
            return None;
        }
        let mut stream = connect_unix_with_timeout(sock_path, 250)?;
        let _ = stream.set_read_timeout(Some(IPC_TIMEOUT));
        let _ = stream.set_write_timeout(Some(IPC_TIMEOUT));
        stream.write_all(b"j/monitors").ok()?;
        let _ = stream.shutdown(Shutdown::Write);

        let mut response = String::new();
        stream
            .take(MAX_IPC_RESPONSE_BYTES)
            .read_to_string(&mut response)
            .ok()?;
        Some(monitors_json_has_session_lock(&response))
    };

    for sock in candidates {
        if query_socket(&sock) == Some(true) {
            return true;
        }
    }

    false
}

/// Non-blocking `AF_UNIX` connect with a strict `poll(2)` deadline so a wedged compositor
/// socket can never stall the daemon watchdog thread.
#[cfg(target_os = "linux")]
fn connect_unix_with_timeout(
    path: &std::path::Path,
    timeout_ms: i32,
) -> Option<std::os::unix::net::UnixStream> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::FromRawFd;
    use std::os::unix::net::UnixStream;

    let bytes = path.as_os_str().as_bytes();
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    if bytes.is_empty() || bytes.len() >= addr.sun_path.len() || bytes.contains(&0) {
        return None;
    }
    for (dst, &src) in addr.sun_path.iter_mut().zip(bytes.iter()) {
        *dst = src as libc::c_char;
    }

    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return None;
    }

    let addr_len =
        (std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1) as libc::socklen_t;
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms.max(0) as u64);
    let close_fd = |fd: libc::c_int| unsafe {
        libc::close(fd);
    };
    loop {
        let rc = unsafe {
            libc::connect(
                fd,
                &addr as *const libc::sockaddr_un as *const libc::sockaddr,
                addr_len,
            )
        };
        if rc == 0 {
            break;
        }
        let errno = io::Error::last_os_error().raw_os_error();
        match errno {
            Some(libc::EINTR) => continue,
            // Linux AF_UNIX returns EAGAIN (not EINPROGRESS) when the listener's backlog is
            // full; the socket is still unconnected, so retry connect() until the deadline.
            Some(libc::EAGAIN) => {
                if std::time::Instant::now() >= deadline {
                    close_fd(fd);
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
                continue;
            }
            Some(libc::EINPROGRESS) => {
                let mut pfd = libc::pollfd {
                    fd,
                    events: libc::POLLOUT,
                    revents: 0,
                };
                loop {
                    let now = std::time::Instant::now();
                    if now >= deadline {
                        close_fd(fd);
                        return None;
                    }
                    let wait_ms = (deadline - now).as_millis().clamp(1, i32::MAX as u128) as i32;
                    let poll_rc = unsafe { libc::poll(&mut pfd, 1, wait_ms) };
                    if poll_rc < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
                    {
                        continue;
                    }
                    if poll_rc <= 0 || (pfd.revents & libc::POLLOUT) == 0 {
                        close_fd(fd);
                        return None;
                    }
                    break;
                }
                let mut so_err: libc::c_int = 0;
                let mut so_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
                let opt_rc = unsafe {
                    libc::getsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_ERROR,
                        &mut so_err as *mut libc::c_int as *mut libc::c_void,
                        &mut so_len,
                    )
                };
                if opt_rc != 0 || so_err != 0 {
                    close_fd(fd);
                    return None;
                }
                break;
            }
            _ => {
                close_fd(fd);
                return None;
            }
        }
    }

    // Clear O_NONBLOCK so subsequent read/write calls honor SO_RCVTIMEO / SO_SNDTIMEO.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) } < 0 {
        unsafe {
            libc::close(fd);
        }
        return None;
    }

    Some(unsafe { UnixStream::from_raw_fd(fd) })
}

#[cfg(not(target_os = "linux"))]
pub fn is_screen_locker_active(_target_uid: u32) -> bool {
    false
}

/// Pure parser for Hyprland `j/monitors` JSON output to detect an active `ext-session-lock`.
pub(crate) fn monitors_json_has_session_lock(json: &str) -> bool {
    let Ok(serde_json::Value::Array(monitors)) = serde_json::from_str::<serde_json::Value>(json)
    else {
        return false;
    };
    monitors.iter().any(|monitor| {
        monitor
            .get("solitaryBlockedBy")
            .and_then(|v| v.as_array())
            .is_some_and(|blockers| blockers.iter().any(|item| item.as_str() == Some("LOCK")))
    })
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
mod swap_tests {
    use super::*;

    const HDR: &str = "Filename\tType\tSize\tUsed\tPriority\n";

    fn crypt(name: &str) -> Option<bool> {
        match name {
            "dm-0" => Some(true),
            "sda2" => Some(false),
            _ => None,
        }
    }
    fn file_block(path: &str) -> Option<String> {
        match path {
            "/swapfile" => Some("dm-0".into()),
            "/plain/swapfile" => Some("sda2".into()),
            _ => None,
        }
    }

    #[test]
    fn classifies_swap_setups() {
        let c = |body: &str| {
            classify_swaps(&format!("{HDR}{body}"), &crypt, &file_block, &|_: &str| {
                None
            })
        };
        assert_eq!(c(""), SwapExposure::None);
        assert_eq!(
            c("/dev/zram0 partition 100 0 100\n"),
            SwapExposure::ZramOnly
        );
        assert_eq!(
            c("/dev/zram0 partition 1 0 100\n/swapfile file 1 0 -2\n"),
            SwapExposure::Encrypted
        );
        assert!(c("/plain/swapfile file 1 0 -2\n").is_unencrypted());
        assert!(matches!(
            c("/btrfs/swapfile file 1 0 -2\n"),
            SwapExposure::Unknown(_)
        ));
        // Unencrypted wins over everything else.
        assert!(c("/swapfile file 1 0 -2\n/plain/swapfile file 1 0 -3\n").is_unencrypted());
    }

    #[test]
    fn classifies_zram_writeback_from_backing_dev() {
        let line = "/dev/zram0 partition 100 0 100\n";
        let classify = |backing: fn(&str) -> Option<String>| {
            classify_swaps(&format!("{HDR}{line}"), &crypt, &file_block, &backing)
        };
        assert_eq!(classify(|_: &str| None), SwapExposure::ZramOnly);
        assert_eq!(classify(|_| Some("none".into())), SwapExposure::ZramOnly);
        assert_eq!(
            classify(|_| Some("  none\n".into())),
            SwapExposure::ZramOnly
        );
        let plain = classify(|_| Some("sda2".into()));
        assert!(plain.is_unencrypted(), "{plain:?}");
        assert_eq!(classify(|_| Some("dm-0".into())), SwapExposure::Encrypted);
        assert_eq!(
            classify(|_| Some("/dev/dm-0".into())),
            SwapExposure::Encrypted
        );
        assert!(matches!(
            classify(|_| Some("nvme0n1p3".into())),
            SwapExposure::Unknown(_)
        ));
        // A named backing device that is not a single block name is not RAM.
        assert!(matches!(
            classify(|_| Some("/".into())),
            SwapExposure::Unknown(_)
        ));
    }
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
        let active_hyprlock =
            "Name:\thyprlock\nState:\tS (sleeping)\nUid:\t1000\t1000\t1000\t1000\n";
        assert!(status_matches_active_locker(active_hyprlock, 1000));
        assert!(!status_matches_active_locker(active_hyprlock, 1001));

        let zombie_hyprlock = "Name:\thyprlock\nState:\tZ (zombie)\nUid:\t1000\t1000\t1000\t1000\n";
        assert!(!status_matches_active_locker(zombie_hyprlock, 1000));

        let truncated_swaylock =
            "Name:\tswaylock-effect\nState:\tS (sleeping)\nUid:\t1000\t1000\t1000\t1000\n";
        assert!(status_matches_active_locker(truncated_swaylock, 1000));
    }

    #[test]
    fn hyprland_monitors_json_detects_session_lock() {
        let locked = r#"[{"id":0,"name":"eDP-1","solitaryBlockedBy":["LOCK","BAR"]}]"#;
        assert!(monitors_json_has_session_lock(locked));

        let multi_monitor_one_locked =
            r#"[{"id":0,"solitaryBlockedBy":["WORKSPACE"]},{"id":1,"solitaryBlockedBy":["LOCK"]}]"#;
        assert!(monitors_json_has_session_lock(multi_monitor_one_locked));

        let unlocked = r#"[{"id":0,"name":"eDP-1","solitaryBlockedBy":["ALPHA","BAR"]}]"#;
        assert!(!monitors_json_has_session_lock(unlocked));

        assert!(!monitors_json_has_session_lock("[]"));
        assert!(!monitors_json_has_session_lock("not-json"));
    }
}
