//! Zeroizing global allocator.
//!
//! Every heap block is wiped before it is returned to the system allocator — on `dealloc` and
//! (via the default `GlobalAlloc::realloc`, which allocates, copies, then calls `dealloc`) on
//! every reallocation. This closes a whole class of "unzeroized heap copy" leaks that explicit
//! `Zeroizing<T>` wrappers cannot reach because the copies are made inside dependencies or std:
//!
//! - `serde_json`'s scratch buffer when decoding strings with escapes (`\n`, `\"`, `\\`) — every
//!   multi-line note, and master passphrases containing quotes/backslashes on daemon unlock;
//! - transient `String`s from display sanitizing, `format!`, and `std` stdout buffering;
//! - `Vec`/`String` growth reallocations (FIDO2 tool output, Base32 TOTP normalization, prompts).
//!
//! Wiping uses `explicit_bzero(3)` on Linux (as fast as `memset`, but guaranteed not to be removed
//! as a dead store before `free`, which an optimizer is otherwise allowed to do), and volatile
//! writes elsewhere.
//!
//! Registered as `#[global_allocator]` in the `omavault` binary (`src/main.rs`). It does not make
//! freed memory unreadable by root or protect live data; it ensures secrets do not linger in
//! *freed* heap chunks after their owners are dropped.

use std::alloc::{GlobalAlloc, Layout, System};

/// Global allocator wrapper that wipes every block before freeing it. Generic over the inner
/// allocator so tests can wrap an instrumented allocator; production uses [`System`].
pub struct ZeroizingAlloc<A: GlobalAlloc = System>(pub A);

impl ZeroizingAlloc<System> {
    pub const fn system() -> Self {
        Self(System)
    }
}

#[cfg(target_os = "linux")]
extern "C" {
    // glibc >= 2.25 and musl >= 1.1.20.
    fn explicit_bzero(s: *mut core::ffi::c_void, n: usize);
}

/// Wipe `len` bytes at `ptr` in a way the optimizer cannot elide.
///
/// # Safety
/// `ptr` must be valid for writes of `len` bytes.
#[inline]
pub unsafe fn wipe(ptr: *mut u8, len: usize) {
    if len == 0 {
        return;
    }
    #[cfg(target_os = "linux")]
    {
        explicit_bzero(ptr.cast(), len);
    }
    #[cfg(not(target_os = "linux"))]
    {
        for i in 0..len {
            core::ptr::write_volatile(ptr.add(i), 0);
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

unsafe impl<A: GlobalAlloc> GlobalAlloc for ZeroizingAlloc<A> {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.0.alloc(layout)
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        self.0.alloc_zeroed(layout)
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        wipe(ptr, layout.size());
        self.0.dealloc(ptr, layout);
    }

    // `realloc` is intentionally NOT overridden: the default implementation allocates a new
    // block, copies, and calls `self.dealloc` on the old one — so the old block is wiped. An
    // in-place `System` realloc could instead release the tail of a shrunk block unwiped.
}
