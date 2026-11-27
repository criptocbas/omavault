//! Phase 4: freed heap blocks must never still contain secrets.
//!
//! This test binary installs a probing global allocator:
//!
//! ```text
//! Probe.dealloc ──scan (PRE)──► ZeroizingAlloc<PostScan>.dealloc ──wipe──► PostScan ──scan (POST)──► System
//! ```
//!
//! `PRE` proves the scenario really frees blocks containing the secret (e.g. serde_json's escape
//! scratch buffer — the leak found by two red-team agents); `POST == 0` proves `ZeroizingAlloc`
//! wiped every one of them before it reached the system allocator.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use omavault::alloc::ZeroizingAlloc;

/// Marker that only appears inside secrets used by this test.
const CANARY: &[u8] = b"Zq7-OMAV-HEAP-CANARY-9xK";

static PRE: AtomicUsize = AtomicUsize::new(0);
static POST: AtomicUsize = AtomicUsize::new(0);
static ARMED: AtomicBool = AtomicBool::new(false);

/// Allocation-free substring search (we are inside the allocator).
unsafe fn block_contains_canary(ptr: *const u8, len: usize) -> bool {
    if len < CANARY.len() {
        return false;
    }
    let hay = core::slice::from_raw_parts(ptr, len);
    let first = CANARY[0];
    let mut i = 0;
    while i + CANARY.len() <= len {
        if hay[i] == first && &hay[i..i + CANARY.len()] == CANARY {
            return true;
        }
        i += 1;
    }
    false
}

struct PostScan;

unsafe impl GlobalAlloc for PostScan {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::Relaxed) && block_contains_canary(ptr, layout.size()) {
            POST.fetch_add(1, Ordering::Relaxed);
        }
        System.dealloc(ptr, layout)
    }
}

static ZEROIZING: ZeroizingAlloc<PostScan> = ZeroizingAlloc(PostScan);

struct Probe;

unsafe impl GlobalAlloc for Probe {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ZEROIZING.alloc(layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ZEROIZING.alloc_zeroed(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::Relaxed) && block_contains_canary(ptr, layout.size()) {
            PRE.fetch_add(1, Ordering::Relaxed);
        }
        ZEROIZING.dealloc(ptr, layout)
    }
    // Default realloc => alloc + copy + self.dealloc(old): old blocks are probed and wiped too.
}

#[global_allocator]
static GLOBAL: Probe = Probe;

fn measure(f: impl FnOnce()) -> (usize, usize) {
    PRE.store(0, Ordering::SeqCst);
    POST.store(0, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
    f();
    ARMED.store(false, Ordering::SeqCst);
    (PRE.load(Ordering::SeqCst), POST.load(Ordering::SeqCst))
}

fn canary_str() -> String {
    String::from_utf8(CANARY.to_vec()).unwrap()
}

// Single #[test] so concurrently running tests cannot pollute the counters.
#[test]
fn freed_heap_never_contains_secrets() {
    // 0. Sanity: the scanner detects a canary in a block freed WITHOUT wiping.
    unsafe {
        let layout = Layout::from_size_align(64, 1).unwrap();
        let p = System.alloc(layout);
        core::ptr::copy_nonoverlapping(CANARY.as_ptr(), p.add(8), CANARY.len());
        ARMED.store(true, Ordering::SeqCst);
        let before = POST.load(Ordering::SeqCst);
        PostScan.dealloc(p, layout);
        ARMED.store(false, Ordering::SeqCst);
        assert_eq!(
            POST.load(Ordering::SeqCst),
            before + 1,
            "scanner must detect canary"
        );
    }

    // 1. Decrypted vault JSON whose note contains an escape (`\n`): serde_json copies the decoded
    //    string through an internal scratch buffer that it frees unwiped (red-team finding).
    let c = canary_str();
    let json = format!(
        r#"{{"schema_version":1,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","entries":[{{"id":"5f0c3d1e-8f1a-4b8e-9a51-2f1f1c2d3e4f","name":"site","username":"u","password":"p","notes":"recovery codes\n{c}\nmore","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}}]}}"#
    );
    let json = zeroize::Zeroizing::new(json.into_bytes());
    let (pre, post) = measure(|| {
        let v: omavault::vault::Vault = serde_json::from_slice(&json).expect("parse vault");
        assert!(v.entries[0].notes.contains(&c));
        drop(v);
    });
    assert!(
        pre > 0,
        "scenario must free a block containing the secret (pre={pre})"
    );
    assert_eq!(
        post, 0,
        "a freed block still contained the secret after ZeroizingAlloc"
    );

    // 2. Daemon unlock request whose master passphrase contains a quote/backslash escape.
    let req = zeroize::Zeroizing::new(
        format!(
            r#"{{"cmd":"unlock","vault_path":"/x","passphrase":"pa\"ss\\{c}","keyfile_path":null,"fido2_device":null}}"#
        )
        .into_bytes(),
    );
    let (pre, post) = measure(|| {
        let r: omavault::daemon::DaemonRequest = serde_json::from_slice(&req).expect("parse req");
        drop(r);
    });
    assert!(
        pre > 0,
        "unlock request parse must exercise the escape path (pre={pre})"
    );
    assert_eq!(post, 0, "master passphrase residue survived in freed heap");

    // 3. Display sanitizing of a revealed note creates transient Strings every frame.
    let note = zeroize::Zeroizing::new(format!("line1\n{c}\tline2"));
    let (pre, post) = measure(|| {
        for _ in 0..4 {
            let shown = omavault::hardening::sanitize_multiline(&note);
            assert!(shown.contains(&c));
            let line = omavault::hardening::sanitize_single_line(&note);
            drop((shown, line));
        }
    });
    assert!(
        pre > 0,
        "sanitizer copies must be freed during the scenario (pre={pre})"
    );
    assert_eq!(
        post, 0,
        "sanitizer copies of the secret survived in freed heap"
    );

    // 4. Growth reallocations: pushing a secret into a growing Vec frees each smaller buffer.
    let (pre, post) = measure(|| {
        let mut v: Vec<u8> = Vec::new();
        for _ in 0..64 {
            v.extend_from_slice(CANARY);
        }
        drop(v);
    });
    assert!(pre > 0);
    assert_eq!(post, 0, "realloc left the old buffer unwiped");
}
