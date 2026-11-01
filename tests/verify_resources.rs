//! Guard the verifier's allocation contract, including authenticated deep trees.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use nullguard::crypto::Argon2Params;
use nullguard::vault::{CreateOptions, Credential, Vault, fs::ROOT_INO};

struct Measured;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

// SAFETY: this forwards the allocator contract unchanged to System. Counters
// neither allocate nor change allocation sizes, alignment, or ownership.
unsafe impl GlobalAlloc for Measured {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(live, Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(pointer, layout) };
    }
}

#[global_allocator]
static ALLOCATOR: Measured = Measured;

#[test]
fn deep_and_wide_verification_stays_within_a_small_heap_budget() {
    // One test in this binary isolates the global allocator measurement from
    // unrelated tests. KDF and fixture construction precede the measurement.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("deep.ngv");
    let password = b"resource regression password";
    Vault::create(&path, password, &CreateOptions {
        size: 4 << 20, kdf: Argon2Params::LOW_MEMORY,
        chunk_size: Some(4096), fill_random: false,
    }, &mut |_, _| {}).unwrap();
    let mut fs = Vault::open(&path, Credential::Password(password), false).unwrap().into_fs().unwrap();
    fs.set_auto_commit(false);
    let mut parent = ROOT_INO;
    for _ in 0..700 {
        fs.create_file(parent, b"a", 0o600).unwrap();
        parent = fs.mkdir(parent, &[b'z'; 255], 0o700).unwrap();
    }
    for index in 0..2000 {
        fs.create_file(ROOT_INO, format!("wide-{index}").as_bytes(), 0o600).unwrap();
    }
    fs.commit().unwrap();
    drop(fs);
    let mut fs = Vault::open(&path, Credential::Password(password), true).unwrap().into_fs().unwrap();
    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);
    let report = fs.verify().unwrap();
    let extra = PEAK.load(Ordering::Relaxed).saturating_sub(baseline);
    assert_eq!((report.files, report.dirs, report.bad_blocks_total), (2700, 701, 0));
    assert!(extra < 8 * 1024 * 1024, "verification allocated {extra} extra bytes");
}
