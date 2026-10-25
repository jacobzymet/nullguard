//! End-to-end tests of vault files: create, unlock, tamper, crash.

use super::*;
use crate::crypto::Keyfile;
use crate::vault::fs::{ROOT_INO, SetAttr};
use std::path::PathBuf;

const PW: &[u8] = b"correct horse battery staple";
const PW2: &[u8] = b"a brand new long password";
/// The weakest parameters `create` accepts, to keep tests fast.
const KDF: Argon2Params = Argon2Params { memory_kib: Argon2Params::MIN_CREATE_MEMORY_KIB, iterations: 2, parallelism: 1 };
/// Where the primary copy's wrapped password key starts.
const PASSWORD_SLOT: u64 = 82;

struct Tmp {
    _dir: tempfile::TempDir,
    path: PathBuf,
}

fn opts(size: u64) -> CreateOptions {
    CreateOptions { size, kdf: KDF, chunk_size: Some(4096), fill_random: false }
}

fn new_vault_with(o: CreateOptions) -> Tmp {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.ngv");
    Vault::create(&path, PW, &o, &mut |_, _| {}).unwrap();
    Tmp { _dir: dir, path }
}

fn new_vault() -> Tmp {
    new_vault_with(opts(4 << 20))
}

fn open_fs(t: &Tmp) -> Fs {
    Vault::open(&t.path, Credential::Password(PW), false).unwrap().into_fs().unwrap()
}

fn patch(path: &Path, offset: u64, f: impl FnOnce(&mut [u8])) {
    let file = OpenOptions::new().read(true).write(true).open(path).unwrap();
    let mut b = [0u8; 1];
    read_exact_at(&file, &mut b, offset).unwrap();
    f(&mut b);
    write_all_at(&file, &b, offset).unwrap();
}

fn chunk_offset(t: &Tmp, chunk: u64) -> u64 {
    let h = Vault::peek_header(&t.path).unwrap();
    DATA_OFFSET + chunk * chunk_stride(h.chunk_size)
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
}

fn read_at(path: &Path, offset: u64, len: u64) -> Vec<u8> {
    std::fs::read(path).unwrap()[offset as usize..(offset + len) as usize].to_vec()
}

fn write_at(path: &Path, offset: u64, bytes: &[u8]) {
    let file = OpenOptions::new().write(true).open(path).unwrap();
    write_all_at(&file, bytes, offset).unwrap();
}

/// Both header copies (primary, backup).
fn header_area(path: &Path) -> Vec<u8> {
    read_at(path, 0, 2 * HEADER_AREA)
}

fn copies_match(path: &Path) -> bool {
    let h = header_area(path);
    h[..HEADER_AREA as usize] == h[HEADER_AREA as usize..]
}

#[test]
fn create_write_reopen_read() {
    let t = new_vault();
    let data = pattern(10_000, 1);
    {
        let mut fs = open_fs(&t);
        let d = fs.mkdir(ROOT_INO, b"docs", 0o755).unwrap();
        let f = fs.create_file(d, b"hello.txt", 0o644).unwrap();
        fs.write(f, 0, &data).unwrap();
        fs.symlink(ROOT_INO, b"link", b"docs/hello.txt").unwrap();
        fs.commit().unwrap();
    }
    let mut fs = open_fs(&t);
    assert!(fs.warnings.is_empty(), "{:?}", fs.warnings);
    let f = fs.resolve("/docs/hello.txt").unwrap();
    assert_eq!(fs.attr(f).unwrap().size, 10_000);
    assert_eq!(&fs.read(f, 0, 20_000).unwrap()[..], &data[..]);
    assert_eq!(&fs.read(f, 4090, 10).unwrap()[..], &data[4090..4100]);
    let l = fs.resolve("/link").unwrap();
    assert_eq!(*fs.readlink(l).unwrap(), b"docs/hello.txt");
    let names: Vec<_> = fs.readdir(ROOT_INO).unwrap().into_iter().map(|e| e.name.to_vec()).collect();
    assert_eq!(names, vec![b".".to_vec(), b"..".to_vec(), b"docs".to_vec(), b"link".to_vec()]);
}

#[test]
fn random_fill_vault() {
    let mut o = opts(2 << 20);
    o.fill_random = true;
    let t = new_vault_with(o);
    {
        let mut fs = open_fs(&t);
        let f = fs.create_file(ROOT_INO, b"a", 0o600).unwrap();
        fs.write(f, 0, b"data").unwrap();
        fs.commit().unwrap();
    }
    let mut fs = open_fs(&t);
    let f = fs.resolve("a").unwrap();
    assert_eq!(&fs.read(f, 0, 100).unwrap()[..], b"data");
    drop(fs);
    // Unused space is random, not zeros.
    let tail = read_at(&t.path, std::fs::metadata(&t.path).unwrap().len() - 4096, 4096);
    assert!(tail.iter().filter(|&&b| b == 0).count() < 100);
}

#[test]
fn plaintext_never_hits_the_disk() {
    let t = new_vault();
    let secret = b"TOP-SECRET-MARKER-0123456789-the-quick-brown-fox";
    {
        let mut fs = open_fs(&t);
        let f = fs.create_file(ROOT_INO, b"TOP-SECRET-FILENAME", 0o600).unwrap();
        for i in 0..20 {
            fs.write(f, i * 5000, secret).unwrap();
        }
    }
    let raw = std::fs::read(&t.path).unwrap();
    for needle in [&secret[..], b"TOP-SECRET-FILENAME", b"TOP-SECRET"] {
        assert!(!raw.windows(needle.len()).any(|w| w == needle), "plaintext found in vault file");
    }
}

#[test]
fn wrong_password_and_wrong_keyfile() {
    let t = new_vault();
    assert!(matches!(Vault::open(&t.path, Credential::Password(b"nope"), false), Err(Error::WrongCredentials)));
    let k = Keyfile::generate().unwrap();
    assert!(matches!(Vault::open(&t.path, Credential::Keyfile(&k), false), Err(Error::WrongCredentials)));
}

#[test]
fn vault_is_locked_while_open() {
    let t = new_vault();
    let _v = Vault::open(&t.path, Credential::Password(PW), false).unwrap();
    assert!(matches!(Vault::open(&t.path, Credential::Password(PW), false), Err(Error::InUse)));
}

#[test]
fn create_never_overwrites() {
    let t = new_vault();
    let before = std::fs::read(&t.path).unwrap();
    assert!(Vault::create(&t.path, PW, &opts(4 << 20), &mut |_, _| {}).is_err());
    assert_eq!(std::fs::read(&t.path).unwrap(), before);
}

#[test]
fn weak_kdf_refused_at_create() {
    let dir = tempfile::tempdir().unwrap();
    let mut o = opts(4 << 20);
    o.kdf = Argon2Params { memory_kib: 1024, iterations: 1, parallelism: 1 };
    assert!(Vault::create(&dir.path().join("v"), PW, &o, &mut |_, _| {}).is_err());
    assert!(!dir.path().join("v").exists(), "failed create must not leave a file");
}

/// Anyone can append a keyfile slot to a header without the master key.
/// The password still unlocks that header, but its hash isn't the one the
/// filesystem recorded, so it's refused. The attacker's keyfile "unlocks"
/// a key that opens nothing.
#[test]
fn injected_keyfile_slot_is_refused() {
    let t = new_vault();
    let mallory = Keyfile::generate().unwrap();
    let mut h = Vault::peek_header(&t.path).unwrap();
    h.add_keyfile(&SecretKey::generate().unwrap(), &mallory).unwrap();
    write_at(&t.path, PRIMARY_OFFSET, &h.to_bytes());
    write_at(&t.path, BACKUP_OFFSET, &h.to_bytes());
    assert!(matches!(Vault::open(&t.path, Credential::Password(PW), false), Err(Error::StaleHeader)));
    assert!(matches!(Vault::open(&t.path, Credential::Keyfile(&mallory), false), Err(Error::Corrupt(_))));
}

/// A damaged primary copy: the backup is used, the user is warned, and a
/// writable open restores the primary.
#[test]
fn damaged_primary_is_reported_and_restored_from_backup() {
    for offset in [PASSWORD_SLOT + 60, 0 /* magic */, HEADER_AREA - 1 /* padding */] {
        let t = new_vault();
        patch(&t.path, PRIMARY_OFFSET + offset, |b| b[0] ^= 0x10);
        let v = Vault::open(&t.path, Credential::Password(PW), true).unwrap();
        assert!(v.warnings.iter().any(|w| w.contains("primary") && w.contains("does not match")), "{:?}", v.warnings);
        assert_eq!(v.check_headers().unwrap().len(), 1);
        drop(v);
        assert!(!copies_match(&t.path), "a read-only open must not write");

        let v = Vault::open(&t.path, Credential::Password(PW), false).unwrap();
        assert!(v.warnings.iter().any(|w| w.contains("restored")), "{:?}", v.warnings);
        drop(v);
        assert!(copies_match(&t.path));
        let v = Vault::open(&t.path, Credential::Password(PW), true).unwrap();
        assert!(v.warnings.is_empty(), "{:?}", v.warnings);
        assert!(v.check_headers().unwrap().is_empty());
        assert!(v.into_fs().is_ok());
    }
}

#[test]
fn damaged_backup_is_restored_from_primary() {
    let t = new_vault();
    patch(&t.path, BACKUP_OFFSET + PASSWORD_SLOT + 60, |b| b[0] ^= 0x10);
    let v = Vault::open(&t.path, Credential::Password(PW), false).unwrap();
    assert!(v.warnings.iter().any(|w| w.contains("backup")), "{:?}", v.warnings);
    drop(v);
    assert!(copies_match(&t.path));
}

#[test]
fn both_headers_destroyed_is_an_error() {
    let t = new_vault();
    patch(&t.path, PRIMARY_OFFSET, |b| b[0] = 0);
    patch(&t.path, BACKUP_OFFSET, |b| b[0] = 0);
    assert!(Vault::open(&t.path, Credential::Password(PW), false).is_err());
}

/// Vaults made by older nullguard versions are refused with instructions.
#[test]
fn older_vaults_are_refused_with_instructions() {
    for version in [1u8, 2] {
        let t = new_vault();
        for base in [PRIMARY_OFFSET, BACKUP_OFFSET] {
            patch(&t.path, base + 8, |b| b[0] = version);
        }
        let err = Vault::open(&t.path, Credential::Password(PW), true).err().unwrap();
        assert!(matches!(err, Error::Header(HeaderError::UnsupportedVersion(v)) if v == version as u16), "{err}");
        assert!(err.to_string().contains("different version of nullguard"));
    }
}

#[test]
fn modified_data_chunk_is_detected() {
    let t = new_vault();
    let chunk;
    {
        let mut fs = open_fs(&t);
        let f = fs.create_file(ROOT_INO, b"f", 0o600).unwrap();
        fs.write(f, 0, &pattern(4096, 3)).unwrap();
        fs.commit().unwrap();
        chunk = fs.chunks_of(f)[0];
    }
    patch(&t.path, chunk_offset(&t, chunk) + 24 + 100, |b| b[0] ^= 1);
    let mut fs = open_fs(&t);
    let f = fs.resolve("f").unwrap();
    assert!(matches!(fs.read(f, 0, 4096), Err(Error::ChunkAuth { .. })));
    let report = fs.verify().unwrap();
    assert_eq!(report.bad_blocks.len(), 1);
}

#[test]
fn moved_chunk_is_detected() {
    // Copy the ciphertext of block 0 over block 1 of the same file.
    let t = new_vault();
    let chunks;
    {
        let mut fs = open_fs(&t);
        let f = fs.create_file(ROOT_INO, b"f", 0o600).unwrap();
        fs.write(f, 0, &pattern(8192, 4)).unwrap();
        fs.commit().unwrap();
        chunks = fs.chunks_of(f);
    }
    let h = Vault::peek_header(&t.path).unwrap();
    let stride = chunk_stride(h.chunk_size) as usize;
    let file = OpenOptions::new().read(true).write(true).open(&t.path).unwrap();
    let mut buf = vec![0u8; stride];
    read_exact_at(&file, &mut buf, chunk_offset(&t, chunks[0])).unwrap();
    write_all_at(&file, &buf, chunk_offset(&t, chunks[1])).unwrap();
    drop(file);
    let mut fs = open_fs(&t);
    let f = fs.resolve("f").unwrap();
    assert!(fs.read(f, 0, 4096).is_ok());
    assert!(fs.read(f, 4096, 4096).is_err());
}

#[test]
fn replayed_old_chunk_is_detected() {
    // An attacker restores an older ciphertext of a chunk that has since
    // been reused for different data. The chunk authenticates under the
    // vault key, but its nonce isn't the one the metadata expects.
    let t = new_vault();
    let h = Vault::peek_header(&t.path).unwrap();
    let stride = chunk_stride(h.chunk_size) as usize;
    let first = {
        let mut fs = open_fs(&t);
        let f = fs.create_file(ROOT_INO, b"f", 0o600).unwrap();
        fs.write(f, 0, &pattern(4096, 1)).unwrap();
        fs.commit().unwrap();
        fs.chunks_of(f)[0]
    };
    let old_file = std::fs::read(&t.path).unwrap();
    // Rewrite and commit until the same chunk index is reused.
    let mut i = 2u8;
    loop {
        let mut fs = open_fs(&t);
        let f = fs.resolve("f").unwrap();
        fs.write(f, 0, &pattern(4096, i)).unwrap();
        fs.commit().unwrap();
        if fs.chunks_of(f)[0] == first {
            break;
        }
        i = i.wrapping_add(1);
        assert!(i != 1, "chunk never reused");
    }
    let off = chunk_offset(&t, first) as usize;
    let file = OpenOptions::new().write(true).open(&t.path).unwrap();
    write_all_at(&file, &old_file[off..off + stride], off as u64).unwrap();
    drop(file);
    let mut fs = open_fs(&t);
    let f = fs.resolve("f").unwrap();
    assert!(matches!(fs.read(f, 0, 4096), Err(Error::Rollback { .. })));
}

#[test]
fn crash_before_commit_keeps_last_committed_state() {
    let t = new_vault();
    {
        let mut fs = open_fs(&t);
        let f = fs.create_file(ROOT_INO, b"f", 0o600).unwrap();
        fs.write(f, 0, &pattern(10_000, 1)).unwrap();
        fs.commit().unwrap();
        // Overwrite everything and add a file, then "lose power".
        fs.write(f, 0, &pattern(20_000, 2)).unwrap();
        fs.create_file(ROOT_INO, b"new", 0o600).unwrap();
        fs.abandon();
    }
    let mut fs = open_fs(&t);
    let f = fs.resolve("f").unwrap();
    assert_eq!(&fs.read(f, 0, 100_000).unwrap()[..], &pattern(10_000, 1)[..]);
    assert!(fs.resolve("new").is_err());
    assert_eq!(fs.verify().unwrap().bad_blocks.len(), 0);
}

// ----------------------------------------------------------------------
// Header changes: rollback and crash safety
// ----------------------------------------------------------------------

/// Putting back an old (authentic) header to revive a removed keyfile is
/// refused: the filesystem was last committed under a different header.
#[test]
fn restoring_an_old_header_to_revive_a_removed_keyfile_is_refused() {
    let bob = Keyfile::generate().unwrap();
    let t = new_vault();
    Vault::open(&t.path, Credential::Password(PW), false).unwrap().add_keyfile(&bob).unwrap();
    let with_bob = header_area(&t.path);
    Vault::open(&t.path, Credential::Password(PW), false).unwrap().remove_keyfile(&bob).unwrap();
    assert!(matches!(Vault::open(&t.path, Credential::Keyfile(&bob), true), Err(Error::WrongCredentials)));

    write_at(&t.path, 0, &with_bob);
    // The old header is authentic, so Bob's slot unlocks it, but it isn't
    // the current header.
    assert!(matches!(Vault::open(&t.path, Credential::Keyfile(&bob), true), Err(Error::StaleHeader)));
    assert!(matches!(Vault::open(&t.path, Credential::Password(PW), true), Err(Error::StaleHeader)));
}

#[test]
fn restoring_an_old_header_to_revive_an_old_password_is_refused() {
    let t = new_vault();
    let old = header_area(&t.path);
    Vault::open(&t.path, Credential::Password(PW), false).unwrap().change_password(PW2, KDF).unwrap();
    write_at(&t.path, 0, &old);
    assert!(matches!(Vault::open(&t.path, Credential::Password(PW), true), Err(Error::StaleHeader)));
}

/// Regression test: nullguard 0.1 recorded a header change in only one
/// superblock, so destroying that superblock made the vault fall back to
/// the older one, which accepted the old header (and with it a removed
/// keyfile). A header change now commits to both slots.
#[test]
fn old_header_stays_refused_even_if_a_superblock_is_destroyed() {
    let bob = Keyfile::generate().unwrap();
    let t = new_vault();
    Vault::open(&t.path, Credential::Password(PW), false).unwrap().add_keyfile(&bob).unwrap();
    let with_bob = header_area(&t.path);
    Vault::open(&t.path, Credential::Password(PW), false).unwrap().remove_keyfile(&bob).unwrap();
    let after_removal = std::fs::read(&t.path).unwrap();
    for slot in 0..2 {
        std::fs::write(&t.path, &after_removal).unwrap();
        write_at(&t.path, 0, &with_bob);
        patch(&t.path, chunk_offset(&t, slot) + 30, |b| b[0] ^= 1);
        assert!(
            matches!(Vault::open(&t.path, Credential::Keyfile(&bob), true), Err(Error::StaleHeader)),
            "superblock {slot} destroyed: the removed keyfile must stay removed"
        );
    }
}

/// A crash right after a header change wrote the backup copy, before its
/// commit: the change didn't happen. The old header is used (and the
/// backup restored), and the new credentials don't work.
#[test]
fn header_change_interrupted_before_its_commit_did_not_happen() {
    let alice = Keyfile::generate().unwrap();
    let t = new_vault();
    let before = std::fs::read(&t.path).unwrap();
    Vault::open(&t.path, Credential::Password(PW), false).unwrap().add_keyfile(&alice).unwrap();
    let new_header = read_at(&t.path, BACKUP_OFFSET, HEADER_AREA);
    std::fs::write(&t.path, &before).unwrap();
    write_at(&t.path, BACKUP_OFFSET, &new_header);

    assert!(matches!(Vault::open(&t.path, Credential::Keyfile(&alice), true), Err(Error::StaleHeader)));
    let v = Vault::open(&t.path, Credential::Password(PW), false).unwrap();
    assert!(v.header().keyfiles.is_empty());
    assert!(v.warnings.iter().any(|w| w.contains("backup")), "{:?}", v.warnings);
    assert!(v.into_fs().is_ok());
    assert!(copies_match(&t.path), "the stale backup was restored");
    assert!(matches!(Vault::open(&t.path, Credential::Keyfile(&alice), true), Err(Error::WrongCredentials)));
}

/// A crash after a header change's commit, before the primary copy was
/// rewritten: the change happened. The new header (backup) is used, the
/// old password no longer works, and the primary is restored.
#[test]
fn header_change_interrupted_after_its_commit_took_effect() {
    let t = new_vault();
    let old_primary = read_at(&t.path, PRIMARY_OFFSET, HEADER_AREA);
    Vault::open(&t.path, Credential::Password(PW), false).unwrap().change_password(PW2, KDF).unwrap();
    write_at(&t.path, PRIMARY_OFFSET, &old_primary);

    assert!(matches!(Vault::open(&t.path, Credential::Password(PW), true), Err(Error::StaleHeader)));
    let v = Vault::open(&t.path, Credential::Password(PW2), false).unwrap();
    assert!(v.warnings.iter().any(|w| w.contains("primary")), "{:?}", v.warnings);
    assert!(v.into_fs().is_ok());
    assert!(copies_match(&t.path), "the stale primary was restored");
    assert!(matches!(Vault::open(&t.path, Credential::Password(PW), true), Err(Error::WrongCredentials)));
}

/// Dropping a filesystem never commits: a command that fails halfway
/// leaves the vault exactly as it was.
#[test]
fn uncommitted_changes_are_discarded() {
    let t = new_vault();
    {
        let mut fs = open_fs(&t);
        fs.create_file(ROOT_INO, b"kept", 0o600).unwrap();
        fs.commit().unwrap();
        fs.unlink(ROOT_INO, b"kept").unwrap();
        fs.create_file(ROOT_INO, b"discarded", 0o600).unwrap();
    }
    let fs = open_fs(&t);
    assert!(fs.resolve("kept").is_ok());
    assert!(fs.resolve("discarded").is_err());
}

#[test]
fn panic_mid_operation_never_commits() {
    let t = new_vault();
    {
        let mut fs = open_fs(&t);
        let f = fs.create_file(ROOT_INO, b"committed", 0o600).unwrap();
        fs.write(f, 0, b"safe").unwrap();
        fs.commit().unwrap();
    }
    let path = t.path.clone();
    let result = std::panic::catch_unwind(move || {
        let mut fs = Vault::open(&path, Credential::Password(PW), false).unwrap().into_fs().unwrap();
        fs.create_file(ROOT_INO, b"half-done", 0o600).unwrap();
        panic!("simulated bug in the middle of an operation");
    });
    assert!(result.is_err());
    let fs = open_fs(&t);
    assert!(fs.resolve("committed").is_ok());
    assert!(fs.resolve("half-done").is_err(), "state from a panicking operation was committed");
}

#[test]
fn poisoned_fs_refuses_writes_and_never_commits() {
    let t = new_vault();
    {
        let mut fs = open_fs(&t);
        fs.create_file(ROOT_INO, b"before", 0o600).unwrap();
        fs.poison();
        assert!(fs.create_file(ROOT_INO, b"after", 0o600).is_err());
        assert!(fs.commit().is_err() || !fs.is_dirty());
    }
    let fs = open_fs(&t);
    assert!(fs.resolve("before").is_err());
}

#[cfg(unix)]
#[test]
fn vault_file_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let t = new_vault();
    let mode = std::fs::metadata(&t.path).unwrap().permissions().mode();
    assert_eq!(mode & 0o077, 0, "vault must not be readable by other users: {mode:o}");
}

/// Windows has no mode bits: the vault gets an explicit permission set for
/// the owner (and SYSTEM) only, replacing what the folder would pass on.
#[cfg(windows)]
#[test]
fn vault_file_is_private() {
    let t = new_vault();
    let f = File::open(&t.path).unwrap();
    // Protected ("P"; Windows may add "AI", auto-inherited bookkeeping),
    // with exactly the two entries nullguard sets.
    let sddl = crate::platform::win::permissions_sddl(&f).unwrap().replacen("D:PAI(", "D:P(", 1);
    assert_eq!(sddl, crate::platform::win::private_permissions_sddl().unwrap());
}

#[test]
fn torn_superblock_falls_back_with_warning() {
    let t = new_vault();
    {
        let mut fs = open_fs(&t);
        let f = fs.create_file(ROOT_INO, b"one", 0o600).unwrap();
        fs.write(f, 0, b"1").unwrap();
        fs.commit().unwrap(); // generation 3 -> slot 1
        let g = fs.create_file(ROOT_INO, b"two", 0o600).unwrap();
        fs.write(g, 0, b"2").unwrap();
        fs.commit().unwrap(); // generation 4 -> slot 0
    }
    // Destroy the newest superblock (slot 0).
    patch(&t.path, chunk_offset(&t, 0) + 30, |b| b[0] ^= 1);
    let fs = open_fs(&t);
    assert!(fs.resolve("one").is_ok());
    assert!(fs.resolve("two").is_err(), "should have fallen back one commit");
    assert!(fs.warnings.iter().any(|w| w.contains("superblock 0")));
}

#[test]
fn change_password() {
    let t = new_vault();
    {
        let mut fs = open_fs(&t);
        let f = fs.create_file(ROOT_INO, b"f", 0o600).unwrap();
        fs.write(f, 0, b"keep me").unwrap();
        fs.commit().unwrap();
    }
    let key = Keyfile::generate().unwrap();
    {
        let mut v = Vault::open(&t.path, Credential::Password(PW), false).unwrap();
        v.add_keyfile(&key).unwrap();
        v.change_password(PW2, KDF).unwrap();
    }
    assert!(matches!(Vault::open(&t.path, Credential::Password(PW), false), Err(Error::WrongCredentials)));
    let v = Vault::open(&t.path, Credential::Password(PW2), false).unwrap();
    assert!(v.warnings.is_empty(), "{:?}", v.warnings);
    assert!(v.check_headers().unwrap().is_empty());
    let mut fs = v.into_fs().unwrap();
    let f = fs.resolve("f").unwrap();
    assert_eq!(&fs.read(f, 0, 100).unwrap()[..], b"keep me");
    drop(fs);
    // The keyfile survived the password change.
    assert!(Vault::open(&t.path, Credential::Keyfile(&key), true).is_ok());
}

#[test]
fn keyfiles_unlock_and_can_be_removed() {
    let alice = Keyfile::generate().unwrap();
    let bob = Keyfile::generate().unwrap();
    let t = new_vault();
    Vault::open(&t.path, Credential::Password(PW), false).unwrap().add_keyfile(&alice).unwrap();
    {
        let mut v = Vault::open(&t.path, Credential::Keyfile(&alice), false).unwrap();
        v.add_keyfile(&bob).unwrap();
        assert!(v.add_keyfile(&bob).is_err(), "duplicate keyfile");
    }
    assert!(Vault::open(&t.path, Credential::Keyfile(&bob), true).unwrap().into_fs().is_ok());
    Vault::open(&t.path, Credential::Password(PW), false).unwrap().remove_keyfile(&bob).unwrap();
    assert!(matches!(Vault::open(&t.path, Credential::Keyfile(&bob), true), Err(Error::WrongCredentials)));
    assert!(Vault::open(&t.path, Credential::Keyfile(&alice), true).is_ok());
    {
        let mut v = Vault::open(&t.path, Credential::Password(PW), false).unwrap();
        assert!(matches!(v.remove_keyfile(&bob), Err(Error::Usage(_))), "already removed");
        assert_eq!(v.remove_all_keyfiles().unwrap(), 1);
        assert!(matches!(v.remove_all_keyfiles(), Err(Error::Usage(_))));
    }
    assert!(matches!(Vault::open(&t.path, Credential::Keyfile(&alice), true), Err(Error::WrongCredentials)));
    assert!(Vault::open(&t.path, Credential::Password(PW), true).unwrap().into_fs().is_ok());
}

/// A keyfile added to one vault doesn't open another.
#[test]
fn keyfiles_are_per_vault() {
    let key = Keyfile::generate().unwrap();
    let a = new_vault();
    let b = new_vault();
    Vault::open(&a.path, Credential::Password(PW), false).unwrap().add_keyfile(&key).unwrap();
    assert!(Vault::open(&a.path, Credential::Keyfile(&key), true).is_ok());
    assert!(matches!(Vault::open(&b.path, Credential::Keyfile(&key), true), Err(Error::WrongCredentials)));
}

#[test]
fn read_only_open_refuses_writes() {
    let t = new_vault();
    let mut fs = Vault::open(&t.path, Credential::Password(PW), true).unwrap().into_fs().unwrap();
    assert!(matches!(fs.create_file(ROOT_INO, b"x", 0o600), Err(Error::ReadOnly)));
}

#[test]
fn truncate_sparse_and_tail_zeroing() {
    let t = new_vault();
    let mut fs = open_fs(&t);
    let f = fs.create_file(ROOT_INO, b"f", 0o600).unwrap();
    fs.write(f, 0, &[0xAA; 6000]).unwrap();
    fs.set_attr(f, &SetAttr { size: Some(100), ..Default::default() }).unwrap();
    fs.set_attr(f, &SetAttr { size: Some(9000), ..Default::default() }).unwrap();
    let r = fs.read(f, 0, 10_000).unwrap();
    assert_eq!(r.len(), 9000);
    assert!(r[..100].iter().all(|&b| b == 0xAA));
    assert!(r[100..].iter().all(|&b| b == 0), "old data must not reappear after truncate+extend");

    // Sparse: write far past EOF, the gap reads as zeros and costs nothing.
    let g = fs.create_file(ROOT_INO, b"sparse", 0o600).unwrap();
    fs.write(g, 1_000_000, b"end").unwrap();
    assert_eq!(fs.attr(g).unwrap().size, 1_000_003);
    assert_eq!(fs.chunks_of(g).len(), 1);
    assert!(fs.read(g, 0, 4096).unwrap().iter().all(|&b| b == 0));
    assert_eq!(&fs.read(g, 1_000_000, 10).unwrap()[..], b"end");
}

#[test]
fn namespace_semantics() {
    let t = new_vault();
    let mut fs = open_fs(&t);
    let a = fs.mkdir(ROOT_INO, b"a", 0o755).unwrap();
    let b = fs.mkdir(a, b"b", 0o755).unwrap();
    let f = fs.create_file(a, b"f", 0o644).unwrap();
    assert!(matches!(fs.create_file(a, b"f", 0o644), Err(Error::Exists)));
    assert!(matches!(fs.create_file(a, b"x/y", 0o644), Err(Error::InvalidName)));
    assert!(matches!(fs.rmdir(ROOT_INO, b"a"), Err(Error::NotEmpty)));
    assert!(matches!(fs.unlink(ROOT_INO, b"a"), Err(Error::IsADirectory)));
    assert!(matches!(fs.rename(ROOT_INO, b"a", b, b"inside", false), Err(Error::InvalidArgument)));
    assert_eq!(fs.attr(a).unwrap().nlink, 3);

    fs.rename(a, b"f", b, b"g", false).unwrap();
    assert_eq!(fs.lookup(b, b"g").unwrap(), f);
    assert!(fs.lookup(a, b"f").is_err());

    // Replace an existing file.
    let h = fs.create_file(b, b"h", 0o644).unwrap();
    fs.write(h, 0, b"old").unwrap();
    fs.write(f, 0, b"new").unwrap();
    assert!(matches!(fs.rename(b, b"g", b, b"h", true), Err(Error::Exists)));
    fs.rename(b, b"g", b, b"h", false).unwrap();
    assert_eq!(&fs.read(fs.lookup(b, b"h").unwrap(), 0, 10).unwrap()[..], b"new");

    // Open-unlinked files stay readable until released.
    fs.open_file(f).unwrap();
    fs.unlink(b, b"h").unwrap();
    assert_eq!(&fs.read(f, 0, 10).unwrap()[..], b"new");
    fs.release_file(f);
    assert!(fs.attr(f).is_err());

    fs.rmdir(a, b"b").unwrap();
    fs.rmdir(ROOT_INO, b"a").unwrap();
    assert_eq!(fs.readdir(ROOT_INO).unwrap().len(), 2);
    assert_eq!(fs.lookup(ROOT_INO, b"..").unwrap(), ROOT_INO);
}

#[test]
fn filling_the_vault_then_freeing_space() {
    let t = new_vault_with(opts(1 << 20)); // ~ 220 chunks of 4 KiB
    let mut fs = open_fs(&t);
    let f = fs.create_file(ROOT_INO, b"big", 0o600).unwrap();
    let chunk = vec![7u8; 4096];
    let mut written = 0u64;
    loop {
        match fs.write(f, written, &chunk) {
            Ok(()) => written += 4096,
            Err(Error::NoSpace) => break,
            Err(e) => panic!("unexpected {e}"),
        }
        assert!(written < 2 << 20, "never ran out of space");
    }
    assert!(written > 600 << 10, "too little usable space: {written}");
    fs.commit().unwrap();
    // Completely full: copy-on-write can't even overwrite, but fails cleanly.
    assert!(matches!(fs.write(f, 0, &[9u8; 4096]), Err(Error::NoSpace)));
    // Shrinking frees superseded chunks, which a commit reclaims on demand.
    fs.set_attr(f, &SetAttr { size: Some(written / 2), ..Default::default() }).unwrap();
    fs.write(f, written / 2, &vec![3u8; (written / 4) as usize]).unwrap();
    assert_eq!(fs.read(f, written / 2, 4).unwrap()[..], [3, 3, 3, 3]);
    fs.unlink(ROOT_INO, b"big").unwrap();
    fs.commit().unwrap();
    let g = fs.create_file(ROOT_INO, b"again", 0o600).unwrap();
    fs.write(g, 0, &vec![1u8; (written / 2) as usize]).unwrap();
    fs.commit().unwrap();
    drop(fs);
    let mut fs = open_fs(&t);
    assert_eq!(fs.verify().unwrap().bad_blocks.len(), 0);
}

/// With auto-commit off (CLI commands), running out of space partway
/// through replacing a file never commits: the original survives intact.
/// (With auto-commit on, the space-reclaiming commit would have persisted
/// "original deleted, replacement half-written".)
#[test]
fn failed_replacement_without_auto_commit_keeps_the_original() {
    let t = new_vault_with(opts(1 << 20));
    let original = pattern(400 << 10, 1);
    {
        let mut fs = open_fs(&t);
        let f = fs.create_file(ROOT_INO, b"doc", 0o600).unwrap();
        fs.write(f, 0, &original).unwrap();
        fs.commit().unwrap();
    }
    {
        let mut fs = open_fs(&t);
        fs.set_auto_commit(false);
        fs.unlink(ROOT_INO, b"doc").unwrap();
        let f = fs.create_file(ROOT_INO, b"doc", 0o600).unwrap();
        // Bigger than the free space; the old file's chunks are only pending.
        let mut off = 0u64;
        let err = loop {
            match fs.write(f, off, &[9u8; 4096]) {
                Ok(()) => off += 4096,
                Err(e) => break e,
            }
            fs.maybe_commit().unwrap();
            assert!(off < 2 << 20, "never ran out of space");
        };
        assert!(matches!(err, Error::NoSpace), "{err}");
        // Dropped without a commit, like a failing CLI command.
    }
    let mut fs = open_fs(&t);
    let f = fs.resolve("doc").unwrap();
    assert_eq!(fs.read(f, 0, original.len() + 1).unwrap()[..], original[..]);
}

/// Differential test: random writes/truncates against an in-memory model,
/// with commits, crash-free reopens and verification.
#[test]
fn random_operations_match_model() {
    for seed in [0xDEADBEEFCAFEF00Du64, 0x0123456789ABCDEF, 0x9E3779B97F4A7C15, 0xC0FFEE1234567, 42] {
        random_operations_with_seed(seed, 1500);
    }
}

fn random_operations_with_seed(seed: u64, steps: usize) {
    let t = new_vault_with(opts(8 << 20));
    let mut model: Vec<u8> = Vec::new();
    let mut state = seed;
    let mut rnd = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut fs = open_fs(&t);
    let mut f = fs.create_file(ROOT_INO, b"m", 0o600).unwrap();
    for step in 0..steps {
        match rnd() % 10 {
            0..=5 => {
                let off = (rnd() % 60_000) as usize;
                let len = (rnd() % 9000) as usize + 1;
                let seed = rnd() as u8;
                let data = pattern(len, seed);
                fs.write(f, off as u64, &data).unwrap();
                if model.len() < off + len {
                    model.resize(off + len, 0);
                }
                model[off..off + len].copy_from_slice(&data);
            }
            6 => {
                let size = (rnd() % 70_000) as usize;
                fs.set_attr(f, &SetAttr { size: Some(size as u64), ..Default::default() }).unwrap();
                model.resize(size, 0);
            }
            7 => fs.commit().unwrap(),
            8 if step % 5 == 0 => {
                fs.commit().unwrap();
                drop(fs);
                fs = open_fs(&t);
                f = fs.resolve("m").unwrap();
            }
            _ => {
                let off = rnd() % 70_000;
                let len = (rnd() % 20_000) as usize;
                let got = fs.read(f, off, len).unwrap();
                let lo = (off as usize).min(model.len());
                let hi = (off as usize + len).min(model.len());
                assert_eq!(&got[..], &model[lo..hi], "mismatch at step {step}");
            }
        }
    }
    assert_eq!(&fs.read(f, 0, 1 << 20).unwrap()[..], &model[..]);
    fs.commit().unwrap();
    drop(fs);
    let mut fs = open_fs(&t);
    assert_eq!(&fs.read(f, 0, 1 << 20).unwrap()[..], &model[..]);
    assert_eq!(fs.verify().unwrap().bad_blocks.len(), 0);
}

/// Shrinking a file never needs free space, so it works on a full vault
/// and can't fail halfway (finding NG-03).
#[test]
fn shrinking_works_on_a_completely_full_vault() {
    let t = new_vault_with(opts(1 << 20));
    let mut fs = open_fs(&t);
    let f = fs.create_file(ROOT_INO, b"big", 0o600).unwrap();
    let mut written = 0u64;
    while fs.write(f, written, &[5u8; 4096]).is_ok() {
        written += 4096;
    }
    fs.commit().unwrap();
    // Not chunk-aligned, so the last kept block keeps stale bytes.
    let new_size = written / 2 + 1234;
    fs.set_attr(f, &SetAttr { size: Some(new_size), ..Default::default() }).unwrap();
    assert_eq!(fs.attr(f).unwrap().size, new_size);
    assert!(fs.read(f, 0, usize::MAX >> 1).unwrap().iter().all(|&b| b == 5));
    // Growing again (both by truncate and by writing past a gap) shows zeros.
    fs.set_attr(f, &SetAttr { size: Some(new_size + 5000), ..Default::default() }).unwrap();
    let r = fs.read(f, new_size, 5000).unwrap();
    assert!(r.iter().all(|&b| b == 0), "stale data resurfaced after growing");
    fs.set_attr(f, &SetAttr { size: Some(new_size), ..Default::default() }).unwrap();
    fs.write(f, new_size + 20_000, b"x").unwrap();
    assert!(fs.read(f, new_size, 20_000).unwrap().iter().all(|&b| b == 0), "stale data resurfaced after a gap write");
    fs.commit().unwrap();
}

/// A file claiming to be larger than the whole vault is rejected when the
/// metadata is loaded (finding NG-06).
#[test]
fn metadata_with_an_impossible_file_size_is_rejected() {
    use crate::vault::fs::Fs;
    let t = new_vault();
    {
        let mut fs = open_fs(&t);
        let f = fs.create_file(ROOT_INO, b"f", 0o600).unwrap();
        // Sparse files up to the vault's capacity are fine...
        fs.set_attr(f, &SetAttr { size: Some(fs.max_file_size()), ..Default::default() }).unwrap();
        // ...anything bigger is refused at the API.
        assert!(matches!(
            fs.set_attr(f, &SetAttr { size: Some(fs.max_file_size() + 1), ..Default::default() }),
            Err(Error::FileTooBig)
        ));
        fs.commit().unwrap();
        let _: &Fs = &fs;
    }
    assert!(Vault::open(&t.path, Credential::Password(PW), true).unwrap().into_fs().is_ok());
}

// ----------------------------------------------------------------------
// Rekey
// ----------------------------------------------------------------------

#[test]
fn rekey_moves_everything_to_a_new_master_key() {
    use crate::vault::fs::Timestamp;
    let t = new_vault();
    let kf = Keyfile::generate().unwrap();
    let big = pattern(20_000, 7);
    let mtime = Timestamp { secs: 1_600_000_000, nanos: 5 };
    {
        let mut fs = open_fs(&t);
        let docs = fs.mkdir(ROOT_INO, b"docs", 0o750).unwrap();
        let deep = fs.mkdir(docs, b"deep", 0o700).unwrap();
        let f = fs.create_file(deep, b"big.bin", 0o640).unwrap();
        fs.write(f, 0, &big).unwrap();
        fs.set_attr(f, &SetAttr { mtime: Some(mtime), ..Default::default() }).unwrap();
        let s = fs.create_file(ROOT_INO, b"sparse", 0o600).unwrap();
        fs.write(s, 1_000_000, b"end").unwrap();
        fs.create_file(ROOT_INO, b"empty", 0o600).unwrap();
        fs.symlink(ROOT_INO, b"link", b"docs/deep/big.bin").unwrap();
        let gone = fs.create_file(ROOT_INO, b"deleted", 0o600).unwrap();
        fs.write(gone, 0, b"bye").unwrap();
        fs.commit().unwrap();
        fs.unlink(ROOT_INO, b"deleted").unwrap();
        fs.commit().unwrap();
    }
    Vault::open(&t.path, Credential::Password(PW), false).unwrap().add_keyfile(&kf).unwrap();
    let old_file = std::fs::read(&t.path).unwrap();

    let r = rekey::rekey(&t.path, Credential::Password(PW), PW2, KDF, &mut |_, _| {}).unwrap();
    assert_eq!((r.files, r.dirs, r.symlinks, r.keyfiles_dropped), (3, 3, 1, 1));
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    assert!(!rekey::temp_path(&t.path).exists(), "temporary file left behind");
    assert_eq!(std::fs::metadata(&t.path).unwrap().len(), old_file.len() as u64, "same capacity");

    // Only the new password opens it.
    assert!(matches!(Vault::open(&t.path, Credential::Password(PW), true), Err(Error::WrongCredentials)));
    assert!(matches!(Vault::open(&t.path, Credential::Keyfile(&kf), true), Err(Error::WrongCredentials)));
    assert_ne!(Vault::peek_header(&t.path).unwrap().vault_id, Header::parse(&old_file).unwrap().vault_id);

    // The old master key opens nothing: someone with an old copy of the
    // header and the old password gets a key the new data ignores.
    let new_headers = header_area(&t.path);
    write_at(&t.path, 0, &old_file[..2 * HEADER_AREA as usize]);
    assert!(matches!(Vault::open(&t.path, Credential::Password(PW), true), Err(Error::Corrupt(_))));
    write_at(&t.path, 0, &new_headers);

    let mut fs = Vault::open(&t.path, Credential::Password(PW2), true).unwrap().into_fs().unwrap();
    assert!(fs.warnings.is_empty(), "{:?}", fs.warnings);
    let f = fs.resolve("/docs/deep/big.bin").unwrap();
    assert_eq!(&fs.read(f, 0, 100_000).unwrap()[..], &big[..]);
    let a = fs.attr(f).unwrap();
    assert_eq!((a.perm, a.mtime), (0o640, mtime));
    assert_eq!(fs.attr(fs.resolve("/docs").unwrap()).unwrap().perm, 0o750);
    let s = fs.resolve("/sparse").unwrap();
    assert_eq!(fs.attr(s).unwrap().size, 1_000_003);
    assert_eq!(&fs.read(s, 1_000_000, 10).unwrap()[..], b"end");
    assert_eq!(fs.chunks_of(s).len(), 1, "holes stay holes");
    assert_eq!(fs.attr(fs.resolve("/empty").unwrap()).unwrap().size, 0);
    assert_eq!(*fs.readlink(fs.resolve("/link").unwrap()).unwrap(), b"docs/deep/big.bin");
    assert!(fs.resolve("/deleted").is_err());
    assert_eq!(fs.verify().unwrap().bad_blocks.len(), 0);
}

/// A rekey that fails partway (here: a tampered block in the old vault)
/// leaves the original byte-for-byte untouched and no temporary file.
#[test]
fn failed_rekey_leaves_the_vault_untouched() {
    let t = new_vault();
    let chunk = {
        let mut fs = open_fs(&t);
        let f = fs.create_file(ROOT_INO, b"f", 0o600).unwrap();
        fs.write(f, 0, &pattern(4096, 1)).unwrap();
        fs.commit().unwrap();
        fs.chunks_of(f)[0]
    };
    patch(&t.path, chunk_offset(&t, chunk) + 24 + 10, |b| b[0] ^= 1);
    let before = std::fs::read(&t.path).unwrap();
    let err = rekey::rekey(&t.path, Credential::Password(PW), PW2, KDF, &mut |_, _| {}).unwrap_err();
    assert!(matches!(err, Error::ChunkAuth { .. }), "{err}");
    assert_eq!(std::fs::read(&t.path).unwrap(), before);
    assert!(!rekey::temp_path(&t.path).exists());

    let err = rekey::rekey(&t.path, Credential::Password(b"wrong password!"), PW2, KDF, &mut |_, _| {}).unwrap_err();
    assert!(matches!(err, Error::WrongCredentials), "{err}");
    assert!(!rekey::temp_path(&t.path).exists());
}

/// Rekeying through a symbolic link replaces the vault it points to, not
/// the link (which would leave the old-key vault in place).
#[cfg(unix)]
#[test]
fn rekey_through_a_symlink_replaces_the_real_vault() {
    let t = new_vault();
    let link = t.path.with_file_name("link.ngv");
    std::os::unix::fs::symlink(&t.path, &link).unwrap();
    rekey::rekey(&link, Credential::Password(PW), PW2, KDF, &mut |_, _| {}).unwrap();
    assert!(std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
    assert!(Vault::open(&t.path, Credential::Password(PW2), true).is_ok());
    assert!(matches!(Vault::open(&t.path, Credential::Password(PW), true), Err(Error::WrongCredentials)));
}

/// A file left by an interrupted rekey is never overwritten or deleted.
#[test]
fn rekey_refuses_to_touch_a_leftover_temporary_file() {
    let t = new_vault();
    let tmp = rekey::temp_path(&t.path);
    std::fs::write(&tmp, b"leftover").unwrap();
    let err = rekey::rekey(&t.path, Credential::Password(PW), PW2, KDF, &mut |_, _| {}).unwrap_err();
    assert!(matches!(err, Error::Usage(_)), "{err}");
    assert_eq!(std::fs::read(&tmp).unwrap(), b"leftover");
    assert!(Vault::open(&t.path, Credential::Password(PW), true).is_ok());
}

// ----------------------------------------------------------------------
// Format versions
// ----------------------------------------------------------------------

fn new_v3_vault() -> Tmp {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v3.ngv");
    Vault::create_versioned(&path, PW, &opts(4 << 20), header::OLDEST_VERSION, &mut |_, _| {}).unwrap();
    Tmp { _dir: dir, path }
}

#[test]
fn new_vaults_use_the_current_format() {
    let t = new_vault();
    assert_eq!(Vault::peek_header(&t.path).unwrap().version, header::FORMAT_VERSION);
}

/// Version 3 vaults (made before format 4) keep working in every way, and
/// stay version 3: nothing rewrites them into a format older nullguard
/// versions can't read.
#[test]
fn version_3_vaults_keep_working() {
    let t = new_v3_vault();
    let kf = Keyfile::generate().unwrap();
    {
        let mut fs = open_fs(&t);
        let f = fs.create_file(ROOT_INO, b"f", 0o600).unwrap();
        fs.write(f, 0, &pattern(10_000, 3)).unwrap();
        let s = fs.create_file(ROOT_INO, b"sparse", 0o600).unwrap();
        fs.write(s, 200_000, b"end").unwrap();
        fs.commit().unwrap();
    }
    let mut v = Vault::open(&t.path, Credential::Password(PW), false).unwrap();
    v.add_keyfile(&kf).unwrap();
    v.change_password(PW2, KDF).unwrap();
    drop(v);
    assert_eq!(Vault::peek_header(&t.path).unwrap().version, header::OLDEST_VERSION);
    for cred in [Credential::Password(PW2), Credential::Keyfile(&kf)] {
        let mut fs = Vault::open(&t.path, cred, true).unwrap().into_fs().unwrap();
        assert!(fs.warnings.is_empty(), "{:?}", fs.warnings);
        let f = fs.resolve("/f").unwrap();
        assert_eq!(&fs.read(f, 0, 20_000).unwrap()[..], &pattern(10_000, 3)[..]);
        let s = fs.resolve("/sparse").unwrap();
        assert_eq!(&fs.read(s, 200_000, 10).unwrap()[..], b"end");
        assert!(fs.read(s, 0, 4096).unwrap().iter().all(|&b| b == 0));
        assert_eq!(fs.verify().unwrap().bad_blocks.len(), 0);
    }
}

/// `rekey` is the way to move a version 3 vault to the current format.
#[test]
fn rekey_upgrades_a_version_3_vault() {
    let t = new_v3_vault();
    {
        let mut fs = open_fs(&t);
        let f = fs.create_file(ROOT_INO, b"f", 0o600).unwrap();
        fs.write(f, 0, b"hello").unwrap();
        fs.commit().unwrap();
    }
    rekey::rekey(&t.path, Credential::Password(PW), PW2, KDF, &mut |_, _| {}).unwrap();
    assert_eq!(Vault::peek_header(&t.path).unwrap().version, header::FORMAT_VERSION);
    let mut fs = Vault::open(&t.path, Credential::Password(PW2), true).unwrap().into_fs().unwrap();
    let f = fs.resolve("/f").unwrap();
    assert_eq!(&fs.read(f, 0, 100).unwrap()[..], b"hello");
}

/// A tiny write far past the end of a file costs one block, not one entry
/// per block in between, so it can't exhaust memory or bloat the metadata.
#[test]
fn far_writes_stay_cheap() {
    let t = new_vault_with(opts(64 << 20));
    let mut fs = open_fs(&t);
    let free_before = fs.statfs().free_blocks;
    let f = fs.create_file(ROOT_INO, b"far", 0o600).unwrap();
    let end = fs.max_file_size();
    fs.write(f, end - 1, b"x").unwrap();
    fs.commit().unwrap();
    assert_eq!(fs.chunks_of(f).len(), 1);
    // One data chunk; the metadata still fits in the chunk it had.
    assert!(free_before - fs.statfs().free_blocks <= 2, "{} chunks used", free_before - fs.statfs().free_blocks);
    drop(fs);
    let mut fs = open_fs(&t);
    let f = fs.resolve("/far").unwrap();
    assert_eq!(&fs.read(f, end - 1, 10).unwrap()[..], b"x");
}
