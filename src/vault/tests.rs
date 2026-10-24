//! End-to-end tests of vault files: create, unlock, tamper, crash.

use super::*;
use crate::crypto::hybrid::HybridSecretKey;
use crate::vault::fs::{ROOT_INO, SetAttr};
use std::path::PathBuf;

const PW: &[u8] = b"correct horse battery staple";
/// The weakest parameters `create` accepts, to keep tests fast.
const KDF: Argon2Params = Argon2Params { memory_kib: Argon2Params::MIN_CREATE_MEMORY_KIB, iterations: 2, parallelism: 1 };

struct Tmp {
    _dir: tempfile::TempDir,
    path: PathBuf,
}

fn opts(size: u64) -> CreateOptions {
    CreateOptions {
        size,
        cipher: CipherSuite::XChaCha20Poly1305,
        kdf: KDF,
        chunk_size: Some(4096),
        fill_random: false,
        recipients: Vec::new(),
    }
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
    h.data_offset + chunk * chunk_stride(h.chunk_size)
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
}

#[test]
fn create_write_reopen_read() {
    let t = new_vault();
    let data = pattern(10_000, 1);
    {
        let mut fs = open_fs(&t);
        let d = fs.mkdir(ROOT_INO, b"docs", 0o755, 0, 0).unwrap();
        let f = fs.create_file(d, b"hello.txt", 0o644, 0, 0).unwrap();
        fs.write(f, 0, &data).unwrap();
        fs.symlink(ROOT_INO, b"link", b"docs/hello.txt", 0, 0).unwrap();
        fs.commit().unwrap();
    }
    let mut fs = open_fs(&t);
    assert!(fs.warnings.is_empty(), "{:?}", fs.warnings);
    let f = fs.resolve("/docs/hello.txt").unwrap();
    assert_eq!(fs.attr(f).unwrap().size, 10_000);
    assert_eq!(&fs.read(f, 0, 20_000).unwrap()[..], &data[..]);
    assert_eq!(&fs.read(f, 4090, 10).unwrap()[..], &data[4090..4100]);
    let l = fs.resolve("/link").unwrap();
    assert_eq!(fs.readlink(l).unwrap(), b"docs/hello.txt");
    let names: Vec<_> = fs.readdir(ROOT_INO).unwrap().into_iter().map(|e| e.name).collect();
    assert_eq!(names, vec![b".".to_vec(), b"..".to_vec(), b"docs".to_vec(), b"link".to_vec()]);
}

#[test]
fn aes_gcm_vault_and_random_fill() {
    let mut o = opts(2 << 20);
    o.cipher = CipherSuite::Aes256Gcm;
    o.fill_random = true;
    let t = new_vault_with(o);
    {
        let mut fs = open_fs(&t);
        let f = fs.create_file(ROOT_INO, b"a", 0o600, 0, 0).unwrap();
        fs.write(f, 0, b"gcm data").unwrap();
        fs.commit().unwrap();
    }
    let mut fs = open_fs(&t);
    let f = fs.resolve("a").unwrap();
    assert_eq!(&fs.read(f, 0, 100).unwrap()[..], b"gcm data");
    drop(fs);
    assert_eq!(Vault::peek_header(&t.path).unwrap().cipher, CipherSuite::Aes256Gcm);
}

#[test]
fn plaintext_never_hits_the_disk() {
    let t = new_vault();
    let secret = b"TOP-SECRET-MARKER-0123456789-the-quick-brown-fox";
    {
        let mut fs = open_fs(&t);
        let f = fs.create_file(ROOT_INO, b"TOP-SECRET-FILENAME", 0o600, 0, 0).unwrap();
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
    let k = HybridSecretKey::generate().unwrap();
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

#[test]
fn header_tampering_is_detected() {
    let t = new_vault();
    // Flip a bit in the MAC of both copies: parses fine, unlocks, MAC fails.
    let signed_len = 64 + 4 + 152; // core + one password slot
    for base in [header::PRIMARY_OFFSET, header::BACKUP_OFFSET] {
        patch(&t.path, base + signed_len + 3, |b| b[0] ^= 0x10);
    }
    assert!(matches!(Vault::open(&t.path, Credential::Password(PW), false), Err(Error::HeaderTampered)));
}

#[test]
fn tampered_primary_with_intact_backup_opens_with_security_warning() {
    let t = new_vault();
    let signed_len = 64 + 4 + 152;
    patch(&t.path, header::PRIMARY_OFFSET + signed_len + 3, |b| b[0] ^= 0x10);
    let v = Vault::open(&t.path, Credential::Password(PW), false).unwrap();
    assert!(v.warnings.iter().any(|w| w.contains("SECURITY") && w.contains("primary")), "{:?}", v.warnings);
}

#[test]
fn damaged_primary_header_falls_back_to_backup_with_warning() {
    let t = new_vault();
    patch(&t.path, 100, |b| b[0] ^= 0xFF); // inside the password slot
    let v = Vault::open(&t.path, Credential::Password(PW), false).unwrap();
    assert!(v.warnings.iter().any(|w| w.contains("differ")));
    assert!(v.warnings.iter().any(|w| w.contains("backup")));
}

#[test]
fn both_headers_destroyed_is_an_error() {
    let t = new_vault();
    patch(&t.path, header::PRIMARY_OFFSET, |b| b[0] = 0);
    patch(&t.path, header::BACKUP_OFFSET, |b| b[0] = 0);
    assert!(Vault::open(&t.path, Credential::Password(PW), false).is_err());
}

#[test]
fn modified_data_chunk_is_detected() {
    let t = new_vault();
    let chunk;
    {
        let mut fs = open_fs(&t);
        let f = fs.create_file(ROOT_INO, b"f", 0o600, 0, 0).unwrap();
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
        let f = fs.create_file(ROOT_INO, b"f", 0o600, 0, 0).unwrap();
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
        let f = fs.create_file(ROOT_INO, b"f", 0o600, 0, 0).unwrap();
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
        let f = fs.create_file(ROOT_INO, b"f", 0o600, 0, 0).unwrap();
        fs.write(f, 0, &pattern(10_000, 1)).unwrap();
        fs.commit().unwrap();
        // Overwrite everything and add a file, then "lose power".
        fs.write(f, 0, &pattern(20_000, 2)).unwrap();
        fs.create_file(ROOT_INO, b"new", 0o600, 0, 0).unwrap();
        fs.abandon();
    }
    let mut fs = open_fs(&t);
    let f = fs.resolve("f").unwrap();
    assert_eq!(&fs.read(f, 0, 100_000).unwrap()[..], &pattern(10_000, 1)[..]);
    assert!(fs.resolve("new").is_err());
    assert_eq!(fs.verify().unwrap().bad_blocks.len(), 0);
}

fn header_area(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap()[..(2 * header::HEADER_AREA) as usize].to_vec()
}

fn restore_header_area(path: &Path, saved: &[u8]) {
    let file = OpenOptions::new().write(true).open(path).unwrap();
    write_all_at(&file, saved, 0).unwrap();
}

/// Putting back an old (authentic) header to revive a removed recipient is
/// detected: the data was committed under a newer header generation.
#[test]
fn restoring_an_old_header_to_revive_a_removed_recipient_is_detected() {
    let bob = HybridSecretKey::generate().unwrap();
    let mut o = opts(4 << 20);
    o.recipients = vec![bob.public_key()];
    let t = new_vault_with(o);
    let old_headers = header_area(&t.path);
    {
        let mut v = Vault::open(&t.path, Credential::Password(PW), false).unwrap();
        v.remove_recipient(&bob.public_key().fingerprint_hex()).unwrap();
        assert_eq!(v.header().generation, 2);
    }
    assert!(matches!(Vault::open(&t.path, Credential::Keyfile(&bob), true), Err(Error::WrongCredentials)));

    restore_header_area(&t.path, &old_headers);
    // The old header itself is authentic, so Bob's slot unlocks it...
    let v = Vault::open(&t.path, Credential::Keyfile(&bob), true).unwrap();
    // ...but the filesystem knows it was committed under generation 2.
    assert!(matches!(v.into_fs(), Err(Error::HeaderRollback { header: 1, recorded: 2 })));
    let v = Vault::open(&t.path, Credential::Password(PW), true).unwrap();
    assert!(matches!(v.into_fs(), Err(Error::HeaderRollback { .. })));
}

#[test]
fn restoring_an_old_header_to_revive_an_old_password_is_detected() {
    let t = new_vault();
    let old_headers = header_area(&t.path);
    {
        let mut v = Vault::open(&t.path, Credential::Password(PW), false).unwrap();
        v.change_password(b"a brand new long password", KDF).unwrap();
    }
    restore_header_area(&t.path, &old_headers);
    let v = Vault::open(&t.path, Credential::Password(PW), true).unwrap();
    assert!(matches!(v.into_fs(), Err(Error::HeaderRollback { .. })));
}

/// If a header change is interrupted after the backup copy was written,
/// the newer backup wins (not the stale primary).
#[test]
fn newest_header_copy_wins_after_interrupted_change() {
    let alice = HybridSecretKey::generate().unwrap();
    let t = new_vault();
    let gen1 = header_area(&t.path);
    {
        let mut v = Vault::open(&t.path, Credential::Password(PW), false).unwrap();
        v.add_recipient(&alice.public_key()).unwrap();
    }
    // Simulate the interruption: the primary still holds generation 1.
    restore_header_area(&t.path, &gen1[..header::HEADER_AREA as usize]);
    let v = Vault::open(&t.path, Credential::Password(PW), false).unwrap();
    assert_eq!(v.header().generation, 2, "must use the newer backup copy");
    assert!(v.into_fs().is_ok());
    assert!(Vault::open(&t.path, Credential::Keyfile(&alice), true).is_ok());
}

/// Dropping a filesystem never commits: a command that fails halfway
/// leaves the vault exactly as it was.
#[test]
fn uncommitted_changes_are_discarded() {
    let t = new_vault();
    {
        let mut fs = open_fs(&t);
        fs.create_file(ROOT_INO, b"kept", 0o600, 0, 0).unwrap();
        fs.commit().unwrap();
        fs.unlink(ROOT_INO, b"kept").unwrap();
        fs.create_file(ROOT_INO, b"discarded", 0o600, 0, 0).unwrap();
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
        let f = fs.create_file(ROOT_INO, b"committed", 0o600, 0, 0).unwrap();
        fs.write(f, 0, b"safe").unwrap();
        fs.commit().unwrap();
    }
    let path = t.path.clone();
    let result = std::panic::catch_unwind(move || {
        let mut fs = Vault::open(&path, Credential::Password(PW), false).unwrap().into_fs().unwrap();
        fs.create_file(ROOT_INO, b"half-done", 0o600, 0, 0).unwrap();
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
        fs.create_file(ROOT_INO, b"before", 0o600, 0, 0).unwrap();
        fs.poison();
        assert!(fs.create_file(ROOT_INO, b"after", 0o600, 0, 0).is_err());
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

#[test]
fn torn_superblock_falls_back_with_warning() {
    let t = new_vault();
    {
        let mut fs = open_fs(&t);
        let f = fs.create_file(ROOT_INO, b"one", 0o600, 0, 0).unwrap();
        fs.write(f, 0, b"1").unwrap();
        fs.commit().unwrap(); // generation 3 -> slot 1
        let g = fs.create_file(ROOT_INO, b"two", 0o600, 0, 0).unwrap();
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
        let f = fs.create_file(ROOT_INO, b"f", 0o600, 0, 0).unwrap();
        fs.write(f, 0, b"keep me").unwrap();
        fs.commit().unwrap();
    }
    let sk = HybridSecretKey::generate().unwrap();
    {
        let mut v = Vault::open(&t.path, Credential::Password(PW), false).unwrap();
        v.add_recipient(&sk.public_key()).unwrap();
        v.change_password(b"a brand new long password", KDF).unwrap();
    }
    assert!(matches!(Vault::open(&t.path, Credential::Password(PW), false), Err(Error::WrongCredentials)));
    let v = Vault::open(&t.path, Credential::Password(b"a brand new long password"), false).unwrap();
    assert!(v.warnings.is_empty());
    assert_eq!(v.header().password_slot_count(), 1);
    let mut fs = v.into_fs().unwrap();
    let f = fs.resolve("f").unwrap();
    assert_eq!(&fs.read(f, 0, 100).unwrap()[..], b"keep me");
    drop(fs);
    // The recipient slot survived the password change.
    assert!(Vault::open(&t.path, Credential::Keyfile(&sk), true).is_ok());
}

#[test]
fn recipients_unlock_and_can_be_removed() {
    let alice = HybridSecretKey::generate().unwrap();
    let bob = HybridSecretKey::generate().unwrap();
    let mut o = opts(4 << 20);
    o.recipients = vec![alice.public_key()];
    let t = new_vault_with(o);
    {
        let mut v = Vault::open(&t.path, Credential::Keyfile(&alice), false).unwrap();
        v.add_recipient(&bob.public_key()).unwrap();
        assert!(v.add_recipient(&bob.public_key()).is_err(), "duplicate recipient");
    }
    assert!(Vault::open(&t.path, Credential::Keyfile(&bob), true).is_ok());
    {
        let mut v = Vault::open(&t.path, Credential::Password(PW), false).unwrap();
        let fp = bob.public_key().fingerprint_hex();
        assert_eq!(v.remove_recipient(&fp[..10]).unwrap(), fp);
    }
    assert!(matches!(Vault::open(&t.path, Credential::Keyfile(&bob), true), Err(Error::WrongCredentials)));
    assert!(Vault::open(&t.path, Credential::Keyfile(&alice), true).is_ok());
}

#[test]
fn read_only_open_refuses_writes() {
    let t = new_vault();
    let mut fs = Vault::open(&t.path, Credential::Password(PW), true).unwrap().into_fs().unwrap();
    assert!(matches!(fs.create_file(ROOT_INO, b"x", 0o600, 0, 0), Err(Error::ReadOnly)));
}

#[test]
fn truncate_sparse_and_tail_zeroing() {
    let t = new_vault();
    let mut fs = open_fs(&t);
    let f = fs.create_file(ROOT_INO, b"f", 0o600, 0, 0).unwrap();
    fs.write(f, 0, &[0xAA; 6000]).unwrap();
    fs.set_attr(f, &SetAttr { size: Some(100), ..Default::default() }).unwrap();
    fs.set_attr(f, &SetAttr { size: Some(9000), ..Default::default() }).unwrap();
    let r = fs.read(f, 0, 10_000).unwrap();
    assert_eq!(r.len(), 9000);
    assert!(r[..100].iter().all(|&b| b == 0xAA));
    assert!(r[100..].iter().all(|&b| b == 0), "old data must not reappear after truncate+extend");

    // Sparse: write far past EOF, the gap reads as zeros and costs nothing.
    let g = fs.create_file(ROOT_INO, b"sparse", 0o600, 0, 0).unwrap();
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
    let a = fs.mkdir(ROOT_INO, b"a", 0o755, 0, 0).unwrap();
    let b = fs.mkdir(a, b"b", 0o755, 0, 0).unwrap();
    let f = fs.create_file(a, b"f", 0o644, 0, 0).unwrap();
    assert!(matches!(fs.create_file(a, b"f", 0o644, 0, 0), Err(Error::Exists)));
    assert!(matches!(fs.create_file(a, b"x/y", 0o644, 0, 0), Err(Error::InvalidName)));
    assert!(matches!(fs.rmdir(ROOT_INO, b"a"), Err(Error::NotEmpty)));
    assert!(matches!(fs.unlink(ROOT_INO, b"a"), Err(Error::IsADirectory)));
    assert!(matches!(fs.rename(ROOT_INO, b"a", b, b"inside", false), Err(Error::InvalidArgument)));
    assert_eq!(fs.attr(a).unwrap().nlink, 3);

    fs.rename(a, b"f", b, b"g", false).unwrap();
    assert_eq!(fs.lookup(b, b"g").unwrap(), f);
    assert!(fs.lookup(a, b"f").is_err());

    // Replace an existing file.
    let h = fs.create_file(b, b"h", 0o644, 0, 0).unwrap();
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
    let f = fs.create_file(ROOT_INO, b"big", 0o600, 0, 0).unwrap();
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
    let g = fs.create_file(ROOT_INO, b"again", 0o600, 0, 0).unwrap();
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
        let f = fs.create_file(ROOT_INO, b"doc", 0o600, 0, 0).unwrap();
        fs.write(f, 0, &original).unwrap();
        fs.commit().unwrap();
    }
    {
        let mut fs = open_fs(&t);
        fs.set_auto_commit(false);
        fs.unlink(ROOT_INO, b"doc").unwrap();
        let f = fs.create_file(ROOT_INO, b"doc", 0o600, 0, 0).unwrap();
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
    let mut f = fs.create_file(ROOT_INO, b"m", 0o600, 0, 0).unwrap();
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
    let f = fs.create_file(ROOT_INO, b"big", 0o600, 0, 0).unwrap();
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
        let f = fs.create_file(ROOT_INO, b"f", 0o600, 0, 0).unwrap();
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
