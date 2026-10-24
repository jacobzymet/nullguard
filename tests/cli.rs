//! Drives the real `nullguard` binary end to end (non-interactively, via
//! `--password-stdin`). Mounting is covered separately on Linux.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

const PW: &str = "correct horse battery staple";
const PW2: &str = "an even better passphrase here";
const FAST_KDF: [&str; 1] = ["--low-memory"];

fn ng(args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_nullguard"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn nullguard");
    child.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    child.wait_with_output().unwrap()
}

fn ok(args: &[&str], stdin: &str) -> String {
    let out = ng(args, stdin);
    assert!(
        out.status.success(),
        "nullguard {args:?} failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn fails(args: &[&str], stdin: &str) -> String {
    let out = ng(args, stdin);
    assert!(!out.status.success(), "nullguard {args:?} unexpectedly succeeded");
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn full_workflow() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v.ngv");
    let v = s(&vault);

    // Weak passwords are refused.
    let err = fails(&[&["create", v, "--size", "8M", "--password-stdin"][..], &FAST_KDF].concat(), "short\n");
    assert!(err.contains("at least 12"), "{err}");
    assert!(!vault.exists());

    let out = ok(&[&["create", v, "--size", "8M", "--password-stdin"][..], &FAST_KDF].concat(), &format!("{PW}\n"));
    assert!(out.contains("Created"), "{out}");
    // Never overwrites.
    fails(&[&["create", v, "--size", "8M", "--password-stdin"][..], &FAST_KDF].concat(), &format!("{PW}\n"));

    let info = ok(&["info", v], "");
    assert!(info.contains("xchacha20-poly1305") && info.contains("password"), "{info}");

    // Put a directory tree in, list it, get it back.
    let src = dir.path().join("src");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("a.txt"), b"alpha").unwrap();
    let big: Vec<u8> = (0..3_000_000u32).map(|i| (i * 7 % 251) as u8).collect();
    std::fs::write(src.join("sub").join("big.bin"), &big).unwrap();
    ok(&["put", v, s(&src), "/", "--password-stdin"], &format!("{PW}\n"));
    let ls = ok(&["ls", v, "/src/sub", "--password-stdin"], &format!("{PW}\n"));
    assert!(ls.contains("big.bin") && ls.contains("3000000"), "{ls}");

    let dst = dir.path().join("out");
    ok(&["get", v, "/src", s(&dst), "--password-stdin"], &format!("{PW}\n"));
    assert_eq!(std::fs::read(dst.join("a.txt")).unwrap(), b"alpha");
    assert_eq!(std::fs::read(dst.join("sub").join("big.bin")).unwrap(), big);

    // Wrong password.
    let err = fails(&["ls", v, "--password-stdin"], "not the password!!\n");
    assert!(err.contains("wrong password"), "{err}");

    // Change password: stdin gives the old one, then the new one.
    ok(&[&["change-password", v, "--password-stdin"][..], &FAST_KDF].concat(), &format!("{PW}\n{PW2}\n"));
    fails(&["ls", v, "--password-stdin"], &format!("{PW}\n"));
    ok(&["ls", v, "--password-stdin"], &format!("{PW2}\n"));

    // Keyfiles: generate, add, unlock, remove.
    let key = dir.path().join("me.key");
    let key2 = dir.path().join("spare.key");
    ok(&["keygen", s(&key)], "");
    ok(&["keygen", s(&key2)], "");
    fails(&["keygen", s(&key)], ""); // never overwrites
    fails(&["ls", v, "--keyfile", s(&key)], ""); // not added yet
    ok(&["add-keyfile", v, s(&key), "--password-stdin"], &format!("{PW2}\n"));
    // A keyfile can add another keyfile.
    ok(&["add-keyfile", v, s(&key2), "--keyfile", s(&key)], "");
    fails(&["add-keyfile", v, s(&key2), "--keyfile", s(&key)], ""); // already added
    assert!(ok(&["info", v], "").contains("keyfiles:    2"));
    let ls = ok(&["ls", v, "/src", "--keyfile", s(&key)], "");
    assert!(ls.contains("a.txt"));
    ok(&["remove-keyfile", v, s(&key), "--password-stdin"], &format!("{PW2}\n"));
    fails(&["ls", v, "--keyfile", s(&key)], "");
    ok(&["ls", v, "--keyfile", s(&key2)], "");
    fails(&["remove-keyfile", v, "--password-stdin"], &format!("{PW2}\n")); // which one?
    let out = ok(&["remove-keyfile", v, "--all", "--password-stdin"], &format!("{PW2}\n"));
    assert!(out.contains("Removed 1 keyfile"), "{out}");
    fails(&["ls", v, "--keyfile", s(&key2)], "");

    // rm, mkdir, verify.
    ok(&["rm", v, "/src/sub", "-r", "--password-stdin"], &format!("{PW2}\n"));
    ok(&["mkdir", v, "/new", "--password-stdin"], &format!("{PW2}\n"));
    let ls = ok(&["ls", v, "/", "--password-stdin"], &format!("{PW2}\n"));
    assert!(ls.contains("new") && ls.contains("src"));
    let out = ok(&["verify", v, "--password-stdin"], &format!("{PW2}\n"));
    assert!(out.contains("OK"), "{out}");
}

#[test]
fn verify_detects_tampering() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v.ngv");
    let v = s(&vault);
    ok(&[&["create", v, "--size", "4M", "--password-stdin"][..], &FAST_KDF].concat(), &format!("{PW}\n"));
    let src = dir.path().join("f.bin");
    std::fs::write(&src, vec![0x42u8; 200_000]).unwrap();
    ok(&["put", v, s(&src), "/", "--password-stdin"], &format!("{PW}\n"));

    // Flip one bit in every 4 KiB of the data area past the two superblocks.
    // Metadata and file data both live there, so the vault must not verify.
    let mut raw = std::fs::read(&vault).unwrap();
    let start = 8192 + 2 * (16 * 1024 + 40);
    for off in (start..raw.len()).step_by(4096) {
        raw[off] ^= 1;
    }
    std::fs::write(&vault, &raw).unwrap();
    let err = fails(&["verify", v, "--password-stdin"], &format!("{PW}\n"));
    assert!(err.contains("failed verification") || err.contains("authentication") || err.contains("modified"), "{err}");
}

#[test]
fn password_handling() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v.ngv");
    let v = s(&vault);
    // Created with a decomposed accent ("e" + U+0301)...
    let decomposed = "cre\u{300}me bru\u{302}le\u{301}e passphrase";
    let composed = "cr\u{e8}me br\u{fb}l\u{e9}e passphrase";
    ok(&[&["create", v, "--size", "4M", "--password-stdin"][..], &FAST_KDF].concat(), &format!("{decomposed}\n"));
    // ...unlocks with the precomposed form another OS/keyboard might send.
    ok(&["ls", v, "--password-stdin"], &format!("{composed}\n"));

    // Re-using the current password is refused.
    let err = fails(&[&["change-password", v, "--password-stdin"][..], &FAST_KDF].concat(), &format!("{composed}\n{decomposed}\n"));
    assert!(err.contains("same as the current"), "{err}");

    // Absurdly long passwords are refused rather than hashed.
    let long = "x".repeat(10_000);
    let err = fails(&["ls", v, "--password-stdin"], &format!("{long}\n"));
    assert!(err.contains("limited to"), "{err}");
}

#[test]
fn failed_get_leaves_no_partial_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v.ngv");
    let v = s(&vault);
    ok(&[&["create", v, "--size", "8M", "--password-stdin"][..], &FAST_KDF].concat(), &format!("{PW}\n"));
    let src = dir.path().join("f.bin");
    std::fs::write(&src, vec![0x42u8; 3_000_000]).unwrap();
    ok(&["put", v, s(&src), "/", "--password-stdin"], &format!("{PW}\n"));

    // Corrupt the last ~200 KiB of the file's data: the first part still
    // decrypts, so a naive copy would leave a partial file behind.
    let mut raw = std::fs::read(&vault).unwrap();
    let stride = 16 * 1024 + 40;
    let data_end = 8192 + (2 + 3_000_000 / (16 * 1024)) * stride;
    for off in (data_end - 200 * 1024..data_end).step_by(4096) {
        raw[off] ^= 1;
    }
    std::fs::write(&vault, &raw).unwrap();
    let out = dir.path().join("out.bin");
    fails(&["get", v, "/f.bin", s(&out), "--password-stdin"], &format!("{PW}\n"));
    assert!(!out.exists(), "partial plaintext was left behind");
}

/// A `put --force` that fails partway (here: the replacement doesn't fit)
/// once committed mid-copy to reclaim the old file's space, leaving a
/// truncated replacement in the vault and the original gone.
#[test]
fn failed_put_force_keeps_the_original_file() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v.ngv");
    let v = s(&vault);
    ok(&[&["create", v, "--size", "8M", "--password-stdin"][..], &FAST_KDF].concat(), &format!("{PW}\n"));
    let src = dir.path().join("f.bin");
    let original = vec![0x11u8; 5_000_000];
    std::fs::write(&src, &original).unwrap();
    ok(&["put", v, s(&src), "/", "--password-stdin"], &format!("{PW}\n"));

    std::fs::write(&src, vec![0x22u8; 7_000_000]).unwrap();
    fails(&["put", v, s(&src), "/", "--force", "--password-stdin"], &format!("{PW}\n"));

    let out = dir.path().join("out.bin");
    ok(&["get", v, "/f.bin", s(&out), "--password-stdin"], &format!("{PW}\n"));
    assert!(std::fs::read(&out).unwrap() == original, "the original file was lost or altered");
}

/// Regression for review finding NG-01: `rm -r <dir>/..` once deleted the
/// parent's contents, then failed, and the deletion was still committed.
#[test]
fn rm_refuses_dot_paths_and_never_commits_on_failure() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v.ngv");
    let v = s(&vault);
    ok(&[&["create", v, "--size", "4M", "--password-stdin"][..], &FAST_KDF].concat(), &format!("{PW}\n"));
    let src = dir.path().join("d");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("a.txt"), b"important").unwrap();
    std::fs::write(src.join("sub").join("b.txt"), b"more").unwrap();
    ok(&["put", v, s(&src), "/", "--password-stdin"], &format!("{PW}\n"));

    for bad in ["/d/sub/..", "/d/.", "/.", "/..", "/d/sub/../"] {
        let err = fails(&["rm", v, bad, "-r", "--password-stdin"], &format!("{PW}\n"));
        assert!(err.contains("invalid path"), "{bad}: {err}");
    }
    let ls = ok(&["ls", v, "/d", "--password-stdin"], &format!("{PW}\n"));
    assert!(ls.contains("a.txt") && ls.contains("sub"), "data was deleted: {ls}");
    let ls = ok(&["ls", v, "/d/sub", "--password-stdin"], &format!("{PW}\n"));
    assert!(ls.contains("b.txt"), "{ls}");
}

/// Regression for review finding NG-04: `verify` once printed "OK" and
/// exited 0 although the primary header had been tampered with.
#[test]
fn verify_fails_when_a_header_copy_is_tampered() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v.ngv");
    let v = s(&vault);
    ok(&[&["create", v, "--size", "4M", "--password-stdin"][..], &FAST_KDF].concat(), &format!("{PW}\n"));
    ok(&["verify", v, "--password-stdin"], &format!("{PW}\n"));
    // Corrupt the primary header's password slot; the backup stays intact.
    let mut raw = std::fs::read(&vault).unwrap();
    raw[82 + 30] ^= 0xFF;
    std::fs::write(&vault, &raw).unwrap();
    // Read-only use still works (from the backup), with a warning...
    let out = ng(&["ls", v, "--password-stdin"], &format!("{PW}\n"));
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(stderr.matches("primary header copy does not match").count(), 1, "{stderr}");
    // ...but verify must fail.
    let err = fails(&["verify", v, "--password-stdin"], &format!("{PW}\n"));
    assert!(err.contains("verification FAILED"), "{err}");
    assert_eq!(err.matches("primary header copy does not match").count(), 2, "warning plus BAD line: {err}");
    // A writable command restores the primary, and the vault verifies again.
    let out = ng(&["mkdir", v, "/x", "--password-stdin"], &format!("{PW}\n"));
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("restored"));
    ok(&["verify", v, "--password-stdin"], &format!("{PW}\n"));
}

#[test]
fn rekey_command() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v.ngv");
    let v = s(&vault);
    let key = dir.path().join("k");
    ok(&[&["create", v, "--size", "4M", "--password-stdin"][..], &FAST_KDF].concat(), &format!("{PW}\n"));
    let src = dir.path().join("notes.txt");
    std::fs::write(&src, b"keep these notes").unwrap();
    ok(&["put", v, s(&src), "/", "--password-stdin"], &format!("{PW}\n"));
    ok(&["keygen", s(&key)], "");
    ok(&["add-keyfile", v, s(&key), "--password-stdin"], &format!("{PW}\n"));

    // Unlock with the current password, then give the new one.
    let out = ok(&[&["rekey", v, "--password-stdin"][..], &FAST_KDF].concat(), &format!("{PW}\n{PW2}\n"));
    assert!(out.contains("Rekeyed") && out.contains("1 files"), "{out}");

    fails(&["ls", v, "--password-stdin"], &format!("{PW}\n"));
    fails(&["ls", v, "--keyfile", s(&key)], "");
    let out = dir.path().join("out.txt");
    ok(&["get", v, "/notes.txt", s(&out), "--password-stdin"], &format!("{PW2}\n"));
    assert_eq!(std::fs::read(&out).unwrap(), b"keep these notes");
    ok(&["verify", v, "--password-stdin"], &format!("{PW2}\n"));
    // Rekeying with a keyfile works too (after adding it back).
    ok(&["add-keyfile", v, s(&key), "--password-stdin"], &format!("{PW2}\n"));
    ok(&[&["rekey", v, "--keyfile", s(&key), "--password-stdin"][..], &FAST_KDF].concat(), &format!("{PW}\n"));
    ok(&["ls", v, "--password-stdin"], &format!("{PW}\n"));
}

/// Settings that used to make weaker vaults no longer exist.
#[test]
fn removed_options_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v.ngv");
    let v = s(&vault);
    for extra in [
        &["--cipher", "aes-256-gcm"][..],
        &["--quick"],
        &["--chunk-size", "4K"],
        &["--kdf-memory", "64"],
        &["--recipient", "x.pub"],
    ] {
        fails(&[&["create", v, "--size", "4M", "--password-stdin"][..], extra].concat(), &format!("{PW}\n"));
        assert!(!vault.exists());
    }
}

#[cfg(unix)]
#[test]
fn keyfiles_readable_by_others_are_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v.ngv");
    let v = s(&vault);
    let key = dir.path().join("k");
    ok(&[&["create", v, "--size", "4M", "--password-stdin"][..], &FAST_KDF].concat(), &format!("{PW}\n"));
    ok(&["keygen", s(&key)], "");
    assert_eq!(std::fs::metadata(&key).unwrap().permissions().mode() & 0o777, 0o600);
    ok(&["add-keyfile", v, s(&key), "--password-stdin"], &format!("{PW}\n"));
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    let err = fails(&["ls", v, "--keyfile", s(&key)], "");
    assert!(err.contains("readable by other users"), "{err}");
}

#[cfg(unix)]
#[test]
fn exported_directories_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v.ngv");
    let v = s(&vault);
    ok(&[&["create", v, "--size", "4M", "--password-stdin"][..], &FAST_KDF].concat(), &format!("{PW}\n"));
    ok(&["mkdir", v, "/secret-folder-name", "--password-stdin"], &format!("{PW}\n"));
    let out = dir.path().join("out");
    ok(&["get", v, "/secret-folder-name", s(&out), "--password-stdin"], &format!("{PW}\n"));
    let mode = std::fs::metadata(&out).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[test]
fn mount_explains_platform_support() {
    let err = fails(&["mount", "x.ngv", "y"], "");
    assert!(err.contains("not supported on this platform"), "{err}");
}
