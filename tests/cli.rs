//! Drives the real `nullguard` binary end to end (non-interactively, via
//! `--password-stdin`). Mounting is covered separately on Linux.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

const PW: &str = "correct horse battery staple";
const PW2: &str = "an even better passphrase here";
const FAST_KDF: [&str; 6] = ["--kdf-memory", "64", "--kdf-iterations", "2", "--kdf-parallelism", "1"];

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

    // Keyfiles: generate (passphrase-protected), share, unlock, revoke.
    let key = dir.path().join("me.key");
    let out = ok(&["keygen", s(&key), "--password-stdin"], "keyfile passphrase 123\n");
    let fp_line = out.lines().find(|l| l.starts_with("Fingerprint")).unwrap();
    let fp = fp_line.split_whitespace().last().unwrap().to_string();
    let pubkey = format!("{}.pub", s(&key));
    ok(&["add-recipient", v, &pubkey, "--password-stdin"], &format!("{PW2}\n"));
    assert!(ok(&["info", v], "").contains(&fp));
    let ls = ok(&["ls", v, "/src", "--keyfile", s(&key), "--password-stdin"], "keyfile passphrase 123\n");
    assert!(ls.contains("a.txt"));
    fails(&["ls", v, "--keyfile", s(&key), "--password-stdin"], "wrong keyfile passphrase\n");
    ok(&["remove-recipient", v, &fp[..12], "--password-stdin"], &format!("{PW2}\n"));
    fails(&["ls", v, "--keyfile", s(&key), "--password-stdin"], "keyfile passphrase 123\n");

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
    ok(&[&["create", v, "--size", "4M", "--quick", "--password-stdin"][..], &FAST_KDF].concat(), &format!("{PW}\n"));
    let src = dir.path().join("f.bin");
    std::fs::write(&src, vec![0x42u8; 200_000]).unwrap();
    ok(&["put", v, s(&src), "/", "--password-stdin"], &format!("{PW}\n"));

    // Flip one bit in every 4 KiB of the data area past the two superblocks.
    // Metadata and file data both live there, so the vault must not verify.
    let mut raw = std::fs::read(&vault).unwrap();
    let start = 128 * 1024 + 2 * (16 * 1024 + 40);
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
    ok(&[&["create", v, "--size", "4M", "--quick", "--password-stdin"][..], &FAST_KDF].concat(), &format!("{decomposed}\n"));
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
    ok(&[&["create", v, "--size", "8M", "--quick", "--password-stdin"][..], &FAST_KDF].concat(), &format!("{PW}\n"));
    let src = dir.path().join("f.bin");
    std::fs::write(&src, vec![0x42u8; 3_000_000]).unwrap();
    ok(&["put", v, s(&src), "/", "--password-stdin"], &format!("{PW}\n"));

    // Corrupt the last ~200 KiB of the file's data: the first part still
    // decrypts, so a naive copy would leave a partial file behind.
    let mut raw = std::fs::read(&vault).unwrap();
    let stride = 16 * 1024 + 40;
    let data_end = 128 * 1024 + (2 + 3_000_000 / (16 * 1024)) * stride;
    for off in (data_end - 200 * 1024..data_end).step_by(4096) {
        raw[off] ^= 1;
    }
    std::fs::write(&vault, &raw).unwrap();
    let out = dir.path().join("out.bin");
    fails(&["get", v, "/f.bin", s(&out), "--password-stdin"], &format!("{PW}\n"));
    assert!(!out.exists(), "partial plaintext was left behind");
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[test]
fn mount_explains_platform_support() {
    let err = fails(&["mount", "x.ngv", "y"], "");
    assert!(err.contains("not supported on this platform"), "{err}");
}
