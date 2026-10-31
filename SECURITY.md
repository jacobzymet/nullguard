# Security policy

nullguard protects data people care about, so security reports get top priority.

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Report them
privately through GitHub's "Report a vulnerability" (private security
advisories) on this repository. Include:

- what an attacker can do (read data, forge or roll back data, crash, ...),
- the affected version or commit,
- steps or a vault file that reproduce it, if you have them.

You'll get an acknowledgement within a few days. Fixes for confirmed issues
are released as soon as possible, and reporters are credited unless they
prefer otherwise.

## Scope

In scope: anything that weakens the guarantees in the README's
[threat model](README.md#threat-model). That includes confidentiality,
tamper and rollback detection, key handling, parsing of untrusted vault
files and keyfiles, and the safety of the mount.

Out of scope: attacks the threat model explicitly excludes (e.g. malware
running as you while the vault is unlocked).

## Assurance

- Cryptography comes only from audited crates: XChaCha20-Poly1305,
  Argon2id and SHA-256 (see the README's
  [cryptographic design](README.md#cryptographic-design)).
- `unsafe` is denied crate-wide except for libc and Windows API calls
  in `src/platform.rs`, its guarded-memory submodule, and our own minimal
  WinFsp bindings in `src/mount/winfsp.rs` (Windows only).
- CI runs `cargo audit` against the RustSec advisory database on every push.
- Parser fuzzing runs on relevant changes and daily, with bounded execution
  and retained failure inputs. Deterministic tests inject torn writes and
  flush failures into commits and password changes.
- Desktop vault work uses a headless helper with no GUI dependencies,
  bounded worker admission, and resource approval checked at derivation.
  Windows helpers additionally prohibit dynamic code, legacy extension
  points and child-process creation. This is not a full OS sandbox; see
  [architecture hardening](docs/architecture-hardening-2026-10-31.md).
- [RAM key protection](docs/ram-key-protection.md) encrypts retained master/data
  keys on Windows, Linux and macOS. Windows uses the OS memory-protection API;
  Linux/macOS use authenticated encryption with wrapping keys in locked,
  guarded pages. Temporary keys are wiped after use. This does not protect
  a compromised host or provide kernel isolation for Unix wrapping keys.
- nullguard has **not yet had an independent security audit**.
