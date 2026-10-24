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

- Cryptography comes only from audited or formally verified crates
  (see the README's [cryptographic design](README.md#cryptographic-design)).
- `unsafe` is denied crate-wide except for a few libc calls in `src/platform.rs`.
- CI runs `cargo audit` against the RustSec advisory database on every push.
  The one current notice (`proc-macro-error2`, unmaintained) is a
  compile-time-only dependency of libcrux's verification annotations and
  ships no code in the binary.
- nullguard has **not yet had an independent security audit**.
