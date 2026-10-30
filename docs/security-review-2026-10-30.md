# Security review — 2026-10-30

Source and regression-test review of the working tree based on `4e64fbe`,
including the uncommitted Windows process-access hardening. This is an
internal engineering pass; no independent security assurance is implied.

## Confirmed findings and fixes

### Medium: runtime security and durability warnings were hidden

The desktop discarded worker stderr, while both mount adapters print
authentication failures, background commit failures and poisoned-session
warnings there. Users could continue seeing an unlocked vault without the
warning that their reads or writes had failed.

`desktop/src/session.rs` now drains stderr from worker startup, forwards
diagnostics to the UI and drains them before reporting worker exit.
Messages are bounded, deduplicated and capped; excess output is still
consumed so the writer cannot block on a full diagnostic pipe. Tests cover
security/commit warnings, flooding, oversized lines and invalid UTF-8.
Actual mounted-vault delivery still needs native mount validation.

### Medium: escaped passwords used an unwiped JSON scratch buffer

`serde_json` decodes escaped strings through its ordinary `Vec<u8>` scratch
buffer. Wiping the packet and `Zeroizing<String>` did not wipe that extra
decoded copy. This is a memory-hygiene issue, not a demonstrated remote
password disclosure.

The private worker request now serializes the password as a numeric byte
array. Valid requests decode through bounded, zeroizing storage; malformed
password errors do not echo the rejected value. Tests cover special
characters, the 4096-byte boundary, oversized input and invalid UTF-8.
Parent and worker are the same executable; no vault-format change is made.

### Low: extended containers were accepted as intact

`Vault::open` rejected truncation but accepted a file longer than the
authenticated header's declared geometry. A regression reproduced acceptance
of a vault extended by one byte. This did not bypass authentication of stored
files, but contradicted the documented fixed-size format.

Both shorter and longer containers are now rejected before header repair.
Regression tests cover read-only/writable opens and confirm that invalid
length does not trigger header repair.

The README now also makes the authentication boundary explicit: unused
random space and superseded chunks are not authenticated by the current
filesystem state. A test demonstrates that modifying a free chunk can pass
verification. Whole-container rollback remains outside the guarantee.
The obsolete claim that format version 3 is supported was removed.

## Validation

- Workspace regressions plus the final desktop rerun: 159 passing tests.
- One native mount integration test skipped: WinFsp is not installed.
- Workspace Clippy, all targets, with warnings denied: passed.
- `git diff --check`: passed.
- `cargo audit --deny yanked`: no known vulnerabilities or yanked packages
  found among 441 locked dependencies. RustSec database revision
  `ee1a49a2769a24a596afc1c20cb33748d2769586`, updated 2026-10-29.
- Three existing maintenance notices remain: `zbus_names`, `zvariant` and
  `zvariant_derive` (RUSTSEC-2026-0371, 0370 and 0372). These are not reported
  as vulnerability advisories by this scan.

Windows private-file and process-access tests ran with normal user
permissions; the restricted execution runner changes ACL behavior.

## Remaining work and limits

- Retained keys are still plaintext in RAM, with best-effort page locking
  and wiping. The previously blocked RAM-encryption refactor was not applied.
- Windows hardening restricts fresh process handles. Existing handles,
  thread-object attacks, privileged callers and compromised hosts remain
  outside that protection. It is not equivalent to VeraCrypt's driver.
- Run native FUSE/WinFsp tests, especially the complete runtime-warning path,
  and repeat platform-specific checks on Linux and macOS.
- Add deterministic I/O-failure and power-loss simulation around commits,
  header changes and rekeying. Existing crash/corruption tests do not exhaust
  possible write/flush failure orderings.
- Metadata allocation bounds and parser invariants were reviewed; no global
  metadata-memory budget or exhaustive malformed-input campaign was added.
- Independent review of the format, cryptographic composition, FFI and
  recovery protocol remains necessary before claiming audited security.
