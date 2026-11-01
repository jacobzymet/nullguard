# Security architecture assessment — 2026-11-01

**Verdict:** substantial defensive engineering, with meaningful room to reduce
attack opportunities and contain failures. This review does not establish that
Nullguard is free of exploitable vulnerabilities or independently audited.

Scope: local source and configuration at `26fc32a`, including the storage format,
credential handling, worker protocol, resource controls, recovery, native mount
adapters and build workflows. No production vaults were used or changed.

Follow-up: the [subsequent implementation](security-hardening-2026-11-01.md)
fixes the verifier defect, confines Linux workers while serving, and adds build
provenance signing. The findings below describe the assessed revision; external
auditing, OS signatures and broader platform isolation remain outstanding.

## Confirmed defect: verification memory amplification (medium)

`Fs::verify` in `src/vault/fs.rs:1380` stores a complete path for each pending
entry. With a deep directory chain and a file sibling at each level, pending
paths consume quadratic memory in directory depth. Metadata and inode limits
do not bound that amplification. `VerifyReport::bad_blocks` additionally retains
full paths per failure without a separate byte or result-count budget.

A bounded reproduction used a newly created 4 MiB test vault, 255-byte directory
names, and empty files. It committed and reopened the filesystem before measuring
verification allocations through an instrumented Rust global allocator:

| Depth | Inodes | Encoded metadata | Extra peak live heap during verification |
| --- | --- | --- | --- |
| 500 | 1,001 | 211,095 bytes | 32,215,867 bytes |
| 700 | 1,401 | 295,495 bytes | 63,029,851 bytes |

Both checks completed successfully with no bad blocks. These measurements prove
amplification; no out-of-memory crash was deliberately triggered. Larger accepted
trees can require far more memory. The CLI copy-depth limit does not apply to
this verifier or to the metadata decoder.

An attacker needs a vault with valid authenticated metadata, such as one they
create and provide with credentials or modify as a co-owner. This does not show
that someone holding only a locked vault can forge such metadata or decrypt it.

Recommended fix: traverse using inode IDs and bounded traversal state; construct
paths only when needed under a byte limit. Bound retained diagnostic count and
bytes while preserving total failure counts. Test deep/wide trees and many
corrupt blocks. Exercise these operations in fuzzing, beyond parser entry points.

The temporary reproducer is under ignored `target/security-review/`; no
application implementation was changed by this assessment.

## Highest-value architectural improvements

1. **Constrain the worker's authority.** `harden_worker_process` in
   `src/platform.rs:56` installs process mitigations, but no filesystem/network
   sandbox. A future worker code-execution exploit could use the user's normal
   file and network permissions. A narrow broker should supply selected vault
   handles and required mount resources; the worker should lose unrelated access.
   Windows [AppContainer isolation](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation)
   and Linux [Landlock](https://docs.kernel.org/userspace-api/landlock.html)
   document relevant mechanisms. Neither is a drop-in mounting solution: design
   and test mount, unmount and recovery permissions on each supported OS.
2. **Obtain independent review of the trusted core.** Established primitives
   reduce cryptographic risk; their composition, custom recovery protocol and
   unsafe native FFI still need outside scrutiny. Prioritize header/key-slot
   binding, interrupted rekey/header changes, and `src/mount/winfsp.rs`'s
   handwritten structures, request offsets and caller authorization. No native
   authorization bypass or plaintext-recovery exploit was demonstrated here.
3. **Authenticate distributed builds.** Current packages are unsigned and macOS
   builds are not notarized. CI produces checksums and artifacts but does not
   implement release signing/provenance attestation. Add an authenticated release
   chain for both desktop and worker, with native tests of shipped packages.
4. **Broaden operational assurance.** Current fuzz targets cover four parsers;
   add stateful filesystem/protocol/recovery campaigns and allocation budgets.
   Actual macFUSE mount testing is absent from the CI matrix. Process-wide memory
   accounting is also separate from the existing selected allocation limits.

## Boundaries that hardening cannot erase

- An unlocked vault exposes plaintext to authorized applications. RAM key
  encryption does not protect it against a compromised host or code executing
  inside the worker.
- Whole-vault rollback remains undetectable without trusted external freshness
  state. An optional local or remote freshness anchor would change portability
  and recovery semantics and needs a separate design.
- Password/keyfile changes rewrap the existing master key. Revocation after
  credential compromise requires rekeying; earlier copies remain decryptable.

## Strengths and validation

The implementation uses memory-safe Rust for most logic, authenticated chunks
bound to vault identity and position, stored nonce checks, domain-separated
keys, strict parsing, credential wiping, private pipes, guarded retained-key
storage, copy-on-write commits and fail-closed handling of ambiguous writes.
Worker isolation removes GUI dependencies from the process retaining vault keys.

- `cargo test --workspace --locked`: **194 passed**, one native mount integration
  test ignored because it requires FUSE/WinFsp setup.
- Refreshed `cargo audit --deny yanked`: **442 dependencies**, no known
  vulnerabilities or yanked packages reported; maintenance warnings remain for
  `zbus_names`, `zvariant`, and `zvariant_derive`.
- Two bounded verification-allocation probes reproduced the finding above.
- Native Linux/macOS runtime or driver mounting was not revalidated in this
  Windows review. Existing documentation and configured CI are not substitutes
  for those checks or for independent security assurance.
