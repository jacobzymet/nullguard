# RAM key protection

Windows, Linux and macOS CLI and desktop operations automatically encrypt
retained vault master keys and chunk-encryption keys in memory. The vault
format and password/keyfile formats are unchanged.

## Key lifetime

`ProtectedKey` retains encrypted bytes in a zeroizing allocation with
best-effort page locking. Each operation copies those bytes into a separate
zeroizing allocation, attempts to lock it, then decrypts there. A callback
receives the plaintext only for the operation. The temporary allocation is
wiped on return, error or panic; the retained allocation stays encrypted.
Concurrent operations use separate temporary copies. RustCrypto also wipes
its cipher key state when dropped, using its enabled `zeroize` feature.

`Vault` retains its master key this way, and `Aead` retains encryption keys
this way. Creation derives the protected data key and drops the plaintext
master before filling the container with random data. Plaintext `SecretKey`
values remain available for short-lived derivation and wrapping operations.

### Windows

Construction encrypts the 32-byte allocation in place with
[`CryptProtectMemory`](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectmemory)
and `CRYPTPROTECTMEMORY_SAME_PROCESS`. Recovery uses `CryptUnprotectMemory`.
The key length satisfies the API's 16-byte block-size requirement. Nullguard
does not create or persist its own Windows wrapping key.

### Linux and macOS

Each retained key uses RustCrypto XChaCha20-Poly1305 with a fresh random
nonce, an independent random 256-bit wrapping key and a fixed RAM-protection
domain label. The authentication tag rejects modified ciphertext/metadata.
This uses the existing primitive directly; it adds no dependency or custom
cryptographic primitive. The memory-management wrapper has not been
independently audited.

The wrapping key is generated directly into a dedicated anonymous mapping:

- Three virtual pages are reserved per retained key. The center page is
  strictly locked with `mlock`; the outer pages remain inaccessible guards.
  The cost is one locked OS page per retained key, in addition to existing
  best-effort locking of temporary and retained allocations.
- The center page is inaccessible (`PROT_NONE`) while idle. A mutex
  serializes brief read-only access during wrapping/unwrapping. The page
  becomes inaccessible again before releasing the mutex, including on panic.
- Linux applies `MADV_DONTDUMP` and `MADV_DONTFORK` to the mapping, excluding
  it from ordinary core dumps and fork children.
- macOS applies `VM_INHERIT_NONE` to exclude the mapping from fork children
  and `MADV_ZERO_WIRED_PAGES` to request zeroing on deallocation without
  first unwiring the page. This macOS advice is **not** a core-dump exclusion;
  the CLI/desktop's existing process hardening disables core dumps.
- Access checks the creator PID before touching the mutex. Fork children
  cannot reuse inherited protected keys and must reopen the vault.
- Drop explicitly wipes the center page before unmapping it. No wrapping
  key is written to a vault or other persistent file.

These Unix wrapping keys still reside in the application's address space.
Guard pages restrict ordinary memory access; they are not kernel isolation
or an equivalent of Windows' OS-managed memory-encryption scheme. A
privileged complete memory capture or code executing in the process can
still recover keys.

The OS mechanisms are documented in [Linux `madvise`](https://man7.org/linux/man-pages/man2/madvise.2.html)
and Apple's [`mman.h`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/mman.h)
and [`vm_inherit.h`](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/vm_inherit.h).

## Failures

Protection/recovery failures wipe the temporary/input allocation and return
`CryptoError::MemoryProtection`. A key that cannot be protected is never
retained in plaintext. Unix mapping, locking and required advice failures
also fail construction; there is no fallback when locked-memory limits are
exhausted. Local key-memory failures propagate through chunk/superblock reads
instead of being treated as vault corruption or triggering an older-state
fallback.

If Unix cannot restore the wrapping page's inaccessible state or securely
clean it up, the process immediately exits without a core dump or exit
callbacks. Uncommitted changes can be lost; existing durable vault commits
retain their normal crash-recovery behavior.

`Aead::new` now returns `Result<Aead, CryptoError>` so callers must handle a
memory-protection failure before using the cipher. This is a library API
change; all in-tree callers have been updated. Other unsupported platforms
return a memory-protection error rather than retaining plaintext keys.

## Limits

This protects retained key allocations between operations, not all RAM.
Plaintext exists while a key is generated, derived or used. Password and
keyfile credential buffers, decrypted file caches, OS buffers, compiler
temporaries and registers are outside this feature's encryption boundary.
Existing wiping and process-access restrictions still apply.

The feature does not protect against code executing inside the process,
administrators, a compromised kernel, complete privileged memory capture
or cold-boot attacks. It does not provide VeraCrypt's driver-level process
isolation.

## Validation (2026-10-30)

- 170 Windows workspace tests and 132 native Linux library tests passed,
  covering vault creation/reopening, password/keyfile changes, rekeying,
  tampering and existing cipher known-answer vectors.
- Retained-key tests check encrypted storage, repeated/concurrent recovery,
  protection/decryption failures and unwinding. Windows tests also attempt
  recovery in a separate process. Unix tests reject modified/swapped RAM
  capsules and confirm decrypted output is wiped on failure.
- Native Linux subprocess tests verify inaccessible idle/guard pages,
  restoration on panic, immediate exit on restore failure, rejection after
  fork without deadlock, refusal when the lock limit is exhausted, and the
  kernel's lock/dump/fork mapping flags.
- Instance-local transient failure tests prove local key-memory errors stop
  superblock/metadata recovery without falling back, wipe failed chunk
  reads, and leave failed chunk/password writes byte-for-byte unchanged.
- A vault created before RAM protection was verified/read by the new
  Windows binary. The old binary read subsequent new writes and verified
  password/keyfile changes made by the new binary; file contents matched.
- The native Linux CLI verified/read that Windows vault, added a file and
  verified the result. The old Windows binary then verified the Linux-written
  vault and exported the added file with matching contents.
- Workspace Clippy and Linux/macOS all-target Clippy passed with warnings
  denied. Public documentation builds also passed with warnings denied for
  Windows, Linux and macOS; CI now enforces documentation builds. The macOS
  offline feature was used for cross-compilation.
- A refreshed `cargo audit --deny yanked` reported no known vulnerabilities
  or yanked packages. Existing maintenance notices for `zbus_names`,
  `zvariant` and `zvariant_derive` remain.
- Native macOS runtime tests and physical memory attacks were not tested.
  One Windows mount test was skipped because WinFsp is unavailable locally.

## Push and release readiness

The change has passed local review and is ready to push for CI validation.
The existing CI matrix runs native macOS tests and Linux/Windows mount
workflows. Those checks must pass for this revision before treating it as
release-validated. Local cross-compilation does not prove macOS runtime
behavior, and passing tests do not constitute an independent security audit.

## CI follow-up (2026-10-31)

The [first pushed run](https://github.com/jacobzymet/nullguard/actions/runs/41040146588)
passed native macOS/Linux tests, both Linux/Windows mount workflows and the
dependency audit. Its Windows process-access test failed because a restricted
handle was granted; the caller's privilege level was not controlled by that test.

The revised test probes with privileges removed from a thread-local copy of
the caller's token, preserving identity and group membership. Every access
right must succeed before hardening and be denied afterwards. It also checks
that supervision stays available, that nested/panicking probes restore the
exact original thread token, and that a caller holding enabled debug privilege
can exercise the documented privileged exception. CI logs the Windows caller's
privileges to make environment differences visible.

Local validation passed: 171 Windows workspace tests, including the three
process-protection tests; one native mount test remains skipped locally.

This follows Microsoft's [process access model](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
and [`CreateRestrictedToken` contract](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken).
The revised Windows test still requires a successful native CI run before
the change is considered release-validated.
