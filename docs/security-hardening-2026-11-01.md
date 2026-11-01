# Security hardening — 2026-11-01

## Verification memory

Verification queues inode IDs and borrows the validated metadata; it no longer
clones complete paths or inodes for traversal. Names are rendered only for
retained error diagnostics. Each diagnostic path is capped at 4096 bytes, the
sample at 128 entries and the combined path/error text at 64 KiB. Abbreviated
paths carry the inode ID. `VerifyReport::bad_blocks_total` counts every failed
block; CLI, desktop worker and rekey validation use that total. Local key-memory
failures terminate verification rather than being classified as damaged data.

Regression tests cover deep/wide authenticated trees under an allocation budget,
many corrupt blocks, abbreviated paths, local protection failures and unlinked
open files. The on-disk format is unchanged.

## Linux worker confinement

After opening the vault, verification workers install an irreversible seccomp
allowlist. Mount workers do so after native FUSE setup and before serving or
reporting `Mounted`. TSYNC covers existing threads; future threads inherit the
filter. Failure to install it aborts the operation. Only x86-64 and AArch64 are
supported by this policy.

The confined process can use already-open vault/FUSE/pipe handles, memory,
threading, signals and clocks. It cannot open new paths, create/connect network
or Unix sockets, execute programs, fork independent processes, create executable
mappings, acquire other processes' handles, or change namespaces/mounts. This is
a syscall boundary, not kernel isolation from vulnerabilities in allowed calls.

A separate keyless Linux broker starts before unlocking. It receives one fixed
mountpoint over anonymous pipes, accepts only activation/lock requests, records
the kernel mount ID and refuses to unmount another filesystem at a reused path.
It never receives a password, keyfile, encryption key or vault file handle.
On worker disconnect/crash it retries clean unmounting of the recorded mount.
Signals and normal locking use that broker, so the worker needs no executable
unmount helper after confinement.

**Remaining isolation limits:** Linux initial unlock and native mount setup
precede confinement. The CLI, Windows workers and macOS workers retain their
existing permissions/mitigations; full filesystem/network isolation there is
not implemented. Windows requires a tested mount broker plus a restricted
engine process; macOS requires native macFUSE validation of its sandbox design.
Neither should be described as fixed by the Linux policy. A compromised worker
can still expose the vault it has unlocked.

Primary contracts: [Linux seccomp](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)
and [no-new-privileges](https://www.kernel.org/doc/html/latest/userspace-api/no_new_privs.html).

## Verifying downloads

CI now has a separate, pinned provenance-signing job after every required native
check and package build. It runs only for pushes to the default branch or `v*`
tags. PR/build jobs have no OIDC/attestation signing permissions. The job signs
the actual downloadable binaries, complete desktop archives and checksum files,
then verifies repository, workflow, source ref and commit. Its signed bundle is
retained as `nullguard-provenance` for offline verification.

For artifacts built after this workflow is merged and passes, use GitHub CLI.
Replace the filename, release tag and full source commit with the intended build:

```sh
gh attestation verify nullguard-desktop-linux.tar.gz --repo jacobzymet/nullguard --signer-workflow jacobzymet/nullguard/.github/workflows/ci.yml --source-ref refs/tags/vX.Y.Z --source-digest FULL_COMMIT_SHA
```

Verify before extracting/running. Older artifacts may lack attestations. Signed
provenance authenticates the build's origin and bytes; it does not demonstrate
that its source is vulnerability-free. The workflow needs its first successful
GitHub run before any artifact can be claimed to have this provenance.

This follows [GitHub's artifact-attestation workflow](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)
and [verification policy](https://cli.github.com/manual/gh_attestation_verify).

**OS signing remains outstanding:** Authenticode and Apple Developer ID signing/
notarization require the maintainer's signing identities. No self-signed identity,
unsigned fallback advertised as signed, or fabricated audit has been added.

## Independent audit handoff

An independent audit requires an external reviewer. Supply a frozen commit,
format/threat-model documentation, dependency lockfile, reproducible builds and
the regression/fuzz corpus. Review should cover:

- Header commitments, key separation, password/keyfile changes and rekeying.
- Torn writes, flush failures, recovery/fallback and rollback guarantees.
- Unsafe guarded-memory, WinFsp ABI/callbacks and requester authorization.
- Worker/broker isolation, protocol state transitions and OS-specific mounts.
- Dependency/release provenance and native package verification.

Track findings privately under `SECURITY.md`, fix and retest them, and obtain a
written independent report before changing the unaudited status. This document
is an engineering record and audit handoff, not that independent report.

## Local validation

- Windows workspace: 197 tests passed; native WinFsp integration remains skipped
  locally. Windows ACL tests require a normal user token, not the restricted
  execution runner's token; the normal-permission run passed.
- Native Linux: 147 library tests, the verifier allocation regression, kernel
  confinement tests and offline worker integration passed. Actual FUSE mount,
  lock/reopen, parent-disconnect and killed-worker cleanup passed as both root
  and an ordinary user in a disposable container.
- The original 700-level reproduction dropped from 63,029,851 to **28,672 bytes**
  of extra peak live heap. Both measurements used the same counting allocator.
- Workspace/Linux/macOS worker Clippy passed with warnings denied. Workflow
  YAML and signing-permission boundaries were checked locally. Signed provenance
  generation and native macOS behavior still require CI/platform validation.
