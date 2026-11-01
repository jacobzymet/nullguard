# Architecture hardening — 2026-10-31

This engineering change reduces reachable dependencies, bounds selected
resource-exhaustion paths and adds failure testing. It is not an independent
audit or a claim that all exploitable paths have been eliminated.

## Headless key-holding worker

The desktop launches a sibling `nullguard-worker` executable by its absolute
application-directory path. It never searches PATH or falls back to running
vault code inside the GUI. The worker crate depends on the vault engine,
bounded JSON protocol and small support crates; it has no graphics, dialogs,
accessibility or tray dependencies.

The worker installs process protections before announcing protocol readiness.
The parent validates a bounded, versioned readiness message before sending
credentials over the existing private anonymous pipe. Startup has a ten-second
readiness timeout; an unsuccessful pre-request worker is terminated. A live
vault writer is never terminated by this startup path.

Desktop packages include the worker. macOS places it inside the app bundle;
Linux/Windows archives contain both executables. Source launches must first
build the worker. A missing or incompatible helper produces an error.

Windows workers use documented kernel mitigation policies to prohibit dynamic
executable code (without opt-outs), legacy extension points and child-process
creation. The GUI keeps its normal graphics and process-launch behavior.
Worker operations/mounting must pass native WinFsp tests with these policies.
Unix process-hardening failures now propagate instead of being ignored.

These policies and the reduced binary are not a filesystem/network sandbox.
Unix mount/unmount helpers still require their normal OS access. A broader
capability sandbox needs a carefully designed broker and native validation;
blanket syscall/privilege denial can prevent clean mount/unmount operations.
Compromising a worker can still expose that unlocked vault's plaintext.

## Resource approval and budgets

The actual password derivation checks an explicit `KdfLimits` approval before
allocating/hashing. Normal unlocks permit at most 1 GiB, four passes and four
lanes. Preflight UI warnings are advisory: replacing a file after selection
does not grant approval for its new parameters. The desktop's explicit costly-
derivation approval and CLI `--allow-expensive-kdf` permit the existing format
ceilings (4 GiB, 64 passes, 64 lanes). The cost is never silently reduced.
Library callers can use `Vault::open_with_kdf_limits` or the corresponding
header/rekey APIs. Direct derivation/new-slot creation uses caller-chosen
parameters within the format caps.

Concurrent derivations inside one process reserve from a 4 GiB aggregate
budget, released on return/error/unwind. Each desktop instance allows four
live workers and one expensive startup at a time; its control channel
coalesces repeated lock requests into bounded storage. Independent app/CLI
instances do not share this cooperative admission budget.
The parent bounds unsolicited status events, coalesces progress, caps warning
messages and accepts lifecycle transitions only once. A lock-failure event
requires a pending parent lock request. Replayed mount events cannot repeatedly
launch the file manager; diagnostic pipes continue to drain independently.

Filesystem policy bounds encoded metadata to 64 MiB, inodes to 100,000 and
the allocation bitmap to 64 MiB. The decrypted cache is limited by both its
entry count and 16 MiB of content. These checks bound selected allocations;
they are not a complete process RSS quota or an exact accounting of every
allocator/tree-node overhead.

Limits are checked before large allocations. A resource-limit failure from
superblock/metadata loading is terminal for that open attempt, so it cannot
silently trigger fallback to an older filesystem state. In-memory growth
also checks inode/encoded-metadata limits before adding entries/committing.
Live stored-block references are capped by the 64 MiB/40-byte serialized
reference budget, and reads return at most 8 MiB per call. Replacing or
deleting existing blocks releases/reuses their accounting normally.
The on-disk format is unchanged; vaults above the new operational ceilings
are refused rather than rewritten. They require resource-policy review,
not weakening cryptography or discarding newer state.

## Failure testing

Test-only, thread-local, one-shot faults simulate truncated/prefix writes and
failed flushes. They are absent from production builds and cannot be enabled
through a vault, environment variable or worker request. Tests cover each
metadata/superblock write/flush boundary and each password-header-change
boundary, asserting recovery of a complete authenticated state. These checks
do not emulate every drive controller, filesystem or physical power loss.

The fault campaign reproduced a retry hazard: a failed header flush could
leave a new header hash committed while the `Vault` object still held the old
header. Retrying a password change on that object could overwrite the sole
matching backup header. Header-update failures now invalidate that object
for subsequent header mutations and filesystem opening; callers must close
and reopen it to resolve the durable state. A regression asserts retry does
not change a single on-disk byte and the committed credentials still open.

Parser fuzzing uses cargo-fuzz 0.13.2 with AddressSanitizer, nightly Rust,
bounded input size, per-input timeout and memory ceilings. Relevant pushes/PRs
run smoke campaigns; daily runs get longer campaigns. Failing artifacts are
retained for reproduction. A green campaign is evidence for its exercised
inputs and runtime, not proof of parser correctness.
Legacy header/metadata seed versions were updated. Unit tests now require
every seed family to include valid current-format examples, preventing seed
drift from silently narrowing fuzz coverage to early rejection paths.

## Local validation

- 194 Windows workspace tests passed; one native mount integration test was
  skipped locally because WinFsp is unavailable. The actual GUI session
  transport verified a vault using the sibling worker and rejected absent
  and incompatible helpers without opening a window.
- 145 native Linux library tests passed, including quota/recovery cases.
  Worker/root cross-target checks passed for Linux and macOS.
- Workspace and worker cross-target Clippy passed with warnings denied.
  Public documentation builds passed with warnings denied.
- All four parsers completed local AddressSanitizer fuzz smoke campaigns.
  Header/metadata campaigns were repeated after correcting legacy seeds;
  current-format seeds substantially increased initial valid-parser coverage.
- Windows desktop ZIP contents and the helper dependency graph were checked:
  both executables are packaged, and the worker graph excludes GUI crates.
- Refreshed RustSec/yanked-package checks passed; the three existing GUI
  dependency maintenance warnings remain. No new third-party dependency was
  introduced by the worker package.

Native CI on all platforms, mount integration and release-package builds
remain required for this revision; local cross-compilation is not their
replacement.

## Primary OS documentation

- [SetProcessMitigationPolicy](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setprocessmitigationpolicy)
- [Dynamic code policy](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_dynamic_code_policy)

Independent review of cryptographic composition, unsafe FFI, recovery and
the proposed wider sandbox remains necessary before claiming audited security.
