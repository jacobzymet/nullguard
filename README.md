# nullguard

**Encrypted vaults that mount as drives.** A small, open-source,
quantum-resistant alternative to VeraCrypt, written in Rust.

A nullguard vault is a single ordinary file. Unlock it with a password or a
keyfile and it appears as a normal folder. Everything inside (file contents,
names, sizes, directory structure) is encrypted and authenticated. Lock it,
and it's an opaque blob that detects tampering with its authenticated contents.

- **A portable CLI, plus an optional desktop app.** The CLI has no installer, no runtime, no DLLs, no driver of its
  own. Copy `nullguard` (or `nullguard.exe`) onto a USB stick next to
  your vault and go.
- **Audited cryptography.** XChaCha20-Poly1305 for data, Argon2id for
  passwords and SHA-256 for hashing, all from audited Rust crates.
- **Tamper-evident.** Stored files and filesystem metadata are authenticated.
  Modified, moved, swapped
  or *replayed* (rolled back) blocks are detected, and so is an old header
  put back to revive a removed keyfile or an old password.
- **Crash-safe.** Copy-on-write with atomic commits: pulling the plug leaves
  the vault exactly as of its last commit. Password and keyfile changes
  are atomic too.
- **Quantum-resistant.** Every key is a 256-bit symmetric key or derived
  from a password. There's no public-key cryptography for a quantum
  computer to break.

> **Status: v0.2, not yet independently audited.** The design is
> deliberately small and heavily tested, but please keep backups and treat
> it as new software until it has had outside review.

> **Built with AI.** nullguard was implemented primarily by artificial
> intelligence, with human direction and review.

---

## Contents

- [Quick start](#quick-start)
- [Desktop app](#desktop-app)
- [Commands](#commands)
- [Platform support](#platform-support)
- [Building a portable binary](#building-a-portable-binary)
- [Compared with VeraCrypt](#compared-with-veracrypt)
- [Threat model](#threat-model)
- [Cryptographic design](#cryptographic-design)
- [Vault file format](#vault-file-format)
- [Code layout](#code-layout)
- [Limitations and roadmap](#limitations-and-roadmap)
- [License](#license)

## Quick start

For a graphical interface, use the [desktop app](#desktop-app). The following
instructions are for the CLI.

Choose your OS: [Linux](#linux), [macOS](#macos), or [Windows](#windows).
Run the commands from the folder containing the binary. The Windows examples
use **PowerShell**.

Mounting runs in the foreground. Use the mounted folder or drive from
another window. To lock it, press Ctrl-C in the mount terminal or run the
unmount command in a second terminal. Wait for the mount terminal to report
`Vault unmounted and locked.` before disconnecting storage.

### Linux

**Mounting requirement:** `/dev/fuse` and `fusermount3`, provided by your
distribution's `fuse3` package. Offline commands do not need FUSE.

```bash
# Create a 10 GiB vault (you'll be asked for a password, twice).
./nullguard create secrets.ngv --size 10G

# Mount on an empty folder.
mkdir ~/vault
./nullguard mount secrets.ngv ~/vault
```

To lock it from a second terminal in the binary's folder:

```bash
./nullguard unmount ~/vault
```

**Work without mounting:**

```bash
./nullguard put secrets.ngv ./taxes /          # copy a folder in
./nullguard ls secrets.ngv /taxes
./nullguard get secrets.ngv /taxes/2025.pdf .   # copy a file out
./nullguard verify secrets.ngv                # check integrity
```

**Use a keyfile:** replace `usb` with an existing folder on your separate
keyfile storage. The generated file has mode `0600`.

```bash
./nullguard keygen usb/recovery.key
./nullguard add-keyfile secrets.ngv usb/recovery.key
./nullguard mount secrets.ngv ~/vault --keyfile usb/recovery.key
```

After unmounting, remove a keyfile's access with:

```bash
./nullguard remove-keyfile secrets.ngv usb/recovery.key
# If a keyfile is lost, remove all keyfiles instead:
./nullguard remove-keyfile secrets.ngv --all
```

### macOS

**Requirement:** install [macFUSE](https://osxfuse.github.io/) before running
the standard binary, including offline commands. To work without macFUSE,
build the [offline-only binary](#build-on-macos).

```bash
# Create a 10 GiB vault (you'll be asked for a password, twice).
./nullguard create secrets.ngv --size 10G

# Mount on an empty folder.
mkdir ~/vault
./nullguard mount secrets.ngv ~/vault
```

To lock it from a second terminal in the binary's folder:

```bash
./nullguard unmount ~/vault
```

**Work without mounting:** use either the standard binary with macFUSE
installed or the offline-only build.

```bash
./nullguard put secrets.ngv ./taxes /          # copy a folder in
./nullguard ls secrets.ngv /taxes
./nullguard get secrets.ngv /taxes/2025.pdf .   # copy a file out
./nullguard verify secrets.ngv                # check integrity
```

**Use a keyfile:** replace `usb` with an existing folder on your separate
keyfile storage. The generated file has mode `0600`.

```bash
./nullguard keygen usb/recovery.key
./nullguard add-keyfile secrets.ngv usb/recovery.key
./nullguard mount secrets.ngv ~/vault --keyfile usb/recovery.key
```

After unmounting, remove a keyfile's access with:

```bash
./nullguard remove-keyfile secrets.ngv usb/recovery.key
# If a keyfile is lost, remove all keyfiles instead:
./nullguard remove-keyfile secrets.ngv --all
```

### Windows

**Mounting requirement:** install [WinFsp](https://winfsp.dev) **2.x** and
choose a free drive letter. These examples use `X:`. Offline commands run
without WinFsp.

```powershell
# Create a 10 GiB vault (you'll be asked for a password, twice).
.\nullguard.exe create .\secrets.ngv --size 10G

# Mount as the X: drive.
.\nullguard.exe mount .\secrets.ngv X:
```

To lock it from a second PowerShell window in the binary's folder:

```powershell
.\nullguard.exe unmount X:
```

**Work without mounting:**

```powershell
.\nullguard.exe put .\secrets.ngv .\taxes /          # copy a folder in
.\nullguard.exe ls .\secrets.ngv /taxes
.\nullguard.exe get .\secrets.ngv /taxes/2025.pdf .   # copy a file out
.\nullguard.exe verify .\secrets.ngv                # check integrity
```

**Use a keyfile:** replace `.\usb` with an existing folder on your separate
keyfile storage. The storage must support file permissions; keyfiles readable
by other users are refused, including those on FAT-formatted drives.

```powershell
.\nullguard.exe keygen .\usb\recovery.key
.\nullguard.exe add-keyfile .\secrets.ngv .\usb\recovery.key
.\nullguard.exe mount .\secrets.ngv X: --keyfile .\usb\recovery.key
```

After unmounting, remove a keyfile's access with:

```powershell
.\nullguard.exe remove-keyfile .\secrets.ngv .\usb\recovery.key
# If a keyfile is lost, remove all keyfiles instead:
.\nullguard.exe remove-keyfile .\secrets.ngv --all
```

### About keyfiles

A keyfile **is** a key: anyone holding it can unlock every vault it was
added to, with no password. Keep it somewhere separate from the vault (a USB
stick, a printout in a safe). Every vault always has exactly one password
as well, which keyfile changes never touch.

Removing a keyfile stops it from unlocking this vault file from now on. It
doesn't change the master key, so someone who already unlocked the vault,
or kept an older copy of the file, can still read what that copy holds. For
full revocation, run `nullguard rekey` (see below).

## Desktop app

`nullguard-desktop` is a separate Rust application built with egui. It uses
the same vault format and engine as the CLI. Its controls look consistent
across operating systems; file selection uses your OS's native dialog.

1. Choose **Create a vault…**, select a location, size, and password, then
   choose **Create and unlock**. Creating a vault reserves its full size on
   disk and fills it with random data; progress and cancellation are available.
2. For an existing vault, choose **Open a vault…**, then enter its password
   or select its keyfile and choose **Unlock vault**.
3. The app chooses an available mount location and opens your file manager.
   Work with the files normally, then choose **Lock vault**. Wait for
   **Locked** before removing storage.

Closing the window locks open vaults and waits for their writes to finish.
If a vault is busy, close the files using it and retry **Lock vault**. When
your desktop supports a tray or menu-bar icon, its menu offers **Show
Nullguard**, **Lock all vaults**, and **Lock and quit**. **Hide to tray / menu
bar** keeps vaults open; it does not lock them.

The app remembers vault locations, but never saves passwords or keyfile
locations. It sends credentials to a worker process through a private pipe,
with no credentials in process arguments or environment variables. Slow
operations run in these workers. **Locked** appears only after the worker
exits. OS and input-method buffers are outside the app's memory-wiping
guarantees, as with other desktop password fields.

**Advanced** offers read-only unlocking and an integrity check. Password
changes, keyfile generation and management, rekeying, and offline file
operations currently use the [CLI](#commands).

Download builds from the successful [CI workflow's artifacts](https://github.com/jacobzymet/nullguard/actions/workflows/ci.yml):
choose the `nullguard-desktop-…` artifact for your OS. These builds are
currently unsigned; macOS builds are not notarized.

### Desktop on Linux

Install your distribution's `fuse3` package, with `/dev/fuse` enabled. Extract
the downloaded archive and run it from your desktop session:

```bash
tar -xzf nullguard-desktop-linux.tar.gz
./nullguard-desktop
```

The GUI needs the system's usual X11 or Wayland and OpenGL libraries; it is
not the fully static musl CLI build. File dialogs on Linux use an XDG desktop
portal; install your desktop's portal backend if dialogs do not open.
Tray availability depends on the desktop environment.

The dependency audit currently reports maintenance warnings for
`zbus_names`, `zvariant`, and `zvariant_derive` in Linux accessibility and
tray dependencies. Their functionality moved into zbus 6; upstream
integration crates still use the older versions. These are maintenance
warnings, with no known vulnerability advisory reported by the scan. CI
continues to check the full lockfile and fails on known vulnerabilities.

To build and launch from source, install Rust **1.95 or newer** and run from
the repository root:

```bash
cargo run -p nullguard-desktop --release --locked
```

### Desktop on macOS

Install [macFUSE](https://macfuse.github.io/) and complete its installation
steps first. Unzip `Nullguard-macos.zip` and open `Nullguard.app`. An unsigned
build may require approval in **System Settings → Privacy & Security**.

To build and launch from source with Rust **1.95 or newer** and macFUSE
installed, run from the repository root:

```bash
cargo run -p nullguard-desktop --release --locked
```

### Desktop on Windows

Install [WinFsp 2.x](https://winfsp.dev/), then open
`nullguard-desktop.exe`. Each unlocked vault receives a free drive letter.
The GUI does not open a console window.

To build and launch from source with Rust **1.95 or newer**, run in
PowerShell from the repository root:

```powershell
cargo run -p nullguard-desktop --release --locked
```

### Testing the desktop app

On Linux and Windows, run `cargo test --workspace --locked` to include the
CLI and desktop tests. On macOS, use:

```bash
cargo test --workspace --locked --features nullguard/macos-no-mount,nullguard-desktop/macos-no-mount
```

Native Linux and Windows CI also test actual desktop worker creation,
mounting, saving, locking, reopening, and a disconnected parent process.
macOS CI builds the GUI and tests its offline worker operations; actual
macFUSE mounting still requires testing on a configured Mac.

## Commands

| Command | What it does |
|---|---|
| `create <vault> --size <N>` | Create a vault. `--low-memory` uses 64 MiB for the password's key derivation instead of 1 GiB. |
| `mount <vault> <mountpoint>` | Unlock and mount. See the [OS-specific quick start](#quick-start) for the mountpoint and [mount options](#mount-options) below. Runs in the foreground; Ctrl-C unmounts. |
| `unmount <mountpoint>` | Request unmounting. The mount process commits changes and reports when the vault is locked. |
| `change-password <vault>` | Re-wrap the master key under a new password (see the caveat below). `--low-memory` as for `create`. |
| `rekey <vault>` | Move the vault to a new master key and new password: old passwords, keyfiles and leaked keys stop working. Copies every file, so it needs free space for a second copy while it runs. Keyfiles must be added again afterwards. `--low-memory` as for `create`. |
| `keygen <file>` | Create a keyfile (never overwrites). |
| `add-keyfile <vault> <keyfile>` | Let a keyfile unlock the vault (up to 16). |
| `remove-keyfile <vault> <keyfile>` | Stop a keyfile from unlocking the vault. `--all` removes every keyfile. |
| `info <vault>` | Show header parameters (no password; not authenticated). |
| `verify <vault>` | Unlock and authenticate both header copies, both superblocks, the metadata and every block. Fails (non-zero exit) on *any* problem or warning. |
| `ls`, `get`, `put`, `rm`, `mkdir` | Work with files without mounting. |

### Mount options

| Option | Linux | macOS | Windows |
|---|---|---|---|
| `--keyfile <file>` | Supported | Supported | Supported |
| `--read-only` | Supported | Supported | Supported |
| `--no-exec` | Supported | Supported | Unavailable |
| `--allow-outside-links` | Supported | Supported | Unavailable; symbolic links are not shown |

### Passwords

Every command that needs a secret reads it from the terminal without echo.
`--password-stdin` reads it from standard input instead (one line per secret)
for scripting. Avoid passwords in shell history or command lines.

New passwords must be at least 12 characters (and at most 4096 bytes, after
the normalization described below). A few
random words (a diceware passphrase) is ideal: the KDF makes each guess
expensive, but nothing can save a guessable password. Passwords are Unicode
NFC-normalized before use, so a password with accents unlocks the same vault
on every OS and keyboard.

## Platform support

| Platform | Mount | Offline commands | Notes |
|---|---|---|---|
| Linux (x86_64, aarch64) | ✅ FUSE | ✅ | Pure-Rust FUSE: needs only `/dev/fuse` and the standard `fusermount3` helper (package `fuse3`, present on virtually all desktop distros). No libfuse. |
| macOS | ✅ FUSE | ✅ | Requires [macFUSE](https://osxfuse.github.io/), a system extension that can't be bundled into an app. The binary links macFUSE's libfuse, so macFUSE must be installed for it to start (`--features macos-no-mount` builds an offline-only binary without it). |
| Windows | ✅ WinFsp | ✅ | Requires [WinFsp](https://winfsp.dev) 2.x (free), installed once; other major versions are refused rather than guessed at. nullguard doesn't bundle it: it loads WinFsp from its install folder at run time, so `nullguard.exe` stays portable and only `mount` needs it. Mounts on a drive letter (`nullguard mount v.ngv X:`). Symbolic links in a vault, and names Windows can't represent, aren't shown. |

## Building a portable binary

Run these commands from the repository root. Install Rust 1.89 or newer
before building.

### Build on Linux

Build a fully static binary:

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --locked --target x86_64-unknown-linux-musl
```

The binary is `target/x86_64-unknown-linux-musl/release/nullguard`.

### Build on macOS

With macFUSE installed, build a binary with mounting support:

```bash
cargo build --release --locked
```

To build an offline-only binary that runs without macFUSE:

```bash
cargo build --release --locked --features macos-no-mount
```

Both builds write `target/release/nullguard`. The offline-only build cannot
mount vaults.

### Build on Windows

Run in PowerShell:

```powershell
cargo build --release --locked
```

The binary is `target\release\nullguard.exe`. The MSVC targets use the static
C runtime configured in `.cargo/config.toml`, so they do not need the Visual
C++ redistributable. WinFsp is loaded at run time and is needed only for
mounting.

Release builds on every OS use LTO and keep integer-overflow checks on (an
overflow aborts instead of wrapping).

### Test on Linux

Run the unit and CLI tests:

```bash
cargo test --locked
```

With FUSE available, build and run the real-mount test:

```bash
cargo build --release --locked
./scripts/mount-test.sh target/release/nullguard
```

### Test on macOS

Run the unit and CLI tests without requiring macFUSE:

```bash
cargo test --locked --features macos-no-mount
```

The automated real-mount scripts target Linux and Windows.

### Test on Windows

Run the unit and CLI tests and build the binary in PowerShell:

```powershell
cargo test --locked
cargo build --release --locked
```

For the real-mount test, install WinFsp 2.x and run the script in **Git Bash**
from the repository root:

```bash
./scripts/mount-test-windows.sh target/release/nullguard.exe
```

### Parser fuzzing

The parsers for untrusted input (header, superblock, metadata, keyfile)
have fuzz tests in `fuzz/`, which throw millions of random and malformed
inputs at each one. They need nightly Rust and
[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz), and are not part of
the nullguard binary. This example uses a Linux shell:

```bash
cd fuzz
cargo +nightly fuzz run header seeds/header -- -max_total_time=600
```

The other targets are `superblock`, `metadata` and `keyfile`.

---

## Compared with VeraCrypt

VeraCrypt is mature and has been audited, and it does things nullguard
doesn't (system/boot-drive encryption, hidden volumes).
The main differences:

| | VeraCrypt | nullguard |
|---|---|---|
| Integrity | XTS mode is unauthenticated: modified sectors decrypt to garbage silently, and blocks can be swapped or rolled back undetected | Every chunk is authenticated (AEAD) and bound to its position and exact version; tampering and rollback are detected |
| Header rollback | An old volume header backup restores old passwords/keyfiles | An old header is refused, even if a superblock is also destroyed |
| What a cloud observer sees between versions | Which 16-byte blocks changed (deterministic per sector) | Which chunks changed; rewritten data is indistinguishable from random |
| Password hashing | PBKDF2; Argon2id is also available for non-system volumes since 1.26.29 | Argon2id, 1 GiB by default (memory-hard) |
| Windows memory protections | Driver-enforced process-memory access protection and optional RAM key encryption | Restricts new process-memory handles; encrypts retained master/data keys using Windows memory protection, with page locking and wiping |
| Algorithm choice | 5 ciphers, cascades and 5 hashes; unlocking tries the combinations | One cipher, one password hash, one hash function |
| Code base | Large C/C++ and assembly, its own kernel driver, bootloader | Small Rust, user space only (on Windows, mounting uses the separately installed WinFsp driver) |
| Plausible deniability | Hidden volumes | Not offered (a vault is recognizable as one) |
| Independent audit | Yes (2016, 2020) | **Not yet** |

VeraCrypt's [current KDF documentation](https://veracrypt.io/en/Header%20Key%20Derivation.html)
describes both PBKDF2 and Argon2id. When Argon2id is selected, its default is
416 MiB and 6 passes; nullguard's default is 1 GiB and 4 passes. These
settings alone do not establish which implementation is safer overall.

## Threat model

### What nullguard protects

- **File contents, file names, directory structure, file sizes and
  timestamps** inside the vault.
- **The integrity of all of the above.** You either get back exactly what you
  stored, or an error saying the vault was modified.

### Adversaries and guarantees

**1. Someone who gets a copy of the vault file** (stolen laptop or USB
stick, cloud sync provider, backup operator, border search of a locked device).

- Learns nothing about the contents beyond what's listed under *What leaks*
  below.
- Must guess the password, and every guess costs a full Argon2id evaluation
  (default **1 GiB of memory, 4 passes, 4 lanes**; with `--low-memory`,
  64 MiB and 3 passes). That makes GPU/ASIC cracking expensive and parallel
  guessing memory-bound. A strong passphrase is still essential.
- Keyfile slots can't be brute-forced at all: they need the 256-bit keyfile.

**2. Someone who can modify the vault file while it is locked** (malicious
cloud storage, an "evil maid" with access to the file, a compromised backup).

- **Changes to stored files and metadata are detected.** Each allocated
  chunk is AEAD-authenticated with its
  vault ID and position as associated data, so flipped bits, moved chunks and
  chunks copied from another vault are rejected.
  Unused random space and superseded chunks are not authenticated by the
  current filesystem state; changes to those bytes are not necessarily
  detected. Truncated containers and extra trailing bytes are refused.
- **Rollback of individual chunks is detected.** The authenticated metadata
  records the exact nonce each data chunk must have, so restoring an older
  (validly encrypted) version of a chunk fails.
- **The header can't be altered** (weaker KDF parameters, injected key
  slots, changed geometry). Each key slot is bound to the vault ID and
  geometry, the KDF parameters and salt are inputs to the password's key,
  and the whole header must match the hash the filesystem recorded. A
  header copy that doesn't is never used: nullguard uses the other copy if
  that one is current, warns, and (on a writable open) restores the bad copy.
  A copy tampered to demand a costlier key derivation than nullguard ever
  sets up is warned about before unlocking, and is tried last, so it can't
  stall unlocking while the other copy is intact.
- **An old header can't be put back.** Every commit records the hash of the
  header in use, and a header change commits to *both* superblock slots.
  Restoring an older, authentic header (to revive a removed keyfile or an
  old password) is refused, even if one superblock is also destroyed. (If a
  crash interrupts a header change between its two commits, one superblock
  still names the old header until the next writable open, which finishes
  the change; until then, destroying the newest superblock could bring the
  old header back.)
- **Destroying the newest commit** (corrupting the newest superblock to force
  the previous one) is detected and reported as a warning. It rolls back at
  most one commit, and never to a previous header. Putting an *older copy*
  of that superblock back instead is not detected: the result is exactly the
  vault as it was one commit earlier, so it falls under the next point.
- **Not prevented:** rolling the *whole* vault back to an earlier, internally
  consistent state, for example by restoring an older copy of the entire
  file. Without trusted state outside the vault, no offline encryption
  format can detect that, and nullguard deliberately keeps no such state:
  it would tie a vault to one computer. Mixing old and new parts
  (header, superblocks, metadata, data blocks) is detected.
  Deleting or destroying the vault can't be prevented either: keep backups.
- **Failures never save half-done work.** Changes become durable only through
  an explicit commit after an operation succeeded. A command that fails
  partway (an error, a typo'd path, a full vault) or hits an internal error
  (a panic) leaves the vault exactly at its last commit: `put`, `rm` and
  `mkdir` are all-or-nothing, so a failed `put --force` keeps the original
  file. (Replacing a file therefore needs room for both copies until the
  command finishes.) Password and keyfile changes take effect at a single
  commit too. A mounted vault commits every few seconds, like a normal
  drive. An I/O error at the moment of committing stops all further writes
  for that session rather than risk reusing space the disk may still
  reference.

**3. Someone who observes the vault file over time** (e.g. every version
synced to the cloud).

- Sees *which* chunks changed between versions and roughly how much was
  written, but not what was written. Written chunks are indistinguishable
  from the random fill of unused space. Every commit rewrites the whole
  metadata, so its size (which grows with the number of files and blocks)
  can be estimated too.

**4. A future quantum computer.**

- There is no public-key cryptography to break. All keys are 256-bit
  symmetric keys (128-bit security against Grover's algorithm), or derived
  from the password with Argon2id. A "harvest now, decrypt later" attacker
  gains nothing from a quantum computer beyond Grover's square-root speedup.

**5. Other users and processes on the same machine while the vault is mounted.**

#### Safeguards on all platforms

- Vault files, keyfiles and exported files are private from the moment they
  are created. Keyfiles that other users can read are refused. The exact
  permission rules are described for each OS below.
- The vault file is locked while open, so two nullguard processes cannot
  corrupt it. Every mounted file is presented as owned by the mounting user;
  vaults do not store file owners.
- Keys live in memory pages locked against swapping and are wiped
  (`zeroize`) when no longer needed. If memory locking fails, nullguard
  reports it. Argon2's working memory and the file names held by the
  filesystem, listings and lookups are wiped when no longer needed, but
  are too large to lock: use encrypted swap.
- Retained vault master/data keys stay encrypted in RAM on Windows, Linux
  and macOS. Operations decrypt separate temporary copies and wipe them
  afterwards, including on failure or panic. Protection failures stop the
  operation without a plaintext fallback. Passwords, keyfile credentials
  and decrypted file caches are outside this encryption boundary. See
  [RAM key protection](docs/ram-key-protection.md) for the mechanisms and limits.
- `--password-stdin` reads from the raw input handle into a wiped buffer,
  so the password does not remain in the standard input buffer while a
  vault is mounted.
- Failed copies remove their incomplete output. With `get --force`, the
  existing destination stays intact until every block authenticates and
  the new file is synced, then it is replaced atomically. A failed `put`
  removes its incomplete file from the vault. `get` never writes through
  symbolic links or merges a vault folder into a local folder owned by
  another user. The destination parent named on the command line may
  belong to anyone, such as `/tmp`; new entries inside it remain private.
  `put` copies regular files and folders only, skips links, named pipes,
  sockets and devices, and checks each entry after opening it without
  following links.

#### Linux protections

- The FUSE mount is accessible only to the mounting user (`allow_other`
  is not enabled). Even root gets permission denied through the mount,
  although root can read process memory; see *Out of scope*.
- The kernel enforces file permission bits (`default_permissions`). The
  mount uses `nodev,nosuid`; `--no-exec` adds `noexec`. `chown` has no effect
  because owners are not stored. Mounting over a non-empty folder is refused.
- New vaults, keyfiles and exported files use mode `0600`; exported folders
  use `0700`. Permissions on FAT-formatted storage depend on its mount
  options.
- Core dumps are disabled. The process is marked non-dumpable, blocking
  `ptrace` and `/proc/<pid>/mem` access by other processes of the same user.
- RAM-wrapping keys use dedicated, strictly locked pages, inaccessible
  between encryption/decryption operations and surrounded by guard pages.
  The kernel excludes these mappings from ordinary core dumps and fork
  children. Failure to lock or protect them stops the operation.
- `get` holds destination folders open and uses directory-relative,
  no-follow operations, preventing a folder-to-link swap from redirecting
  output. `put` lists and enters source folders through their open handles.
  Ctrl-C and SIGTERM commit changes and unmount.

#### macOS protections

- The FUSE mount is accessible only to the mounting user (`allow_other`
  is not enabled). The kernel enforces file permission bits
  (`default_permissions`). The mount uses `nodev,nosuid`; `--no-exec` adds
  `noexec`. `chown` has no effect because owners are not stored. Mounting
  over a non-empty folder is refused.
- New vaults, keyfiles and exported files use mode `0600`; exported folders
  use `0700`.
- Core dumps are disabled. Debugger attachment is refused with
  `PT_DENY_ATTACH`.
- RAM-wrapping keys use dedicated, strictly locked pages, inaccessible
  between encryption/decryption operations and surrounded by guard pages.
  These mappings are excluded from fork children and request wired-page
  zeroing on deallocation. Failure to lock or protect them stops the operation.
- `get` holds destination folders open and uses directory-relative,
  no-follow operations, preventing a folder-to-link swap from redirecting
  output. `put` lists and enters source folders through their open handles.
  Ctrl-C and SIGTERM commit changes and unmount.

#### Windows protections

- Each mounted file and folder has a fixed security descriptor granting
  the mounting user full access and nobody else any. Opens from other
  users, low-integrity processes, app containers and restricted tokens are
  refused uniformly, whether or not the requested name exists, so those
  callers cannot probe file names. Administrators can override permissions;
  see *Out of scope*.
- The drive letter exists only in the mounting user's session. Other users
  can see the drive's size and free space. Closed files' contents are kept
  out of the standby cache. While nullguard writes to the vault file,
  other programs cannot open, rename or delete it. During read-only
  commands (`ls`, `get`, `verify`), other programs may read the encrypted file.
- New vaults, keyfiles and exported files and folders receive explicit
  permissions for the current user and SYSTEM, without inheriting the
  destination folder's permissions. FAT-formatted storage has no file
  permissions and counts as readable by everyone, so keyfiles there are
  refused.
- `get` holds destination folders open so they cannot be renamed or
  replaced while copying. It refuses links, folders owned by another
  user, and file replacements through short 8.3 aliases such as
  `REPORT~1.PDF`. `put` holds each source folder on the way open.
- Before accepting credentials, the CLI, desktop app and desktop workers
  restrict new process handles to limited queries, waiting, termination
  and reading permissions. New handles for reading/writing process memory,
  injection, handle duplication and changing the process's permissions are
  refused, including for the same user. Startup fails if this restriction
  cannot be installed. This is user-space hardening, not VeraCrypt's
  driver-enforced protection: existing handles, thread-object attacks,
  administrators with debug privileges and malware running as you remain
  outside the guarantee.
- Retained vault master keys and chunk-encryption keys are encrypted in
  RAM with Windows `CryptProtectMemory`, restricted to the same process.
- Crash reports exclude heap
  memory, and a crash ends the process before a dump is taken. Mounting
  excludes `nullguard.exe` from Windows Error Reporting for the current
  user, a lasting setting under
  `HKCU\Software\Microsoft\Windows\Windows Error Reporting\ExcludedApplications`.
  Ctrl-C, closing the console, logging off and shutting down trigger
  commit and unmount. Windows allows only a few seconds for the final
  commit on console close, logoff and shutdown.

### Out of scope

nullguard can't protect you against:

- **Malware or an administrator/root on the machine while the vault is
  unlocked.** They can read the mounted files and the process memory.
- **Keyloggers, a compromised OS, or a tampered nullguard binary.** Verify
  release checksums and build from source if in doubt.
- **Physical attacks on a running, unlocked machine** (cold boot, DMA).
- **Plaintext copies made outside the vault**: the OS page cache, swap
  (use encrypted swap), editor temp files, thumbnails, files you `get`.
- **Coercion.** There are no hidden volumes or plausible deniability. A
  vault is recognizable as a nullguard vault (it has a magic number and
  version).
- **Secure deletion.** Deleting a file frees its chunks, but their old
  ciphertext stays on disk until the space is reused. Anyone who later gets
  the vault's key (e.g. your password) can recover deleted files, and the
  names of deleted files and folders (from superseded metadata), from an
  old or current copy. `rekey` copies only the files you still have into a
  new vault file, so deleted files don't come along; the old file's bytes
  may still survive on the disk itself (SSDs, copy-on-write filesystems,
  backups).

### What leaks

Even to an attacker with the vault file, these are visible by design:

- That the file is a nullguard vault, its version number, and its total size.
  (While a vault is mounted on Windows, other local users can also see how
  much of it is free.)
- The chunk size, the password's Argon2id parameters, and how many keyfiles
  can unlock it (but nothing that identifies them).

### Trust between people sharing a vault

Sharing a vault means giving someone a keyfile (or the password). Everyone
who can unlock a vault holds the same master key, so each of them can read
and change everything, including the header: a co-owner can add or remove
keyfiles or change the password, and nullguard can't prevent that. Share a
vault only with people you'd trust with the data itself. nullguard does
treat a vault's *contents* as untrusted input, though. File names are
shown with control and bidi-override characters escaped, so a planted name
can't inject terminal escape sequences or impersonate another name. Names
that would be unsafe on the local OS are refused by `get`. Unix filename
bytes are preserved during `put` and `get`; names that cannot be represented
on Windows are refused instead of silently changed. Recursive
commands stop at 1024 levels of nesting. A mounted vault doesn't follow
symbolic links that lead out of it (to an absolute path, or up past the
vault's root, also by way of other links): otherwise someone who can write
to the vault could plant a link such as `Documents -> /tmp/drop`, and what
you save "into the vault" would land outside it in plaintext, or editing a
vault file would change one of your own. `mount --allow-outside-links`
follows them anyway, for links you made on purpose. (`get` and `put` never
follow links, and Windows doesn't show them.)

### Changing a password: what it does and doesn't do

`change-password` re-wraps the master key; it doesn't re-encrypt data. Anyone
who has an **old copy** of the vault file *and* the **old password** can still
decrypt that old copy, and with it, recover the master key. If you change
your password because it was compromised, use `rekey` instead. Also note
that overwriting the header on SSDs and copy-on-write filesystems doesn't
guarantee the old bytes are physically erased.

### Rekeying

`rekey` replaces the master key itself. It creates a new vault next to the
old one (`<vault>.rekey-tmp`, same capacity, new random master key, your
new password), copies every file, directory and symlink across with their
permissions and times, authenticates every block of the copy, and then
replaces the old vault file with the new one in a single rename. If
anything fails before that rename, the new file is deleted and the old
vault is unchanged. The vault stays locked against other nullguard
processes for the whole copy.

Afterwards the old password, the old keyfiles and the old master key no
longer open the vault file. Copies of the file made *before* the rekey are
unaffected: they still open with the old credentials and still hold what
they held then. A rekeyed vault is simply a new vault with the same files,
in the current format.

---

## Cryptographic design

nullguard implements **no cryptographic primitives**. Everything comes from
established, audited crates, and their wiring is checked against official
test vectors (XChaCha20-Poly1305: draft-irtf-cfrg-xchacha A.3.1; Argon2id:
RFC 9106 §5.3; HMAC-SHA256: RFC 4231).

| Purpose | Algorithm | Crate | Assurance |
|---|---|---|---|
| Encryption | XChaCha20-Poly1305 | `chacha20poly1305` | RustCrypto; audited by NCC Group (2020) |
| Password KDF | Argon2id v1.3 | `argon2` | RustCrypto; widely deployed |
| Key derivation, MAC, hashing | HKDF-SHA256, HMAC-SHA256, SHA-256 | `hkdf`, `hmac`, `sha2` | RustCrypto |
| Memory hygiene | zeroize, mlock | `zeroize`, `region` | |

### Key hierarchy

```text
password ──Argon2id(salt, m, t, p)──────────────────► KEK ──┐
keyfile  ──HKDF-SHA256(salt = vault ID)─────────────► KEK ──┴─ XChaCha20-Poly1305 unwrap ─► master key (256-bit, random)
                                                                                                │
                                                     HKDF-SHA256(master, "nullguard/v2/data-key") ─► data key
```

The master key is random and never derived from the password, so changing
the password or adding a keyfile doesn't touch the data.

### Nonces: never reused

Every chunk write gets a **fresh random 192-bit nonce** from the OS CSPRNG,
which XChaCha20-Poly1305 takes natively. There's no counter that could
repeat after a crash, a restored backup or a copied vault. The chance of a
collision is about 2⁻⁹⁶ even after 2⁴⁸ writes.

Nonces are authenticated implicitly (a different nonce fails the tag), and
the filesystem metadata records each data chunk's expected nonce, which is
what detects replayed chunks.

### Key commitment

Poly1305 isn't key-committing: without an extra check an attacker could
craft one key slot that "unlocks" under many candidate passwords at once,
and learn whether yours is among them from how the unlock fails (a
partitioning-oracle attack). Every wrapped key therefore carries an
HMAC-SHA256 commitment to its KEK, checked in constant time *before*
decrypting. HMAC-SHA256 is collision-resistant in its key, so a slot opens
under exactly one KEK. The commitment and the encryption each use their
own key derived from the KEK (HKDF-SHA256), so no key is used by two
different primitives.

---

## Vault file format

All integers are little-endian. "‖" is concatenation.

### File layout

```text
offset 0       primary header   (4096 bytes)
offset 4096    backup header    (4096 bytes, identical copy)
offset 8192    chunk 0, chunk 1, ..., chunk N-1
```

The file is exactly `8192 + N × (chunk_size + 40)` bytes. On creation the
chunk area is filled with random bytes.

### Header (4 KiB, stored twice)

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | magic `NULLGARD` |
| 8 | 2 | version = 4 (older versions are refused) |
| 10 | 16 | vault ID (random) |
| 26 | 4 | chunk size: power of two, 4 KiB to 1 MiB |
| 30 | 8 | chunk count N (≥ 16) |
| 38 | 4 / 4 / 4 | Argon2id memory (KiB), iterations, parallelism |
| 50 | 32 | Argon2id salt |
| 82 | 104 | password slot: wrapped master key |
| 186 | 2 | keyfile slot count K (0–16) |
| 188 | 104 × K | keyfile slots: wrapped master key |
| … | … | zero padding to 4096 bytes (must be zero) |

The cipher is always XChaCha20-Poly1305, so the header doesn't store it.
Parsing is strict: unknown versions, out-of-range values and non-zero
padding are rejected, so every header has exactly one valid encoding.
Argon2 parameters are capped when *reading* (≤ 4 GiB, ≤ 64 passes, ≤ 64
lanes), so a crafted vault can't exhaust memory or CPU.

**Wrapped key** (104 bytes): `nonce (24) ‖ commitment (32) ‖ ciphertext (32) ‖ tag (16)`, where

```text
enc_key          = HKDF-SHA256(prk = KEK, info = "nullguard/v4/slot-encryption-key")
commit_key       = HKDF-SHA256(prk = KEK, info = "nullguard/v4/slot-commitment-key")
aad              = "nullguard/v2/keyslot" ‖ header[0..38]
commitment       = HMAC-SHA256(commit_key, "nullguard/v2/key-commitment" ‖ nonce ‖ aad)
ciphertext ‖ tag = XChaCha20-Poly1305(enc_key, nonce, master_key, aad)
```

`header[0..38]` is the magic, version, vault ID and geometry, so a slot
works only in the vault, and with the geometry, it was made for.

**Password KEK.** `Argon2id(password, salt, m, t, p)` with a 32-byte output
and no secret or associated data. The password is in Unicode Normalization
Form C, encoded as UTF-8 (new passwords: at most 4096 bytes).

**Keyfile KEK.** `HKDF-SHA256(salt = vault ID, ikm = keyfile secret, info = "nullguard/v2/keyfile-kek")`.
Keyfile slots carry no identifier: unlocking tries each one (one HMAC per
slot), so the header doesn't reveal which keyfiles open it.

### Chunks

```text
chunk i at  8192 + i × (chunk_size + 40):   nonce (24) ‖ ciphertext (chunk_size) ‖ tag (16)
aad_i = "NGCHUNK2" ‖ vault_id (16) ‖ chunk_size (u32) ‖ i (u64)
```

### Filesystem

Chunks 0 and 1 are **superblock slots**. Every other chunk is either free
(random bytes), a metadata chunk, or a data block.

**Superblock** (plaintext of chunk 0 or 1, zero-padded to `chunk_size`):

| Size | Field |
|---|---|
| 8 | magic `NGSUPER2` |
| 8 | generation (stored in slot `generation mod 2`) |
| 32 | SHA-256 of the vault header this commit was made under |
| 8 | metadata length in bytes |
| 32 | SHA-256 of the metadata |
| 4 | extent count E |
| 12 × E | extents of metadata chunks: `start u64 ‖ length u32` |

**Metadata** (concatenated plaintext of the listed chunks, truncated to its
length, zero padding enforced):

```text
"NGMETA03" ‖ next_inode u64 ‖ inode_count u64 ‖ inode*

inode = ino u64 ‖ kind u8 (1 file, 2 dir, 3 symlink) ‖ perm u16
        ‖ (atime, mtime, ctime, crtime) each as secs i64 ‖ nanos u32
        ‖ file:    size u64 ‖ block_count u64 ‖ (index u64 ‖ chunk u64 ‖ nonce (24))*
        ‖ dir:     parent u64 ‖ entry_count u32 ‖ (name_len u16 ‖ name ‖ ino u64)*
        ‖ symlink: len u32 ‖ target
```

A file lists only the blocks it stores, by strictly increasing index; the
rest are holes (zeros). So a small write far past the end of a file costs
one entry, not one per block in between.

The metadata is validated as untrusted input even though it's
authenticated: the root is inode 1, every inode is linked exactly once,
parent links are correct, there are no unreachable cycles, names are valid,
and every chunk is in range and referenced at most once. Bytes past a
file's end in its last block are unspecified (shrinking a file never
rewrites data, so it works even on a full vault). They are never returned
by reads, and are zeroed before the file grows over them. A file's size
can't exceed the vault's capacity.

### How it is all authenticated

```text
key slot (AEAD + commitment) ─► master key ─► superblock (AEAD)
    ├─► SHA-256 of the header   → the header in use must match it exactly
    └─► SHA-256 of the metadata → per-block chunk index and nonce → chunk AEAD
```

**Opening.** A header copy is used only if it parses, unlocks with the
given password or keyfile, *and* its SHA-256 equals the one recorded in the
newest readable superblock. The filesystem then loads the newest superblock
whose metadata verifies, but only among superblocks recording that same
header hash: it never falls back to a superblock made under another header.
If the other header copy differs, the user is warned, and a writable open
restores it from the header in use.

**Header changes** (password change, keyfile added or removed):

1. Write the new header to the backup copy, then fsync. A crash here
   changes nothing: the old header is still the current one.
2. Commit the filesystem **twice**, recording the new header's hash in both
   superblock slots. The first commit is the moment the change takes
   effect; after the second, no superblock names the old header.
3. Write the new header to the primary copy, then fsync. A crash before
   this leaves a stale primary, which the next writable open restores.

**Commit protocol** (copy-on-write):

1. Modified file blocks are always written to *free* chunks. Chunks the live
   state no longer references wait in a pending list, unless they were
   allocated after the last commit, in which case they're freed at once.
2. On commit, the metadata is written to free chunks, then everything is fsynced.
3. The new superblock (generation + 1) goes into the *other* slot, then fsync.
4. Only now are the old metadata chunks and pending chunks freed.

A crash at any point leaves the previous commit intact. On open, both
superblocks are decrypted; if either fails, a warning is printed (damage or
tampering). Commits happen every ~2 s while there are changes (adaptively
less often if commits are slow), on `fsync`, and on unmount.

### Keyfiles

```text
# comments ...
nullguard-keyfile-v2:<base64( secret (32) )>
```

Keyfiles are never overwritten. See the [Linux](#linux-protections),
[macOS](#macos-protections) and [Windows](#windows-protections) permission
rules above.

---

## Code layout

```text
src/
  crypto/        wrappers over audited crates
    aead.rs        XChaCha20-Poly1305, 192-bit random nonces
    kdf.rs         Argon2id parameters and limits
    keyfile.rs     keyfile encoding and its key derivation
    secret.rs      zeroizing, page-locked key type, HKDF subkeys
  vault/         the container format
    header.rs      versioned header, key slots, strict parser
    chunks.rs      authenticated chunk store
    fs.rs          copy-on-write filesystem, metadata, commits
    mod.rs         create / open / change password / keyfiles
    rekey.rs       move a vault to a new master key
  mount/         OS integration
    fuse.rs        FUSE (Linux, macOS)
    winfsp.rs      WinFsp (Windows): our own minimal bindings + adapter
  cli.rs         command line
  platform.rs    process hardening, no-follow file access for `get` and `put`,
                 Windows file permissions
  platform/
    key_memory.rs  locked, guarded Unix RAM-wrapping key pages
                 (platform code and mount/winfsp.rs contain the `unsafe`)
tests/cli.rs     end-to-end tests of the binary
scripts/mount-test.sh  real FUSE mount test (Linux)
desktop/
  src/app.rs          egui desktop interface and session states
  src/worker.rs       vault operations and mounts in isolated worker processes
  src/protocol.rs     bounded private-pipe messages, OS-native paths
  src/secret_input.rs masked password input without plaintext undo history
  src/paths.rs        private settings, mount locations, file-manager opening
  src/tray.rs         platform tray / menu-bar integration
  tests/worker.rs     real executable and native-mount integration tests
```

## Limitations and roadmap

- **An independent security audit.**
- **Incremental metadata** (a B-tree instead of rewriting all metadata per
  commit). The current design is best for vaults up to some hundreds of GB
  and up to around a million blocks per commit cycle. Larger vaults
  automatically get bigger chunks (16 KiB up to 1 MiB).
- **Resize.**

Not planned, to keep nullguard small: hidden volumes (plausible
deniability), hard links, extended attributes, and a local anti-rollback
record.

Security issues: please report them privately; see [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
