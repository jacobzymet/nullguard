# nullguard

**Encrypted vaults that mount as drives.** A small, open-source,
quantum-resistant alternative to VeraCrypt, written in Rust.

A nullguard vault is a single ordinary file. Unlock it with a password or a
keyfile and it appears as a normal folder. Everything inside (file contents,
names, sizes, directory structure) is encrypted and authenticated. Lock it,
and it's an opaque blob that detects any tampering.

- **One portable binary.** No installer, no runtime, no DLLs, no kernel
  driver. Copy `nullguard` (or `nullguard.exe`) onto a USB stick next to
  your vault and go.
- **Audited cryptography.** XChaCha20-Poly1305 for data, Argon2id for
  passwords and SHA-256 for hashing, all from audited Rust crates.
- **Tamper-evident.** Every byte is authenticated. Modified, moved, swapped
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

---

## Contents

- [Quick start](#quick-start)
- [Upgrading from 0.1](#upgrading-from-01)
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

```bash
# Create a 10 GiB vault (you'll be asked for a password, twice).
nullguard create secrets.ngv --size 10G

# Mount it (Linux/macOS). The vault stays unlocked until you unmount.
mkdir ~/vault
nullguard mount secrets.ngv ~/vault

# ... use ~/vault like any folder ...

# Lock it again (or press Ctrl-C in the mount terminal).
nullguard unmount ~/vault
```

Without mounting (works everywhere, including Windows today):

```bash
nullguard put secrets.ngv ./taxes /            # copy a folder in
nullguard ls  secrets.ngv /taxes
nullguard get secrets.ngv /taxes/2025.pdf .    # copy a file out
nullguard verify secrets.ngv                   # check every block's integrity
```

Keyfiles (for scripts, a recovery key, or a second person):

```bash
nullguard keygen usb/recovery.key            # a random 256-bit key, mode 0600
nullguard add-keyfile secrets.ngv usb/recovery.key
nullguard mount secrets.ngv ~/vault --keyfile usb/recovery.key
nullguard remove-keyfile secrets.ngv usb/recovery.key
nullguard remove-keyfile secrets.ngv --all   # lost a keyfile? remove them all
```

A keyfile **is** a key: anyone holding it can unlock every vault it was
added to, with no password. Keep it somewhere separate from the vault (a USB
stick, a printout in a safe). Every vault always has exactly one password
as well, which keyfile changes never touch.

Removing a keyfile stops it from unlocking this vault file from now on. It
doesn't change the master key, so someone who already unlocked the vault,
or kept an older copy of the file, can still read what that copy holds. For
full revocation, copy your files into a new vault.

## Upgrading from 0.1

nullguard 0.2 can't open vaults made by 0.1. To move a vault over, use the
old binary to copy the files out and the new one to copy them in:

```bash
nullguard-0.1 get old.ngv / ./plain       # mind where plaintext lands
nullguard create new.ngv --size 10G
nullguard put new.ngv ./plain /
```

Old public-key keyfiles (`keygen` from 0.1) don't work with 0.2: create new
keyfiles with `nullguard keygen`.

## Commands

| Command | What it does |
|---|---|
| `create <vault> --size <N>` | Create a vault. `--low-memory` uses 64 MiB for the password's key derivation instead of 1 GiB. |
| `mount <vault> <dir>` | Unlock and mount. `--keyfile`, `--read-only`, `--no-exec`. Runs in the foreground; Ctrl-C unmounts. |
| `unmount <dir>` | Unmount and lock (commits all changes first). |
| `change-password <vault>` | Re-wrap the master key under a new password (see the caveat below). `--low-memory` as for `create`. |
| `keygen <file>` | Create a keyfile (never overwrites). |
| `add-keyfile <vault> <keyfile>` | Let a keyfile unlock the vault (up to 16). |
| `remove-keyfile <vault> <keyfile>` | Stop a keyfile from unlocking the vault. `--all` removes every keyfile. |
| `info <vault>` | Show header parameters (no password; not authenticated). |
| `verify <vault>` | Unlock and authenticate both header copies, both superblocks, the metadata and every block. Fails (non-zero exit) on *any* problem or warning. |
| `ls`, `get`, `put`, `rm`, `mkdir` | Work with files without mounting. |

Every command that needs a secret reads it from the terminal without echo.
`--password-stdin` reads it from standard input instead (one line per secret)
for scripting. Avoid passwords in shell history or command lines.

New passwords must be at least 12 characters (and at most 4096 bytes). A few
random words (a diceware passphrase) is ideal: the KDF makes each guess
expensive, but nothing can save a guessable password. Passwords are Unicode
NFC-normalized before use, so a password with accents unlocks the same vault
on every OS and keyboard.

Inside a mounted vault, every file appears owned by you, the user who
mounted it, whatever machine or OS created it (like a USB stick). File
permission bits are kept and enforced. `chown` has no effect.

## Platform support

| Platform | Mount | Offline commands | Notes |
|---|---|---|---|
| Linux (x86_64, aarch64) | ✅ FUSE | ✅ | Pure-Rust FUSE: needs only `/dev/fuse` and the standard `fusermount3` helper (package `fuse3`, present on virtually all desktop distros). No libfuse. |
| macOS | ✅ FUSE | ✅ | Requires [macFUSE](https://osxfuse.github.io/), a system extension that can't be bundled into an app. The binary links macFUSE's libfuse, so macFUSE must be installed for it to start (`--features macos-no-mount` builds an offline-only binary without it). |
| Windows | ⏳ planned (WinFsp) | ✅ | Until then use `put`/`get`/`ls`/`rm`/`mkdir`. |

## Building a portable binary

```bash
# Linux: fully static binary (runs on any distro)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl

# Windows: static C runtime (configured in .cargo/config.toml), no VC++ redistributable
cargo build --release

# macOS
cargo build --release
```

Release builds use LTO and keep integer-overflow checks on (an overflow is a
security bug, so it aborts instead of wrapping). Run the tests with `cargo test`
and the real-mount test with `scripts/mount-test.sh target/release/nullguard`
(Linux, needs FUSE).

---

## Compared with VeraCrypt

VeraCrypt is mature and has been audited, and it does things nullguard
doesn't (system/boot-drive encryption, hidden volumes, Windows mounting).
The main differences:

| | VeraCrypt | nullguard |
|---|---|---|
| Integrity | XTS mode is unauthenticated: modified sectors decrypt to garbage silently, and blocks can be swapped or rolled back undetected | Every chunk is authenticated (AEAD) and bound to its position and exact version; tampering and rollback are detected |
| Header rollback | An old volume header backup restores old passwords/keyfiles | An old header is refused, even if a superblock is also destroyed |
| What a cloud observer sees between versions | Which 16-byte blocks changed (deterministic per sector) | Which chunks changed; rewritten data is indistinguishable from random |
| Password hashing | PBKDF2 by default (not memory-hard: cheap on GPUs) | Argon2id, 1 GiB by default (memory-hard) |
| Algorithm choice | 5 ciphers, cascades and 5 hashes; unlocking tries the combinations | One cipher, one password hash, one hash function |
| Code base | Large C/C++ and assembly, kernel driver, bootloader | Small Rust, user space only |
| Plausible deniability | Hidden volumes | Not offered (a vault is recognizable as one) |
| Independent audit | Yes (2016, 2020) | **Not yet** |

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

- **Any change is detected.** Every chunk is AEAD-authenticated with its
  vault ID and position as associated data, so flipped bits, moved chunks and
  chunks copied from another vault are rejected.
- **Rollback of individual chunks is detected.** The authenticated metadata
  records the exact nonce each data chunk must have, so restoring an older
  (validly encrypted) version of a chunk fails.
- **The header can't be altered** (weaker KDF parameters, injected key
  slots, changed geometry). Each key slot is bound to the vault ID and
  geometry, the KDF parameters and salt are inputs to the password's key,
  and the whole header must match the hash the filesystem recorded. A
  header copy that doesn't is never used: nullguard uses the other copy if
  that one is current, warns, and (on a writable open) restores the bad copy.
- **An old header can't be put back.** Every commit records the hash of the
  header in use, and a header change commits to *both* superblock slots.
  Restoring an older, authentic header (to revive a removed keyfile or an
  old password) is refused, even if one superblock is also destroyed.
- **Destroying the newest commit** (corrupting the newest superblock to force
  the previous one) is detected and reported as a warning. It rolls back at
  most one commit, and never to a previous header. Putting an *older copy*
  of that superblock back instead is not detected: the result is exactly the
  vault as it was one commit earlier, so it falls under the next point.
- **Not prevented:** rolling the *whole* vault back to an earlier, internally
  consistent state, for example by restoring an older copy of the entire
  file. Without trusted state outside the vault, no offline encryption
  format can detect that (see the roadmap). Mixing old and new parts
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
  from the random fill of unused space.

**4. A future quantum computer.**

- There is no public-key cryptography to break. All keys are 256-bit
  symmetric keys (128-bit security against Grover's algorithm), or derived
  from the password with Argon2id. A "harvest now, decrypt later" attacker
  gains nothing from a quantum computer beyond Grover's square-root speedup.

**5. Other users and processes on the same machine while the vault is mounted.**

- The mount is only accessible to the user who mounted it (no `allow_other`).
  That includes root: on Linux, even root gets "permission denied" (it could
  still read the process's memory, see *Out of scope*). The kernel enforces
  file permissions (`default_permissions`), and the mount is `nodev,nosuid`
  (`--no-exec` adds `noexec`). nullguard refuses to mount over a non-empty
  folder, which would hide its contents. Ctrl-C and SIGTERM (e.g. at shutdown)
  commit and unmount cleanly.
- On Linux and macOS, vault files and keyfiles are created readable only by
  their owner (`0600`), so other local users can't even copy them to attack
  offline. Keyfiles that other users can read are refused, as ssh does with
  private keys. On Windows, files get the permissions of the folder they're
  created in (your user profile is private by default); keep vaults and
  keyfiles there or in another folder only you can read.
- Keys live in memory pages locked against swapping and are wiped
  (`zeroize`) when no longer needed. If the OS refuses to lock memory,
  nullguard says so. Argon2's working memory (from which the derived key
  could otherwise be recomputed) and file names are wiped too, but they are
  too large to lock, so they can reach unencrypted swap: use encrypted swap.
  Core dumps are disabled. On Linux the process is marked non-dumpable, which
  also blocks `ptrace` and `/proc/<pid>/mem` access by other processes of the
  same user. On macOS it refuses debugger attachment (`PT_DENY_ATTACH`).
- The vault file is locked while open, so two nullguard processes can't
  corrupt it. On Windows, while nullguard writes to a vault no other program
  can open, rename or delete it. During read-only commands (`ls`, `get`,
  `verify`) other programs may still read the (encrypted) file.
- `--password-stdin` reads straight from the raw input handle into a wiped
  buffer, so no copy of the password stays in the process's standard input
  buffer while a vault is mounted.
- Partial results never linger: a `get` that fails (e.g. on a tampered
  block) deletes the incomplete output file, and a `put` that fails removes
  the incomplete file from the vault. `get` creates output folders readable
  only by you (`0700`), never writes through a symbolic link, and with
  `--force` replaces existing files with new private ones.

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
  the vault's key (e.g. your password) can recover deleted files from an
  old or current copy. To truly destroy data, move what you keep into a new
  vault and destroy the old file and key.

### What leaks

Even to an attacker with the vault file, these are visible by design:

- That the file is a nullguard vault, its version number, and its total size.
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
that would be unsafe on the local OS are refused by `get`. Recursive
commands stop at 1024 levels of nesting.

### Changing a password: what it does and doesn't do

`change-password` re-wraps the master key; it doesn't re-encrypt data. Anyone
who has an **old copy** of the vault file *and* the **old password** can still
decrypt that old copy, and with it, recover the master key. If you change
your password because it was compromised, create a new vault and copy your
files into it. (A built-in `rekey` is on the roadmap.) Also note that
overwriting the header on SSDs and copy-on-write filesystems doesn't
guarantee the old bytes are physically erased.

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
under exactly one KEK.

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
| 8 | 2 | version = 2 |
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
aad              = "nullguard/v2/keyslot" ‖ header[0..38]
commitment       = HMAC-SHA256(KEK, "nullguard/v2/key-commitment" ‖ nonce ‖ aad)
ciphertext ‖ tag = XChaCha20-Poly1305(KEK, nonce, master_key, aad)
```

`header[0..38]` is the magic, version, vault ID and geometry, so a slot
works only in the vault, and with the geometry, it was made for.

**Password KEK.** `Argon2id(password, salt, m, t, p)` with a 32-byte output
and no secret or associated data. The password is in Unicode Normalization
Form C, encoded as UTF-8 (at most 4096 bytes).

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
"NGMETA02" ‖ next_inode u64 ‖ inode_count u64 ‖ inode*

inode = ino u64 ‖ kind u8 (1 file, 2 dir, 3 symlink) ‖ perm u16 ‖ uid u32 ‖ gid u32
        ‖ (atime, mtime, ctime, crtime) each as secs i64 ‖ nanos u32
        ‖ file:    size u64 ‖ block_count u64 ‖ block*      block = 0 u64 (hole)
                                                                  | chunk u64 ‖ nonce (24)
        ‖ dir:     parent u64 ‖ entry_count u32 ‖ (name_len u16 ‖ name ‖ ino u64)*
        ‖ symlink: len u32 ‖ target
```

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

Keyfiles are created with mode 0600 and are never overwritten.

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
  mount/         OS integration (FUSE on Linux and macOS)
  cli.rs         command line
  platform.rs    process hardening (the only module with `unsafe`)
tests/cli.rs     end-to-end tests of the binary
scripts/mount-test.sh  real FUSE mount test (Linux)
```

## Limitations and roadmap

- **An independent security audit.**
- **Fuzzing** of every parser (header, superblock, metadata, keyfile).
- **Windows mounting** via WinFsp.
- **`rekey`**: re-encrypt everything under a new master key (for compromised passwords).
- **Anti-rollback state**: an optional local record of the last seen
  commit, to detect whole-vault rollback.
- **Incremental metadata** (a B-tree instead of rewriting all metadata per
  commit). The current design is best for vaults up to some hundreds of GB
  and up to around a million blocks per commit cycle. Larger vaults
  automatically get bigger chunks (16 KiB up to 1 MiB).
- **Resize**, hard links, extended attributes.
- Hidden volumes / plausible deniability (under consideration).

Security issues: please report them privately; see [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
