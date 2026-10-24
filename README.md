# nullguard

**Encrypted vaults that mount as drives.** An open-source, post-quantum-ready
alternative to VeraCrypt, written in Rust.

A nullguard vault is a single ordinary file. Unlock it with a password or a
keyfile and it appears as a normal folder. Everything inside (file contents,
names, sizes, directory structure) is encrypted and authenticated. Lock it,
and it's an opaque blob that detects any tampering.

- **One portable binary.** No installer, no runtime, no DLLs. Copy
  `nullguard` (or `nullguard.exe`) onto a USB stick next to your vault and go.
- **Modern, conservative cryptography** from audited or formally verified
  crates: XChaCha20-Poly1305 (default) or AES-256-GCM, Argon2id, and hybrid
  ML-KEM-1024 + X25519 for keyfiles and sharing.
- **Tamper-evident.** Every byte is authenticated. Modified, moved, swapped
  or *replayed* (rolled back) blocks are detected, not silently accepted.
- **Crash-safe.** Copy-on-write with atomic commits: pulling the plug leaves
  the vault exactly as of its last commit.
- **Versioned format** so algorithms can be upgraded without breaking old vaults.

> **Status: v0.1, not yet independently audited.** The design is
> deliberately simple and heavily tested, but please keep backups and treat
> it as new software until it has had outside review.

---

## Contents

- [Quick start](#quick-start)
- [Commands](#commands)
- [Platform support](#platform-support)
- [Building a portable binary](#building-a-portable-binary)
- [Threat model](#threat-model)
- [Cryptographic design](#cryptographic-design)
- [Vault format specification (v1)](#vault-format-specification-v1)
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

Keyfiles and sharing (post-quantum hybrid public keys):

```bash
nullguard keygen alice.key                  # writes alice.key (secret) + alice.key.pub
nullguard add-recipient secrets.ngv alice.key.pub
nullguard mount secrets.ngv ~/vault --keyfile alice.key
nullguard info secrets.ngv                  # lists key slots and fingerprints
nullguard remove-recipient secrets.ngv <fingerprint>
```

Revoking a recipient stops their keyfile from unlocking this vault file from
now on. It doesn't rotate the master key, so someone who already unlocked the
vault, or kept an older copy of the file, can still read what that copy
holds. For full revocation, copy your files into a new vault.

## Commands

| Command | What it does |
|---|---|
| `create <vault> --size <N>` | Create a vault. Options: `--cipher xchacha20-poly1305\|aes-256-gcm`, `--kdf-memory <MiB>`, `--kdf-iterations`, `--kdf-parallelism`, `--chunk-size`, `--recipient <pubkey>` (repeatable), `--quick` (skip random fill). |
| `mount <vault> <dir>` | Unlock and mount. `--keyfile`, `--read-only`, `--no-exec`. Runs in the foreground; Ctrl-C unmounts. |
| `unmount <dir>` | Unmount and lock (commits all changes first). |
| `change-password <vault>` | Re-wrap the master key under a new password (see the caveat below). |
| `keygen <file>` | Create a hybrid ML-KEM-1024 + X25519 keyfile (passphrase-protected by default). |
| `add-recipient` / `remove-recipient` | Grant or revoke a keyfile's access. |
| `info <vault>` | Show header parameters and key slots (no password; not authenticated). |
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
  (default **1 GiB of memory, 4 passes, 4 lanes**). That makes GPU/ASIC
  cracking expensive and parallel guessing memory-bound. A strong passphrase
  is still essential.
- Keyfile slots can't be brute-forced at all. They need the 768-bit hybrid
  secret, and the keyfile itself is encrypted with its own Argon2id
  passphrase by default.

**2. Someone who can modify the vault file while it is locked** (malicious
cloud storage, an "evil maid" with access to the file, a compromised backup).

- **Any change is detected.** Every chunk is AEAD-authenticated with its
  vault ID and position as associated data, so flipped bits, moved chunks and
  chunks copied from another vault are rejected.
- **Rollback of individual chunks is detected.** The authenticated metadata
  records the exact nonce each data chunk must have, so restoring an older
  (validly encrypted) version of a chunk fails.
- **The header can't be altered** (cipher downgrade, weaker KDF parameters,
  injected key slots, changed geometry). Each key slot's wrap is bound to the
  vault parameters, and after unlocking, an HMAC under a master-key-derived
  key covers the entire header. A header copy that fails the MAC is never
  used: nullguard falls back to the other copy only if that one is authentic,
  and prints a security warning either way.
- **An old header can't be put back.** Every header change (new password,
  recipient added or removed) increments an authenticated header generation,
  and every filesystem commit records the generation it was made under.
  Restoring an older, authentic copy of the header (to revive a removed
  recipient or an old password) is refused on open. Of two authentic header
  copies, the newer generation is always used.
- **Destroying the newest commit** (corrupting the newest superblock to force
  the previous one) is detected and reported as a warning. It rolls back at
  most one commit. Putting an *older copy* of that superblock back instead
  is not detected: the result is exactly the vault as it was one commit
  earlier, so it falls under the next point.
- **Not prevented:** rolling the *whole* vault back to an earlier, internally
  consistent state, for example by restoring an older copy of the entire file
  (header and data together, or the header plus the previous superblock).
  Without trusted state outside the vault, no offline encryption format can
  detect that (see the roadmap). Mixing old and new parts below the
  superblock (metadata, data blocks) is detected.
  Deleting or destroying the vault can't be prevented either: keep backups.
- **Failures never save half-done work.** Changes become durable only through
  an explicit commit after an operation succeeded. A command that fails
  partway (an error, a typo'd path, a full vault) or hits an internal error
  (a panic) leaves the vault exactly at its last commit: `put`, `rm` and
  `mkdir` are all-or-nothing, so a failed `put --force` keeps the original
  file. (Replacing a file therefore needs room for both copies until the
  command finishes.) A mounted vault commits every few seconds, like a
  normal drive. An I/O error at the
  moment of committing stops all further writes for that session rather than
  risk reusing space the disk may still reference.

**3. Someone who observes the vault file over time** (e.g. every version
synced to the cloud).

- Sees *which* chunks changed between versions and roughly how much was
  written, but not what was written. Written chunks are indistinguishable
  from the random fill of unused space.

**4. A future quantum computer.**

- Data and key wrapping use 256-bit symmetric keys (128-bit security against
  Grover's algorithm).
- Keyfile and sharing slots use **hybrid ML-KEM-1024 + X25519**: an attacker
  must break both the post-quantum and the classical scheme, which defeats
  "harvest now, decrypt later".
- Password slots don't use public-key crypto at all, so their strength rests
  only on the password and Argon2id.

**5. Other users and processes on the same machine while the vault is mounted.**

- The mount is only accessible to the user who mounted it (no `allow_other`).
  That includes root: on Linux, even root gets "permission denied" (it could
  still read the process's memory, see *Out of scope*). The kernel enforces
  file permissions (`default_permissions`), and the mount is `nodev,nosuid`
  (`--no-exec` adds `noexec`). nullguard refuses to mount over a non-empty
  folder, which would hide its contents. Ctrl-C and SIGTERM (e.g. at shutdown)
  commit and unmount cleanly.
- On Linux and macOS, vault files are created readable only by their owner
  (`0600`), so other local users can't even copy them to attack offline.
  On Windows, files get the permissions of the folder they're created in
  (your user profile is private by default); keep vaults there or in another
  folder only you can read. Unencrypted keyfiles
  that other users can read are refused, as ssh does with private keys.
  Passphrase-protected keyfiles with loose permissions get a warning.
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
- **Coercion.** v1 has no hidden volumes or plausible deniability. A vault is
  recognizable as a nullguard vault (it has a magic number and version).
- **Secure deletion.** Deleting a file frees its chunks, but their old
  ciphertext stays on disk until the space is reused. Anyone who later gets
  the vault's key (e.g. your password) can recover deleted files from an
  old or current copy. To truly destroy data, move what you keep into a new
  vault and destroy the old file and key.

### What leaks

Even to an attacker with the vault file, these are visible by design:

- That the file is a nullguard vault, its format version, and its total size.
- The cipher, chunk size, Argon2id parameters, and the number and kind of key
  slots, including each keyfile recipient's fingerprint (a hash of their
  public key). That lets someone who knows a recipient's public key confirm
  they have access.
- With `--quick` (no random fill): which regions have ever been written, and
  so roughly how much data the vault holds. The default random fill hides this.

### Trust between people sharing a vault

Everyone who can unlock a vault holds the same master key, so each of them
can read and change everything, including the header. A co-owner can add or
remove key slots or change the password, and nullguard can't prevent that.
Share a vault only with people you'd trust with the data itself. nullguard
does treat a vault's *contents* as untrusted input, though. File names are
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
established crates, and their wiring is checked against official test
vectors (XChaCha20-Poly1305: draft-irtf-cfrg-xchacha A.3.1; Argon2id: RFC 9106
§5.3; HMAC-SHA256: RFC 4231).

| Purpose | Algorithm | Crate | Assurance |
|---|---|---|---|
| Data encryption (default) | XChaCha20-Poly1305 | `chacha20poly1305` | RustCrypto; audited by NCC Group (2020) |
| Data encryption (option) | AES-256-GCM | `aes-gcm` | RustCrypto; audited by NCC Group (2020) |
| Password KDF | Argon2id v1.3 | `argon2` | RustCrypto; widely deployed |
| Post-quantum KEM | ML-KEM-1024 (FIPS 203) | `libcrux-ml-kem` | Formally verified (hax/F\*: panic freedom, correctness, secret independence); used by OpenSSH and Firefox |
| Classical KEM | X25519 | `x25519-dalek` | dalek-cryptography; audited (Quarkslab 2019) |
| Key derivation, MAC | HKDF-SHA256, HMAC-SHA256 | `hkdf`, `hmac`, `sha2` | RustCrypto |
| Memory hygiene | zeroize, mlock | `zeroize`, `region` | |

### Key hierarchy

```text
password ──Argon2id(salt, m, t, p)──► KEK ──┐
keyfile  ──ML-KEM-1024 + X25519─────► KEK ──┼─ XChaCha20-Poly1305 unwrap ─► master key (256-bit, random)
                                            ┘                                     │
                                       HKDF-SHA256(master, "nullguard/v1/data-key")    ─► data key
                                       HKDF-SHA256(master, "nullguard/v1/header-mac")  ─► header MAC key
```

The master key is random and never derived from the password, so changing
the password or adding a keyfile doesn't touch the data.

### Nonces: never reused

Every chunk write gets a **fresh random 192-bit nonce** from the OS CSPRNG.
There's no counter that could repeat after a crash, a restored backup or a
copied vault. The chance of a collision is about 2⁻⁹⁶ even after 2⁴⁸ writes.

- **XChaCha20-Poly1305** takes the 192-bit nonce natively.
- **AES-256-GCM** has only a 96-bit nonce, which is too small for random
  nonces at disk scale. nullguard derives a one-time key per write:
  `k = HKDF-SHA256(data_key, "nullguard/v1/aes-256-gcm/subkey" || nonce[0..12])`,
  then encrypts with `AES-256-GCM(k, nonce[12..24])`. This is the same idea as
  XChaCha's HChaCha step (and XAES-256-GCM), and it gives AES-GCM the same
  192-bit nonce space.

Nonces are authenticated implicitly (a different nonce fails the tag), and
the filesystem metadata records each data chunk's expected nonce, which is
what detects replayed chunks.

### Hybrid KEM combiner

```text
(ct_M, ss_M) = ML-KEM-1024.Encaps(pk_M)
(ct_X, ss_X) = X25519 ephemeral-static with pk_X   (all-zero/low-order results rejected)
prk = HKDF-Extract(salt = "nullguard/v1/hybrid-kem/mlkem1024+x25519", ikm = ss_M || ss_X)
KEK = HKDF-Expand(prk, info = ct_X || ct_M || pk_X || SHA-256(pk_M), 32)
```

Both shared secrets go into the key, and the full transcript (both
ciphertexts and the recipient's keys) is bound into it, in the style of
X-Wing. ML-KEM public keys are validated (FIPS 203 modulus check) when imported.

---

## Vault format specification (v1)

All integers are little-endian. "‖" is concatenation.

### File layout

```text
offset 0          primary header   (65 536 bytes)
offset 65 536     backup header    (65 536 bytes, identical copy)
offset 131 072    chunk 0, chunk 1, ..., chunk N-1
```

The file is exactly `131072 + N × (chunk_size + 40)` bytes. On creation the
chunk area is filled with random bytes unless `--quick` is given.

### Header (64 KiB, stored twice)

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | magic `NULLGARD` |
| 8 | 2 | format version = 1 |
| 10 | 2 | cipher suite: 1 = XChaCha20-Poly1305, 2 = AES-256-GCM (with the subkey construction above) |
| 12 | 4 | flags, must be 0 |
| 16 | 16 | vault ID (random) |
| 32 | 4 | chunk size: power of two, 4 KiB to 1 MiB |
| 36 | 8 | chunk count N (≥ 16) |
| 44 | 8 | data offset = 131 072 |
| 52 | 2 | key slot count (1–32, of which at most 4 password slots) |
| 54 | 8 | header generation (≥ 1; +1 on every header change) |
| 62 | 2 | reserved, must be 0 |
| 64 | … | key slots, each `type u8 ‖ 0x00 ‖ body_len u16 ‖ body` |
| … | 32 | header MAC |
| … | … | zero padding to 65 536 bytes (must be zero) |

Parsing is strict: unknown versions, cipher IDs, slot types, KDF or KEM IDs,
non-zero reserved bytes or padding, and out-of-range values are rejected, so
every header has exactly one valid encoding. Argon2 parameters are capped
when *reading* (≤ 4 GiB, ≤ 64 passes, ≤ 64 lanes), so a crafted vault can't
exhaust memory or CPU.

**Password slot** (type 1, body 152 bytes):

| Size | Field |
|---|---|
| 1 | KDF ID = 1 (Argon2id v1.3) |
| 3 | reserved, 0 |
| 4 / 4 / 4 | memory (KiB), iterations, parallelism |
| 32 | salt |
| 104 | wrapped key: nonce (24) ‖ commitment (32) ‖ ciphertext (32) ‖ tag (16) |

**Recipient (keyfile) slot** (type 2, body 1724 bytes):

| Size | Field |
|---|---|
| 1 | KEM ID = 1 (ML-KEM-1024 + X25519, combiner above) |
| 3 | reserved, 0 |
| 16 | recipient fingerprint = SHA-256("nullguard/v1/recipient-fingerprint" ‖ pk_X ‖ pk_M)[0..16] |
| 32 | X25519 ephemeral public key (ct_X) |
| 1568 | ML-KEM-1024 ciphertext (ct_M) |
| 104 | wrapped key, as in password slots |

**Password encoding.** The Argon2id input is the password in Unicode
Normalization Form C, encoded as UTF-8 (at most 4096 bytes). The KEK is
`Argon2id(password, salt, m, t, p)` with a 32-byte output and no secret or
associated data.

**Key wrapping.**

```text
aad        = "nullguard/v1/keyslot" ‖ header[0..52] ‖ slot_type ‖ slot body up to the wrapped key
commitment = HMAC-SHA256(KEK, "nullguard/v1/key-commitment" ‖ nonce ‖ aad)
ciphertext ‖ tag = XChaCha20-Poly1305(KEK, nonce, master_key, aad)
```

On unlock the commitment is checked (in constant time) *before* decrypting.
Poly1305 isn't key-committing: without this check an attacker could craft
one slot that "unlocks" under many candidate passwords at once, and learn
whether yours is among them from how the unlock fails (a partitioning-oracle
attack). HMAC-SHA256 is collision-resistant in its key, so a slot opens under
exactly one KEK.

`header[0..52]` covers everything in the fixed header except the slot count
and reserved bytes, so slots can be added or removed without re-wrapping the others.

**Header MAC.** `HMAC-SHA256(header_mac_key, header[0..64] ‖ all encoded slots)`.
It's verified (in constant time) right after the master key is unwrapped,
before anything else is trusted. It detects modification of any field or
slot, and it makes unlocking key-committing.

**Two copies.** Headers are written backup first, then primary, each followed
by an fsync. On open, every copy that parses, unlocks and passes its MAC is a
candidate, and the one with the highest header generation is used. The user
is warned if the copies differ, if a copy fails, or if a newer copy exists
that these credentials don't open (an interrupted change, or tampering).

**Header changes and rollback.** A header change writes generation *g + 1*
to both copies, then immediately makes a filesystem commit that records
*g + 1* in the superblock. On open, if the newest valid superblock records
a header generation *greater* than the unlocked header's, the header is an
old one that was put back, and opening fails. A header *newer* than the
superblock is accepted: that's a change interrupted before its commit, and
the next commit catches up.

### Chunks

```text
chunk i at  131072 + i × (chunk_size + 40):   nonce (24) ‖ ciphertext (chunk_size) ‖ tag (16)
aad_i = "NGCHUNK1" ‖ vault_id (16) ‖ cipher_id (u16) ‖ chunk_size (u32) ‖ i (u64)
```

### Filesystem

Chunks 0 and 1 are **superblock slots**. Every other chunk is either free
(random bytes), a metadata chunk, or a data block.

**Superblock** (plaintext of chunk 0 or 1, zero-padded to `chunk_size`):

| Size | Field |
|---|---|
| 8 | magic `NGSUPER1` |
| 4 | filesystem version = 1 |
| 4 | reserved, 0 |
| 8 | generation (stored in slot `generation mod 2`) |
| 8 | header generation this commit was made under |
| 8 | metadata length in bytes |
| 32 | SHA-256 of the metadata |
| 4 | extent count E |
| 12 × E | extents of metadata chunks: `start u64 ‖ length u32` |

On open, both superblocks are decrypted. The valid one with the highest
generation whose metadata also verifies is used. If any slot fails, a warning
is printed (damage or tampering). Bytes past a file's end in its last block
are unspecified (shrinking a file never rewrites data, so it works even on a
full vault). They are never returned by reads, and are zeroed before the file
grows over them. A file's size can't exceed the vault's capacity.

**Metadata** (concatenated plaintext of the listed chunks, truncated to its
length, zero padding enforced):

```text
"NGMETA01" ‖ next_inode u64 ‖ inode_count u64 ‖ inode*

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
and every chunk is in range and referenced at most once.

**Authentication chain.** Superblock (AEAD) → SHA-256 of metadata →
per-block chunk index and nonce → chunk AEAD. Modifying, swapping or replaying
anything below the superblock is detected.

**Commit protocol** (copy-on-write):

1. Modified file blocks are always written to *free* chunks. Chunks the live
   state no longer references wait in a pending list, unless they were
   allocated after the last commit, in which case they're freed at once.
2. On commit, the metadata is written to free chunks, then everything is fsynced.
3. The new superblock (generation + 1) goes into the *other* slot, then fsync.
4. Only now are the old metadata chunks and pending chunks freed.

A crash at any point leaves the previous commit intact. Commits happen
every ~2 s while there are changes (adaptively less often if commits are
slow), on `fsync`, and on unmount.

### Keyfiles

```text
# comments ...
nullguard-secret-key-1:<base64( x25519_secret (32) ‖ mlkem_seed d‖z (64) ‖ checksum (4) )>
nullguard-encrypted-secret-key-1:<base64( m u32 ‖ t u32 ‖ p u32 ‖ salt (32) ‖ nonce (24) ‖ commitment (32) ‖ ct (96) ‖ tag (16) )>
nullguard-public-key-1:<base64( x25519_public (32) ‖ mlkem1024_public (1568) )>
```

Encrypted keyfiles use `XChaCha20-Poly1305(Argon2id(passphrase, salt, m, t, p), ...)`
with the prefix and parameters as associated data, and the same key
commitment as key slots. Secret keyfiles are created
with mode 0600 and are never overwritten.

---

## Code layout

```text
src/
  crypto/        wrappers over audited crates
    aead.rs        cipher suites, 192-bit nonces, AES-GCM subkeys
    kdf.rs         Argon2id parameters and limits
    hybrid.rs      ML-KEM-1024 + X25519 KEM, keyfile encoding
    secret.rs      zeroizing, page-locked key type, HKDF subkeys
  vault/         the container format
    header.rs      versioned header, key slots, MAC, strict parser
    chunks.rs      authenticated chunk store
    fs.rs          copy-on-write filesystem, metadata, commits
    mod.rs         create / open / change password / recipients
  mount/         OS integration (FUSE on Linux and macOS)
  cli.rs         command line
  platform.rs    process hardening (the only module with `unsafe`)
tests/cli.rs     end-to-end tests of the binary
scripts/mount-test.sh  real FUSE mount test (Linux)
```

## Limitations and roadmap

- **Windows mounting** via WinFsp.
- **`rekey`**: re-encrypt everything under a new master key (for compromised passwords).
- **Anti-rollback state**: an optional local record of the last seen
  generation, to detect whole-vault rollback.
- **Incremental metadata** (a B-tree instead of rewriting all metadata per
  commit). The current design is best for vaults up to some hundreds of GB
  and up to around a million blocks per commit cycle. Larger vaults
  automatically get bigger chunks (16 KiB up to 1 MiB).
- **Resize**, hard links, extended attributes.
- Hidden volumes / plausible deniability (under consideration).
- An independent security audit.

Security issues: please report them privately; see [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
