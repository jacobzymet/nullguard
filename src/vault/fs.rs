//! The filesystem stored inside a vault.
//!
//! Design (see README "Vault format" for the byte layout):
//!
//! * Chunks 0 and 1 are two **superblock** slots. A commit writes the slot
//!   the current one isn't in, so a torn write can never destroy the last
//!   good state. The valid superblock with the highest generation wins.
//! * The superblock points to the **metadata blob** (directory tree, inode
//!   attributes, and for every data block its chunk index *and nonce*) and
//!   holds its SHA-256. Since superblocks are authenticated chunks, this
//!   gives an authentication chain superblock -> metadata -> every block.
//!   A stale copy of any block is detected (its nonce differs).
//! * Data is **copy-on-write**: a modified block is always written to a
//!   free chunk, and chunks a commit stops referencing are only reused after
//!   the next commit is durable. A crash (or yanked USB stick) leaves the
//!   vault exactly as of the last commit.
//! * Metadata lives in memory while the vault is open and is rewritten
//!   whole on each commit (every few seconds while dirty, on fsync, and on
//!   unmount).

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{NONCE_LEN, ct_eq};

use super::Error;
use super::chunks::ChunkStore;
use super::header::Reader;

pub const ROOT_INO: u64 = 1;
pub const MAX_NAME_LEN: usize = 255;
pub const MAX_SYMLINK_LEN: usize = 4095;

const SUPERBLOCK_SLOTS: u64 = 2;
const SUPER_MAGIC: &[u8; 8] = b"NGSUPER1";
const META_MAGIC: &[u8; 8] = b"NGMETA01";
const FS_VERSION: u32 = 1;
const SUPER_FIXED_LEN: usize = 8 + 4 + 4 + 8 + 8 + 8 + 32 + 4;
const EXTENT_LEN: usize = 12;

const CACHE_CAPACITY: usize = 256;
const COMMIT_INTERVAL: Duration = Duration::from_secs(2);

const KIND_FILE: u8 = 1;
const KIND_DIR: u8 = 2;
const KIND_SYMLINK: u8 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    Symlink,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp {
    pub secs: i64,
    pub nanos: u32,
}

impl Timestamp {
    pub fn now() -> Self {
        Self::from_system(SystemTime::now())
    }

    pub fn from_system(t: SystemTime) -> Self {
        let secs = |d: Duration| i64::try_from(d.as_secs()).unwrap_or(i64::MAX);
        match t.duration_since(UNIX_EPOCH) {
            Ok(d) => Self { secs: secs(d), nanos: d.subsec_nanos() },
            Err(e) => {
                let d = e.duration();
                if d.subsec_nanos() == 0 {
                    Self { secs: -secs(d), nanos: 0 }
                } else {
                    Self { secs: -secs(d) - 1, nanos: 1_000_000_000 - d.subsec_nanos() }
                }
            }
        }
    }

    /// Never panics: times the platform can't represent become the epoch.
    pub fn to_system(self) -> SystemTime {
        let base = if self.secs >= 0 {
            UNIX_EPOCH.checked_add(Duration::from_secs(self.secs as u64))
        } else {
            UNIX_EPOCH.checked_sub(Duration::from_secs(self.secs.unsigned_abs()))
        };
        base.and_then(|t| t.checked_add(Duration::from_nanos(self.nanos as u64))).unwrap_or(UNIX_EPOCH)
    }
}

/// A data block reference: which chunk holds it, and the nonce it must have.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockRef {
    pub chunk: u64,
    pub nonce: [u8; NONCE_LEN],
}

#[derive(Clone, Debug)]
pub enum Node {
    /// `blocks[i]` holds bytes `i*chunk_size ..`; `None` is a hole (zeros).
    /// Bytes past `size` in the last block are unspecified (they may hold
    /// data from before a truncate). They are never returned by reads, and
    /// are zeroed before the file grows over them (`zero_past_eof`).
    File { size: u64, blocks: Vec<Option<BlockRef>> },
    Dir { parent: u64, entries: BTreeMap<Vec<u8>, u64> },
    Symlink { target: Vec<u8> },
}

#[derive(Clone, Debug)]
pub struct Inode {
    pub perm: u16,
    pub uid: u32,
    pub gid: u32,
    pub atime: Timestamp,
    pub mtime: Timestamp,
    pub ctime: Timestamp,
    pub crtime: Timestamp,
    pub node: Node,
}

impl Inode {
    pub fn kind(&self) -> Kind {
        match self.node {
            Node::File { .. } => Kind::File,
            Node::Dir { .. } => Kind::Dir,
            Node::Symlink { .. } => Kind::Symlink,
        }
    }
}

/// Attributes as reported to the OS.
#[derive(Clone, Debug)]
pub struct Attr {
    pub ino: u64,
    pub kind: Kind,
    pub size: u64,
    /// Allocated space in 512-byte units.
    pub blocks: u64,
    pub perm: u16,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub atime: Timestamp,
    pub mtime: Timestamp,
    pub ctime: Timestamp,
    pub crtime: Timestamp,
    pub blksize: u32,
}

#[derive(Clone, Debug)]
pub struct DirEntry {
    pub name: Vec<u8>,
    pub ino: u64,
    pub kind: Kind,
}

#[derive(Clone, Debug, Default)]
pub struct SetAttr {
    pub perm: Option<u16>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub size: Option<u64>,
    pub atime: Option<Timestamp>,
    pub mtime: Option<Timestamp>,
}

#[derive(Clone, Debug)]
pub struct StatFs {
    pub block_size: u32,
    pub total_blocks: u64,
    pub free_blocks: u64,
    pub files: u64,
}

/// Result of [`Fs::verify`].
#[derive(Clone, Debug, Default)]
pub struct VerifyReport {
    pub files: u64,
    pub dirs: u64,
    pub symlinks: u64,
    pub blocks_checked: u64,
    pub bad_blocks: Vec<(String, u64, String)>,
}

struct Superblock {
    generation: u64,
    /// Generation of the vault header in use when this commit was made.
    header_generation: u64,
    meta_len: u64,
    meta_hash: [u8; 32],
    meta_chunks: Vec<u64>,
}

/// Allocation bitmap over chunk indices.
struct Bitmap {
    words: Vec<u64>,
    len: u64,
    free: u64,
    cursor: u64,
}

impl Bitmap {
    #[cfg(test)]
    fn new(len: u64) -> Self {
        Self::try_new(len).expect("bitmap allocation")
    }

    /// Fallible version: a huge (e.g. sparse, petabyte-sized) vault fails
    /// cleanly instead of aborting the process.
    fn try_new(len: u64) -> Result<Self, Error> {
        let n = usize::try_from(len.div_ceil(64)).map_err(|_| Error::NoSpace)?;
        let mut words = Vec::new();
        words
            .try_reserve_exact(n)
            .map_err(|_| Error::Corrupt("not enough memory for this vault's allocation map".into()))?;
        words.resize(n, 0);
        Ok(Self { words, len, free: len, cursor: 0 })
    }

    fn get(&self, i: u64) -> bool {
        self.words[(i / 64) as usize] & (1 << (i % 64)) != 0
    }

    /// Mark used; returns false if it already was.
    fn set(&mut self, i: u64) -> bool {
        if i >= self.len || self.get(i) {
            return false;
        }
        self.words[(i / 64) as usize] |= 1 << (i % 64);
        self.free -= 1;
        true
    }

    fn clear(&mut self, i: u64) {
        if i < self.len && self.get(i) {
            self.words[(i / 64) as usize] &= !(1 << (i % 64));
            self.free += 1;
        }
    }

    /// Next free index at or after the cursor (wrapping), marked used.
    fn alloc(&mut self) -> Option<u64> {
        if self.free == 0 {
            return None;
        }
        let nwords = self.words.len() as u64;
        let start_word = self.cursor / 64;
        for k in 0..=nwords {
            let w = (start_word + k) % nwords;
            let word = self.words[w as usize];
            if word != u64::MAX {
                let bit = (!word).trailing_zeros() as u64;
                let i = w * 64 + bit;
                if i < self.len {
                    self.set(i);
                    self.cursor = i + 1;
                    return Some(i);
                }
            }
        }
        None
    }
}

/// FIFO cache of decrypted chunks. Chunks are immutable while allocated
/// (copy-on-write), so entries never go stale; they are dropped when the
/// chunk is freed. Entries are zeroized on eviction.
struct Cache {
    map: HashMap<u64, Zeroizing<Vec<u8>>>,
    order: VecDeque<u64>,
}

impl Cache {
    fn new() -> Self {
        Self { map: HashMap::new(), order: VecDeque::new() }
    }

    fn get(&self, chunk: u64) -> Option<&[u8]> {
        self.map.get(&chunk).map(|v| v.as_slice())
    }

    fn insert(&mut self, chunk: u64, data: Zeroizing<Vec<u8>>) {
        if self.map.insert(chunk, data).is_none() {
            self.order.push_back(chunk);
        }
        while self.order.len() > CACHE_CAPACITY {
            if let Some(old) = self.order.pop_front() {
                self.map.remove(&old);
            }
        }
    }

    fn remove(&mut self, chunk: u64) {
        if self.map.remove(&chunk).is_some() {
            self.order.retain(|&c| c != chunk);
        }
    }
}

pub struct Fs {
    store: ChunkStore,
    chunk_size: u64,
    inodes: HashMap<u64, Inode>,
    next_ino: u64,
    generation: u64,
    /// Generation of the unlocked vault header, recorded in every commit.
    header_generation: u64,
    bitmap: Bitmap,
    meta_chunks: Vec<u64>,
    /// Chunks the last commit references but the live state no longer
    /// does. Freed after the next commit.
    pending_free: Vec<u64>,
    /// Chunks allocated since the last commit (safe to free immediately).
    uncommitted: HashSet<u64>,
    cache: Cache,
    open_counts: HashMap<u64, u32>,
    /// Unlinked inodes that are still open.
    orphans: HashSet<u64>,
    dirty: bool,
    last_commit: Instant,
    last_commit_took: Duration,
    /// Security-relevant observations made while opening (e.g. a damaged
    /// superblock). Callers must show these to the user.
    pub warnings: Vec<String>,
    /// Set when a commit failed after writing its superblock (see `commit_now`).
    poisoned: bool,
    /// Whether the filesystem may commit on its own: timed commits in
    /// `maybe_commit`, and commits that reclaim space when the vault is
    /// full. On for mounts; off for CLI commands, which must be
    /// all-or-nothing (see [`Fs::set_auto_commit`]).
    auto_commit: bool,
}

impl Fs {
    /// Create an empty filesystem (root directory only) and commit it to
    /// both superblock slots.
    pub fn format(store: ChunkStore, uid: u32, gid: u32, header_generation: u64) -> Result<Self, Error> {
        let mut fs = Self::empty(store, header_generation)?;
        let now = Timestamp::now();
        fs.inodes.insert(
            ROOT_INO,
            Inode {
                perm: 0o700,
                uid,
                gid,
                atime: now,
                mtime: now,
                ctime: now,
                crtime: now,
                node: Node::Dir { parent: ROOT_INO, entries: BTreeMap::new() },
            },
        );
        fs.next_ino = ROOT_INO + 1;
        fs.commit_now()?;
        fs.commit_now()?; // fill both superblock slots
        Ok(fs)
    }

    fn empty(store: ChunkStore, header_generation: u64) -> Result<Self, Error> {
        let mut bitmap = Bitmap::try_new(store.chunk_count())?;
        for i in 0..SUPERBLOCK_SLOTS {
            bitmap.set(i);
        }
        Ok(Self {
            chunk_size: store.chunk_size() as u64,
            store,
            inodes: HashMap::new(),
            next_ino: ROOT_INO + 1,
            generation: 0,
            header_generation,
            bitmap,
            meta_chunks: Vec::new(),
            pending_free: Vec::new(),
            uncommitted: HashSet::new(),
            cache: Cache::new(),
            open_counts: HashMap::new(),
            orphans: HashSet::new(),
            dirty: false,
            last_commit: Instant::now(),
            last_commit_took: Duration::ZERO,
            warnings: Vec::new(),
            poisoned: false,
            auto_commit: true,
        })
    }

    /// Open the filesystem from the newest valid superblock.
    ///
    /// `header_generation` is the generation of the vault header that was
    /// just unlocked. If the filesystem was last committed under a *newer*
    /// header, this header is an old one put back (for example to undo a
    /// password change or a recipient's removal) and opening is refused.
    pub fn open(store: ChunkStore, header_generation: u64) -> Result<Self, Error> {
        let mut fs = Self::empty(store, header_generation)?;
        let mut supers = Vec::new();
        for slot in 0..SUPERBLOCK_SLOTS {
            match fs.read_superblock(slot) {
                Ok(sb) => supers.push(sb),
                Err(e) => fs.warnings.push(format!(
                    "superblock {slot} is unreadable ({e}). This means damage or tampering; \
                     the vault may have been rolled back by one commit."
                )),
            }
        }
        supers.sort_by_key(|s| std::cmp::Reverse(s.generation));
        let mut last_err = None;
        for (i, sb) in supers.iter().enumerate() {
            if sb.header_generation > header_generation {
                // Don't fall back to an older superblock: that would help
                // the rollback succeed.
                return Err(Error::HeaderRollback { header: header_generation, recorded: sb.header_generation });
            }
            match fs.load_metadata(sb) {
                Ok(()) => {
                    if i > 0 {
                        fs.warnings.push(format!(
                            "the newest metadata (generation {}) failed verification; using generation {}. \
                             The vault was damaged or tampered with, and recent changes are lost.",
                            supers[0].generation, sb.generation
                        ));
                    }
                    return Ok(fs);
                }
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| Error::Corrupt("no valid superblock: the vault is damaged or was tampered with".into())))
    }

    fn read_superblock(&mut self, slot: u64) -> Result<Superblock, Error> {
        let mut buf = Zeroizing::new(vec![0u8; self.chunk_size as usize]);
        self.store.read(slot, None, &mut buf)?;
        let mut r = Reader::new(&buf);
        let bad = |_| Error::Corrupt("malformed superblock".into());
        if r.take(8).map_err(bad)? != SUPER_MAGIC || r.u32().map_err(bad)? != FS_VERSION || r.u32().map_err(bad)? != 0 {
            return Err(Error::Corrupt("unknown superblock format".into()));
        }
        let generation = r.u64().map_err(bad)?;
        let header_generation = r.u64().map_err(bad)?;
        let meta_len = r.u64().map_err(bad)?;
        let meta_hash = r.array::<32>().map_err(bad)?;
        let n = r.u32().map_err(bad)? as u64;
        let mut meta_chunks = Vec::new();
        for _ in 0..n {
            let start = r.u64().map_err(bad)?;
            let len = r.u32().map_err(bad)? as u64;
            let end = start.checked_add(len).filter(|&e| e <= self.store.chunk_count() && start >= SUPERBLOCK_SLOTS);
            if len == 0 || end.is_none() || meta_chunks.len() as u64 + len > self.store.chunk_count() {
                return Err(Error::Corrupt("superblock extent out of range".into()));
            }
            meta_chunks.extend(start..start + len);
        }
        if (meta_chunks.len() as u64) != meta_len.div_ceil(self.chunk_size).max(1) {
            return Err(Error::Corrupt("superblock extent length mismatch".into()));
        }
        if r.rest().iter().any(|&b| b != 0) {
            return Err(Error::Corrupt("superblock padding is not zero".into()));
        }
        Ok(Superblock { generation, header_generation, meta_len, meta_hash, meta_chunks })
    }

    fn load_metadata(&mut self, sb: &Superblock) -> Result<(), Error> {
        let cs = self.chunk_size as usize;
        let blob_len = sb.meta_chunks.len() * cs;
        let mut blob = Zeroizing::new(Vec::new());
        blob.try_reserve_exact(blob_len)
            .map_err(|_| Error::Corrupt("not enough memory to load the vault's metadata".into()))?;
        blob.resize(blob_len, 0);
        for (i, &c) in sb.meta_chunks.iter().enumerate() {
            self.store.read(c, None, &mut blob[i * cs..(i + 1) * cs])?;
        }
        if blob[sb.meta_len as usize..].iter().any(|&b| b != 0) {
            return Err(Error::Corrupt("metadata padding is not zero".into()));
        }
        blob.truncate(sb.meta_len as usize);
        if !ct_eq(&Sha256::digest(blob.as_slice()), &sb.meta_hash) {
            return Err(Error::Corrupt("metadata hash mismatch: the vault was modified".into()));
        }
        let (next_ino, inodes) = decode_metadata(&blob, self.chunk_size, self.max_file_size())?;

        // Rebuild the allocation bitmap; any chunk used twice is corruption.
        let mut bitmap = Bitmap::try_new(self.store.chunk_count())?;
        for i in 0..SUPERBLOCK_SLOTS {
            bitmap.set(i);
        }
        for &c in &sb.meta_chunks {
            if !bitmap.set(c) {
                return Err(Error::Corrupt("metadata chunk referenced twice".into()));
            }
        }
        for inode in inodes.values() {
            if let Node::File { blocks, .. } = &inode.node {
                for b in blocks.iter().flatten() {
                    if b.chunk >= self.store.chunk_count() || !bitmap.set(b.chunk) {
                        return Err(Error::Corrupt("data chunk out of range or referenced twice".into()));
                    }
                }
            }
        }
        self.inodes = inodes;
        self.next_ino = next_ino;
        self.bitmap = bitmap;
        self.generation = sb.generation;
        self.meta_chunks = sb.meta_chunks.clone();
        Ok(())
    }

    // ------------------------------------------------------------------
    // Commit
    // ------------------------------------------------------------------

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Allow or forbid commits the caller didn't ask for (on by default).
    ///
    /// With auto-commit off, nothing becomes durable until an explicit
    /// [`Fs::commit`], so an operation that fails partway (for example a
    /// `put --force` that runs out of space after replacing a file) leaves
    /// the vault exactly as it was. The cost: space held by chunks freed
    /// since the last commit can't be reused until that commit.
    pub fn set_auto_commit(&mut self, enabled: bool) {
        self.auto_commit = enabled;
    }

    /// Commit if dirty and enough time has passed (adaptive: never spend
    /// more than ~10% of the time committing). Does nothing with
    /// auto-commit off.
    pub fn maybe_commit(&mut self) -> Result<(), Error> {
        let wait = COMMIT_INTERVAL.max(self.last_commit_took * 10);
        if self.auto_commit && self.dirty && self.last_commit.elapsed() >= wait {
            self.commit_now()?;
        }
        Ok(())
    }

    /// Commit if dirty.
    /// Commit now, even with no file changes, so the superblock records the
    /// current header generation (called right after a header change).
    pub fn commit_header_change(&mut self) -> Result<(), Error> {
        self.commit_now()
    }

    pub fn commit(&mut self) -> Result<(), Error> {
        if self.dirty { self.commit_now() } else { Ok(()) }
    }

    fn commit_now(&mut self) -> Result<(), Error> {
        if self.store.is_read_only() {
            return Ok(());
        }
        self.check_writable()?;
        let started = Instant::now();
        let blob = encode_metadata(self.next_ino, &self.inodes, self.reachable());
        let cs = self.chunk_size as usize;
        let nchunks = blob.len().div_ceil(cs).max(1);

        let new_chunks = self.alloc_run(nchunks as u64)?;
        let mut superblock_attempted = false;
        let result = (|| {
            let mut buf = Zeroizing::new(vec![0u8; cs]);
            for (i, &c) in new_chunks.iter().enumerate() {
                buf.fill(0);
                let part = &blob[(i * cs).min(blob.len())..((i + 1) * cs).min(blob.len())];
                buf[..part.len()].copy_from_slice(part);
                self.store.write(c, &buf)?;
            }
            let extents = to_extents(&new_chunks);
            let max_extents = (cs - SUPER_FIXED_LEN) / EXTENT_LEN;
            if extents.len() > max_extents {
                return Err(Error::NoSpace);
            }
            let mut sb = Zeroizing::new(Vec::with_capacity(cs));
            sb.extend_from_slice(SUPER_MAGIC);
            sb.extend_from_slice(&FS_VERSION.to_le_bytes());
            sb.extend_from_slice(&0u32.to_le_bytes());
            sb.extend_from_slice(&(self.generation + 1).to_le_bytes());
            sb.extend_from_slice(&self.header_generation.to_le_bytes());
            sb.extend_from_slice(&(blob.len() as u64).to_le_bytes());
            sb.extend_from_slice(&Sha256::digest(blob.as_slice()));
            sb.extend_from_slice(&(extents.len() as u32).to_le_bytes());
            for (start, len) in &extents {
                sb.extend_from_slice(&start.to_le_bytes());
                sb.extend_from_slice(&(*len as u32).to_le_bytes());
            }
            sb.resize(cs, 0);
            // Data and metadata must be durable before the superblock
            // points at them, and the superblock before old chunks are reused.
            self.store.sync()?;
            superblock_attempted = true;
            self.store.write((self.generation + 1) % SUPERBLOCK_SLOTS, &sb)?;
            self.store.sync()?;
            Ok(())
        })();
        if let Err(e) = result {
            if superblock_attempted {
                // The new superblock may or may not be on disk. Reusing any
                // chunk now could corrupt whichever state survives, so stop
                // writing for the rest of this session.
                self.poisoned = true;
                return Err(e);
            }
            for c in new_chunks {
                self.bitmap.clear(c);
            }
            return Err(e);
        }

        self.generation += 1;
        let old_meta = std::mem::replace(&mut self.meta_chunks, new_chunks);
        for c in old_meta.into_iter().chain(std::mem::take(&mut self.pending_free)) {
            self.release_chunk(c);
        }
        self.uncommitted.clear();
        self.dirty = false;
        self.last_commit = Instant::now();
        self.last_commit_took = started.elapsed();
        Ok(())
    }

    /// Allocate `n` chunks for metadata, contiguous if possible.
    fn alloc_run(&mut self, n: u64) -> Result<Vec<u64>, Error> {
        if self.bitmap.free < n {
            return Err(Error::NoSpace);
        }
        // Look for a contiguous run first: keeps the superblock extent list short.
        let mut run_start = None;
        let mut run_len = 0;
        let mut i = SUPERBLOCK_SLOTS;
        while i < self.bitmap.len {
            if i.is_multiple_of(64) && self.bitmap.words[(i / 64) as usize] == u64::MAX {
                run_len = 0;
                run_start = None;
                i += 64;
                continue;
            }
            let used = self.bitmap.get(i);
            i += 1;
            let i = i - 1;
            if used {
                run_len = 0;
                run_start = None;
            } else {
                if run_start.is_none() {
                    run_start = Some(i);
                }
                run_len += 1;
                if run_len == n {
                    let s = run_start.expect("run start set");
                    for c in s..s + n {
                        self.bitmap.set(c);
                    }
                    return Ok((s..s + n).collect());
                }
            }
        }
        let mut out = Vec::with_capacity(n as usize);
        for _ in 0..n {
            out.push(self.bitmap.alloc().expect("free count checked"));
        }
        Ok(out)
    }

    fn release_chunk(&mut self, c: u64) {
        self.bitmap.clear(c);
        self.cache.remove(c);
    }

    /// Drop a chunk from the live state.
    fn free_chunk(&mut self, c: u64) {
        if self.uncommitted.remove(&c) {
            self.release_chunk(c); // never committed: reuse immediately
        } else {
            self.pending_free.push(c);
        }
    }

    /// Chunks kept free so the next metadata commit always fits.
    fn reserve(&self) -> u64 {
        let m = self.meta_chunks.len() as u64;
        m + m / 4 + 4
    }

    fn alloc_data_chunk(&mut self) -> Result<u64, Error> {
        if self.auto_commit && self.bitmap.free <= self.reserve() && !self.pending_free.is_empty() {
            // Free space is held by superseded chunks: commit to reclaim it.
            // (This commits mid-operation, so it's only allowed with auto-commit.)
            self.commit_now()?;
        }
        if self.bitmap.free <= self.reserve() {
            return Err(Error::NoSpace);
        }
        let c = self.bitmap.alloc().ok_or(Error::NoSpace)?;
        self.uncommitted.insert(c);
        Ok(c)
    }

    /// Inodes reachable from the root, in a deterministic order.
    fn reachable(&self) -> Vec<u64> {
        let mut out = vec![ROOT_INO];
        let mut i = 0;
        while i < out.len() {
            if let Some(Inode { node: Node::Dir { entries, .. }, .. }) = self.inodes.get(&out[i]) {
                out.extend(entries.values().copied());
            }
            i += 1;
        }
        out
    }

    // ------------------------------------------------------------------
    // Block I/O
    // ------------------------------------------------------------------

    fn read_block(&mut self, b: &BlockRef, out: &mut [u8]) -> Result<(), Error> {
        if let Some(d) = self.cache.get(b.chunk) {
            out.copy_from_slice(d);
            return Ok(());
        }
        self.store.read(b.chunk, Some(&b.nonce), out)?;
        self.cache.insert(b.chunk, Zeroizing::new(out.to_vec()));
        Ok(())
    }

    fn write_new_block(&mut self, data: &[u8]) -> Result<BlockRef, Error> {
        let chunk = self.alloc_data_chunk()?;
        match self.store.write(chunk, data) {
            Ok(nonce) => {
                self.cache.insert(chunk, Zeroizing::new(data.to_vec()));
                Ok(BlockRef { chunk, nonce })
            }
            Err(e) => {
                self.uncommitted.remove(&chunk);
                self.release_chunk(chunk);
                Err(e)
            }
        }
    }

    // ------------------------------------------------------------------
    // Queries
    // ------------------------------------------------------------------

    fn inode(&self, ino: u64) -> Result<&Inode, Error> {
        self.inodes.get(&ino).ok_or(Error::NotFound)
    }

    fn inode_mut(&mut self, ino: u64) -> Result<&mut Inode, Error> {
        self.inodes.get_mut(&ino).ok_or(Error::NotFound)
    }

    fn dir_entries(&self, ino: u64) -> Result<&BTreeMap<Vec<u8>, u64>, Error> {
        match &self.inode(ino)?.node {
            Node::Dir { entries, .. } => Ok(entries),
            _ => Err(Error::NotADirectory),
        }
    }

    pub fn lookup(&self, parent: u64, name: &[u8]) -> Result<u64, Error> {
        let entries = self.dir_entries(parent)?;
        match name {
            b"." => Ok(parent),
            b".." => match &self.inode(parent)?.node {
                Node::Dir { parent: p, .. } => Ok(*p),
                _ => unreachable!("checked above"),
            },
            _ => entries.get(name).copied().ok_or(Error::NotFound),
        }
    }

    pub fn attr(&self, ino: u64) -> Result<Attr, Error> {
        let i = self.inode(ino)?;
        let (size, used, nlink) = match &i.node {
            Node::File { size, blocks } => (*size, blocks.iter().flatten().count() as u64 * self.chunk_size, 1),
            Node::Dir { entries, .. } => {
                let subdirs = entries
                    .values()
                    .filter(|e| matches!(self.inodes.get(e).map(|n| &n.node), Some(Node::Dir { .. })))
                    .count();
                (0, 0, 2 + subdirs as u32)
            }
            Node::Symlink { target } => (target.len() as u64, 0, 1),
        };
        let nlink = if self.orphans.contains(&ino) { 0 } else { nlink };
        Ok(Attr {
            ino,
            kind: i.kind(),
            size,
            blocks: used / 512,
            perm: i.perm,
            nlink,
            uid: i.uid,
            gid: i.gid,
            atime: i.atime,
            mtime: i.mtime,
            ctime: i.ctime,
            crtime: i.crtime,
            blksize: self.chunk_size as u32,
        })
    }

    /// Directory listing including `.` and `..`.
    pub fn readdir(&self, ino: u64) -> Result<Vec<DirEntry>, Error> {
        let parent = self.lookup(ino, b"..")?;
        let mut out = vec![
            DirEntry { name: b".".to_vec(), ino, kind: Kind::Dir },
            DirEntry { name: b"..".to_vec(), ino: parent, kind: Kind::Dir },
        ];
        for (name, &child) in self.dir_entries(ino)? {
            out.push(DirEntry { name: name.clone(), ino: child, kind: self.inode(child)?.kind() });
        }
        Ok(out)
    }

    pub fn readlink(&self, ino: u64) -> Result<Vec<u8>, Error> {
        match &self.inode(ino)?.node {
            Node::Symlink { target } => Ok(target.clone()),
            _ => Err(Error::InvalidArgument),
        }
    }

    pub fn statfs(&self) -> StatFs {
        StatFs {
            block_size: self.chunk_size as u32,
            total_blocks: self.store.chunk_count(),
            free_blocks: (self.bitmap.free + self.pending_free.len() as u64).saturating_sub(self.reserve()),
            files: self.inodes.len() as u64,
        }
    }

    /// Largest file the vault could hold.
    pub fn max_file_size(&self) -> u64 {
        self.store.chunk_count() * self.chunk_size
    }

    /// Resolve an absolute `/`-separated path inside the vault (no symlink
    /// following). Used by the offline CLI commands.
    pub fn resolve(&self, path: &str) -> Result<u64, Error> {
        let mut ino = ROOT_INO;
        for part in path.split(['/', '\\']).filter(|p| !p.is_empty() && *p != ".") {
            ino = self.lookup(ino, part.as_bytes())?;
        }
        Ok(ino)
    }

    // ------------------------------------------------------------------
    // Namespace operations
    // ------------------------------------------------------------------

    fn check_writable(&self) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Corrupt("an earlier commit failed with an I/O error; remount the vault".into()));
        }
        if self.store.is_read_only() { Err(Error::ReadOnly) } else { Ok(()) }
    }

    fn touch_dir(&mut self, ino: u64) {
        if let Some(i) = self.inodes.get_mut(&ino) {
            let now = Timestamp::now();
            i.mtime = now;
            i.ctime = now;
        }
    }

    fn add_entry(&mut self, parent: u64, name: &[u8], perm: u16, uid: u32, gid: u32, node: Node) -> Result<u64, Error> {
        self.check_writable()?;
        validate_name(name)?;
        if self.dir_entries(parent)?.contains_key(name) {
            return Err(Error::Exists);
        }
        let ino = self.next_ino;
        self.next_ino = self.next_ino.checked_add(1).ok_or(Error::NoSpace)?;
        let now = Timestamp::now();
        self.inodes.insert(
            ino,
            Inode { perm: perm & 0o7777, uid, gid, atime: now, mtime: now, ctime: now, crtime: now, node },
        );
        if let Node::Dir { entries, .. } = &mut self.inode_mut(parent)?.node {
            entries.insert(name.to_vec(), ino);
        }
        self.touch_dir(parent);
        self.dirty = true;
        Ok(ino)
    }

    pub fn create_file(&mut self, parent: u64, name: &[u8], perm: u16, uid: u32, gid: u32) -> Result<u64, Error> {
        self.add_entry(parent, name, perm, uid, gid, Node::File { size: 0, blocks: Vec::new() })
    }

    pub fn mkdir(&mut self, parent: u64, name: &[u8], perm: u16, uid: u32, gid: u32) -> Result<u64, Error> {
        self.add_entry(parent, name, perm, uid, gid, Node::Dir { parent, entries: BTreeMap::new() })
    }

    pub fn symlink(&mut self, parent: u64, name: &[u8], target: &[u8], uid: u32, gid: u32) -> Result<u64, Error> {
        if target.is_empty() || target.len() > MAX_SYMLINK_LEN || target.contains(&0) {
            return Err(Error::InvalidArgument);
        }
        self.add_entry(parent, name, 0o777, uid, gid, Node::Symlink { target: target.to_vec() })
    }

    /// Remove the entry `name` from `parent` and dispose of the inode
    /// (or keep it as an orphan while it is open).
    fn detach(&mut self, parent: u64, name: &[u8]) -> Result<u64, Error> {
        let ino = self.lookup(parent, name)?;
        if let Node::Dir { entries, .. } = &mut self.inode_mut(parent)?.node {
            entries.remove(name);
        }
        self.touch_dir(parent);
        if self.open_counts.get(&ino).copied().unwrap_or(0) > 0 {
            self.orphans.insert(ino);
        } else {
            self.destroy_inode(ino);
        }
        self.dirty = true;
        Ok(ino)
    }

    fn destroy_inode(&mut self, ino: u64) {
        if let Some(Inode { node: Node::File { blocks, .. }, .. }) = self.inodes.remove(&ino) {
            for b in blocks.into_iter().flatten() {
                self.free_chunk(b.chunk);
            }
        }
    }

    pub fn unlink(&mut self, parent: u64, name: &[u8]) -> Result<(), Error> {
        self.check_writable()?;
        validate_name(name)?;
        let ino = self.lookup(parent, name)?;
        if self.inode(ino)?.kind() == Kind::Dir {
            return Err(Error::IsADirectory);
        }
        self.detach(parent, name)?;
        Ok(())
    }

    pub fn rmdir(&mut self, parent: u64, name: &[u8]) -> Result<(), Error> {
        self.check_writable()?;
        validate_name(name)?;
        let ino = self.lookup(parent, name)?;
        if !self.dir_entries(ino)?.is_empty() {
            return Err(Error::NotEmpty);
        }
        self.detach(parent, name)?;
        Ok(())
    }

    /// Rename `parent/name` to `new_parent/new_name`, replacing a compatible
    /// target (POSIX semantics) unless `no_replace`.
    pub fn rename(
        &mut self,
        parent: u64,
        name: &[u8],
        new_parent: u64,
        new_name: &[u8],
        no_replace: bool,
    ) -> Result<(), Error> {
        self.check_writable()?;
        validate_name(name)?;
        validate_name(new_name)?;
        let ino = self.lookup(parent, name)?;
        self.dir_entries(new_parent)?;
        let is_dir = self.inode(ino)?.kind() == Kind::Dir;

        if is_dir {
            // Refuse to move a directory inside itself.
            let mut p = new_parent;
            loop {
                if p == ino {
                    return Err(Error::InvalidArgument);
                }
                if p == ROOT_INO {
                    break;
                }
                p = self.lookup(p, b"..")?;
            }
        }

        if let Ok(existing) = self.lookup(new_parent, new_name) {
            if existing == ino {
                return Ok(());
            }
            if no_replace {
                return Err(Error::Exists);
            }
            match (is_dir, self.inode(existing)?.kind() == Kind::Dir) {
                (true, false) => return Err(Error::NotADirectory),
                (false, true) => return Err(Error::IsADirectory),
                (true, true) if !self.dir_entries(existing)?.is_empty() => return Err(Error::NotEmpty),
                _ => {}
            }
            self.detach(new_parent, new_name)?;
        }

        if let Node::Dir { entries, .. } = &mut self.inode_mut(parent)?.node {
            entries.remove(name);
        }
        if let Node::Dir { entries, .. } = &mut self.inode_mut(new_parent)?.node {
            entries.insert(new_name.to_vec(), ino);
        }
        let now = Timestamp::now();
        let moved = self.inode_mut(ino)?;
        moved.ctime = now;
        if let Node::Dir { parent: p, .. } = &mut moved.node {
            *p = new_parent;
        }
        self.touch_dir(parent);
        self.touch_dir(new_parent);
        self.dirty = true;
        Ok(())
    }

    // ------------------------------------------------------------------
    // File content
    // ------------------------------------------------------------------

    pub fn open_file(&mut self, ino: u64) -> Result<(), Error> {
        self.inode(ino)?;
        *self.open_counts.entry(ino).or_insert(0) += 1;
        Ok(())
    }

    pub fn release_file(&mut self, ino: u64) {
        if let Some(n) = self.open_counts.get_mut(&ino) {
            *n -= 1;
            if *n == 0 {
                self.open_counts.remove(&ino);
                if self.orphans.remove(&ino) {
                    self.destroy_inode(ino);
                    self.dirty = true;
                }
            }
        }
    }

    fn file_parts(&self, ino: u64) -> Result<(u64, &Vec<Option<BlockRef>>), Error> {
        match &self.inode(ino)?.node {
            Node::File { size, blocks } => Ok((*size, blocks)),
            Node::Dir { .. } => Err(Error::IsADirectory),
            Node::Symlink { .. } => Err(Error::InvalidArgument),
        }
    }

    fn block_ref(&self, ino: u64, idx: u64) -> Result<Option<BlockRef>, Error> {
        Ok(self.file_parts(ino)?.1.get(idx as usize).copied().flatten())
    }

    /// Read up to `len` bytes at `offset`. Fails if any block in range fails
    /// authentication (no partial plaintext of a tampered block is returned).
    pub fn read(&mut self, ino: u64, offset: u64, len: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
        let (size, _) = self.file_parts(ino)?;
        if offset >= size || len == 0 {
            return Ok(Zeroizing::new(Vec::new()));
        }
        let end = size.min(offset.saturating_add(len as u64));
        let cs = self.chunk_size;
        let mut out = Zeroizing::new(Vec::with_capacity((end - offset) as usize));
        let mut buf = Zeroizing::new(vec![0u8; cs as usize]);
        let mut pos = offset;
        while pos < end {
            let idx = pos / cs;
            let within = (pos % cs) as usize;
            let take = ((cs - within as u64).min(end - pos)) as usize;
            match self.block_ref(ino, idx)? {
                Some(b) => {
                    self.read_block(&b, &mut buf)?;
                    out.extend_from_slice(&buf[within..within + take]);
                }
                None => {
                    let n = out.len() + take;
                    out.resize(n, 0);
                }
            }
            pos += take as u64;
        }
        Ok(out)
    }

    fn set_block(&mut self, ino: u64, idx: u64, new: BlockRef) -> Result<(), Error> {
        let old = match &mut self.inode_mut(ino)?.node {
            Node::File { blocks, .. } => {
                let idx = idx as usize;
                if blocks.len() <= idx {
                    blocks.resize(idx + 1, None);
                }
                blocks[idx].replace(new)
            }
            _ => return Err(Error::InvalidArgument),
        };
        if let Some(o) = old {
            self.free_chunk(o.chunk);
        }
        Ok(())
    }

    /// Write `data` at `offset`, growing the file as needed.
    pub fn write(&mut self, ino: u64, offset: u64, data: &[u8]) -> Result<(), Error> {
        self.check_writable()?;
        self.file_parts(ino)?;
        if data.is_empty() {
            return Ok(());
        }
        let end = offset.checked_add(data.len() as u64).ok_or(Error::FileTooBig)?;
        if end > self.max_file_size() {
            return Err(Error::FileTooBig);
        }
        let cs = self.chunk_size;
        // Writing past EOF without touching the old last block (leaving a
        // gap): zero that block's stale tail first, since it becomes part of
        // the file.
        let (old_size, _) = self.file_parts(ino)?;
        if old_size % cs != 0 && offset / cs > old_size / cs {
            self.zero_past_eof(ino, old_size)?;
        }
        let mut buf = Zeroizing::new(vec![0u8; cs as usize]);
        let mut pos = offset;
        while pos < end {
            let idx = pos / cs;
            let bstart = idx * cs;
            let to = end.min(bstart + cs);
            let whole = pos == bstart && to == bstart + cs;
            buf.fill(0);
            if !whole && let Some(b) = self.block_ref(ino, idx)? {
                self.read_block(&b, &mut buf)?;
                // Stale bytes past the current EOF must not resurface.
                let (cur_size, _) = self.file_parts(ino)?;
                if bstart < cur_size && cur_size < bstart + cs {
                    buf[(cur_size - bstart) as usize..].fill(0);
                }
            }
            buf[(pos - bstart) as usize..(to - bstart) as usize]
                .copy_from_slice(&data[(pos - offset) as usize..(to - offset) as usize]);
            let new = self.write_new_block(&buf)?;
            self.set_block(ino, idx, new)?;
            if let Node::File { size, .. } = &mut self.inode_mut(ino)?.node {
                *size = (*size).max(to);
            }
            self.dirty = true;
            pos = to;
        }
        let now = Timestamp::now();
        let i = self.inode_mut(ino)?;
        i.mtime = now;
        i.ctime = now;
        Ok(())
    }

    fn truncate(&mut self, ino: u64, new_size: u64) -> Result<(), Error> {
        if new_size > self.max_file_size() {
            return Err(Error::FileTooBig);
        }
        let (old_size, _) = self.file_parts(ino)?;
        if new_size < old_size {
            // Shrinking never writes or allocates: it can't fail halfway,
            // can't trigger a commit mid-operation, and works on a full vault
            // (which is when people delete things). Bytes past the new EOF in
            // the last block stay unreadable until zeroed on growth.
            let keep = new_size.div_ceil(self.chunk_size) as usize;
            let dropped: Vec<BlockRef> = match &mut self.inode_mut(ino)?.node {
                Node::File { blocks, .. } if blocks.len() > keep => blocks.split_off(keep).into_iter().flatten().collect(),
                _ => Vec::new(),
            };
            for b in dropped {
                self.free_chunk(b.chunk);
            }
        } else if new_size > old_size {
            // Growing exposes the old last block's tail: zero it first (if
            // this fails, the file is unchanged).
            self.zero_past_eof(ino, old_size)?;
        }
        if let Node::File { size, .. } = &mut self.inode_mut(ino)?.node {
            *size = new_size;
        }
        self.dirty = true;
        Ok(())
    }

    /// Zero the bytes past `size` in the file's last block, if that block
    /// is partial and exists. Copy-on-write: the zeroed copy goes to a new
    /// chunk, and nothing changes if that fails.
    fn zero_past_eof(&mut self, ino: u64, size: u64) -> Result<(), Error> {
        let cs = self.chunk_size;
        let tail = (size % cs) as usize;
        if tail == 0 {
            return Ok(());
        }
        let idx = size / cs;
        if let Some(b) = self.block_ref(ino, idx)? {
            let mut buf = Zeroizing::new(vec![0u8; cs as usize]);
            self.read_block(&b, &mut buf)?;
            if buf[tail..].iter().any(|&x| x != 0) {
                buf[tail..].fill(0);
                let new = self.write_new_block(&buf)?;
                self.set_block(ino, idx, new)?;
            }
        }
        Ok(())
    }

    pub fn set_attr(&mut self, ino: u64, set: &SetAttr) -> Result<Attr, Error> {
        self.check_writable()?;
        self.inode(ino)?;
        if let Some(size) = set.size {
            self.truncate(ino, size)?;
            let i = self.inode_mut(ino)?;
            i.mtime = Timestamp::now();
        }
        let i = self.inode_mut(ino)?;
        if let Some(p) = set.perm {
            i.perm = p & 0o7777;
        }
        if let Some(u) = set.uid {
            i.uid = u;
        }
        if let Some(g) = set.gid {
            i.gid = g;
        }
        if let Some(t) = set.atime {
            i.atime = t;
        }
        if let Some(t) = set.mtime {
            i.mtime = t;
        }
        i.ctime = Timestamp::now();
        self.dirty = true;
        self.attr(ino)
    }

    /// Decrypt and authenticate every block of every file.
    pub fn verify(&mut self) -> Result<VerifyReport, Error> {
        let mut report = VerifyReport::default();
        let mut stack = vec![(ROOT_INO, String::from("/"))];
        let mut buf = Zeroizing::new(vec![0u8; self.chunk_size as usize]);
        while let Some((ino, path)) = stack.pop() {
            let inode = self.inode(ino)?.clone();
            match inode.node {
                Node::Dir { entries, .. } => {
                    report.dirs += 1;
                    for (name, child) in entries {
                        let base = if path == "/" { String::new() } else { path.clone() };
                        stack.push((child, format!("{base}/{}", String::from_utf8_lossy(&name))));
                    }
                }
                Node::Symlink { .. } => report.symlinks += 1,
                Node::File { blocks, .. } => {
                    report.files += 1;
                    for (idx, b) in blocks.iter().enumerate() {
                        if let Some(b) = b {
                            report.blocks_checked += 1;
                            // Bypass the cache: check what is on disk.
                            if let Err(e) = self.store.read(b.chunk, Some(&b.nonce), &mut buf) {
                                report.bad_blocks.push((path.clone(), idx as u64, e.to_string()));
                            }
                        }
                    }
                }
            }
        }
        Ok(report)
    }
}

impl Fs {
    /// Drop without committing, like a crash or power loss. (Dropping never
    /// commits; this name just makes tests read clearly.)
    #[doc(hidden)]
    pub fn abandon(self) {}

    /// Mark the in-memory state as untrustworthy (e.g. after a panic in the
    /// middle of an operation): nothing more is written. The vault keeps its
    /// last committed state.
    pub fn poison(&mut self) {
        self.poisoned = true;
    }
}

impl Drop for Fs {
    fn drop(&mut self) {
        // Dropping deliberately does NOT commit. Changes become durable only
        // through an explicit `commit()` after an operation succeeded, so a
        // command that fails halfway (or panics) can never persist a
        // half-done change. The vault stays at its last commit.
        //
        // Wipe file names and symlink targets (cached file contents are
        // already wiped by `Zeroizing`).
        for inode in self.inodes.values_mut() {
            match &mut inode.node {
                Node::Dir { entries, .. } => {
                    for (mut name, _) in std::mem::take(entries) {
                        name.zeroize();
                    }
                }
                Node::Symlink { target } => target.zeroize(),
                Node::File { .. } => {}
            }
        }
    }
}

fn validate_name(name: &[u8]) -> Result<(), Error> {
    if name.is_empty() || name == b"." || name == b".." || name.contains(&b'/') || name.contains(&0) {
        return Err(Error::InvalidName);
    }
    if name.len() > MAX_NAME_LEN {
        return Err(Error::NameTooLong);
    }
    Ok(())
}

fn to_extents(chunks: &[u64]) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = Vec::new();
    for &c in chunks {
        match out.last_mut() {
            Some((s, l)) if *s + *l == c && *l < u32::MAX as u64 => *l += 1,
            _ => out.push((c, 1)),
        }
    }
    out
}

// ----------------------------------------------------------------------
// Metadata encoding
// ----------------------------------------------------------------------

fn put_ts(out: &mut Vec<u8>, t: Timestamp) {
    out.extend_from_slice(&t.secs.to_le_bytes());
    out.extend_from_slice(&t.nanos.to_le_bytes());
}

fn encode_metadata(next_ino: u64, inodes: &HashMap<u64, Inode>, order: Vec<u64>) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::new());
    out.extend_from_slice(META_MAGIC);
    out.extend_from_slice(&next_ino.to_le_bytes());
    out.extend_from_slice(&(order.len() as u64).to_le_bytes());
    for ino in order {
        let i = &inodes[&ino];
        out.extend_from_slice(&ino.to_le_bytes());
        out.push(match i.node {
            Node::File { .. } => KIND_FILE,
            Node::Dir { .. } => KIND_DIR,
            Node::Symlink { .. } => KIND_SYMLINK,
        });
        out.extend_from_slice(&i.perm.to_le_bytes());
        out.extend_from_slice(&i.uid.to_le_bytes());
        out.extend_from_slice(&i.gid.to_le_bytes());
        for t in [i.atime, i.mtime, i.ctime, i.crtime] {
            put_ts(&mut out, t);
        }
        match &i.node {
            Node::File { size, blocks } => {
                out.extend_from_slice(&size.to_le_bytes());
                out.extend_from_slice(&(blocks.len() as u64).to_le_bytes());
                for b in blocks {
                    match b {
                        Some(b) => {
                            out.extend_from_slice(&b.chunk.to_le_bytes());
                            out.extend_from_slice(&b.nonce);
                        }
                        None => out.extend_from_slice(&0u64.to_le_bytes()),
                    }
                }
            }
            Node::Dir { parent, entries } => {
                out.extend_from_slice(&parent.to_le_bytes());
                out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
                for (name, child) in entries {
                    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
                    out.extend_from_slice(name);
                    out.extend_from_slice(&child.to_le_bytes());
                }
            }
            Node::Symlink { target } => {
                out.extend_from_slice(&(target.len() as u32).to_le_bytes());
                out.extend_from_slice(target);
            }
        }
    }
    out
}

/// Strictly decode and validate metadata. Although metadata is
/// authenticated, it is still treated as untrusted input: no panics, no
/// unbounded allocations, and the tree must be well formed.
fn decode_metadata(blob: &[u8], chunk_size: u64, max_file_size: u64) -> Result<(u64, HashMap<u64, Inode>), Error> {
    let bad = |what: &str| Error::Corrupt(format!("malformed metadata: {what}"));
    let mut r = Reader::new(blob);
    let e = |_| bad("truncated");
    if r.take(8).map_err(e)? != META_MAGIC {
        return Err(bad("bad magic"));
    }
    let next_ino = r.u64().map_err(e)?;
    let count = r.u64().map_err(e)?;
    // Each inode takes at least 63 bytes, which bounds `count` by the blob.
    if count == 0 || count > blob.len() as u64 / 63 {
        return Err(bad("inode count"));
    }
    let mut inodes = HashMap::with_capacity(count as usize);
    for _ in 0..count {
        let ino = r.u64().map_err(e)?;
        let kind = r.u8().map_err(e)?;
        let perm = r.u16().map_err(e)?;
        let uid = r.u32().map_err(e)?;
        let gid = r.u32().map_err(e)?;
        // Only permission bits: anything higher would be OR-ed into the
        // file type reported to the OS (e.g. a file shown as a socket).
        if perm & !0o7777 != 0 {
            return Err(bad("permission bits"));
        }
        let mut ts = [Timestamp { secs: 0, nanos: 0 }; 4];
        for t in &mut ts {
            *t = Timestamp { secs: r.i64().map_err(e)?, nanos: r.u32().map_err(e)? };
            if t.nanos >= 1_000_000_000 {
                return Err(bad("timestamp"));
            }
        }
        let node = match kind {
            KIND_FILE => {
                let size = r.u64().map_err(e)?;
                // No file can be bigger than the vault (a fake huge sparse
                // file would make `get` fill the disk with zeros).
                if size > max_file_size {
                    return Err(bad("file larger than the vault"));
                }
                let n = r.u64().map_err(e)?;
                if n > size.div_ceil(chunk_size) || n > r.rest().len() as u64 / 8 {
                    return Err(bad("block count"));
                }
                let mut blocks = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    let chunk = r.u64().map_err(e)?;
                    if chunk == 0 {
                        blocks.push(None);
                    } else {
                        if chunk < SUPERBLOCK_SLOTS {
                            return Err(bad("block points at a superblock"));
                        }
                        blocks.push(Some(BlockRef { chunk, nonce: r.array().map_err(e)? }));
                    }
                }
                Node::File { size, blocks }
            }
            KIND_DIR => {
                let parent = r.u64().map_err(e)?;
                let n = r.u32().map_err(e)?;
                let mut entries = BTreeMap::new();
                for _ in 0..n {
                    let len = r.u16().map_err(e)? as usize;
                    let name = r.take(len).map_err(e)?.to_vec();
                    validate_name(&name).map_err(|_| bad("entry name"))?;
                    let child = r.u64().map_err(e)?;
                    if entries.insert(name, child).is_some() {
                        return Err(bad("duplicate entry"));
                    }
                }
                Node::Dir { parent, entries }
            }
            KIND_SYMLINK => {
                let len = r.u32().map_err(e)? as usize;
                if len == 0 || len > MAX_SYMLINK_LEN {
                    return Err(bad("symlink length"));
                }
                let target = r.take(len).map_err(e)?;
                // Same rule as `Fs::symlink`.
                if target.contains(&0) {
                    return Err(bad("symlink target"));
                }
                Node::Symlink { target: target.to_vec() }
            }
            _ => return Err(bad("inode kind")),
        };
        if ino == 0 || ino >= next_ino {
            return Err(bad("inode number"));
        }
        let inode = Inode { perm, uid, gid, atime: ts[0], mtime: ts[1], ctime: ts[2], crtime: ts[3], node };
        if inodes.insert(ino, inode).is_some() {
            return Err(bad("duplicate inode"));
        }
    }
    if !r.is_empty() {
        return Err(bad("trailing bytes"));
    }

    // The tree: root is a directory that is its own parent, every other
    // inode is referenced exactly once, directory parent links are right,
    // and everything is reachable from the root (no detached cycles).
    match inodes.get(&ROOT_INO) {
        Some(Inode { node: Node::Dir { parent: ROOT_INO, .. }, .. }) => {}
        _ => return Err(bad("root directory")),
    }
    let mut seen = HashSet::from([ROOT_INO]);
    let mut queue = vec![ROOT_INO];
    while let Some(dir) = queue.pop() {
        if let Some(Inode { node: Node::Dir { entries, .. }, .. }) = inodes.get(&dir) {
            for &child in entries.values() {
                if !seen.insert(child) {
                    return Err(bad("inode linked twice"));
                }
                match inodes.get(&child) {
                    None => return Err(bad("dangling entry")),
                    Some(Inode { node: Node::Dir { parent, .. }, .. }) => {
                        if *parent != dir {
                            return Err(bad("wrong parent link"));
                        }
                        queue.push(child);
                    }
                    Some(_) => {}
                }
            }
        }
    }
    if seen.len() != inodes.len() {
        return Err(bad("unreachable inodes"));
    }
    Ok((next_ino, inodes))
}

#[cfg(test)]
impl Fs {
    /// Chunk indices holding a file's blocks (for tamper tests).
    pub(crate) fn chunks_of(&self, ino: u64) -> Vec<u64> {
        match &self.inodes[&ino].node {
            Node::File { blocks, .. } => blocks.iter().flatten().map(|b| b.chunk).collect(),
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_roundtrip() {
        for t in [UNIX_EPOCH, SystemTime::now(), UNIX_EPOCH - Duration::new(5, 250)] {
            assert_eq!(Timestamp::from_system(t).to_system(), t);
        }
        // Extreme values must not panic.
        for secs in [i64::MAX, i64::MIN, i64::MIN + 1] {
            let _ = Timestamp { secs, nanos: 999_999_999 }.to_system();
        }
    }

    #[test]
    fn extents_compress_runs() {
        assert_eq!(to_extents(&[5, 6, 7, 9, 10, 2]), vec![(5, 3), (9, 2), (2, 1)]);
        assert!(to_extents(&[]).is_empty());
    }

    #[test]
    fn bitmap_alloc_and_free() {
        let mut b = Bitmap::new(130);
        let mut got = HashSet::new();
        while let Some(i) = b.alloc() {
            assert!(got.insert(i));
        }
        assert_eq!(got.len(), 130);
        b.clear(77);
        assert_eq!(b.alloc(), Some(77));
        assert_eq!(b.alloc(), None);
    }

    #[test]
    fn names_are_validated() {
        for bad in [&b""[..], b".", b"..", b"a/b", b"a\0b"] {
            assert!(validate_name(bad).is_err());
        }
        assert!(validate_name(&[b'x'; 256]).is_err());
        assert!(validate_name(&[b'x'; 255]).is_ok());
        assert!(validate_name("ünïcødé".as_bytes()).is_ok());
    }

    fn sample_tree() -> (u64, HashMap<u64, Inode>) {
        let ts = Timestamp { secs: 1, nanos: 2 };
        let mk = |node| Inode { perm: 0o644, uid: 1, gid: 2, atime: ts, mtime: ts, ctime: ts, crtime: ts, node };
        let mut inodes = HashMap::new();
        inodes.insert(ROOT_INO, mk(Node::Dir { parent: ROOT_INO, entries: BTreeMap::from([(b"f".to_vec(), 2), (b"d".to_vec(), 3)]) }));
        inodes.insert(2, mk(Node::File { size: 5000, blocks: vec![Some(BlockRef { chunk: 9, nonce: [7; 24] })] }));
        inodes.insert(3, mk(Node::Dir { parent: ROOT_INO, entries: BTreeMap::from([(b"l".to_vec(), 4)]) }));
        inodes.insert(4, mk(Node::Symlink { target: b"../f".to_vec() }));
        (5, inodes)
    }

    #[test]
    fn metadata_roundtrip() {
        let (next, inodes) = sample_tree();
        let order = vec![1, 2, 3, 4];
        let blob = encode_metadata(next, &inodes, order);
        let (n2, back) = decode_metadata(&blob, 4096, 1 << 30).unwrap();
        assert_eq!(n2, next);
        assert_eq!(back.len(), 4);
        assert!(matches!(&back[&2].node, Node::File { size: 5000, blocks } if blocks[0] == Some(BlockRef { chunk: 9, nonce: [7; 24] })));
    }

    #[test]
    fn metadata_rejects_files_larger_than_the_vault() {
        let (next, mut inodes) = sample_tree();
        if let Node::File { size, .. } = &mut inodes.get_mut(&2).unwrap().node {
            *size = u64::MAX;
        }
        let blob = encode_metadata(next, &inodes, vec![1, 2, 3, 4]);
        assert!(decode_metadata(&blob, 4096, 1 << 30).is_err());
        assert!(decode_metadata(&blob, 4096, u64::MAX).is_ok());
    }

    #[test]
    fn metadata_rejects_bad_trees() {
        let (next, mut inodes) = sample_tree();
        // Link the file twice.
        if let Node::Dir { entries, .. } = &mut inodes.get_mut(&3).unwrap().node {
            entries.insert(b"again".to_vec(), 2);
        }
        let blob = encode_metadata(next, &inodes, vec![1, 2, 3, 4]);
        assert!(decode_metadata(&blob, 4096, 1 << 30).is_err());

        // A detached cycle.
        let (next, mut inodes) = sample_tree();
        let ts = Timestamp { secs: 0, nanos: 0 };
        let mk = |node| Inode { perm: 0, uid: 0, gid: 0, atime: ts, mtime: ts, ctime: ts, crtime: ts, node };
        inodes.insert(10, mk(Node::Dir { parent: 11, entries: BTreeMap::from([(b"x".to_vec(), 11)]) }));
        inodes.insert(11, mk(Node::Dir { parent: 10, entries: BTreeMap::from([(b"y".to_vec(), 10)]) }));
        let blob = encode_metadata(next.max(12), &inodes, vec![1, 2, 3, 4, 10, 11]);
        assert!(decode_metadata(&blob, 4096, 1 << 30).is_err());
    }

    #[test]
    fn metadata_rejects_file_type_bits_and_nul_in_symlinks() {
        // perm with S_IFSOCK-style type bits.
        let (next, mut inodes) = sample_tree();
        inodes.get_mut(&2).unwrap().perm = 0o140644;
        let blob = encode_metadata(next, &inodes, vec![1, 2, 3, 4]);
        assert!(decode_metadata(&blob, 4096, 1 << 30).is_err());
        // Setuid/setgid/sticky are ordinary permission bits and stay allowed.
        let (next, mut inodes) = sample_tree();
        inodes.get_mut(&2).unwrap().perm = 0o7777;
        let blob = encode_metadata(next, &inodes, vec![1, 2, 3, 4]);
        assert!(decode_metadata(&blob, 4096, 1 << 30).is_ok());

        let (next, mut inodes) = sample_tree();
        inodes.get_mut(&4).unwrap().node = Node::Symlink { target: b"a\0b".to_vec() };
        let blob = encode_metadata(next, &inodes, vec![1, 2, 3, 4]);
        assert!(decode_metadata(&blob, 4096, 1 << 30).is_err());
    }

    #[test]
    fn metadata_corruption_never_panics() {
        let (next, inodes) = sample_tree();
        let base = encode_metadata(next, &inodes, vec![1, 2, 3, 4]);
        let mut state = 0x2545F4914F6CDD1Du64;
        let mut rnd = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..20_000 {
            let mut b = base.to_vec();
            for _ in 0..(rnd() % 4 + 1) {
                let pos = (rnd() as usize) % b.len();
                b[pos] = rnd() as u8;
            }
            if rnd() % 10 == 0 {
                b.truncate((rnd() as usize) % b.len());
            }
            let _ = decode_metadata(&b, 4096, 1 << 30);
        }
    }
}
