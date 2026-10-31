//! FUSE adapter (Linux via /dev/fuse + fusermount3, macOS via macFUSE).

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use fuser::{
    Config, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo, KernelConfig,
    LockOwner, MountOption, OpenFlags, RenameFlags, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, Request, Session, SessionACL, TimeOrNow, WriteFlags,
};

use super::MountOptions;
use crate::vault::Error;
use crate::vault::fs::{Attr, Fs, Kind, MAX_NAME_LEN, SetAttr, Timestamp};

const TTL: Duration = Duration::from_secs(1);

struct NullguardFs {
    inner: Arc<Mutex<Fs>>,
    next_fh: AtomicU64,
    /// Set if a panic poisoned the state: refuse all further operations
    /// (and never commit possibly inconsistent metadata).
    broken: Arc<AtomicBool>,
    /// Every file is presented as owned by the user who mounted the vault.
    /// A vault is a personal container that moves between machines (and
    /// OSes), where user ids mean nothing, so it doesn't store any: like a
    /// USB stick.
    uid: u32,
    gid: u32,
    /// Follow symbolic links that lead out of the vault (see `MountOptions`).
    allow_outside_links: bool,
    /// Links already reported as refused (each is reported once).
    refused_links: Mutex<HashSet<u64>>,
}

fn errno(e: &Error) -> Errno {
    let code = match e {
        Error::NotFound => libc::ENOENT,
        Error::Exists => libc::EEXIST,
        Error::NotADirectory => libc::ENOTDIR,
        Error::IsADirectory => libc::EISDIR,
        Error::NotEmpty => libc::ENOTEMPTY,
        Error::InvalidName | Error::InvalidArgument => libc::EINVAL,
        Error::NameTooLong => libc::ENAMETOOLONG,
        Error::FileTooBig => libc::EFBIG,
        Error::NoSpace => libc::ENOSPC,
        Error::ResourceLimit(_) => libc::EDQUOT,
        Error::ReadOnly => libc::EROFS,
        Error::ChunkAuth { .. } | Error::Rollback { .. } | Error::Corrupt(_) => {
            // Integrity failures are security events: always report them.
            eprintln!("nullguard: SECURITY WARNING: {e}");
            libc::EIO
        }
        other => {
            eprintln!("nullguard: I/O error: {other}");
            libc::EIO
        }
    };
    Errno::from_i32(code)
}

fn file_type(k: Kind) -> FileType {
    match k {
        Kind::File => FileType::RegularFile,
        Kind::Dir => FileType::Directory,
        Kind::Symlink => FileType::Symlink,
    }
}

fn to_fuse(a: &Attr, uid: u32, gid: u32) -> FileAttr {
    FileAttr {
        ino: INodeNo(a.ino),
        size: a.size,
        blocks: a.blocks,
        atime: a.atime.to_system(),
        mtime: a.mtime.to_system(),
        ctime: a.ctime.to_system(),
        crtime: a.crtime.to_system(),
        kind: file_type(a.kind),
        perm: a.perm,
        nlink: a.nlink,
        uid,
        gid,
        rdev: 0,
        blksize: a.blksize,
        flags: 0,
    }
}

fn ts(t: TimeOrNow) -> Timestamp {
    match t {
        TimeOrNow::SpecificTime(s) => Timestamp::from_system(s),
        TimeOrNow::Now => Timestamp::now(),
    }
}

impl NullguardFs {
    fn fs(&self) -> Result<MutexGuard<'_, Fs>, Errno> {
        if self.broken.load(Ordering::SeqCst) {
            return Err(Errno::from_i32(libc::EIO));
        }
        match self.inner.lock() {
            Ok(g) => Ok(g),
            Err(_) => {
                self.broken.store(true, Ordering::SeqCst);
                eprintln!("nullguard: internal error; refusing further operations to protect the vault");
                Err(Errno::from_i32(libc::EIO))
            }
        }
    }

    /// Run one filesystem operation. A panic (a bug) is caught here, before
    /// it can unwind with half-updated state: the filesystem is poisoned so
    /// nothing more is written, and the vault keeps its last commit.
    fn run<T>(&self, f: impl FnOnce(&mut Fs) -> Result<T, Error>) -> Result<T, Errno> {
        let mut fs = self.fs()?;
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(&mut fs))) {
            Ok(r) => r.map_err(|e| errno(&e)),
            Err(_) => {
                fs.poison();
                self.broken.store(true, Ordering::SeqCst);
                eprintln!("nullguard: internal error; refusing further operations until remounted (the last commit is kept)");
                Err(Errno::from_i32(libc::EIO))
            }
        }
    }

    fn attr(&self, a: &Attr) -> FileAttr {
        to_fuse(a, self.uid, self.gid)
    }

    fn fh(&self) -> FileHandle {
        FileHandle(self.next_fh.fetch_add(1, Ordering::Relaxed))
    }
}

impl Filesystem for NullguardFs {
    fn init(&mut self, _req: &Request, _config: &mut KernelConfig) -> std::io::Result<()> {
        Ok(())
    }

    fn destroy(&mut self) {
        if let Ok(mut fs) = self.fs()
            && let Err(e) = fs.commit()
        {
            eprintln!("nullguard: final commit failed: {e}");
        }
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        match self.run(|fs| {
            let ino = fs.lookup(parent.0, name.as_bytes())?;
            fs.attr(ino)
        }) {
            Ok(a) => reply.entry(&TTL, &self.attr(&a), Generation(0)),
            Err(e) => reply.error(e),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match self.run(|fs| fs.attr(ino.0)) {
            Ok(a) => reply.attr(&TTL, &self.attr(&a)),
            Err(e) => reply.error(e),
        }
    }

    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<std::time::SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<std::time::SystemTime>,
        _chgtime: Option<std::time::SystemTime>,
        _bkuptime: Option<std::time::SystemTime>,
        _flags: Option<fuser::BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let set = SetAttr {
            perm: mode.map(|m| (m & 0o7777) as u16),
            // Ownership is always the mounting user (see `NullguardFs::uid`) and
            // isn't stored, so chown is accepted but has no effect, as on a FAT drive.
            size,
            atime: atime.map(ts),
            mtime: mtime.map(ts),
        };
        match self.run(|fs| fs.set_attr(ino.0, &set)) {
            Ok(a) => reply.attr(&TTL, &self.attr(&a)),
            Err(e) => reply.error(e),
        }
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        let allow = self.allow_outside_links;
        match self.run(|fs| Ok((fs.readlink(ino.0)?, !allow && fs.link_leaves_vault(ino.0)?))) {
            Ok((target, false)) => reply.data(&target),
            // The kernel follows a link by asking for its target: refusing
            // to give it keeps the link from leading out of the vault.
            Ok((target, true)) => {
                if self.refused_links.lock().is_ok_and(|mut seen| seen.insert(ino.0)) {
                    eprintln!(
                        "nullguard: not following a symbolic link that leads out of the vault (to {}). \
                         Mount with --allow-outside-links to follow such links.",
                        crate::cli::display_name(&target)
                    );
                }
                reply.error(Errno::from_i32(libc::EACCES));
            }
            Err(e) => reply.error(e),
        }
    }

    fn mkdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, mode: u32, umask: u32, reply: ReplyEntry) {
        let perm = (mode & !umask & 0o7777) as u16;
        match self.run(|fs| {
            let ino = fs.mkdir(parent.0, name.as_bytes(), perm)?;
            fs.attr(ino)
        }) {
            Ok(a) => reply.entry(&TTL, &self.attr(&a), Generation(0)),
            Err(e) => reply.error(e),
        }
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        match self.run(|fs| fs.unlink(parent.0, name.as_bytes())) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        match self.run(|fs| fs.rmdir(parent.0, name.as_bytes())) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn symlink(&self, _req: &Request, parent: INodeNo, link_name: &OsStr, target: &Path, reply: ReplyEntry) {
        match self.run(|fs| {
            let ino = fs.symlink(parent.0, link_name.as_bytes(), target.as_os_str().as_bytes())?;
            fs.attr(ino)
        }) {
            Ok(a) => reply.entry(&TTL, &self.attr(&a), Generation(0)),
            Err(e) => reply.error(e),
        }
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        #[cfg(target_os = "linux")]
        let (no_replace, unsupported) = (
            flags.contains(RenameFlags::RENAME_NOREPLACE),
            flags.intersects(RenameFlags::RENAME_EXCHANGE | RenameFlags::RENAME_WHITEOUT),
        );
        #[cfg(not(target_os = "linux"))]
        let (no_replace, unsupported) = (false, !flags.is_empty());
        if unsupported {
            return reply.error(Errno::from_i32(libc::EINVAL));
        }
        match self.run(|fs| fs.rename(parent.0, name.as_bytes(), newparent.0, newname.as_bytes(), no_replace)) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn open(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        match self.run(|fs| fs.open_file(ino.0)) {
            Ok(()) => reply.opened(self.fh(), FopenFlags::empty()),
            Err(e) => reply.error(e),
        }
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        match self.run(|fs| fs.read(ino.0, offset, size as usize)) {
            Ok(d) => reply.data(&d),
            Err(e) => reply.error(e),
        }
    }

    fn write(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        match self.run(|fs| fs.write(ino.0, offset, data)) {
            Ok(()) => reply.written(data.len() as u32),
            Err(e) => reply.error(e),
        }
    }

    fn flush(&self, _req: &Request, _ino: INodeNo, _fh: FileHandle, _lock_owner: LockOwner, reply: ReplyEmpty) {
        reply.ok();
    }

    fn release(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        match self.run(|fs| {
            fs.release_file(ino.0);
            Ok(())
        }) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn fsync(&self, _req: &Request, _ino: INodeNo, _fh: FileHandle, _datasync: bool, reply: ReplyEmpty) {
        match self.run(|fs| fs.commit()) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        match self.run(|fs| fs.readdir(ino.0).map(|_| ())) {
            Ok(()) => reply.opened(self.fh(), FopenFlags::empty()),
            Err(e) => reply.error(e),
        }
    }

    fn readdir(&self, _req: &Request, ino: INodeNo, _fh: FileHandle, offset: u64, mut reply: ReplyDirectory) {
        match self.run(|fs| fs.readdir(ino.0)) {
            Ok(entries) => {
                for (i, e) in entries.iter().enumerate().skip(offset as usize) {
                    if reply.add(INodeNo(e.ino), (i + 1) as u64, file_type(e.kind), OsStr::from_bytes(&e.name)) {
                        break;
                    }
                }
                reply.ok();
            }
            Err(e) => reply.error(e),
        }
    }

    fn releasedir(&self, _req: &Request, _ino: INodeNo, _fh: FileHandle, _flags: OpenFlags, reply: ReplyEmpty) {
        reply.ok();
    }

    fn fsyncdir(&self, _req: &Request, _ino: INodeNo, _fh: FileHandle, _datasync: bool, reply: ReplyEmpty) {
        match self.run(|fs| fs.commit()) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        match self.run(|fs| Ok(fs.statfs())) {
            Ok(s) => reply.statfs(
                s.total_blocks,
                s.free_blocks,
                s.free_blocks,
                s.files,
                u32::MAX as u64,
                s.block_size,
                MAX_NAME_LEN as u32,
                s.block_size,
            ),
            Err(e) => reply.error(e),
        }
    }

    fn create(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        // The casts are needed on macOS, where mode constants are u16.
        #[allow(clippy::unnecessary_cast)]
        let fmt = mode & libc::S_IFMT as u32;
        #[allow(clippy::unnecessary_cast)]
        let regular = fmt == 0 || fmt == libc::S_IFREG as u32;
        if !regular {
            return reply.error(Errno::from_i32(libc::EPERM)); // no device nodes, fifos or sockets
        }
        let perm = (mode & !umask & 0o7777) as u16;
        match self.run(|fs| {
            let ino = fs.create_file(parent.0, name.as_bytes(), perm)?;
            fs.open_file(ino)?;
            fs.attr(ino)
        }) {
            Ok(a) => reply.created(&TTL, &self.attr(&a), Generation(0), self.fh(), FopenFlags::empty()),
            Err(e) => reply.error(e),
        }
    }
}

pub fn mount(fs: Fs, mountpoint: &Path, opts: &MountOptions) -> Result<(), Error> {
    let shared = Arc::new(Mutex::new(fs));
    let broken = Arc::new(AtomicBool::new(false));
    let ngfs = NullguardFs {
        inner: shared.clone(),
        next_fh: AtomicU64::new(1),
        broken: broken.clone(),
        uid: crate::platform::uid(),
        gid: crate::platform::gid(),
        allow_outside_links: opts.allow_outside_links,
        refused_links: Mutex::new(HashSet::new()),
    };

    let mut config = Config::default();
    config.mount_options = vec![
        MountOption::FSName("nullguard".into()),
        MountOption::Subtype("nullguard".into()),
        // Let the kernel enforce file permissions.
        MountOption::DefaultPermissions,
        // Device files and setuid binaries inside a vault are never honoured.
        MountOption::NoDev,
        MountOption::NoSuid,
        MountOption::NoAtime,
    ];
    if opts.read_only {
        config.mount_options.push(MountOption::RO);
    }
    if opts.no_exec {
        config.mount_options.push(MountOption::NoExec);
    }
    // Only the user who mounted the vault may access it (no allow_other).
    config.acl = SessionACL::Owner;

    let mut session = Session::new(ngfs, mountpoint, &config)?;
    let unmounter = Arc::new(Mutex::new(session.unmount_callable()));
    {
        let unmounter = unmounter.clone();
        let handler = ctrlc::set_handler(move || {
            eprintln!("\nnullguard: unmounting...");
            if let Ok(mut u) = unmounter.lock() {
                let _ = u.unmount();
            }
        });
        if handler.is_err() {
            eprintln!(
                "nullguard: WARNING: could not install the Ctrl-C handler; use `nullguard unmount` to lock the vault"
            );
        }
    }

    // Background commits while dirty.
    let stop = Arc::new(AtomicBool::new(false));
    let committer = {
        let shared = shared.clone();
        let stop = stop.clone();
        let broken = broken.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(500));
                if broken.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(mut fs) = shared.lock() else { break };
                // Same rule as for FUSE operations: a panic must not leave
                // half-updated state that a later commit could persist.
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| fs.maybe_commit())) {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => eprintln!("nullguard: commit failed: {e}"),
                    Err(_) => {
                        fs.poison();
                        broken.store(true, Ordering::SeqCst);
                        eprintln!("nullguard: internal error while committing; refusing further operations");
                        break;
                    }
                }
            }
        })
    };

    if let Some(ready) = &opts.on_ready {
        ready();
    }
    let result = session.run();
    stop.store(true, Ordering::SeqCst);
    let _ = committer.join();

    if broken.load(Ordering::SeqCst) {
        return Err(Error::Corrupt("an internal error occurred; the last changes were not committed".into()));
    }
    let commit = match shared.lock() {
        Ok(mut fs) => fs.commit(),
        Err(_) => Err(Error::Corrupt("internal error; the last changes were not committed".into())),
    };
    result?;
    commit
}

pub fn unmount(mountpoint: &Path) -> Result<(), Error> {
    let attempts: &[(&str, &[&str])] = if cfg!(target_os = "macos") {
        &[("umount", &[]), ("diskutil", &["unmount"])]
    } else {
        &[("fusermount3", &["-u"]), ("fusermount", &["-u"])]
    };
    let mut last = String::from("no unmount helper found");
    for (cmd, args) in attempts {
        match std::process::Command::new(cmd).args(*args).arg(mountpoint).status() {
            Ok(s) if s.success() => return Ok(()),
            Ok(s) => last = format!("{cmd} exited with {s}"),
            Err(e) => last = format!("{cmd}: {e}"),
        }
    }
    Err(Error::Usage(format!("could not unmount {}: {last}", mountpoint.display())))
}
