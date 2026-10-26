//! The `nullguard` command line.

use std::ffi::{OsStr, OsString};
#[cfg(unix)]
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use zeroize::Zeroizing;

use crate::crypto::{Argon2Params, Keyfile};
use crate::mount::{self, MountOptions};
use crate::vault::fs::{Fs, Kind, Timestamp};
use crate::vault::{self, CreateOptions, Credential, Vault};

/// Minimum length (in characters) for new vault passwords.
pub const MIN_PASSWORD_CHARS: usize = 12;
/// Maximum length of any password or passphrase, in bytes.
pub const MAX_PASSWORD_BYTES: usize = 4096;

#[derive(Parser)]
#[command(name = "nullguard", version, about = "Encrypted vaults that mount as drives.", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new encrypted vault file.
    Create {
        /// Path of the new vault file (must not exist).
        vault: PathBuf,
        /// Vault size, e.g. 500M, 10G, 1T.
        #[arg(long, short)]
        size: String,
        #[command(flatten)]
        kdf: KdfArgs,
        /// Read the password from standard input instead of the terminal.
        #[arg(long)]
        password_stdin: bool,
    },
    /// Unlock a vault and mount it as a drive (Linux, macOS, and Windows with WinFsp).
    Mount {
        vault: PathBuf,
        /// Where to mount: an existing empty directory (Linux, macOS) or a free drive letter such as X: (Windows).
        mountpoint: PathBuf,
        #[command(flatten)]
        unlock: UnlockArgs,
        /// Mount read-only.
        #[arg(long)]
        read_only: bool,
        /// Forbid running programs stored in the vault (Linux, macOS).
        #[arg(long)]
        no_exec: bool,
        /// Follow symbolic links that lead out of the vault (Linux, macOS). By
        /// default they aren't followed: in a vault someone else can write to,
        /// such a link could send what you save "into the vault" elsewhere.
        #[arg(long)]
        allow_outside_links: bool,
    },
    /// Unmount (lock) a mounted vault.
    Unmount { mountpoint: PathBuf },
    /// Change the vault password. Keyfiles keep working.
    ChangePassword {
        vault: PathBuf,
        #[command(flatten)]
        unlock: UnlockArgs,
        #[command(flatten)]
        kdf: KdfArgs,
    },
    /// Move the vault to a new master key and password, so old passwords,
    /// keyfiles and leaked keys stop working. Copies every file, so it needs
    /// free disk space for a second copy of the vault while it runs.
    Rekey {
        vault: PathBuf,
        #[command(flatten)]
        unlock: UnlockArgs,
        #[command(flatten)]
        kdf: KdfArgs,
    },
    /// Generate a new keyfile (a random 256-bit key).
    Keygen {
        /// Where to write the keyfile (must not exist).
        out: PathBuf,
    },
    /// Let a keyfile unlock this vault.
    AddKeyfile {
        vault: PathBuf,
        /// The keyfile to add (from `nullguard keygen`).
        #[arg(value_name = "NEW_KEYFILE")]
        new_keyfile: PathBuf,
        #[command(flatten)]
        unlock: UnlockArgs,
    },
    /// Stop a keyfile from unlocking this vault (or, with --all, every keyfile).
    #[command(group(clap::ArgGroup::new("which").required(true).args(["target", "all"])))]
    RemoveKeyfile {
        vault: PathBuf,
        /// The keyfile to remove.
        #[arg(value_name = "KEYFILE")]
        target: Option<PathBuf>,
        /// Remove every keyfile, e.g. after losing one (then add back the ones you still have).
        #[arg(long)]
        all: bool,
        #[command(flatten)]
        unlock: UnlockArgs,
    },
    /// Show a vault's header (no password needed; nothing shown is authenticated).
    Info { vault: PathBuf },
    /// Unlock and check the integrity of every block in the vault.
    Verify {
        vault: PathBuf,
        #[command(flatten)]
        unlock: UnlockArgs,
    },
    /// List a directory inside the vault (without mounting).
    Ls {
        vault: PathBuf,
        #[arg(default_value = "/")]
        path: String,
        #[command(flatten)]
        unlock: UnlockArgs,
    },
    /// Copy a file or directory out of the vault (without mounting).
    Get {
        vault: PathBuf,
        path: String,
        dest: PathBuf,
        /// Overwrite existing local files.
        #[arg(long)]
        force: bool,
        #[command(flatten)]
        unlock: UnlockArgs,
    },
    /// Copy a file or directory into the vault (without mounting).
    Put {
        vault: PathBuf,
        src: PathBuf,
        #[arg(default_value = "/")]
        path: String,
        /// Overwrite existing files in the vault.
        #[arg(long)]
        force: bool,
        #[command(flatten)]
        unlock: UnlockArgs,
    },
    /// Delete a file (or with -r a directory) inside the vault.
    Rm {
        vault: PathBuf,
        path: String,
        #[arg(short, long)]
        recursive: bool,
        #[command(flatten)]
        unlock: UnlockArgs,
    },
    /// Create a directory inside the vault.
    Mkdir {
        vault: PathBuf,
        path: String,
        #[command(flatten)]
        unlock: UnlockArgs,
    },
}

#[derive(Args, Clone)]
struct UnlockArgs {
    /// Unlock with a keyfile instead of the password.
    #[arg(long, short)]
    keyfile: Option<PathBuf>,
    /// Read passwords from standard input (one per line) instead of the terminal.
    #[arg(long)]
    password_stdin: bool,
}

/// The password's key derivation: one strong default, one setting for
/// machines that can't spare the memory. No other knobs, so there is no way
/// to pick weak parameters.
#[derive(Args, Clone)]
struct KdfArgs {
    /// Use 64 MiB for the password's key derivation instead of 1 GiB, for
    /// machines with little memory. Cheaper to unlock, but also cheaper for
    /// an attacker to guess.
    #[arg(long)]
    low_memory: bool,
}

impl KdfArgs {
    fn params(&self) -> Argon2Params {
        if self.low_memory { Argon2Params::LOW_MEMORY } else { Argon2Params::DEFAULT }
    }
}

/// Reads secrets from the terminal (no echo) or, with `--password-stdin`,
/// line by line from standard input.
struct Prompter {
    stdin: bool,
}

impl Prompter {
    /// Read one secret, NFC-normalized (see `kdf::normalize_password`).
    fn read(&self, prompt: &str) -> Result<Zeroizing<String>> {
        let raw = if self.stdin {
            read_secret_line_from_stdin()?
        } else {
            Zeroizing::new(rpassword::prompt_password(prompt).context("reading password from terminal")?)
        };
        if raw.len() > MAX_PASSWORD_BYTES {
            bail!("passwords are limited to {MAX_PASSWORD_BYTES} bytes");
        }
        Ok(crate::crypto::kdf::normalize_password(&raw))
    }

    /// Read a new password (twice when interactive) and enforce the policy.
    fn new_password(&self, what: &str) -> Result<Zeroizing<String>> {
        let pw = self.read(&format!("New {what}: "))?;
        // The limit applies to the normalized form, which is what the key is
        // derived from (normalizing can make some text longer). Unlocking
        // only limits what is typed, so no existing password stops working.
        if pw.len() > MAX_PASSWORD_BYTES {
            bail!("passwords are limited to {MAX_PASSWORD_BYTES} bytes");
        }
        if pw.chars().count() < MIN_PASSWORD_CHARS {
            bail!("the {what} must be at least {MIN_PASSWORD_CHARS} characters (a few random words is ideal)");
        }
        if !self.stdin {
            let again = self.read(&format!("Repeat {what}: "))?;
            if !crate::crypto::ct_eq(pw.as_bytes(), again.as_bytes()) {
                bail!("the {what}s do not match");
            }
        }
        Ok(pw)
    }
}

/// Read one line (a secret) from standard input.
///
/// Rust's `io::stdin()` reads through a shared 8 KiB buffer that is never
/// wiped, so a password read that way would stay in memory for as long as
/// the process runs (for `mount`, as long as the vault is unlocked). Instead
/// this reads byte by byte from a duplicate of the raw stdin handle, straight
/// into a pre-sized buffer that is wiped on drop. Only the bytes of this one
/// line are consumed, so several secrets can be read in turn.
fn read_secret_line_from_stdin() -> Result<Zeroizing<String>> {
    #[cfg(unix)]
    let mut raw = std::fs::File::from(std::os::fd::AsFd::as_fd(&io::stdin()).try_clone_to_owned()?);
    #[cfg(windows)]
    let mut raw = std::fs::File::from(std::os::windows::io::AsHandle::as_handle(&io::stdin()).try_clone_to_owned()?);
    let mut line = Zeroizing::new(Vec::with_capacity(MAX_PASSWORD_BYTES + 2));
    let mut byte = Zeroizing::new([0u8; 1]);
    let mut got_any = false;
    loop {
        match raw.read(byte.as_mut_slice()) {
            Ok(0) => break,
            Ok(_) => {
                got_any = true;
                if byte[0] == b'\n' {
                    break;
                }
                if line.len() > MAX_PASSWORD_BYTES {
                    bail!("passwords are limited to {MAX_PASSWORD_BYTES} bytes");
                }
                line.push(byte[0]);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e).context("reading password from stdin"),
        }
    }
    if !got_any {
        bail!("standard input ended before a password was read");
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    let bytes = std::mem::take(&mut *line);
    match String::from_utf8(bytes) {
        Ok(s) => Ok(Zeroizing::new(s)),
        Err(e) => {
            let _wipe = Zeroizing::new(e.into_bytes());
            bail!("the password is not valid UTF-8")
        }
    }
}

/// Largest keyfile accepted (real ones are under 200 bytes).
const MAX_KEYFILE_BYTES: u64 = 4096;

/// Read and parse a keyfile: refuse one other users can read, and read it
/// into one pre-sized, wiped-on-drop buffer.
fn read_keyfile(path: &Path) -> Result<Keyfile> {
    let what = || format!("reading keyfile {}", path.display());
    let file = std::fs::File::open(path).with_context(what)?;
    check_keyfile_permissions(path, &file)?;
    let mut text = Zeroizing::new(String::with_capacity(MAX_KEYFILE_BYTES as usize + 1));
    file.take(MAX_KEYFILE_BYTES + 1).read_to_string(&mut text).with_context(what)?;
    if text.len() as u64 > MAX_KEYFILE_BYTES {
        bail!("{} is too large to be a nullguard keyfile", path.display());
    }
    Keyfile::decode(&text).with_context(what)
}

/// Holds whichever secret unlocks the vault.
enum Unlocker {
    Password(Zeroizing<String>),
    Keyfile(Keyfile),
}

impl Unlocker {
    fn from_args(args: &UnlockArgs, p: &Prompter) -> Result<Self> {
        match &args.keyfile {
            None => Ok(Self::Password(p.read("Vault password: ")?)),
            Some(path) => Ok(Self::Keyfile(read_keyfile(path)?)),
        }
    }

    fn credential(&self) -> Credential<'_> {
        match self {
            Self::Password(p) => Credential::Password(p.as_bytes()),
            Self::Keyfile(k) => Credential::Keyfile(k),
        }
    }
}

fn warn_all(warnings: &[String]) {
    for w in warnings {
        eprintln!("WARNING: {w}");
    }
    warn_memory_lock();
}

/// Tell the user (once) if key memory couldn't be locked against swapping.
fn warn_memory_lock() {
    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if crate::crypto::secret::memory_lock_failed() && !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        eprintln!(
            "WARNING: could not lock key memory into RAM, so keys could be written to swap. \
             Use encrypted swap, or raise the locked-memory limit (ulimit -l)."
        );
    }
}

/// Refuse keyfiles that other users can read, like ssh does for private
/// keys. (Checked on the open file, so it can't be swapped in between.)
fn check_keyfile_permissions(path: &Path, file: &std::fs::File) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = file.metadata()?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            bail!(
                "keyfile {} is readable by other users (mode {mode:o}); refusing to use it. \
                 Fix with: chmod 600 {}",
                path.display(),
                path.display()
            );
        }
    }
    #[cfg(windows)]
    if crate::platform::win::readable_by_others(file).with_context(|| format!("checking {}", path.display()))? {
        bail!(
            "keyfile {} is readable by other users of this computer; refusing to use it. Keep it in a \
             folder only you can read (a drive without file permissions, such as a FAT-formatted USB \
             stick, counts as readable by everyone), or fix it with: \
             icacls \"{}\" /inheritance:r /grant:r \"%USERNAME%:F\"",
            path.display(),
            path.display()
        );
    }
    Ok(())
}

fn unlock(path: &Path, args: &UnlockArgs, read_only: bool) -> Result<(Vault, Prompter, Unlocker)> {
    let p = Prompter { stdin: args.password_stdin };
    let u = Unlocker::from_args(args, &p)?;
    if let Unlocker::Password(_) = u
        && let Some(w) = vault::unusual_kdf_warning(path)
    {
        eprintln!("WARNING: {w}");
    }
    eprintln!("Unlocking (deriving key)...");
    let v = Vault::open(path, u.credential(), read_only).with_context(|| format!("opening {}", path.display()))?;
    warn_all(&v.warnings);
    Ok((v, p, u))
}

fn open_fs(path: &Path, args: &UnlockArgs, read_only: bool) -> Result<Fs> {
    let (v, _, _) = unlock(path, args, read_only)?;
    let fs = v.into_fs()?;
    warn_all(&fs.warnings);
    Ok(fs)
}

/// Offline mutations commit only after the entire command succeeds.
/// Mounts use `open_fs` instead, keeping timed commits and reclamation on.
fn open_transaction(path: &Path, args: &UnlockArgs) -> Result<Fs> {
    let mut fs = open_fs(path, args, false)?;
    // Commands are all-or-nothing: nothing is committed until the whole
    // command has succeeded (see `Fs::set_auto_commit`).
    fs.set_auto_commit(false);
    Ok(fs)
}

/// Parse sizes like `4096`, `512K`, `100M`, `10G`, `1T`, `1GiB` (binary units).
pub fn parse_size(s: &str) -> Result<u64> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: u64 = num.parse().map_err(|_| anyhow!("invalid size {s:?}"))?;
    let mult: u64 = match unit.trim().to_ascii_lowercase().trim_end_matches("ib").trim_end_matches('b') {
        "" => 1,
        "k" => 1 << 10,
        "m" => 1 << 20,
        "g" => 1 << 30,
        "t" => 1 << 40,
        _ => bail!("invalid size unit in {s:?} (use K, M, G or T)"),
    };
    n.checked_mul(mult).ok_or_else(|| anyhow!("size {s:?} is too large"))
}

/// Progress display for filling a new vault with random data.
fn fill_progress() -> impl FnMut(u64, u64) {
    let mut last = 0;
    move |done, total| {
        let pct = done * 100 / total.max(1);
        if pct != last {
            last = pct;
            eprint!("\rFilling with random data: {pct:3}%");
            if pct == 100 {
                eprintln!();
            }
        }
    }
}

fn human(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 { format!("{n} B") } else { format!("{v:.1} {}", UNITS[u]) }
}

/// Create a file that only the current user can read (unix: mode 0600;
/// Windows: an explicit owner-only permission set).
///
/// Never overwrites an existing entry or writes through a symbolic link.
fn create_private(path: &Path) -> io::Result<std::fs::File> {
    if let Ok(meta) = std::fs::symlink_metadata(path)
        && meta.file_type().is_symlink()
    {
        return Err(io::Error::new(io::ErrorKind::AlreadyExists, "refusing to write through a symbolic link"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)
    }
    #[cfg(windows)]
    {
        // Nobody else may open it while it is being written.
        crate::platform::win::create_private_file(path, 0)
    }
}

/// Windows also knows most files by a short 8.3 alias (`REPORT~1.PDF` for
/// `report final.pdf`). Before replacing or merging into an existing entry,
/// make sure `name` is its real name, not another file's alias: a vault
/// entry named like an alias must never clobber an unrelated local file.
#[cfg(windows)]
fn check_real_name(path: &Path, name: &OsStr) -> io::Result<()> {
    let real = std::fs::canonicalize(path)?;
    let fold = |s: &OsStr| s.to_string_lossy().to_lowercase();
    if real.file_name().map(fold) == Some(fold(name)) {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!(
            "refusing to replace {}: on this drive that name is a short alias of another file ({})",
            display_path(path),
            display_path(&real)
        ),
    ))
}

pub fn run() -> Result<()> {
    crate::platform::harden_process();
    let cli = Cli::parse();
    match cli.command {
        Command::Create { vault, size, kdf, password_stdin } => {
            let size = parse_size(&size)?;
            let opts = CreateOptions { size, kdf: kdf.params(), chunk_size: None, fill_random: true };
            let pw = Prompter { stdin: password_stdin }.new_password("vault password")?;
            eprintln!("Creating vault (deriving key, {} MiB of memory)...", opts.kdf.memory_kib / 1024);
            Vault::create(&vault, pw.as_bytes(), &opts, &mut fill_progress())
                .with_context(|| format!("creating {}", vault.display()))?;
            let h = Vault::peek_header(&vault)?;
            println!(
                "Created {} ({} usable, {} chunks).",
                vault.display(),
                human(h.chunk_count * h.chunk_size as u64),
                human(h.chunk_size as u64)
            );
        }

        Command::Mount { vault, mountpoint, unlock: u, read_only, no_exec, allow_outside_links } => {
            if !mount::SUPPORTED {
                return Err(mount::unsupported().into());
            }
            // Mounting over files would hide them (and make it easy to save
            // something "into the vault" that actually lands outside it later).
            mount::check_mountpoint(&mountpoint)?;
            let fs = open_fs(&vault, &u, read_only)?;
            // Check again: unlocking takes seconds, and something may have
            // appeared in the folder (or taken the drive letter) meanwhile.
            mount::check_mountpoint(&mountpoint)?;
            let mp = mountpoint.clone();
            let opts = MountOptions {
                read_only,
                no_exec,
                allow_outside_links,
                on_ready: Some(Box::new(move || {
                    eprintln!(
                        "Vault mounted at {}. Press Ctrl-C here, or run `nullguard unmount {}`, to lock it.",
                        mp.display(),
                        mp.display()
                    );
                })),
            };
            mount::mount(fs, &mountpoint, &opts)?;
            eprintln!("Vault unmounted and locked.");
        }

        Command::Unmount { mountpoint } => {
            // Hand the helper an absolute path, so a name like "-x" can never
            // be read as an option by the (setuid) fusermount3. (On Windows
            // the mount point is a drive letter.)
            #[cfg(not(windows))]
            let mountpoint = std::path::absolute(&mountpoint)?;
            mount::unmount(&mountpoint)?;
            eprintln!("Unmounted {}.", mountpoint.display());
        }

        Command::ChangePassword { vault, unlock: u, kdf } => {
            let params = kdf.params();
            let (mut v, p, old) = unlock(&vault, &u, false)?;
            let pw = p.new_password("vault password")?;
            if let Unlocker::Password(old) = &old
                && crate::crypto::ct_eq(old.as_bytes(), pw.as_bytes())
            {
                bail!("the new password is the same as the current one");
            }
            eprintln!("Re-wrapping the master key...");
            v.change_password(pw.as_bytes(), params)?;
            println!("Password changed.");
            eprintln!(
                "Note: the master key is unchanged. Anyone holding an OLD copy of this vault file \
                 and the OLD password can still decrypt that copy. If the old password was compromised, \
                 create a new vault and copy your files over."
            );
        }

        Command::Rekey { vault, unlock: u, kdf } => {
            let p = Prompter { stdin: u.password_stdin };
            let current = Unlocker::from_args(&u, &p)?;
            let pw = p.new_password("vault password")?;
            eprintln!("Unlocking, then creating the new vault next to the old one...");
            let r = vault::rekey::rekey(&vault, current.credential(), pw.as_bytes(), kdf.params(), &mut fill_progress())
                .with_context(|| format!("rekeying {}", vault.display()))?;
            warn_all(&r.warnings);
            println!(
                "Rekeyed {}: {} files, {} directories and {} symlinks moved to a new master key.",
                vault.display(),
                r.files,
                r.dirs,
                r.symlinks
            );
            if r.keyfiles_dropped > 0 {
                eprintln!(
                    "{} keyfile(s) no longer unlock the vault. Add back the ones you still trust with \
                     `nullguard add-keyfile`.",
                    r.keyfiles_dropped
                );
            }
            eprintln!(
                "Note: copies of the vault file made before the rekey still open with the old password \
                 or keyfiles, and still contain what they contained then."
            );
        }

        Command::Keygen { out } => {
            let key = Keyfile::generate()?;
            create_private(&out)
                .and_then(|mut f| f.write_all(key.encode().as_bytes()).and_then(|_| f.sync_all()))
                .with_context(|| format!("writing {} (it must not exist yet)", out.display()))?;
            println!("Keyfile: {}", out.display());
            eprintln!(
                "Anyone with this file can unlock every vault you add it to: keep it secret, and keep a backup.\n\
                 Add it to a vault with: nullguard add-keyfile <vault> {}",
                out.display()
            );
        }

        Command::AddKeyfile { vault, new_keyfile, unlock: u } => {
            let key = read_keyfile(&new_keyfile)?;
            let (mut v, _, _) = unlock(&vault, &u, false)?;
            v.add_keyfile(&key)?;
            println!("Added keyfile {}.", new_keyfile.display());
        }

        Command::RemoveKeyfile { vault, target, all, unlock: u } => {
            let key = target.as_deref().map(read_keyfile).transpose()?;
            let (mut v, _, _) = unlock(&vault, &u, false)?;
            match key {
                Some(key) => {
                    v.remove_keyfile(&key)?;
                    println!("Removed the keyfile.");
                }
                None => {
                    debug_assert!(all);
                    let n = v.remove_all_keyfiles()?;
                    println!("Removed {n} keyfile(s). The password still unlocks the vault.");
                }
            }
            eprintln!(
                "Note: the master key is unchanged. Anyone who already unlocked the vault, or kept an \
                 older copy of the vault file, can still read what that copy holds. For full revocation, \
                 copy your files into a new vault."
            );
        }

        Command::Info { vault } => {
            let h = Vault::peek_header(&vault)?;
            println!("nullguard vault (version {})", vault::header::FORMAT_VERSION);
            println!("  cipher:      {}", crate::crypto::aead::CIPHER_NAME);
            println!("  chunk size:  {}", human(h.chunk_size as u64));
            println!("  capacity:    {} ({} chunks)", human(h.chunk_count * h.chunk_size as u64), h.chunk_count);
            println!("  file size:   {}", human(h.file_len()));
            println!(
                "  password:    argon2id m={} MiB t={} p={}",
                h.kdf.memory_kib / 1024,
                h.kdf.iterations,
                h.kdf.parallelism
            );
            println!("  keyfiles:    {}", h.keyfiles.len());
            println!("(Header values are not authenticated until the vault is unlocked.)");
        }

        Command::Verify { vault, unlock: u } => {
            // `verify` passes only if *everything* is intact: both header
            // copies, both superblocks, the metadata and every data block.
            // Any warning raised while opening counts as a failure.
            let (v, _, _) = unlock(&vault, &u, true)?;
            let mut problems: Vec<String> = v.warnings.clone();
            for p in v.check_headers()? {
                if !problems.contains(&p) {
                    problems.push(p);
                }
            }
            let mut fs = v.into_fs()?;
            warn_all(&fs.warnings);
            problems.extend(fs.warnings.iter().cloned());
            let r = fs.verify()?;
            println!(
                "Checked {} files, {} directories, {} symlinks, {} blocks.",
                r.files, r.dirs, r.symlinks, r.blocks_checked
            );
            for (path, idx, err) in &r.bad_blocks {
                eprintln!("BAD: {} block {idx}: {err}", display_name(path.as_bytes()));
            }
            for p in &problems {
                eprintln!("BAD: {p}");
            }
            if !r.bad_blocks.is_empty() || !problems.is_empty() {
                bail!(
                    "verification FAILED ({} bad block(s), {} other problem(s)): the vault was modified or damaged",
                    r.bad_blocks.len(),
                    problems.len()
                );
            }
            println!("OK: both header copies, the metadata and all data blocks are authentic.");
        }

        Command::Ls { vault, path, unlock: u } => {
            let fs = open_fs(&vault, &u, true)?;
            let ino = resolve(&fs, &path)?;
            let entries = if fs.attr(ino)?.kind == Kind::Dir {
                fs.readdir(ino)?.into_iter().filter(|e| e.name != b"." && e.name != b"..").collect()
            } else {
                vec![vault::fs::DirEntry { name: vault::fs::Name::new(path.as_bytes()), ino, kind: Kind::File }]
            };
            for e in entries {
                let a = fs.attr(e.ino)?;
                let t = match a.kind {
                    Kind::Dir => 'd',
                    Kind::File => '-',
                    Kind::Symlink => 'l',
                };
                let mut line = format!(
                    "{t}{:o}  {:>10}  {}  {}",
                    a.perm,
                    a.size,
                    fmt_time(a.mtime),
                    display_name(&e.name)
                );
                if a.kind == Kind::Symlink {
                    line.push_str(&format!(" -> {}", display_name(&fs.readlink(e.ino)?)));
                }
                println!("{line}");
            }
        }

        Command::Get { vault, path, dest, force, unlock: u } => {
            let mut fs = open_fs(&vault, &u, true)?;
            let ino = resolve(&fs, &path)?;
            // The local folder the copy goes into, and its name there.
            let (folder, name) = if dest.is_dir() && fs.attr(ino)?.kind != Kind::Dir {
                let name = base_name(&path)?;
                if !safe_local_name(name) {
                    bail!("refusing to create a local file with the unsafe name {}", display_name(name.as_bytes()));
                }
                (LocalDir::open(&dest)?, OsString::from(name))
            } else {
                let (parent, name) = split_dest(&dest)?;
                (LocalDir::open(&parent)?, name)
            };
            let n = export(&mut fs, ino, &folder, &name, force, 0)?;
            println!("Copied {n} file(s) to {}.", display_path(&folder.path_of(&name)));
        }

        Command::Put { vault, src, path, force, unlock: u } => {
            let mut fs = open_transaction(&vault, &u)?;
            let (parent, name) = match fs.resolve(&path) {
                Ok(ino) if fs.attr(ino)?.kind == Kind::Dir => {
                    let name = src.file_name()
                        .ok_or_else(|| anyhow!("cannot determine a name for {}", src.display()))?;
                    let name = vault::fs::Name::new(local_name_bytes(name)?);
                    (ino, name)
                }
                _ => {
                    let (dir, name) = split_path(&path)?;
                    (resolve(&fs, dir)?, vault::fs::Name::new(name.as_bytes()))
                }
            };
            let n = import(&mut fs, &src, parent, &name, force, 0)?;
            fs.commit()?;
            println!("Copied {n} file(s) into the vault.");
        }

        Command::Rm { vault, path, recursive, unlock: u } => {
            let mut fs = open_transaction(&vault, &u)?;
            let (dir, name) = split_path(&path)?;
            let parent = resolve(&fs, dir)?;
            remove(&mut fs, parent, name.as_bytes(), recursive, 0)?;
            fs.commit()?;
            println!("Removed {path}.");
        }

        Command::Mkdir { vault, path, unlock: u } => {
            let mut fs = open_transaction(&vault, &u)?;
            let (dir, name) = split_path(&path)?;
            let parent = resolve(&fs, dir)?;
            fs.mkdir(parent, name.as_bytes(), 0o700)?;
            fs.commit()?;
            println!("Created {path}.");
        }
    }
    Ok(())
}

fn fmt_time(t: Timestamp) -> String {
    // Days since epoch to a civil date (Howard Hinnant's algorithm).
    let days = t.secs.div_euclid(86_400);
    let secs = t.secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}", secs / 3600, secs % 3600 / 60)
}

/// Resolve a path inside the vault, naming it in the error.
fn resolve(fs: &Fs, path: &str) -> Result<u64> {
    fs.resolve(path).with_context(|| format!("{path:?} in the vault"))
}

fn split_path(path: &str) -> Result<(&str, &str)> {
    let trimmed = path.trim_end_matches(['/', '\\']);
    let (dir, name) = match trimmed.rfind(['/', '\\']) {
        Some(i) => (&trimmed[..i], &trimmed[i + 1..]),
        None => ("/", trimmed),
    };
    // "." and ".." would name the parent or grandparent directory itself:
    // `rm -r /a/b/..` must never mean "delete everything in /a".
    if name.is_empty() || name == "." || name == ".." {
        bail!("invalid path {path:?}: it must end in a file or directory name");
    }
    Ok((if dir.is_empty() { "/" } else { dir }, name))
}

fn base_name(path: &str) -> Result<&str> {
    Ok(split_path(path)?.1)
}

const COPY_BUF: usize = 1 << 20;

/// Deepest directory nesting the recursive commands (`get`, `put`, `rm -r`)
/// follow. Bounds recursion, so a crafted directory tree can't overflow
/// the stack.
const MAX_DEPTH: usize = 1024;

fn check_depth(depth: usize) -> Result<()> {
    if depth > MAX_DEPTH {
        bail!("directory tree is nested more than {MAX_DEPTH} levels deep; refusing to continue");
    }
    Ok(())
}

/// Render vault-controlled text (file names, symlink targets) safely for a
/// terminal. Anyone who can write to a shared vault picks its file names,
/// so control characters (which could inject terminal escape sequences)
/// and Unicode bidi/invisible formatting characters (which could make one
/// name look like another) are shown escaped.
pub(crate) fn display_name(raw: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw);
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let dangerous = c.is_control()
            || matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2069}' | '\u{feff}');
        if dangerous {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    out
}

/// [`display_name`] for a local path that contains vault-controlled names
/// (the destinations `get` writes to).
fn display_path(path: &Path) -> String {
    display_name(path.as_os_str().as_encoded_bytes())
}

/// Whether a vault entry name can be used as a local file name without
/// escaping the destination directory (or, on Windows, writing into an
/// NTFS alternate data stream or a device such as `CON`).
fn safe_local_name(name: &str) -> bool {
    if !safe_name_bytes(name.as_bytes()) {
        return false;
    }
    if cfg!(windows) && windows_reserved(name) {
        return false;
    }
    if cfg!(windows)
        && (name.contains(['<', '>', ':', '"', '|', '?', '*'])
            || name.chars().any(|c| (c as u32) < 32)
            || name.ends_with(['.', ' ']))
    {
        return false;
    }
    true
}

fn safe_name_bytes(name: &[u8]) -> bool {
    !name.is_empty() && name != b"." && name != b".." && !name.iter().any(|b| matches!(b, b'/' | b'\\' | 0))
}

/// Preserve native Unix name bytes; reject Windows names whose UTF-16
/// cannot be represented by the vault instead of substituting characters.
fn local_name_bytes(name: &OsStr) -> Result<&[u8]> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Ok(name.as_bytes())
    }
    #[cfg(windows)]
    {
        name.to_str().map(str::as_bytes)
            .ok_or_else(|| anyhow!("cannot copy a file name containing invalid Unicode"))
    }
}

/// Convert without changing a name: distinct vault entries must never
/// collapse into one output name through replacement characters.
fn export_name(name: &[u8]) -> Result<OsString> {
    #[cfg(unix)]
    if safe_name_bytes(name) {
        use std::os::unix::ffi::OsStringExt;
        return Ok(OsString::from_vec(name.to_vec()));
    }
    #[cfg(windows)]
    if let Ok(text) = std::str::from_utf8(name)
        && safe_local_name(text)
    {
        return Ok(OsString::from(text));
    }
    bail!("refusing to create a local file with the unsafe or unrepresentable name {}", display_name(name))
}

/// Windows device names (`CON`, `NUL`, `COM1`, `LPT¹`, `CONIN$`, ...). Windows
/// matches them case-insensitively, ignoring any extension and trailing
/// spaces or dots before it, so `nul .txt` is the NUL device.
fn windows_reserved(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or("").trim_end_matches([' ', '.']).to_ascii_uppercase();
    if ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"].contains(&stem.as_str()) {
        return true;
    }
    let mut chars = stem.chars();
    let prefix: String = chars.by_ref().take(3).collect();
    let rest: Vec<char> = chars.collect();
    (prefix == "COM" || prefix == "LPT")
        && rest.len() == 1
        && matches!(rest[0], '1'..='9' | '\u{b9}' | '\u{b2}' | '\u{b3}')
}

/// Why a local entry of this type isn't copied by `put`, if it isn't.
fn skipped_kind(t: &std::fs::FileType) -> Option<&'static str> {
    if t.is_symlink() {
        Some("a symbolic link")
    } else if t.is_dir() || t.is_file() {
        None
    } else {
        Some("not a regular file") // named pipes, sockets, devices
    }
}

/// Open a local file or folder for `put` without following a link: on
/// Linux and macOS a link fails to open (and a named pipe opens without
/// waiting for a writer); on Windows a link opens as itself. What was
/// opened is checked afterwards (`import_open`).
fn open_source(path: &Path, is_dir: bool) -> io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let _ = is_dir;
        OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)
    }
    #[cfg(windows)]
    {
        // A folder is held open so nobody can swap it while it is copied.
        if is_dir { crate::platform::win::open_dir(path, true) } else { crate::platform::win::open_no_follow(path) }
    }
}

/// Copy the local file or folder `src` into the vault as `parent/name`.
///
/// Only regular files and folders are copied; symbolic links, named pipes,
/// sockets and devices are skipped. Every entry is opened without following
/// links and checked once open, so an entry swapped for a link (or a pipe)
/// while the copy runs is never read through. On Linux and macOS, folders
/// are listed and entered through their open handles; on Windows, each
/// folder on the way is held open, so it can't be swapped.
fn import(fs: &mut Fs, src: &Path, parent: u64, name: &[u8], force: bool, depth: usize) -> Result<u64> {
    let meta = std::fs::symlink_metadata(src).with_context(|| format!("reading {}", src.display()))?;
    if let Some(why) = skipped_kind(&meta.file_type()) {
        eprintln!("skipping {} ({why})", src.display());
        return Ok(0);
    }
    let handle = open_source(src, meta.is_dir()).with_context(|| format!("opening {}", src.display()))?;
    import_open(fs, handle, src, parent, name, force, depth)
}

/// [`import`] for an entry that is already open: copy what was opened.
fn import_open(
    fs: &mut Fs,
    handle: std::fs::File,
    shown: &Path,
    parent: u64,
    name: &[u8],
    force: bool,
    depth: usize,
) -> Result<u64> {
    check_depth(depth)?;
    let meta = handle.metadata().with_context(|| format!("reading {}", shown.display()))?;
    if let Some(why) = skipped_kind(&meta.file_type()) {
        eprintln!("skipping {} ({why})", shown.display());
        return Ok(0);
    }
    if meta.is_file() {
        return import_file(fs, handle, &meta, shown, parent, name, force);
    }
    let dir = match fs.lookup(parent, name) {
        Ok(ino) if fs.attr(ino)?.kind == Kind::Dir => ino,
        Ok(_) => bail!("{} exists in the vault and is not a directory", display_name(name)),
        Err(_) => fs.mkdir(parent, name, 0o700)?,
    };
    let mut n = 0;
    #[cfg(unix)]
    {
        use crate::platform::at::{self, Entry};
        let listing = || format!("listing {}", shown.display());
        for child in at::list(&handle).with_context(listing)? {
            let path = shown.join(&child);
            match at::entry(&handle, &child).with_context(listing)? {
                Entry::Missing => continue, // removed meanwhile
                Entry::Symlink => eprintln!("skipping {} (a symbolic link)", path.display()),
                Entry::Other => eprintln!("skipping {} (not a regular file)", path.display()),
                Entry::File | Entry::Dir => {
                    let h = at::open_read(&handle, &child).with_context(|| format!("opening {}", path.display()))?;
                    n += import_open(fs, h, &path, dir, local_name_bytes(&child)?, force, depth + 1)?;
                }
            }
        }
    }
    #[cfg(windows)]
    {
        // `handle` holds this folder (and the callers hold its parents), so
        // the path still names the folder that was checked.
        for entry in std::fs::read_dir(shown).with_context(|| format!("listing {}", shown.display()))? {
            let entry = entry?;
            let path = entry.path();
            let kind = entry.file_type()?;
            if let Some(why) = skipped_kind(&kind) {
                eprintln!("skipping {} ({why})", path.display());
                continue;
            }
            let h = open_source(&path, kind.is_dir()).with_context(|| format!("opening {}", path.display()))?;
            let child = entry.file_name();
            n += import_open(fs, h, &path, dir, local_name_bytes(&child)?, force, depth + 1)?;
        }
    }
    Ok(n)
}

/// Copy an open regular file into the vault as `parent/name`.
fn import_file(
    fs: &mut Fs,
    mut f: std::fs::File,
    meta: &std::fs::Metadata,
    shown: &Path,
    parent: u64,
    name: &[u8],
    force: bool,
) -> Result<u64> {
    if let Ok(existing) = fs.lookup(parent, name) {
        if !force {
            bail!("{} already exists in the vault (use --force to overwrite)", display_name(name));
        }
        if fs.attr(existing)?.kind == Kind::Dir {
            bail!("{} is a directory in the vault", display_name(name));
        }
        fs.unlink(parent, name)?;
    }
    let ino = fs.create_file(parent, name, 0o600)?;
    let copy = (|| -> Result<()> {
        let mut buf = Zeroizing::new(vec![0u8; COPY_BUF]);
        let mut off = 0u64;
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            fs.write(ino, off, &buf[..n])?;
            off += n as u64;
        }
        if let Ok(m) = meta.modified() {
            fs.set_attr(ino, &vault::fs::SetAttr { mtime: Some(Timestamp::from_system(m)), ..Default::default() })?;
        }
        Ok(())
    })();
    if let Err(e) = copy {
        // Don't leave a truncated file behind in the vault.
        let _ = fs.unlink(parent, name);
        return Err(e.context(format!("copying {}", shown.display())));
    }
    Ok(1)
}

/// Split a local destination into the folder it is in and its own name.
fn split_dest(dest: &Path) -> Result<(PathBuf, OsString)> {
    // "." or ".." have no name of their own: use the real path.
    let full = if dest.file_name().is_none() {
        std::fs::canonicalize(dest).with_context(|| format!("finding {}", display_path(dest)))?
    } else {
        dest.to_path_buf()
    };
    match (full.parent(), full.file_name()) {
        (Some(p), Some(n)) => {
            let p = if p.as_os_str().is_empty() { Path::new(".") } else { p };
            Ok((p.to_path_buf(), n.to_owned()))
        }
        _ => bail!("can't copy to {}: name a folder or a file", display_path(dest)),
    }
}

/// A local folder that `get` writes into.
///
/// On Linux and macOS the folder is held open, and every name in it is
/// created relative to that handle without following symbolic links. So
/// nobody can redirect the copy elsewhere (for example into another of
/// your folders) by swapping a folder for a link while it runs. Existing
/// folders the copy merges into must belong to you. On Windows the folder
/// is held open so it can't be renamed or replaced meanwhile, links are
/// refused when opened, existing folders must belong to you too, and new
/// files and folders are private from the moment they exist.
struct LocalDir {
    path: PathBuf,
    handle: std::fs::File,
}

impl LocalDir {
    /// An existing folder named on the command line. (Links in a path the
    /// user typed are the user's choice, and are followed.)
    fn open(path: &Path) -> Result<Self> {
        let what = || format!("opening {}", display_path(path));
        if !std::fs::metadata(path).with_context(what)?.is_dir() {
            bail!("{} is not a directory", display_path(path));
        }
        #[cfg(unix)]
        let handle = std::fs::File::open(path).with_context(what)?;
        #[cfg(windows)]
        let handle = crate::platform::win::open_dir(path, false).with_context(what)?;
        Ok(Self { path: path.to_path_buf(), handle })
    }

    fn path_of(&self, name: &OsStr) -> PathBuf {
        self.path.join(name)
    }

    /// The folder `name` in this one: created (readable only by you) if
    /// it is missing. An existing one must be a real folder, not a link,
    /// and must belong to you: copying plaintext into a folder someone else
    /// controls would let them meddle with it.
    fn subdir(&self, name: &OsStr) -> Result<Self> {
        let path = self.path_of(name);
        let not_a_dir = || anyhow!("{} exists and is not a directory", display_path(&path));
        let a_link = || anyhow!("refusing to export into {}: it is a symbolic link", display_path(&path));
        let creating = || format!("creating {}", display_path(&path));
        #[cfg(unix)]
        {
            use crate::platform::at::{self, Entry};
            use std::os::unix::fs::MetadataExt;
            match at::entry(&self.handle, name).with_context(creating)? {
                // Plaintext file names inside: only the owner may list it.
                Entry::Missing => at::make_dir(&self.handle, name, 0o700).with_context(creating)?,
                Entry::Dir => {}
                Entry::Symlink => return Err(a_link()),
                Entry::File | Entry::Other => return Err(not_a_dir()),
            }
            // Fails if the folder was swapped for a link meanwhile.
            let handle = at::open_dir(&self.handle, name).with_context(|| format!("opening {}", display_path(&path)))?;
            if handle.metadata()?.uid() != crate::platform::uid() {
                bail!(
                    "{} already exists and belongs to another user; refusing to copy into it",
                    display_path(&path)
                );
            }
            Ok(Self { path, handle })
        }
        #[cfg(windows)]
        {
            use crate::platform::win;
            let _ = &self.handle; // holds this folder while its children are used
            let handle = match std::fs::symlink_metadata(&path) {
                Ok(m) if m.file_type().is_symlink() => return Err(a_link()),
                Ok(m) if !m.is_dir() => return Err(not_a_dir()),
                // Opening refuses a link that replaced the folder meanwhile.
                Ok(_) => {
                    let h = win::open_dir(&path, true).with_context(|| format!("opening {}", display_path(&path)))?;
                    check_real_name(&path, name)?;
                    if !win::owned_by_me(&h).with_context(|| format!("checking {}", display_path(&path)))? {
                        bail!(
                            "{} already exists and belongs to another user; refusing to copy into it",
                            display_path(&path)
                        );
                    }
                    h
                }
                // Plaintext file names inside: only you may list it.
                Err(e) if e.kind() == io::ErrorKind::NotFound => win::create_private_dir(&path).with_context(creating)?,
                Err(e) => return Err(e).with_context(creating),
            };
            Ok(Self { path, handle })
        }
    }

    /// Create a new private file, never replacing an existing entry.
    fn create_file(&self, name: &OsStr) -> io::Result<std::fs::File> {
        #[cfg(unix)]
        {
            use crate::platform::at::{self, Entry};
            if at::entry(&self.handle, name)? == Entry::Symlink {
                return Err(io::Error::new(io::ErrorKind::AlreadyExists, "refusing to write through a symbolic link"));
            }
            at::create_file(&self.handle, name, 0o600)
        }
        #[cfg(windows)]
        {
            create_private(&self.path_of(name))
        }
    }

    /// Check a forced replacement without removing anything. Check again
    /// immediately before publishing, including Windows short-name aliases.
    fn check_replaceable(&self, name: &OsStr) -> io::Result<()> {
        let link = || io::Error::new(io::ErrorKind::AlreadyExists, "refusing to write through a symbolic link");
        let other = || io::Error::new(io::ErrorKind::AlreadyExists, "the destination is not a regular file");
        #[cfg(unix)]
        {
            use crate::platform::at::{self, Entry};
            match at::entry(&self.handle, name)? {
                Entry::Missing | Entry::File => Ok(()),
                Entry::Symlink => Err(link()),
                _ => Err(other()),
            }
        }
        #[cfg(windows)]
        {
            let path = self.path_of(name);
            match std::fs::symlink_metadata(&path) {
                Ok(m) if m.file_type().is_symlink() => Err(link()),
                Ok(m) if m.is_file() => check_real_name(&path, name),
                Ok(_) => Err(other()),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e),
            }
        }
    }

    /// Stage forced exports next to their destination. The old file stays
    /// intact until every block authenticates and the new file is synced.
    fn begin_export(&self, name: &OsStr, force: bool) -> Result<ExportFile<'_>> {
        if !force {
            let file = self.create_file(name)?;
            return Ok(ExportFile { dir: self, name: name.to_owned(), file: Some(file), finished: false });
        }
        self.check_replaceable(name)?;
        for _ in 0..16 {
            let random = crate::crypto::random::array::<16>()?;
            let mut temp = String::from(".nullguard-");
            for b in random {
                use std::fmt::Write as _;
                write!(&mut temp, "{b:02x}")?;
            }
            temp.push_str(".tmp");
            let temp = OsString::from(temp);
            // A vault entry can itself have a temporary-looking name.
            if temp == name {
                continue;
            }
            match self.create_file(&temp) {
                Ok(file) => return Ok(ExportFile { dir: self, name: temp, file: Some(file), finished: false }),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        }
        bail!("could not create a unique private export file")
    }

    fn replace_file(&self, from: &OsStr, to: &OsStr) -> io::Result<()> {
        self.check_replaceable(to)?;
        #[cfg(unix)]
        {
            crate::platform::at::rename_file(&self.handle, from, to)
        }
        #[cfg(windows)]
        {
            // The directory and all its parents stay open throughout the
            // export, so these paths cannot be redirected through a link.
            std::fs::rename(self.path_of(from), self.path_of(to))
        }
    }

    fn remove_file(&self, name: &OsStr) -> io::Result<()> {
        #[cfg(unix)]
        {
            crate::platform::at::remove_file(&self.handle, name)
        }
        #[cfg(windows)]
        {
            std::fs::remove_file(self.path_of(name))
        }
    }
}

/// Deletes only the newly created output if copying, authentication,
/// syncing, or publishing fails. Also cleans up during unwinding.
struct ExportFile<'a> {
    dir: &'a LocalDir,
    name: OsString,
    file: Option<std::fs::File>,
    finished: bool,
}

impl ExportFile<'_> {
    fn file(&mut self) -> &mut std::fs::File {
        self.file.as_mut().expect("export file is open until finished")
    }

    fn finish(mut self, name: &OsStr, force: bool) -> io::Result<()> {
        self.file().sync_all()?;
        // Windows refuses to rename an open file without delete sharing.
        drop(self.file.take());
        if force {
            self.dir.replace_file(&self.name, name)?;
        }
        self.finished = true;
        Ok(())
    }
}

impl Drop for ExportFile<'_> {
    fn drop(&mut self) {
        drop(self.file.take());
        if !self.finished {
            let _ = self.dir.remove_file(&self.name);
        }
    }
}

/// Copy the vault entry `ino` to `name` in the local folder `dir`.
fn export(fs: &mut Fs, ino: u64, dir: &LocalDir, name: &OsStr, force: bool, depth: usize) -> Result<u64> {
    check_depth(depth)?;
    let a = fs.attr(ino)?;
    let dest = dir.path_of(name);
    match a.kind {
        Kind::Dir => {
            let sub = dir.subdir(name)?;
            let mut n = 0;
            for e in fs.readdir(ino)? {
                if e.name == b"." || e.name == b".." {
                    continue;
                }
                let child = export_name(&e.name)?;
                n += export(fs, e.ino, &sub, &child, force, depth + 1)?;
            }
            Ok(n)
        }
        Kind::Symlink => {
            eprintln!("skipping symlink {}", display_path(&dest));
            Ok(0)
        }
        Kind::File => {
            let mut out = dir.begin_export(name, force).with_context(|| {
                format!("creating {} (use --force to overwrite existing files)", display_path(&dest))
            })?;
            let copy = (|| -> Result<()> {
                let mut off = 0;
                while off < a.size {
                    let chunk = fs.read(ino, off, COPY_BUF)?;
                    out.file().write_all(&chunk)?;
                    off += chunk.len() as u64;
                }
                out.finish(name, force)?;
                Ok(())
            })();
            if let Err(e) = copy {
                return Err(e.context(format!("copying out to {}", display_path(&dest))));
            }
            Ok(1)
        }
    }
}

fn remove(fs: &mut Fs, parent: u64, name: &[u8], recursive: bool, depth: usize) -> Result<()> {
    check_depth(depth)?;
    if name.is_empty() || name == b"." || name == b".." {
        bail!("refusing to remove {:?}", display_name(name));
    }
    let ino = fs.lookup(parent, name)?;
    if fs.attr(ino)?.kind == Kind::Dir {
        if !recursive {
            bail!("{} is a directory (use -r)", display_name(name));
        }
        for e in fs.readdir(ino)? {
            if e.name != b"." && e.name != b".." {
                remove(fs, ino, &e.name, true, depth + 1)?;
            }
        }
        fs.rmdir(parent, name)?;
    } else {
        fs.unlink(parent, name)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_open_keeps_timed_commits_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.ngv");
        let key_path = dir.path().join("key");
        let key = Keyfile::generate().unwrap();
        create_private(&key_path).unwrap().write_all(key.encode().as_bytes()).unwrap();
        let password = b"correct horse battery staple";
        let opts = CreateOptions { size: 1 << 20, kdf: Argon2Params::LOW_MEMORY, chunk_size: Some(4096), fill_random: false };
        Vault::create(&path, password, &opts, &mut |_, _| {}).unwrap();
        let mut vault = Vault::open(&path, Credential::Password(password), false).unwrap();
        vault.add_keyfile(&key).unwrap();
        drop(vault);
        let args = UnlockArgs { keyfile: Some(key_path), password_stdin: false };
        // Exercise the actual opening helper used by the mount command.
        let mut fs = open_fs(&path, &args, false).unwrap();
        let ino = fs.create_file(vault::fs::ROOT_INO, b"timed", 0o600).unwrap();
        fs.write(ino, 0, b"persist without an explicit flush").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2200));
        fs.maybe_commit().unwrap();
        assert!(!fs.is_dirty(), "mount opening disabled periodic commits");
        drop(fs); // no explicit commit or clean unmount
        let mut fs = open_fs(&path, &args, true).unwrap();
        let ino = fs.resolve("/timed").unwrap();
        assert_eq!(&*fs.read(ino, 0, 100).unwrap(), b"persist without an explicit flush");
    }

    #[test]
    fn aborted_export_keeps_the_original_and_removes_staging() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("original");
        std::fs::write(&path, b"keep me").unwrap();
        let dir = LocalDir::open(temp.path()).unwrap();
        {
            let mut staged = dir.begin_export(OsStr::new("original"), true).unwrap();
            staged.file().write_all(b"partial").unwrap();
            assert_eq!(std::fs::read(&path).unwrap(), b"keep me");
            // Dropping models an error before publication.
        }
        assert_eq!(std::fs::read(&path).unwrap(), b"keep me");
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
    }

    #[test]
    fn failed_export_publication_keeps_the_destination() {
        let temp = tempfile::tempdir().unwrap();
        let dir = LocalDir::open(temp.path()).unwrap();
        let name = OsStr::new("destination");
        let mut staged = dir.begin_export(name, true).unwrap();
        staged.file().write_all(b"complete").unwrap();
        // An incompatible entry appearing before publication must survive.
        std::fs::create_dir(temp.path().join(name)).unwrap();
        assert!(staged.finish(name, true).is_err());
        assert!(temp.path().join(name).is_dir());
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn forced_export_uses_the_open_directory_after_a_path_swap() {
        let temp = tempfile::tempdir().unwrap();
        let out = temp.path().join("out");
        let moved = temp.path().join("moved");
        let elsewhere = temp.path().join("elsewhere");
        std::fs::create_dir(&out).unwrap();
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::write(elsewhere.join("file"), b"leave this alone").unwrap();
        let dir = LocalDir::open(&out).unwrap();
        let name = OsStr::new("file");
        let mut staged = dir.begin_export(name, true).unwrap();
        staged.file().write_all(b"vault plaintext").unwrap();
        std::fs::rename(&out, &moved).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &out).unwrap();
        staged.finish(name, true).unwrap();
        assert_eq!(std::fs::read(moved.join("file")).unwrap(), b"vault plaintext");
        assert_eq!(std::fs::read(elsewhere.join("file")).unwrap(), b"leave this alone");
        assert_eq!(std::fs::read_dir(&moved).unwrap().count(), 1);
    }

    #[cfg(windows)]
    #[test]
    fn unrepresentable_names_are_rejected_without_substitution() {
        use std::os::windows::ffi::OsStringExt;
        let invalid = OsString::from_wide(&[0xd800]);
        assert!(local_name_bytes(&invalid).is_err());
        assert!(export_name(b"f\xff").is_err());
        assert!(export_name(b"NUL").is_err());
        assert!(export_name(b"file:stream").is_err());
    }

    #[test]
    fn sizes() {
        assert_eq!(parse_size("4096").unwrap(), 4096);
        assert_eq!(parse_size("16K").unwrap(), 16 << 10);
        assert_eq!(parse_size("500M").unwrap(), 500 << 20);
        assert_eq!(parse_size("10G").unwrap(), 10 << 30);
        assert_eq!(parse_size("1GiB").unwrap(), 1 << 30);
        assert_eq!(parse_size("2tb").unwrap(), 2 << 40);
        assert!(parse_size("10X").is_err());
        assert!(parse_size("G").is_err());
        assert!(parse_size("99999999999T").is_err());
    }

    #[test]
    fn paths() {
        assert_eq!(split_path("/a/b").unwrap(), ("/a", "b"));
        assert_eq!(split_path("b").unwrap(), ("/", "b"));
        assert_eq!(split_path("/b/").unwrap(), ("/", "b"));
        assert!(split_path("/").is_err());
        for bad in ["/.", "/..", "/a/.", "/a/b/..", "a/../", "."] {
            assert!(split_path(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn displayed_names_cannot_inject_terminal_sequences() {
        assert_eq!(display_name(b"report.pdf"), "report.pdf");
        assert_eq!(display_name("caf\u{e9}".as_bytes()), "caf\u{e9}");
        let evil = display_name(b"x\x1b]0;pwned\x07\x1b[2J\r\n\x7f");
        assert!(!evil.chars().any(|c| c.is_control()), "{evil:?}");
        assert!(evil.contains("\\u{1b}"));
        // Bidi override ("Trojan Source"-style spoofing) is escaped too.
        let spoof = display_name("invoice\u{202e}fdp.exe".as_bytes());
        assert!(!spoof.contains('\u{202e}') && spoof.contains("\\u{202e}"));
        // Invalid UTF-8 doesn't panic.
        assert!(!display_name(&[0xff, 0xfe, b'a']).is_empty());
        // Local paths built from vault names (what `get` prints) too.
        let p = Path::new("out").join("\x1b]0;pwned\x07name");
        assert!(!display_path(&p).chars().any(|c| c.is_control()), "{:?}", display_path(&p));
    }

    #[test]
    fn recursion_is_bounded() {
        assert!(check_depth(MAX_DEPTH).is_ok());
        assert!(check_depth(MAX_DEPTH + 1).is_err());
    }

    #[test]
    fn local_names() {
        for bad in ["", ".", "..", "a/b", "a\\b", "a\0b"] {
            assert!(!safe_local_name(bad), "{bad:?}");
        }
        assert!(safe_local_name("report.pdf"));
        if cfg!(windows) {
            for bad in ["file:stream", "CON", "nul.txt", "COM1", "a?", "trailing."] {
                assert!(!safe_local_name(bad), "{bad:?}");
            }
        }
        // Device-name matching is tested on every OS (it's pure string logic).
        for dev in ["CON", "nul.txt", "NUL .txt", "aux..log", "COM1", "lpt9.dat", "COM\u{b9}", "conin$", "CONOUT$.x"] {
            assert!(windows_reserved(dev), "{dev:?}");
        }
        for ok in ["comp.txt", "comm.log", "COM0", "COM10", "console.txt", "nullguard.ngv", "lpt.txt"] {
            assert!(!windows_reserved(ok), "{ok:?}");
        }
    }

    #[test]
    fn time_format() {
        assert_eq!(fmt_time(Timestamp { secs: 0, nanos: 0 }), "1970-01-01 00:00");
        assert_eq!(fmt_time(Timestamp { secs: 1_700_000_000, nanos: 0 }), "2023-11-14 22:13");
    }
}
