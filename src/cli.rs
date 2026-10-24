//! The `nullguard` command line.

use std::fs::OpenOptions;
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use zeroize::Zeroizing;

use crate::crypto::{Argon2Params, CipherSuite, HybridPublicKey, HybridSecretKey};
use crate::mount::{self, MountOptions};
use crate::vault::fs::{Fs, Kind, Timestamp};
use crate::vault::header::{KeySlot, chunk_stride};
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
        /// Data cipher: xchacha20-poly1305 (default) or aes-256-gcm.
        #[arg(long, default_value = "xchacha20-poly1305")]
        cipher: String,
        #[command(flatten)]
        kdf: KdfArgs,
        /// Chunk size, a power of two from 4K to 1M (default: picked from the vault size).
        #[arg(long)]
        chunk_size: Option<String>,
        /// Skip filling the vault with random data. Faster, but reveals how
        /// much of the vault is used.
        #[arg(long)]
        quick: bool,
        /// Also allow this public key's keyfile to unlock the vault (repeatable).
        #[arg(long = "recipient", value_name = "PUBKEY_FILE")]
        recipients: Vec<PathBuf>,
        /// Read the password from standard input instead of the terminal.
        #[arg(long)]
        password_stdin: bool,
    },
    /// Unlock a vault and mount it as a drive (Linux, macOS).
    Mount {
        vault: PathBuf,
        /// Existing empty directory to mount on.
        mountpoint: PathBuf,
        #[command(flatten)]
        unlock: UnlockArgs,
        /// Mount read-only.
        #[arg(long)]
        read_only: bool,
        /// Forbid running programs stored in the vault.
        #[arg(long)]
        no_exec: bool,
    },
    /// Unmount (lock) a mounted vault.
    Unmount { mountpoint: PathBuf },
    /// Change the vault password (replaces all password slots).
    ChangePassword {
        vault: PathBuf,
        #[command(flatten)]
        unlock: UnlockArgs,
        #[command(flatten)]
        kdf: KdfArgs,
    },
    /// Generate a post-quantum hybrid keyfile (ML-KEM-1024 + X25519).
    Keygen {
        /// Where to write the secret keyfile; the public key goes to <FILE>.pub.
        out: PathBuf,
        /// Store the keyfile unencrypted (not recommended).
        #[arg(long)]
        no_passphrase: bool,
        /// Read the passphrase from standard input.
        #[arg(long)]
        password_stdin: bool,
    },
    /// Let another keyfile unlock this vault (share it, or add your own keyfile).
    AddRecipient {
        vault: PathBuf,
        /// Public key file (from `nullguard keygen`).
        pubkey: PathBuf,
        #[command(flatten)]
        unlock: UnlockArgs,
    },
    /// Revoke a recipient's key slot, by fingerprint (see `info`).
    RemoveRecipient {
        vault: PathBuf,
        fingerprint: String,
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

#[derive(Args, Clone)]
struct KdfArgs {
    /// Argon2id memory cost in MiB (minimum 64).
    #[arg(long, default_value_t = Argon2Params::DEFAULT.memory_kib / 1024)]
    kdf_memory: u32,
    /// Argon2id passes (minimum 2).
    #[arg(long, default_value_t = Argon2Params::DEFAULT.iterations)]
    kdf_iterations: u32,
    /// Argon2id lanes.
    #[arg(long, default_value_t = Argon2Params::DEFAULT.parallelism)]
    kdf_parallelism: u32,
}

impl KdfArgs {
    fn params(&self) -> Result<Argon2Params> {
        let p = Argon2Params {
            memory_kib: self.kdf_memory.checked_mul(1024).ok_or_else(|| anyhow!("--kdf-memory is too large"))?,
            iterations: self.kdf_iterations,
            parallelism: self.kdf_parallelism,
        };
        p.validate_for_new_slot()?;
        Ok(p)
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
            // Bounded read into a buffer that never reallocates.
            let mut line = Zeroizing::new(String::with_capacity(MAX_PASSWORD_BYTES + 3));
            io::stdin()
                .lock()
                .take(MAX_PASSWORD_BYTES as u64 + 2)
                .read_line(&mut line)
                .context("reading password from stdin")?;
            if line.is_empty() {
                bail!("standard input ended before a password was read");
            }
            while line.ends_with('\n') || line.ends_with('\r') {
                line.pop();
            }
            line
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

/// Holds whichever secret unlocks the vault.
enum Unlocker {
    Password(Zeroizing<String>),
    Keyfile(HybridSecretKey),
}

impl Unlocker {
    fn from_args(args: &UnlockArgs, p: &Prompter) -> Result<Self> {
        match &args.keyfile {
            None => Ok(Self::Password(p.read("Vault password: ")?)),
            Some(path) => {
                let text = Zeroizing::new(
                    std::fs::read_to_string(path).with_context(|| format!("reading keyfile {}", path.display()))?,
                );
                check_keyfile_permissions(path, HybridSecretKey::keyfile_is_encrypted(&text))?;
                let pass = if HybridSecretKey::keyfile_is_encrypted(&text) {
                    Some(p.read("Keyfile passphrase: ")?)
                } else {
                    None
                };
                let key = HybridSecretKey::from_keyfile(&text, pass.as_ref().map(|s| s.as_bytes()))?;
                Ok(Self::Keyfile(key))
            }
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

/// Refuse (unencrypted) or warn about (encrypted) keyfiles that other users
/// can read, like ssh does for private keys.
fn check_keyfile_permissions(path: &Path, encrypted: bool) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            let fix = format!("chmod 600 {}", path.display());
            if !encrypted {
                bail!(
                    "keyfile {} is readable by other users (mode {mode:o}) and has no passphrase; \
                     refusing to use it. Fix with: {fix}",
                    path.display()
                );
            }
            eprintln!("WARNING: keyfile {} is readable by other users (mode {mode:o}). Fix with: {fix}", path.display());
        }
    }
    #[cfg(not(unix))]
    let _ = (path, encrypted);
    Ok(())
}

fn unlock(path: &Path, args: &UnlockArgs, read_only: bool) -> Result<(Vault, Prompter, Unlocker)> {
    let p = Prompter { stdin: args.password_stdin };
    let u = Unlocker::from_args(args, &p)?;
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

/// Create a file that only the current user can read (unix: mode 0600).
fn create_private(path: &Path, overwrite: bool) -> io::Result<std::fs::File> {
    let mut o = OpenOptions::new();
    o.write(true);
    if overwrite {
        o.create(true).truncate(true);
    } else {
        o.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}

pub fn run() -> Result<()> {
    crate::platform::harden_process();
    let cli = Cli::parse();
    match cli.command {
        Command::Create { vault, size, cipher, kdf, chunk_size, quick, recipients, password_stdin } => {
            let size = parse_size(&size)?;
            let cipher = CipherSuite::from_name(&cipher).ok_or_else(|| anyhow!("unknown cipher {cipher:?}"))?;
            let chunk_size = match chunk_size {
                Some(s) => Some(u32::try_from(parse_size(&s)?).map_err(|_| anyhow!("chunk size too large"))?),
                None => None,
            };
            let recipients = recipients
                .iter()
                .map(|p| {
                    let t = std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?;
                    HybridPublicKey::decode(&t).with_context(|| format!("parsing public key {}", p.display()))
                })
                .collect::<Result<Vec<_>>>()?;
            let opts = CreateOptions { size, cipher, kdf: kdf.params()?, chunk_size, fill_random: !quick, recipients };
            if quick {
                eprintln!("WARNING: --quick skips random fill; an observer can tell how much of the vault is used.");
            }
            let pw = Prompter { stdin: password_stdin }.new_password("vault password")?;
            eprintln!("Creating vault (deriving key, {} MiB of memory)...", opts.kdf.memory_kib / 1024);
            let mut last = 0;
            Vault::create(&vault, pw.as_bytes(), &opts, &mut |done, total| {
                let pct = done * 100 / total.max(1);
                if pct != last {
                    last = pct;
                    eprint!("\rFilling with random data: {pct:3}%");
                    if pct == 100 {
                        eprintln!();
                    }
                }
            })
            .with_context(|| format!("creating {}", vault.display()))?;
            let h = Vault::peek_header(&vault)?;
            println!(
                "Created {} ({} usable, {}, {} chunks).",
                vault.display(),
                human(h.chunk_count * h.chunk_size as u64),
                h.cipher.name(),
                human(h.chunk_size as u64)
            );
        }

        Command::Mount { vault, mountpoint, unlock: u, read_only, no_exec } => {
            if !mount::SUPPORTED {
                return Err(mount::unsupported().into());
            }
            let meta = std::fs::metadata(&mountpoint)
                .with_context(|| format!("mount point {} does not exist", mountpoint.display()))?;
            if !meta.is_dir() {
                bail!("mount point {} is not a directory", mountpoint.display());
            }
            // Mounting over files would hide them (and make it easy to save
            // something "into the vault" that actually lands outside it later).
            if std::fs::read_dir(&mountpoint)?.next().is_some() {
                bail!("mount point {} is not empty", mountpoint.display());
            }
            let fs = open_fs(&vault, &u, read_only)?;
            let mp = mountpoint.clone();
            let opts = MountOptions {
                read_only,
                no_exec,
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
            mount::unmount(&mountpoint)?;
            eprintln!("Unmounted {}.", mountpoint.display());
        }

        Command::ChangePassword { vault, unlock: u, kdf } => {
            let params = kdf.params()?;
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

        Command::Keygen { out, no_passphrase, password_stdin } => {
            let pub_path = PathBuf::from(format!("{}.pub", out.display()));
            if out.exists() || pub_path.exists() {
                bail!("{} or {} already exists; refusing to overwrite", out.display(), pub_path.display());
            }
            let sk = HybridSecretKey::generate()?;
            let text = if no_passphrase {
                eprintln!("WARNING: the keyfile will be stored unencrypted. Anyone who copies it can unlock your vaults.");
                sk.to_keyfile(None)?
            } else {
                let p = Prompter { stdin: password_stdin };
                let pass = p.new_password("keyfile passphrase")?;
                eprintln!("Encrypting keyfile...");
                sk.to_keyfile(Some((pass.as_bytes(), Argon2Params::DEFAULT)))?
            };
            create_private(&out, false)
                .and_then(|mut f| f.write_all(text.as_bytes()).and_then(|_| f.sync_all()))
                .with_context(|| format!("writing {}", out.display()))?;
            let pk = sk.public_key();
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&pub_path)
                .and_then(|mut f| f.write_all(pk.encode().as_bytes()))
                .with_context(|| format!("writing {}", pub_path.display()))?;
            println!("Secret keyfile: {} (keep it secret, keep a backup)", out.display());
            println!("Public key:     {}", pub_path.display());
            println!("Fingerprint:    {}", pk.fingerprint_hex());
        }

        Command::AddRecipient { vault, pubkey, unlock: u } => {
            let text = std::fs::read_to_string(&pubkey).with_context(|| format!("reading {}", pubkey.display()))?;
            let pk = HybridPublicKey::decode(&text)?;
            let (mut v, _, _) = unlock(&vault, &u, false)?;
            v.add_recipient(&pk)?;
            println!("Added recipient {}.", pk.fingerprint_hex());
        }

        Command::RemoveRecipient { vault, fingerprint, unlock: u } => {
            let (mut v, _, _) = unlock(&vault, &u, false)?;
            let fp = v.remove_recipient(&fingerprint)?;
            println!("Removed recipient {fp}.");
        }

        Command::Info { vault } => {
            let h = Vault::peek_header(&vault)?;
            println!("nullguard vault (format version {})", vault::header::FORMAT_VERSION);
            println!("  cipher:      {}", h.cipher.name());
            println!("  chunk size:  {}", human(h.chunk_size as u64));
            println!("  capacity:    {} ({} chunks)", human(h.chunk_count * h.chunk_size as u64), h.chunk_count);
            println!("  file size:   {}", human(h.data_offset + h.chunk_count * chunk_stride(h.chunk_size)));
            println!("  key slots:");
            for (i, s) in h.slots.iter().enumerate() {
                match s {
                    KeySlot::Password(p) => println!(
                        "    [{i}] password  argon2id m={} MiB t={} p={}",
                        p.kdf.memory_kib / 1024,
                        p.kdf.iterations,
                        p.kdf.parallelism
                    ),
                    KeySlot::Recipient(r) => println!(
                        "    [{i}] keyfile   ml-kem-1024+x25519 fingerprint {}",
                        crate::crypto::hybrid::hex(&r.fingerprint)
                    ),
                }
            }
            println!("(Header values are not authenticated until the vault is unlocked.)");
        }

        Command::Verify { vault, unlock: u } => {
            let mut fs = open_fs(&vault, &u, true)?;
            let r = fs.verify()?;
            println!(
                "Checked {} files, {} directories, {} symlinks, {} blocks.",
                r.files, r.dirs, r.symlinks, r.blocks_checked
            );
            if r.bad_blocks.is_empty() {
                println!("OK: header, metadata and all data blocks are authentic.");
            } else {
                for (path, idx, err) in &r.bad_blocks {
                    eprintln!("BAD: {path} block {idx}: {err}");
                }
                bail!("{} block(s) failed verification: the vault was modified or damaged", r.bad_blocks.len());
            }
        }

        Command::Ls { vault, path, unlock: u } => {
            let fs = open_fs(&vault, &u, true)?;
            let ino = resolve(&fs, &path)?;
            let entries = if fs.attr(ino)?.kind == Kind::Dir {
                fs.readdir(ino)?.into_iter().filter(|e| e.name != b"." && e.name != b"..").collect()
            } else {
                vec![vault::fs::DirEntry { name: path.clone().into_bytes(), ino, kind: Kind::File }]
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
                    String::from_utf8_lossy(&e.name)
                );
                if a.kind == Kind::Symlink {
                    line.push_str(&format!(" -> {}", String::from_utf8_lossy(&fs.readlink(e.ino)?)));
                }
                println!("{line}");
            }
        }

        Command::Get { vault, path, dest, force, unlock: u } => {
            let mut fs = open_fs(&vault, &u, true)?;
            let ino = resolve(&fs, &path)?;
            let dest = if dest.is_dir() && fs.attr(ino)?.kind != Kind::Dir {
                dest.join(base_name(&path)?)
            } else {
                dest
            };
            let n = export(&mut fs, ino, &dest, force)?;
            println!("Copied {n} file(s) to {}.", dest.display());
        }

        Command::Put { vault, src, path, force, unlock: u } => {
            let mut fs = open_fs(&vault, &u, false)?;
            let (parent, name) = match fs.resolve(&path) {
                Ok(ino) if fs.attr(ino)?.kind == Kind::Dir => {
                    let name = src
                        .file_name()
                        .ok_or_else(|| anyhow!("cannot determine a name for {}", src.display()))?
                        .to_string_lossy()
                        .into_owned();
                    (ino, name)
                }
                _ => {
                    let (dir, name) = split_path(&path)?;
                    (resolve(&fs, dir)?, name.to_owned())
                }
            };
            let n = import(&mut fs, &src, parent, name.as_bytes(), force)?;
            fs.commit()?;
            println!("Copied {n} file(s) into the vault.");
        }

        Command::Rm { vault, path, recursive, unlock: u } => {
            let mut fs = open_fs(&vault, &u, false)?;
            let (dir, name) = split_path(&path)?;
            let parent = resolve(&fs, dir)?;
            remove(&mut fs, parent, name.as_bytes(), recursive)?;
            fs.commit()?;
            println!("Removed {path}.");
        }

        Command::Mkdir { vault, path, unlock: u } => {
            let mut fs = open_fs(&vault, &u, false)?;
            let (dir, name) = split_path(&path)?;
            let parent = resolve(&fs, dir)?;
            fs.mkdir(parent, name.as_bytes(), 0o700, crate::platform::uid(), crate::platform::gid())?;
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
    if name.is_empty() {
        bail!("invalid path {path:?}");
    }
    Ok((if dir.is_empty() { "/" } else { dir }, name))
}

fn base_name(path: &str) -> Result<&str> {
    Ok(split_path(path)?.1)
}

const COPY_BUF: usize = 1 << 20;

/// Whether a vault entry name can be used as a local file name without
/// escaping the destination directory (or, on Windows, writing into an
/// NTFS alternate data stream or a device such as `CON`).
fn safe_local_name(name: &str) -> bool {
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\', '\0']) {
        return false;
    }
    if cfg!(windows) {
        let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
        let reserved = ["CON", "PRN", "AUX", "NUL"].contains(&stem.as_str())
            || ((stem.starts_with("COM") || stem.starts_with("LPT")) && stem.len() == 4);
        if reserved
            || name.contains(['<', '>', ':', '"', '|', '?', '*'])
            || name.chars().any(|c| (c as u32) < 32)
            || name.ends_with(['.', ' '])
        {
            return false;
        }
    }
    true
}

fn import(fs: &mut Fs, src: &Path, parent: u64, name: &[u8], force: bool) -> Result<u64> {
    let meta = std::fs::symlink_metadata(src).with_context(|| format!("reading {}", src.display()))?;
    let (uid, gid) = (crate::platform::uid(), crate::platform::gid());
    if meta.is_dir() {
        let dir = match fs.lookup(parent, name) {
            Ok(ino) if fs.attr(ino)?.kind == Kind::Dir => ino,
            Ok(_) => bail!("{} exists in the vault and is not a directory", String::from_utf8_lossy(name)),
            Err(_) => fs.mkdir(parent, name, 0o700, uid, gid)?,
        };
        let mut n = 0;
        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            let child = entry.file_name();
            n += import(fs, &entry.path(), dir, child.to_string_lossy().as_bytes(), force)?;
        }
        return Ok(n);
    }
    if meta.file_type().is_symlink() {
        eprintln!("skipping symlink {}", src.display());
        return Ok(0);
    }
    if let Ok(existing) = fs.lookup(parent, name) {
        if !force {
            bail!("{} already exists in the vault (use --force to overwrite)", String::from_utf8_lossy(name));
        }
        if fs.attr(existing)?.kind == Kind::Dir {
            bail!("{} is a directory in the vault", String::from_utf8_lossy(name));
        }
        fs.unlink(parent, name)?;
    }
    let mut f = std::fs::File::open(src).with_context(|| format!("opening {}", src.display()))?;
    let ino = fs.create_file(parent, name, 0o600, uid, gid)?;
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
            fs.maybe_commit()?;
        }
        if let Ok(m) = meta.modified() {
            fs.set_attr(ino, &vault::fs::SetAttr { mtime: Some(Timestamp::from_system(m)), ..Default::default() })?;
        }
        Ok(())
    })();
    if let Err(e) = copy {
        // Don't leave a truncated file behind in the vault.
        let _ = fs.unlink(parent, name);
        return Err(e.context(format!("copying {}", src.display())));
    }
    Ok(1)
}

fn export(fs: &mut Fs, ino: u64, dest: &Path, force: bool) -> Result<u64> {
    let a = fs.attr(ino)?;
    match a.kind {
        Kind::Dir => {
            if !dest.exists() {
                std::fs::create_dir(dest).with_context(|| format!("creating {}", dest.display()))?;
            }
            let mut n = 0;
            for e in fs.readdir(ino)? {
                if e.name == b"." || e.name == b".." {
                    continue;
                }
                let name = String::from_utf8_lossy(&e.name).into_owned();
                if !safe_local_name(&name) {
                    bail!("refusing to create a local file with the unsafe name {name:?}");
                }
                n += export(fs, e.ino, &dest.join(&name), force)?;
            }
            Ok(n)
        }
        Kind::Symlink => {
            eprintln!("skipping symlink {}", dest.display());
            Ok(0)
        }
        Kind::File => {
            let mut out = create_private(dest, force).with_context(|| {
                format!("creating {} (use --force to overwrite existing files)", dest.display())
            })?;
            let copy = (|| -> Result<()> {
                let mut off = 0;
                while off < a.size {
                    let chunk = fs.read(ino, off, COPY_BUF)?;
                    out.write_all(&chunk)?;
                    off += chunk.len() as u64;
                }
                out.sync_all()?;
                Ok(())
            })();
            if let Err(e) = copy {
                // Never leave partial plaintext behind, e.g. when a block
                // fails authentication halfway through.
                drop(out);
                let _ = std::fs::remove_file(dest);
                return Err(e.context(format!("copying out to {}", dest.display())));
            }
            Ok(1)
        }
    }
}

fn remove(fs: &mut Fs, parent: u64, name: &[u8], recursive: bool) -> Result<()> {
    let ino = fs.lookup(parent, name)?;
    if fs.attr(ino)?.kind == Kind::Dir {
        if !recursive {
            bail!("{} is a directory (use -r)", String::from_utf8_lossy(name));
        }
        for e in fs.readdir(ino)? {
            if e.name != b"." && e.name != b".." {
                remove(fs, ino, &e.name, true)?;
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
    }

    #[test]
    fn time_format() {
        assert_eq!(fmt_time(Timestamp { secs: 0, nanos: 0 }), "1970-01-01 00:00");
        assert_eq!(fmt_time(Timestamp { secs: 1_700_000_000, nanos: 0 }), "2023-11-14 22:13");
    }
}
