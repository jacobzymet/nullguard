use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

use crate::protocol::LocalPath;

#[derive(Default, Deserialize, Serialize)]
pub struct Settings {
    #[serde(default)]
    pub recent: Vec<LocalPath>,
}

pub fn data_dir() -> Result<PathBuf> {
    let dirs = ProjectDirs::from("com", "Nulliance", "Nullguard")
        .context("Could not locate your application-data folder")?;
    let path = dirs.data_local_dir().to_owned();
    private_dir(&path)?;
    Ok(path)
}

pub fn private_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
        let meta = fs::symlink_metadata(path)?;
        if !meta.is_dir()
            || meta.file_type().is_symlink()
            || meta.uid() != nullguard::platform::uid()
        {
            bail!("The application-data folder must be a real folder owned by you.");
        }
        // Existing folders must also be private before storing vault paths.
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            bail!(
                "The application-data folder is readable by other users. Set its permissions to 700."
            );
        }
    }
    #[cfg(windows)]
    if !path.exists() {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        nullguard::platform::win::create_private_dir(path)?;
    }
    Ok(())
}

pub fn load(dir: &Path) -> Result<Settings> {
    let path = dir.join("vaults.json");
    match File::open(path) {
        Ok(file) => {
            let mut bytes = Vec::new();
            file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
            if bytes.len() > 1024 * 1024 {
                bail!("The recent-vault list is too large. Your vault files are unaffected.");
            }
            let mut settings: Settings = serde_json::from_slice(&bytes)
                .context("Could not read the recent-vault list. Your vault files are unaffected")?;
            settings.recent.truncate(50);
            settings.recent.retain(|p| p.decode().is_ok());
            Ok(settings)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Settings::default()),
        Err(e) => Err(e.into()),
    }
}

pub fn save(dir: &Path, settings: &Settings) -> Result<()> {
    let temp = dir.join(format!("vaults-{}.tmp", random_id()?));
    let result = (|| -> Result<()> {
        let mut file = private_file(&temp)?;
        serde_json::to_writer(&mut file, settings)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, dir.join("vaults.json"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

pub fn private_file(path: &Path) -> std::io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    }
    #[cfg(windows)]
    {
        nullguard::platform::win::create_private_file(path, 0)
    }
}

pub fn random_id() -> Result<String> {
    use std::fmt::Write;
    let mut text = String::new();
    for byte in nullguard::crypto::random::array::<12>()? {
        write!(&mut text, "{byte:02x}")?;
    }
    Ok(text)
}

pub fn mountpoint(dir: &Path, vault: &Path) -> Result<PathBuf> {
    check_dependencies()?;
    #[cfg(windows)]
    {
        let _ = (dir, vault);
        for letter in (b'D'..=b'Z').rev() {
            let path = PathBuf::from(format!("{}:", letter as char));
            if nullguard::mount::check_mountpoint(&path).is_ok() {
                return Ok(path);
            }
        }
        bail!("No free drive letter is available. Disconnect an unused drive and try again.");
    }
    #[cfg(unix)]
    {
        let _ = vault;
        let mounts = dir.join("mounts");
        private_dir(&mounts)?;
        let path = mounts.join(random_id()?);
        private_dir(&path)?;
        Ok(path)
    }
}

pub fn cleanup_mountpoint(path: &Path) {
    #[cfg(unix)]
    {
        let _ = fs::remove_dir(path);
    } // only an empty directory; never recursive
    #[cfg(windows)]
    {
        let _ = path;
    }
}

pub fn check_dependencies() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        if !Path::new("/dev/fuse").exists() {
            bail!(
                "FUSE is unavailable. Install your distribution's fuse3 package and enable /dev/fuse, then try again."
            );
        }
        let found = std::env::var_os("PATH").is_some_and(|paths| {
            std::env::split_paths(&paths).any(|p| p.join("fusermount3").is_file())
        });
        if !found {
            bail!(
                "Install your distribution's fuse3 package so fusermount3 is available, then try again."
            );
        }
    }
    #[cfg(target_os = "macos")]
    {
        if cfg!(feature = "macos-no-mount") {
            bail!(
                "This build has mounting disabled. Use the standard desktop build with macFUSE installed."
            );
        }
        if !Path::new("/Library/Filesystems/macfuse.fs").exists() {
            bail!("Install macFUSE from macfuse.github.io, then reopen Nullguard.");
        }
    }
    #[cfg(windows)]
    {
        // This performs the existing registry/version-independent availability
        // check. A busy letter proves the driver check has not run yet.
        for letter in (b'D'..=b'Z').rev() {
            let path = PathBuf::from(format!("{}:", letter as char));
            match nullguard::mount::check_mountpoint(&path) {
                Ok(()) => return Ok(()),
                Err(e) if e.to_string().contains("already in use") => continue,
                Err(e) => return Err(e.into()),
            }
        }
        bail!("No free drive letter is available.");
    }
    #[allow(unreachable_code)]
    Ok(())
}

pub fn open_folder(path: &Path) -> Result<()> {
    #[cfg(target_os = "windows")]
    let mut command = std::process::Command::new("explorer.exe");
    #[cfg(target_os = "macos")]
    let mut command = std::process::Command::new("/usr/bin/open");
    #[cfg(target_os = "linux")]
    let mut command = std::process::Command::new("xdg-open");
    let mut child = command
        .arg(path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("The vault is unlocked, but the file manager could not be opened")?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

pub fn display(path: &Path) -> String {
    path.to_string_lossy()
        .chars()
        .flat_map(|c| {
            if c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') {
                c.escape_unicode().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn saved_settings_contain_paths_only_and_are_private() {
        let dir = tempfile::tempdir().unwrap();
        let settings = Settings {
            recent: vec![LocalPath::new(Path::new("private.ngv"))],
        };
        save(dir.path(), &settings).unwrap();
        assert_eq!(load(dir.path()).unwrap().recent, settings.recent);
        let text = fs::read_to_string(dir.path().join("vaults.json")).unwrap();
        assert!(!text.contains("password") && !text.contains("keyfile"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(dir.path().join("vaults.json"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        save(dir.path(), &Settings::default()).unwrap();
        assert!(load(dir.path()).unwrap().recent.is_empty());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
