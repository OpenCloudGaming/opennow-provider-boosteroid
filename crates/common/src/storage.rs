use crate::{hex, invalid, random_bytes};
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::{
    ambient_authority,
    fs::{Dir, DirBuilder, OpenOptions},
};
use fs2::FileExt;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
};

#[cfg(windows)]
#[path = "windows.rs"]
mod platform;

const MAX_ENTRIES: usize = 8192;

pub(crate) struct PrivateRoot {
    dir: Dir,
}

impl PrivateRoot {
    pub(crate) fn open(path: &Path, create: bool) -> io::Result<Self> {
        if !path.is_absolute() || path.as_os_str().len() > 4096 {
            return Err(invalid("Private root must be an absolute bounded path"));
        }
        let mut anchor = PathBuf::new();
        let mut components = Vec::new();
        for component in path.components() {
            match component {
                Component::Prefix(prefix) => anchor.push(prefix.as_os_str()),
                Component::RootDir => anchor.push(std::path::MAIN_SEPARATOR.to_string()),
                Component::Normal(name) => components.push(name),
                _ => {
                    return Err(invalid(
                        "Private root must not contain traversal components",
                    ));
                }
            }
        }
        if components.is_empty() || components.len() > 128 {
            return Err(invalid("Private root must not be a filesystem root"));
        }
        let mut dir = Dir::open_ambient_dir(anchor, ambient_authority())?;
        for (index, name) in components.iter().enumerate() {
            let last = index + 1 == components.len();
            #[cfg(windows)]
            let opened = if last {
                platform::open_directory(&dir, name.as_ref(), false)
            } else {
                dir.open_dir_nofollow(name)
            };
            #[cfg(unix)]
            let opened = dir.open_dir_nofollow(name);
            let next = match opened {
                Ok(next) => next,
                Err(error) if error.kind() == io::ErrorKind::NotFound && create && last => {
                    let builder = DirBuilder::new();
                    #[cfg(unix)]
                    let builder = {
                        use cap_std::fs::DirBuilderExt;
                        let mut builder = builder;
                        builder.mode(0o700);
                        builder
                    };
                    dir.create_dir_with(name, &builder)?;
                    #[cfg(unix)]
                    dir.open(".")?.sync_all()?;
                    #[cfg(unix)]
                    let next = dir.open_dir_nofollow(name)?;
                    #[cfg(windows)]
                    let next = platform::open_directory(&dir, name.as_ref(), true)?;
                    #[cfg(windows)]
                    platform::make_private(&next.try_clone()?.into_std_file())?;
                    next
                }
                Err(error) => return Err(error),
            };
            dir = next;
        }
        validate_handle(&dir.try_clone()?.into_std_file(), true, 0)?;
        Ok(Self { dir })
    }

    fn open_file(&self, name: &str, create: bool) -> io::Result<File> {
        validate_handle(&self.dir.try_clone()?.into_std_file(), true, 0)?;
        validate_name(name)?;
        let mut options = OpenOptions::new();
        options.read(true).write(create).follow(FollowSymlinks::No);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NONBLOCK);
        }
        if create {
            options.create_new(true);
            #[cfg(windows)]
            {
                use cap_std::fs::OpenOptionsExt;
                use windows_sys::Win32::Storage::FileSystem::{
                    DELETE, FILE_GENERIC_READ, FILE_GENERIC_WRITE, WRITE_DAC,
                };
                options.access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | WRITE_DAC | DELETE);
            }
        }
        let file = self.dir.open_with(name, &options)?.into_std();
        #[cfg(windows)]
        if create {
            platform::make_private(&file)?;
        }
        validate_handle(&file, false, u64::MAX)?;
        Ok(file)
    }

    pub(crate) fn lock(&self, name: &str) -> io::Result<File> {
        let file = match self.open_file(name, true) {
            Ok(file) => {
                file.sync_all()?;
                self.sync()?;
                file
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let mut options = OpenOptions::new();
                options.read(true).write(true).follow(FollowSymlinks::No);
                #[cfg(unix)]
                {
                    use cap_std::fs::OpenOptionsExt;
                    options.custom_flags(libc::O_NONBLOCK);
                }
                self.dir.open_with(name, &options)?.into_std()
            }
            Err(error) => return Err(error),
        };
        validate_handle(&file, false, 0)?;
        FileExt::try_lock_exclusive(&file)?;
        if !same_file(&file, &self.open_file(name, false)?)? {
            return Err(invalid("Lock file changed during attachment"));
        }
        Ok(file)
    }

    pub(crate) fn read(&self, name: &str, maximum: usize) -> io::Result<Option<Vec<u8>>> {
        let file = match self.open_file(name, false) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        validate_handle(&file, false, maximum as u64)?;
        let mut bytes = Vec::new();
        (&file).take(maximum as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > maximum {
            return Err(invalid("Private file exceeds its limit"));
        }
        validate_handle(&file, false, maximum as u64)?;
        Ok(Some(bytes))
    }

    pub(crate) fn replace(&self, name: &str, bytes: &[u8], maximum: usize) -> io::Result<()> {
        validate_name(name)?;
        if bytes.len() > maximum {
            return Err(invalid("Private file exceeds its limit"));
        }
        self.read(name, maximum)?;
        self.check_entry_bound()?;
        let temporary = format!(".tmp-{}", hex(&random_bytes()?));
        let result = (|| {
            let mut file = self.open_file(&temporary, true)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            #[cfg(unix)]
            self.dir.rename(&temporary, &self.dir, name)?;
            #[cfg(windows)]
            platform::replace(&self.dir.try_clone()?.into_std_file(), &file, name)?;
            self.sync()
        })();
        if result.is_err() {
            let _ = self.dir.remove_file(&temporary);
        }
        result
    }

    pub(crate) fn remove_abandoned_temps(&self) -> io::Result<()> {
        self.check_entry_bound()?;
        let mut changed = false;
        for entry in self.dir.entries()? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if name.len() == 69
                && name.starts_with(".tmp-")
                && name[5..].bytes().all(|b| b.is_ascii_hexdigit())
            {
                let file = self.open_file(name, false)?;
                validate_handle(&file, false, crate::MAX_CONTROL_STATE_BYTES as u64)?;
                self.dir.remove_file(name)?;
                changed = true;
            }
        }
        if changed {
            self.sync()?;
        }
        Ok(())
    }

    fn check_entry_bound(&self) -> io::Result<()> {
        for (count, entry) in self.dir.entries()?.enumerate() {
            entry?;
            if count >= MAX_ENTRIES {
                return Err(invalid("Private directory entry limit exceeded"));
            }
        }
        Ok(())
    }

    fn sync(&self) -> io::Result<()> {
        #[cfg(unix)]
        return self.dir.open(".")?.sync_all();
        #[cfg(windows)]
        return Ok(());
    }
}

fn validate_name(name: &str) -> io::Result<()> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
        || name == "."
        || name == ".."
    {
        return Err(invalid("Invalid private filename"));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_handle(file: &File, directory: bool, maximum: u64) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    let euid = unsafe { libc::geteuid() };
    if metadata.uid() != euid
        || metadata.mode() & 0o077 != 0
        || (directory && !metadata.is_dir())
        || (!directory
            && (!metadata.is_file() || metadata.nlink() != 1 || metadata.len() > maximum))
    {
        return Err(invalid(
            "Private path has unsafe type, ownership, permissions, links or size",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn validate_handle(file: &File, directory: bool, maximum: u64) -> io::Result<()> {
    platform::validate(file, directory, maximum)
}

#[cfg(unix)]
fn same_file(left: &File, right: &File) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let left = left.metadata()?;
    let right = right.metadata()?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

#[cfg(windows)]
fn same_file(left: &File, right: &File) -> io::Result<bool> {
    platform::same_file(left, right)
}
