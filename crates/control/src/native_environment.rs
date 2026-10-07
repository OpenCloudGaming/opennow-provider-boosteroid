#[cfg(target_os = "linux")]
pub fn prepare_before_threads() {
    if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some() {
        return;
    }
    let uid = unsafe { libc::geteuid() };
    for path in [
        format!("/run/user/{uid}/bus"),
        String::from("/run/flatpak/bus"),
    ] {
        if let Some(address) = validated_address(std::path::Path::new(&path), uid) {
            unsafe { std::env::set_var("DBUS_SESSION_BUS_ADDRESS", address) };
            return;
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn prepare_before_threads() {}

#[cfg(target_os = "linux")]
fn validated_address(path: &std::path::Path, uid: u32) -> Option<String> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let socket = std::fs::symlink_metadata(path).ok()?;
    let parent = std::fs::symlink_metadata(path.parent()?).ok()?;
    if !socket.file_type().is_socket()
        || socket.uid() != uid
        || !parent.is_dir()
        || parent.mode() & 0o022 != 0
        || !matches!(parent.uid(), owner if owner == uid || owner == 0)
    {
        return None;
    }
    Some(format!("unix:path={}", path.to_str()?))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::{fs::symlink, net::UnixListener};

    #[test]
    fn native_bus_discovery_requires_an_owned_socket_not_a_file_or_symlink() {
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("bus");
        let uid = unsafe { libc::geteuid() };
        assert!(validated_address(&socket, uid).is_none());
        std::fs::write(&socket, b"not a socket").unwrap();
        assert!(validated_address(&socket, uid).is_none());
        std::fs::remove_file(&socket).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        assert!(validated_address(&socket, uid).is_some());
        assert!(validated_address(&socket, uid.wrapping_add(1)).is_none());
        let alias = root.path().join("alias");
        symlink(&socket, &alias).unwrap();
        assert!(validated_address(&alias, uid).is_none());
        drop(listener);
    }
}
