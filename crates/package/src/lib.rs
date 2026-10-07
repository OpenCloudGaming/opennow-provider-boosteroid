use opennow_plugin_api::PackageFile;
use opennow_plugin_package::{EXPANDED_LIMIT, FILE_LIMIT, MANIFEST_LIMIT};
use sha2::{Digest, Sha256};
use std::io::{self, Write};
use std::path::Path;

const ARCHIVE_LIMIT: u64 = 64 * 1024 * 1024;

pub fn create(control: &Path, media: &Path, notices: &Path, destination: &Path) -> io::Result<()> {
    let control = capture_executable(control)?;
    let media = capture_executable(media)?;
    let notices = opennow_plugin_package::read_bounded(
        opennow_plugin_package::open_regular(notices)
            .map_err(|_| io::Error::other("Expected regular dependency notices"))?,
        FILE_LIMIT,
    )
    .map_err(|_| io::Error::other("Dependency notices exceed package bounds"))?;
    if notices.is_empty() || std::str::from_utf8(&notices).is_err() {
        return Err(io::Error::other(
            "Dependency notices must contain UTF-8 text",
        ));
    }
    let control_name = if cfg!(windows) {
        "bin/control.exe"
    } else {
        "bin/control"
    };
    let media_name = if cfg!(windows) {
        "bin/media.exe"
    } else {
        "bin/media"
    };
    let files = [
        (control_name, control),
        (media_name, media),
        ("LICENSE.txt", include_bytes!("../../../LICENSE").to_vec()),
        ("NOTICE.txt", include_bytes!("../../../NOTICE").to_vec()),
        (
            "OpenNOW-SDK-MIT.txt",
            include_bytes!("../../../licenses/OpenNOW-SDK-MIT.txt").to_vec(),
        ),
        ("THIRD_PARTY_NOTICES.txt", notices),
    ];
    let manifest = boosteroid_common::manifest(
        opennow_plugin_package::current_target(),
        files
            .iter()
            .map(|(path, bytes)| PackageFile {
                path: (*path).into(),
                sha256: format!("{:x}", Sha256::digest(bytes)),
            })
            .collect(),
    );
    manifest
        .validate()
        .map_err(|_| io::Error::other("Invalid package manifest"))?;
    let manifest = serde_json::to_vec_pretty(&manifest)
        .map_err(|_| io::Error::other("Cannot encode package manifest"))?;
    let expanded = files
        .iter()
        .try_fold(manifest.len() as u64, |size, (_, bytes)| {
            size.checked_add(bytes.len() as u64)
                .filter(|total| *total <= EXPANDED_LIMIT)
                .ok_or_else(|| io::Error::other("Package exceeds expanded size limit"))
        })?;
    if manifest.len() as u64 > MANIFEST_LIMIT || expanded > EXPANDED_LIMIT {
        return Err(io::Error::other(
            "Package exceeds manifest or expanded size limit",
        ));
    }
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut snapshot = tempfile::NamedTempFile::new_in(parent)?;
    let mut archive = zip::ZipWriter::new(snapshot.as_file_mut());
    archive.start_file(
        "manifest.json",
        zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(0o600),
    )?;
    archive.write_all(&manifest)?;
    for (name, bytes) in files {
        archive.start_file(
            name,
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated)
                .unix_permissions(if name.starts_with("bin/") {
                    0o755
                } else {
                    0o600
                }),
        )?;
        archive.write_all(&bytes)?;
    }
    let file = archive.finish()?;
    if file.metadata()?.len() > ARCHIVE_LIMIT {
        return Err(io::Error::other("Package exceeds compressed size limit"));
    }
    file.sync_all()?;
    snapshot
        .persist_noclobber(destination)
        .map_err(|failure| failure.error)?;
    Ok(())
}

fn capture_executable(path: &Path) -> io::Result<Vec<u8>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    let link = metadata.file_type().is_symlink();
    #[cfg(windows)]
    let link = {
        use std::os::windows::fs::MetadataExt;
        link || metadata.file_attributes() & 0x400 != 0
    };
    if !metadata.is_file() || link {
        return Err(io::Error::other("Expected a regular native executable"));
    }
    let bytes = opennow_plugin_package::read_bounded(file, FILE_LIMIT)
        .map_err(|_| io::Error::other("Executable exceeds package size limit"))?;
    let mut snapshot = tempfile::NamedTempFile::new()?;
    snapshot.write_all(&bytes)?;
    snapshot.flush()?;
    opennow_plugin_package::validate_executable(snapshot.path())
        .map_err(|_| io::Error::other("Executable does not match this host target"))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn package_inventory_matches_captured_bytes_and_refuses_overwrite() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("provider.opennow-plugin");
        let executable = std::env::current_exe().unwrap();
        let notices = directory.path().join("notices.txt");
        std::fs::write(&notices, "Synthetic package-test notices").unwrap();
        create(&executable, &executable, &notices, &destination).unwrap();
        let original = std::fs::read(&destination).unwrap();
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(&original)).unwrap();
        let manifest: opennow_plugin_api::provider::ProviderManifest =
            serde_json::from_reader(archive.by_name("manifest.json").unwrap()).unwrap();
        manifest.validate().unwrap();
        assert_eq!(manifest.id.as_str(), boosteroid_common::PLUGIN_ID);
        assert_eq!(archive.len(), manifest.files.len() + 1);
        for file in manifest.files {
            let mut bytes = Vec::new();
            archive
                .by_name(&file.path)
                .unwrap()
                .read_to_end(&mut bytes)
                .unwrap();
            assert_eq!(file.sha256, format!("{:x}", Sha256::digest(bytes)));
        }
        assert!(create(&executable, &executable, &notices, &destination).is_err());
        assert_eq!(std::fs::read(destination).unwrap(), original);
    }

    #[test]
    fn invalid_executable_never_publishes_an_archive() {
        let directory = tempfile::tempdir().unwrap();
        let invalid = directory.path().join("not-a-program");
        let destination = directory.path().join("provider.opennow-plugin");
        std::fs::write(&invalid, b"not a native executable").unwrap();
        assert!(create(&invalid, &invalid, &invalid, &destination).is_err());
        assert!(!destination.exists());
    }

    #[test]
    fn cargo_hardlinked_executables_are_captured_as_independent_payloads() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("program");
        let alias = directory.path().join("cargo-output");
        std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
        std::fs::hard_link(&executable, &alias).unwrap();
        let notices = directory.path().join("notices.txt");
        std::fs::write(&notices, "Synthetic package-test notices").unwrap();
        let destination = directory.path().join("provider.opennow-plugin");
        create(&executable, &alias, &notices, &destination).unwrap();
        let mut archive = zip::ZipArchive::new(std::fs::File::open(destination).unwrap()).unwrap();
        let manifest: opennow_plugin_api::provider::ProviderManifest =
            serde_json::from_reader(archive.by_name("manifest.json").unwrap()).unwrap();
        let expected = std::fs::read(executable).unwrap();
        for file in manifest
            .files
            .iter()
            .filter(|file| file.path.starts_with("bin/"))
        {
            let mut actual = Vec::new();
            archive
                .by_name(&file.path)
                .unwrap()
                .read_to_end(&mut actual)
                .unwrap();
            assert_eq!(actual, expected);
        }
    }

    #[cfg(unix)]
    #[test]
    fn executable_symlinks_are_rejected_before_capture() {
        let directory = tempfile::tempdir().unwrap();
        let link = directory.path().join("program-link");
        std::os::unix::fs::symlink(std::env::current_exe().unwrap(), &link).unwrap();
        assert!(capture_executable(&link).is_err());
    }
}
