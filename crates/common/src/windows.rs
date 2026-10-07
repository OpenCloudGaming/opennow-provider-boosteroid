use crate::invalid;
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt, OpenOptionsMaybeDirExt};
use cap_std::fs::{Dir, OpenOptions, OpenOptionsExt};
use std::{
    ffi::{OsString, c_void},
    fs::File,
    io,
    mem::{offset_of, size_of, zeroed},
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::AsRawHandle,
    },
    path::{Path, PathBuf},
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, LocalFree},
    Security::{
        Authorization::{GetSecurityInfo, SE_FILE_OBJECT, SetSecurityInfo},
        *,
    },
    Storage::FileSystem::*,
    System::{
        Threading::{GetCurrentProcess, OpenProcessToken},
        WindowsProgramming::{
            FILE_RENAME_FLAG_POSIX_SEMANTICS, FILE_RENAME_FLAG_REPLACE_IF_EXISTS,
        },
    },
};

pub(super) fn open_directory(parent: &Dir, name: &Path, acl_write: bool) -> io::Result<Dir> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .maybe_dir(true)
        .follow(FollowSymlinks::No)
        .access_mode(FILE_GENERIC_READ | if acl_write { WRITE_DAC } else { 0 });
    let file = parent.open_with(name, &options)?.into_std();
    if !file.metadata()?.is_dir() {
        return Err(invalid("Private root must be a directory"));
    }
    Ok(Dir::from_std_file(file))
}

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
struct Descriptor(*mut c_void);
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

fn current_user() -> io::Result<Vec<usize>> {
    unsafe {
        let mut token = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = Handle(token);
        let mut size = 0;
        GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut size);
        if size == 0 || size > 65536 {
            return Err(invalid("Invalid process identity"));
        }
        let mut storage = vec![0usize; (size as usize).div_ceil(size_of::<usize>())];
        if GetTokenInformation(
            token.0,
            TokenUser,
            storage.as_mut_ptr().cast(),
            size,
            &mut size,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(storage)
    }
}

pub(super) fn make_private(file: &File) -> io::Result<()> {
    let user = current_user()?;
    unsafe {
        let sid = (*(user.as_ptr().cast::<TOKEN_USER>())).User.Sid;
        let size = size_of::<ACL>() + size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>()
            + GetLengthSid(sid) as usize;
        let mut storage = vec![0usize; size.div_ceil(size_of::<usize>())];
        let acl = storage.as_mut_ptr().cast::<ACL>();
        if InitializeAcl(acl, size as u32, ACL_REVISION) == 0
            || AddAccessAllowedAceEx(
                acl,
                ACL_REVISION,
                OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
                FILE_ALL_ACCESS,
                sid,
            ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        let status = SetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            acl,
            null(),
        );
        if status != 0 {
            return Err(call_error(
                "SetSecurityInfo",
                io::Error::from_raw_os_error(status as i32),
            ));
        }
    }
    Ok(())
}

fn information(file: &File) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    unsafe {
        let mut info = zeroed();
        if GetFileInformationByHandle(file.as_raw_handle(), &mut info) == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(info)
    }
}

pub(super) fn validate(file: &File, directory: bool, maximum: u64) -> io::Result<()> {
    let info = information(file)?;
    let length = (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow);
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
        || (!directory && (info.nNumberOfLinks != 1 || length > maximum))
    {
        return Err(invalid("Private path has unsafe type, links or size"));
    }
    let user = current_user()?;
    unsafe {
        let sid = (*(user.as_ptr().cast::<TOKEN_USER>())).User.Sid;
        let mut owner = null_mut();
        let mut acl = null_mut();
        let mut descriptor = null_mut();
        let status = GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut acl,
            null_mut(),
            &mut descriptor,
        );
        if status != 0 {
            return Err(call_error(
                "GetSecurityInfo",
                io::Error::from_raw_os_error(status as i32),
            ));
        }
        let _descriptor = Descriptor(descriptor);
        if owner.is_null() || EqualSid(owner, sid) == 0 || acl.is_null() || IsValidAcl(acl) == 0 {
            return Err(invalid("Private path has unsafe ownership or ACL"));
        }
        for index in 0..(*acl).AceCount {
            let mut ace = null_mut();
            if GetAce(acl, u32::from(index), &mut ace) == 0 {
                return Err(io::Error::last_os_error());
            }
            let header = &*ace.cast::<ACE_HEADER>();
            if u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0 {
                continue;
            }
            match header.AceType {
                0 => {
                    let allowed = &*ace.cast::<ACCESS_ALLOWED_ACE>();
                    let trustee = (&raw const allowed.SidStart).cast_mut().cast();
                    if EqualSid(trustee, sid) == 0
                        && IsWellKnownSid(trustee, WinLocalSystemSid) == 0
                        && IsWellKnownSid(trustee, WinBuiltinAdministratorsSid) == 0
                        && IsWellKnownSid(trustee, WinCreatorOwnerRightsSid) == 0
                    {
                        return Err(invalid("Private path grants another principal access"));
                    }
                }
                1 => {}
                _ => return Err(invalid("Private path uses an unsupported ACL entry")),
            }
        }
    }
    Ok(())
}

fn call_error(operation: &'static str, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{operation}: {error}"))
}

pub(super) fn same_file(left: &File, right: &File) -> io::Result<bool> {
    let left = information(left)?;
    let right = information(right)?;
    Ok((
        left.dwVolumeSerialNumber,
        left.nFileIndexHigh,
        left.nFileIndexLow,
    ) == (
        right.dwVolumeSerialNumber,
        right.nFileIndexHigh,
        right.nFileIndexLow,
    ))
}

pub(super) fn replace(root: &File, file: &File, to: &str) -> io::Result<()> {
    let mut path = vec![0u16; 32768];
    let length = unsafe {
        GetFinalPathNameByHandleW(
            root.as_raw_handle(),
            path.as_mut_ptr(),
            path.len() as u32,
            0,
        )
    };
    if length == 0 {
        return Err(call_error(
            "GetFinalPathNameByHandleW",
            io::Error::last_os_error(),
        ));
    }
    if length as usize >= path.len() {
        return Err(invalid("Private root path exceeds Windows limit"));
    }
    let path = PathBuf::from(OsString::from_wide(&path[..length as usize])).join(to);
    let name: Vec<u16> = path.as_os_str().encode_wide().collect();
    let size = size_of::<FILE_RENAME_INFO>() + name.len() * size_of::<u16>();
    let mut buffer = vec![0usize; size.div_ceil(size_of::<usize>())];
    unsafe {
        let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
        (*info).Anonymous.Flags =
            FILE_RENAME_FLAG_REPLACE_IF_EXISTS | FILE_RENAME_FLAG_POSIX_SEMANTICS;
        (*info).RootDirectory = null_mut();
        (*info).FileNameLength = (name.len() * size_of::<u16>()) as u32;
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            buffer
                .as_mut_ptr()
                .cast::<u8>()
                .add(offset_of!(FILE_RENAME_INFO, FileName))
                .cast(),
            name.len(),
        );
        if SetFileInformationByHandle(
            file.as_raw_handle(),
            FileRenameInfoEx,
            info.cast(),
            size as u32,
        ) == 0
        {
            return Err(call_error(
                "SetFileInformationByHandle(atomic replace)",
                io::Error::last_os_error(),
            ));
        }
    }
    file.sync_all()
        .map_err(|error| call_error("FlushFileBuffers(after rename)", error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cap_fs_ext::DirExt;
    use cap_std::ambient_authority;

    #[test]
    fn directory_acl_operations_require_explicit_handle_rights() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap().join("state");
        let owner = crate::AuthorizationWriter::open(&root).unwrap();
        drop(owner);
        let parent = Dir::open_ambient_dir(root.parent().unwrap(), ambient_authority()).unwrap();
        let sparse = parent.open_dir_nofollow("state").unwrap().into_std_file();
        validate(&sparse, true, 0).unwrap();
        assert_eq!(
            make_private(&sparse).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        let reader = open_directory(&parent, Path::new("state"), false)
            .unwrap()
            .into_std_file();
        validate(&reader, true, 0).unwrap();
        assert_eq!(
            make_private(&reader).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        let writable = open_directory(&parent, Path::new("state"), true)
            .unwrap()
            .into_std_file();
        make_private(&writable).unwrap();
        validate(&writable, true, 0).unwrap();
    }

    #[test]
    fn an_everyone_allow_entry_is_rejected_even_for_the_current_owner() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap().join("state");
        let owner = crate::AuthorizationWriter::open(&root).unwrap();
        drop(owner);
        let parent = Dir::open_ambient_dir(root.parent().unwrap(), ambient_authority()).unwrap();
        let writable = open_directory(&parent, Path::new("state"), true)
            .unwrap()
            .into_std_file();
        unsafe {
            let mut sid_storage = [0usize; 16];
            let mut sid_length = std::mem::size_of_val(&sid_storage) as u32;
            let sid = sid_storage.as_mut_ptr().cast();
            assert_ne!(
                CreateWellKnownSid(WinWorldSid, null_mut(), sid, &mut sid_length),
                0
            );
            let mut acl_storage = [0usize; 64];
            let acl = acl_storage.as_mut_ptr().cast::<ACL>();
            assert_ne!(
                InitializeAcl(
                    acl,
                    std::mem::size_of_val(&acl_storage) as u32,
                    ACL_REVISION
                ),
                0
            );
            assert_ne!(
                AddAccessAllowedAce(acl, ACL_REVISION, FILE_ALL_ACCESS, sid),
                0
            );
            assert_eq!(
                SetSecurityInfo(
                    writable.as_raw_handle(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    null_mut(),
                    null_mut(),
                    acl,
                    null()
                ),
                0
            );
        }
        let error = validate(&writable, true, 0).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("another principal"));
        assert!(crate::AuthorizationWriter::open(&root).is_err());
    }

    fn set_inheritable_allow(file: &File, kind: WELL_KNOWN_SID_TYPE) {
        unsafe {
            let mut sid_storage = [0usize; 16];
            let mut sid_length = std::mem::size_of_val(&sid_storage) as u32;
            let sid = sid_storage.as_mut_ptr().cast();
            assert_ne!(
                CreateWellKnownSid(kind, null_mut(), sid, &mut sid_length),
                0
            );
            let mut acl_storage = [0usize; 64];
            let acl = acl_storage.as_mut_ptr().cast::<ACL>();
            assert_ne!(
                InitializeAcl(
                    acl,
                    std::mem::size_of_val(&acl_storage) as u32,
                    ACL_REVISION
                ),
                0
            );
            assert_ne!(
                AddAccessAllowedAceEx(
                    acl,
                    ACL_REVISION,
                    OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
                    FILE_ALL_ACCESS,
                    sid
                ),
                0
            );
            assert_eq!(
                SetSecurityInfo(
                    file.as_raw_handle(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    null_mut(),
                    null_mut(),
                    acl,
                    null()
                ),
                0
            );
        }
    }

    #[test]
    fn normal_host_created_directory_with_inherited_owner_rights_is_accepted() {
        let temp = tempfile::tempdir().unwrap();
        let parent_path = temp.path().canonicalize().unwrap().join("parent");
        drop(crate::AuthorizationWriter::open(&parent_path).unwrap());
        let parent =
            Dir::open_ambient_dir(parent_path.parent().unwrap(), ambient_authority()).unwrap();
        let writable = open_directory(&parent, Path::new("parent"), true)
            .unwrap()
            .into_std_file();
        set_inheritable_allow(&writable, WinCreatorOwnerRightsSid);
        let host_root = parent_path.join("host-data");
        std::fs::create_dir_all(&host_root).unwrap();
        let writer = crate::AuthorizationWriter::open(&host_root).unwrap();
        writer.write_control_state(br#"{"version":1}"#).unwrap();
        assert_eq!(
            writer.read_control_state().unwrap().unwrap(),
            br#"{"version":1}"#
        );
        drop(writer);
        assert!(crate::AuthorizationWriter::open(&host_root).is_ok());
    }

    #[test]
    fn users_and_unrelated_group_allow_entries_remain_rejected() {
        for kind in [WinBuiltinUsersSid, WinAuthenticatedUserSid] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().canonicalize().unwrap().join("state");
            drop(crate::AuthorizationWriter::open(&root).unwrap());
            let parent =
                Dir::open_ambient_dir(root.parent().unwrap(), ambient_authority()).unwrap();
            let writable = open_directory(&parent, Path::new("state"), true)
                .unwrap()
                .into_std_file();
            set_inheritable_allow(&writable, kind);
            let error = validate(&writable, true, 0).unwrap_err();
            assert!(error.to_string().contains("another principal"));
            assert!(crate::AuthorizationWriter::open(&root).is_err());
        }
    }

    #[test]
    fn directory_owned_by_another_principal_is_rejected() {
        let root = std::env::var_os("SystemRoot").expect("Windows system directory");
        let directory = Dir::open_ambient_dir(root, ambient_authority())
            .unwrap()
            .into_std_file();
        let user = current_user().unwrap();
        unsafe {
            let sid = (*(user.as_ptr().cast::<TOKEN_USER>())).User.Sid;
            let mut owner = null_mut();
            let mut descriptor = null_mut();
            assert_eq!(
                GetSecurityInfo(
                    directory.as_raw_handle(),
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION,
                    &mut owner,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    &mut descriptor
                ),
                0
            );
            let _descriptor = Descriptor(descriptor);
            assert_eq!(
                EqualSid(owner, sid),
                0,
                "System directory must be an independently owned test fixture"
            );
        }
        let error = validate(&directory, true, 0).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("unsafe ownership"));
    }
}
