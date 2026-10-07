# boosteroid-common

Private storage, session authorization and worker grants shared by the two native Boosteroid executables. This crate makes no network requests, stores no account credentials and contains neither a control nor media executable. Both SDK dependencies are pinned to OpenNOW `683eaa0ecfb60738388def065944c7284154be5c` at `https://github.com/OpenCloudGaming/opennow`.

## Control usage

Open one `AuthorizationWriter` for the absolute plugin data root and keep it alive for the process lifetime. The root's parent must already exist. The writer creates the final directory privately if missing; existing roots must already have safe permissions/ownership. A second writer fails with the OS file-lock error. Its methods serialize concurrent mutations inside the process.

1. `register_session` creates Pending generation 1; repeating registration preserves every existing state, including Revoked.
2. `activate_session` advances Pending to Active without changing generation and is idempotent for Active. It rejects Revoked.
3. `issue_grant` requires Active, validates media/connection/bitrate, creates a cryptographically random 32-byte nonce, and durably records the SHA-256 hash of the **exact serialized private payload** before returning `SecretBytes`. A random token not present in the registry, a modified payload, or even differently formatted JSON is not authorized.
4. `revoke_session` durably creates/preserves a tombstone, increments generation once, and removes attach grants. Call it **before** remote cleanup or updating the control journal. A crash between revocation and the journal write cannot reactivate the session. Revoking an unknown key creates a tombstone too.

`authorization_status(root, session)` returns only:

```rust,ignore
Option<SessionAuthorization>
enum SessionAuthorization {
    Pending { generation: u64 },
    Active { generation: u64 },
    Revoked { generation: u64 },
}
```

The enum is Clone/Copy/Debug/Eq/Serialize/Deserialize and has `generation(&self) -> u64`. `None` means no session record; malformed/insecure storage is an error, not absence. Recovery must honor a Revoked status even if `read_control_state()` returns an older Active phase. Revoked keys are never recycled; use a new logical key for a new session. Common deliberately does not delete tombstones.

Control state is a bounded JSON **object** (maximum 1 MiB), written atomically. Known credential-key names are rejected as defense in depth. That guard does **not** prove arbitrary JSON is secret-free: callers must serialize typed metadata only and keep access/refresh tokens, auth-data and gateway secrets in their credential store or explicitly temporary memory. The common grant registry persists only hashes/expiry and logical authorization, not gateway connection material.

## Media usage

```rust,ignore
let lock = lock_worker_session(root, &bootstrap.binding.session)?;
let active = authorize_worker(root, &bootstrap, current_unix_ms)?;
// Hold lock until the worker has closed all transport/input/media resources.
// Before networking and periodically while running:
if !session_authorized(root, &active)? {
    stop_local_transport();
}
```

`WorkerSessionLock` is an opaque RAII guard. The empty persistent lock file is only coordination; authorization readers do not acquire the control writer lock or mutate authorization. Worker locks are per logical session. They exclude concurrent workers, not revocation. Acquire the lock **before** authorization and hold it for the full attachment. Dropping a guard explicitly unlocks it, including when another thread is concurrently spawning a child process; the kernel also releases it after process termination.

`authorize_worker` checks the SDK bootstrap version/limits/authentication-token length/attempt generation/control port, exact plugin ID, registered payload digest with constant-time digest comparison, Active state/generation, attach expiry, session binding, offer ID, runtime epoch and entire accepted-media value. Lease/attempt IDs are validated SDK identifier types supplied by the host; prepare never invents them. The caller must deserialize the real `WorkerBootstrap` with the SDK and use a trustworthy current Unix timestamp. The host still verifies its private Hello authentication token itself.

`AuthorizedMedia` contains the SDK session/accepted media, private `GatewayConnection`, and `revocation_generation`. Use only the value returned by `authorize_worker` as a live authorization. `session_authorized` deliberately checks durable session state/generation, **not attach expiry, current owner PID, heartbeat or control-process epoch**. Thus writer restart and later token expiry do not kill healthy workers. Explicit per-session revocation does. Filesystem errors must stop/fail the worker rather than be converted to `true`.

`GatewayConnection` is Clone/Serialize/Deserialize, with redacted Debug. Its fields are `upstream_session_id: String`, `session_query: SecretString`, `gateways: Vec<String>`, `home_url: Option<SecretString>`, `peer_id: String`, and `bitrate_kbps: u32`. Bitrate uses the SDK's `1..=200_000` bounds. Gateway lists are 1–16 bounded strings. Endpoint allowlisting, DNS and HTTPS certificate validation remain the networking consumer's responsibility; common validates structure and authenticates the precise grant, not arbitrary Internet destinations.

## Storage and bounds

Directory operations are rooted in capability handles. Every path component is opened without following symlinks; relative paths, traversal, insecure owners/modes, links and nonregular files fail closed. Files are limited before and during reads. Grants are at most 64 KiB, authorization records at most 32 KiB, with at most 64 unexpired grants per session; a full grant registry returns WouldBlock. Expired grants are pruned during later issuance. Directory enumeration is bounded at 8192 entries. Consumers must not log raw bootstrap/state bytes or private IO payloads.

On Unix, new roots/files use 0700/0600 and existing paths must be owned by the effective user with no group/other permissions. Atomic replacement writes a same-directory random temporary file, fsyncs it, renames through the anchored directory, then fsyncs a **readable** reopened directory descriptor. Capability directory descriptors can be O_PATH and cannot themselves be fsynced. Creation also syncs the parent directory. Startup removes only private regular bounded temporary files with the exact internal name shape; it never promotes an incomplete temporary record.

On Windows, handle-based metadata rejects reparse points and multiple links, validates current-user ownership and ACLs, and permits only the current user, SYSTEM and Administrators in effective allow entries. After proving the object owner equals the current user, it recognizes both that user's SID and `OWNER RIGHTS` (`S-1-3-4`, `WinCreatorOwnerRightsSid`) as the current owner. This accepts normal host-created directories without changing their ACLs; Everyone, Users, unrelated groups, a different owner and unsupported ACE types remain rejected. Newly created paths receive a protected owner-only inheritable DACL. Directory ACL readers request `FILE_GENERIC_READ` (including `READ_CONTROL`); creation handles additionally request `WRITE_DAC` directly rather than trying to upgrade a capability handle with `ReOpenFile`. New file handles also request `DELETE` for replacement. Unsupported/unsafe ACL entries fail closed.

Replacement requires Windows 10 version 1607 or later and a filesystem supporting `FileRenameInfoEx` POSIX replacement (tested on Windows 11 build 26200, NTFS). It uses `SetFileInformationByHandle(FileRenameInfoEx)` with `FILE_RENAME_FLAG_REPLACE_IF_EXISTS | FILE_RENAME_FLAG_POSIX_SEMANTICS`, allowing already-open readers to finish reading the old object while new opens see the replacement. The destination is an absolute name resolved from the held root handle; the tested Win32 API rejected a relative RootDirectory/name pair with error 87. Ordering is full temporary-file write, `FlushFileBuffers`, handle-based rename, then `FlushFileBuffers` on the renamed file before success. Unsupported OS/filesystem behavior returns the contextual Win32 error; there is **no fallback** to non-atomic or legacy replacement. The earlier `MoveFileExW` path failed the concurrent-reader regression with error 5 and is no longer used.

Native Windows tests now cover fresh root creation, ACL handle rights, rejection of an Everyone allow entry, hard-link rejection, held-reader replacement, separate-process readers/locks and crash ordering. Tests and strict native MSVC Clippy passed with Rust 1.99.0. macOS runtime verification and hardware power-loss testing remain pending; filesystem/device flush guarantees are not established by process-kill tests.

This is an ownership boundary between cooperating native components, not a sandbox against another malicious process under the same OS user. That user can edit/delete its own files; OS-private storage cannot defend against that. Durability assumes the local filesystem and device honor flush/atomic-replace semantics. Process-kill tests cover ordering, not hardware power-loss fault injection.

## Manifest and verification

`manifest(target, files)` returns schema/provider protocol 2 with roles `bin/control[.exe]` and `bin/media[.exe]`. Exact capabilities are browser auth, accounts, library catalog, catalog details, launch, sessions and media worker. No fake/anonymous auth, HDR, microphone, settings or unimplemented feature capability is advertised. The packaging caller must run SDK manifest/package validation on the supplied target and actual file inventory.

Run `bash verify.sh` from this directory. It executes formatting, offline locked tests and strict Clippy. `bash verify.sh windows` additionally cross-checks all targets for `x86_64-pc-windows-gnu` (install that Rust target first). Tests use only clearly offline placeholder values, real private temporary files, real child-process locks/readers and a killed writer at the committed-revocation crash point. No Boosteroid account or service behavior is exercised.
