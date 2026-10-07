use boosteroid_common::*;
use opennow_media_protocol::{lease::WorkerBinding, wire::WorkerBootstrap};
use opennow_plugin_api::{
    PackageFile, PluginId,
    media::{
        AcceptedMedia, AudioCodec, AudioFormat, Chroma, ChromaLocation, ColorDescription,
        ColorRange, InputCapabilities, Matrix, MediaLimits, Primaries, Transfer, VideoEncoding,
        VideoFormat,
    },
    provider::{AttemptId, OfferId, SecretBytes, SecretString, SessionId, SessionKey, Text},
};
use serde_json::json;
use std::{
    fs,
    io::{self, BufRead, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

fn new_root() -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap().join("state");
    (temp, root)
}
fn session() -> SessionKey {
    SessionKey {
        account: None,
        remote_id: SessionId::new("offline-logical-session").unwrap(),
    }
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
fn accepted() -> AcceptedMedia {
    AcceptedMedia {
        offer_id: OfferId::new("offline-offer").unwrap(),
        runtime_epoch: 11,
        video: VideoFormat {
            encoding: VideoEncoding::H264AnnexB,
            width: 1280,
            height: 720,
            fps: 60,
            bit_depth: 8,
            chroma: Chroma::Yuv420,
            color: ColorDescription {
                range: ColorRange::Limited,
                primaries: Primaries::Bt709,
                transfer: Transfer::Bt709,
                matrix: Matrix::Bt709,
                chroma_location: ChromaLocation::Left,
            },
        },
        audio: Some(AudioFormat {
            codec: AudioCodec::Opus,
            sample_rate: 48000,
            channels: 2,
        }),
        input: InputCapabilities {
            keyboard: true,
            relative_mouse: true,
            absolute_mouse: true,
            text: false,
            gamepad_slots: 4,
            rumble: true,
        },
    }
}
fn connection() -> GatewayConnection {
    GatewayConnection {
        upstream_session_id: "offline-upstream".into(),
        session_query: SecretString::new("sessionId=offline-no-service").unwrap(),
        gateways: vec!["gateway.invalid".into()],
        home_url: None,
        peer_id: "offline-peer".into(),
        bitrate_kbps: 25000,
    }
}
fn bootstrap(grant: SecretBytes) -> WorkerBootstrap {
    WorkerBootstrap {
        version: 1,
        binding: WorkerBinding {
            lease_id: Text::new("offline-lease").unwrap(),
            source_id: PluginId::new(PLUGIN_ID).unwrap(),
            session: session(),
            attempt_id: AttemptId::new("offline-attempt").unwrap(),
        },
        attempt_generation: 9,
        control_port: 12345,
        authentication: SecretBytes::new(vec![7; 32]).unwrap(),
        accepted: accepted(),
        limits: MediaLimits {
            max_video_access_unit_bytes: 1024 * 1024,
            max_audio_packet_bytes: 8192,
            max_buffered_video_bytes: 2 * 1024 * 1024,
            max_buffered_video_frames: 2,
            max_buffered_audio_ms: 50,
            max_control_message_bytes: 65536,
            max_pending_input_events: 128,
        },
        provider_bootstrap: grant,
    }
}
fn active_writer(root: &Path) -> AuthorizationWriter {
    let writer = AuthorizationWriter::open(root).unwrap();
    writer.register_session(&session()).unwrap();
    writer.activate_session(&session()).unwrap();
    writer
}
fn child(root: &Path, scenario: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "child_process", "--nocapture"])
        .env("BOOSTEROID_COMMON_TEST_ROOT", root)
        .env("BOOSTEROID_COMMON_TEST_SCENARIO", scenario)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

#[test]
fn fresh_directory_writer_open_commits_private_root_and_durable_state() {
    let (_temp, root) = new_root();
    assert!(!root.exists());
    let writer = AuthorizationWriter::open(&root).unwrap();
    writer.write_control_state(br#"{"version":1}"#).unwrap();
    drop(writer);
    let writer = AuthorizationWriter::open(&root).unwrap();
    assert_eq!(
        writer.read_control_state().unwrap().unwrap(),
        br#"{"version":1}"#
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(root.join("control-state.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn session_lifecycle_is_irreversible_across_owner_restarts() {
    let (_temp, root) = new_root();
    let writer = AuthorizationWriter::open(&root).unwrap();
    assert_eq!(authorization_status(&root, &session()).unwrap(), None);
    assert!(writer.activate_session(&session()).is_err());
    writer.register_session(&session()).unwrap();
    assert_eq!(
        authorization_status(&root, &session()).unwrap(),
        Some(SessionAuthorization::Pending { generation: 1 })
    );
    assert!(
        writer
            .issue_grant(&session(), &accepted(), connection(), now() + 60000)
            .is_err()
    );
    writer.activate_session(&session()).unwrap();
    writer.activate_session(&session()).unwrap();
    writer.register_session(&session()).unwrap();
    assert_eq!(
        authorization_status(&root, &session()).unwrap(),
        Some(SessionAuthorization::Active { generation: 1 })
    );
    let bootstrap = bootstrap(
        writer
            .issue_grant(&session(), &accepted(), connection(), now() + 60000)
            .unwrap(),
    );
    let active = authorize_worker(&root, &bootstrap, now()).unwrap();
    drop(writer);
    let writer = AuthorizationWriter::open(&root).unwrap();
    assert!(session_authorized(&root, &active).unwrap());
    writer.revoke_session(&session()).unwrap();
    writer.revoke_session(&session()).unwrap();
    writer.register_session(&session()).unwrap();
    assert!(writer.activate_session(&session()).is_err());
    assert!(
        writer
            .issue_grant(&session(), &accepted(), connection(), now() + 60000)
            .is_err()
    );
    drop(writer);
    let writer = AuthorizationWriter::open(&root).unwrap();
    writer.register_session(&session()).unwrap();
    assert!(writer.activate_session(&session()).is_err());
    assert_eq!(
        authorization_status(&root, &session()).unwrap(),
        Some(SessionAuthorization::Revoked { generation: 2 })
    );
    assert!(!session_authorized(&root, &active).unwrap());
    assert!(authorize_worker(&root, &bootstrap, now()).is_err());
}

#[test]
fn revoking_unknown_session_leaves_an_irreversible_tombstone() {
    let (_temp, root) = new_root();
    let writer = AuthorizationWriter::open(&root).unwrap();
    writer.revoke_session(&session()).unwrap();
    writer.register_session(&session()).unwrap();
    assert!(writer.activate_session(&session()).is_err());
    assert_eq!(
        authorization_status(&root, &session()).unwrap(),
        Some(SessionAuthorization::Revoked { generation: 2 })
    );
}

#[test]
fn expired_attach_does_not_revoke_a_healthy_worker() {
    let (_temp, root) = new_root();
    let writer = active_writer(&root);
    let expiry = now() + 1000;
    let bootstrap = bootstrap(
        writer
            .issue_grant(&session(), &accepted(), connection(), expiry)
            .unwrap(),
    );
    let active = authorize_worker(&root, &bootstrap, expiry - 1).unwrap();
    assert!(authorize_worker(&root, &bootstrap, expiry).is_err());
    assert!(authorize_worker(&root, &bootstrap, expiry + 10000).is_err());
    drop(writer);
    let _writer = AuthorizationWriter::open(&root).unwrap();
    assert!(session_authorized(&root, &active).unwrap());
}

#[test]
fn exact_payload_registry_blocks_forgery_reencoding_and_cross_session_replay() {
    let (_temp, root) = new_root();
    let writer = active_writer(&root);
    let grant = writer
        .issue_grant(&session(), &accepted(), connection(), now() + 60000)
        .unwrap();
    let other = writer
        .issue_grant(&session(), &accepted(), connection(), now() + 60000)
        .unwrap();
    assert_ne!(grant.expose_secret(), other.expose_secret());
    let original: serde_json::Value = serde_json::from_slice(grant.expose_secret()).unwrap();
    for (key, replacement) in [
        ("expiresAtMs", json!(u64::MAX)),
        ("revocationGeneration", json!(42)),
        ("nonce", json!(vec![0u8; 32])),
        ("version", json!(2)),
    ] {
        let mut modified = original.clone();
        modified[key] = replacement;
        let forged = bootstrap(SecretBytes::new(serde_json::to_vec(&modified).unwrap()).unwrap());
        assert!(authorize_worker(&root, &forged, now()).is_err());
    }
    let mut modified = original.clone();
    modified["connection"]["bitrateKbps"] = json!(50000);
    assert!(
        authorize_worker(
            &root,
            &bootstrap(SecretBytes::new(serde_json::to_vec(&modified).unwrap()).unwrap()),
            now()
        )
        .is_err()
    );
    let pretty = SecretBytes::new(serde_json::to_vec_pretty(&original).unwrap()).unwrap();
    assert!(authorize_worker(&root, &bootstrap(pretty), now()).is_err());
    let mut replay = bootstrap(grant);
    replay.binding.session.remote_id = SessionId::new("other-logical-session").unwrap();
    writer.register_session(&replay.binding.session).unwrap();
    writer.activate_session(&replay.binding.session).unwrap();
    assert!(authorize_worker(&root, &replay, now()).is_err());
    let (_temp2, root2) = new_root();
    let _writer2 = active_writer(&root2);
    assert!(authorize_worker(&root2, &bootstrap(other), now()).is_err());
}

#[test]
fn host_binding_and_media_cannot_be_substituted() {
    let (_temp, root) = new_root();
    let writer = active_writer(&root);
    let original = bootstrap(
        writer
            .issue_grant(&session(), &accepted(), connection(), now() + 60000)
            .unwrap(),
    );
    let mut mutations = Vec::new();
    let mut changed = original.clone();
    changed.accepted.runtime_epoch += 1;
    mutations.push(changed);
    let mut changed = original.clone();
    changed.accepted.offer_id = OfferId::new("other-offer").unwrap();
    mutations.push(changed);
    let mut changed = original.clone();
    changed.accepted.video.width += 2;
    mutations.push(changed);
    let mut changed = original.clone();
    changed.accepted.input.text = true;
    mutations.push(changed);
    let mut changed = original.clone();
    changed.accepted.audio = None;
    mutations.push(changed);
    let mut changed = original.clone();
    changed.binding.source_id = PluginId::new("org.opennow.other").unwrap();
    mutations.push(changed);
    let mut changed = original.clone();
    changed.attempt_generation = 0;
    mutations.push(changed);
    let mut changed = original.clone();
    changed.authentication = SecretBytes::new(vec![1; 31]).unwrap();
    mutations.push(changed);
    let mut changed = original.clone();
    changed.control_port = 0;
    mutations.push(changed);
    let mut changed = original.clone();
    changed.limits.max_buffered_video_frames = 0;
    mutations.push(changed);
    for changed in mutations {
        assert!(authorize_worker(&root, &changed, now()).is_err());
    }
    assert!(authorize_worker(&root, &original, now()).is_ok());
}

#[test]
fn journal_is_bounded_valid_json_and_does_not_accept_known_credential_fields() {
    let (_temp, root) = new_root();
    let writer = AuthorizationWriter::open(&root).unwrap();
    assert!(writer.read_control_state().unwrap().is_none());
    writer
        .write_control_state(br#"{"version":1,"phase":"allocating"}"#)
        .unwrap();
    let before = writer.read_control_state().unwrap();
    for state in [
        vec![b' '; MAX_CONTROL_STATE_BYTES + 1],
        b"null".to_vec(),
        b"{broken".to_vec(),
        br#"{"nested":[{"refresh_token":"offline"}]}"#.to_vec(),
        br#"{"accessToken":"offline"}"#.to_vec(),
        vec![b'['; 129],
    ] {
        assert!(writer.write_control_state(&state).is_err());
        assert_eq!(writer.read_control_state().unwrap(), before);
    }
    drop(writer);
    assert_eq!(
        AuthorizationWriter::open(&root)
            .unwrap()
            .read_control_state()
            .unwrap(),
        before
    );
}

#[test]
fn invalid_connection_and_grant_counts_are_bounded() {
    let (_temp, root) = new_root();
    let writer = active_writer(&root);
    let mut bad = connection();
    bad.bitrate_kbps = 0;
    assert!(
        writer
            .issue_grant(&session(), &accepted(), bad, now() + 60000)
            .is_err()
    );
    let mut bad = connection();
    bad.bitrate_kbps = 200001;
    assert!(
        writer
            .issue_grant(&session(), &accepted(), bad, now() + 60000)
            .is_err()
    );
    assert!(
        writer
            .issue_grant(&session(), &accepted(), connection(), 0)
            .is_err()
    );
    for _ in 0..64 {
        writer
            .issue_grant(&session(), &accepted(), connection(), now() + 60000)
            .unwrap();
    }
    assert_eq!(
        writer
            .issue_grant(&session(), &accepted(), connection(), now() + 60000)
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
}

#[test]
fn writer_and_worker_process_locks_are_exclusive_but_readers_do_not_lock() {
    let (_temp, root) = new_root();
    let writer = active_writer(&root);
    let bootstrap = bootstrap(
        writer
            .issue_grant(&session(), &accepted(), connection(), now() + 60000)
            .unwrap(),
    );
    assert!(AuthorizationWriter::open(&root).is_err());
    assert!(
        child(&root, "writer-excluded")
            .output()
            .unwrap()
            .status
            .success()
    );
    let lock = lock_worker_session(&root, &session()).unwrap();
    assert!(lock_worker_session(&root, &session()).is_err());
    assert!(
        child(&root, "worker-excluded")
            .output()
            .unwrap()
            .status
            .success()
    );
    let mut reader = child(&root, "authorize-reader").spawn().unwrap();
    reader
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&bootstrap).unwrap())
        .unwrap();
    assert!(reader.wait_with_output().unwrap().status.success());
    drop(lock);
    assert!(
        child(&root, "worker-available")
            .output()
            .unwrap()
            .status
            .success()
    );
    drop(writer);
    assert!(AuthorizationWriter::open(&root).is_ok());
}

#[test]
fn crash_after_revocation_before_control_journal_update_does_not_restore_authorization() {
    let (_temp, root) = new_root();
    let mut process = child(&root, "crash-after-revoke").spawn().unwrap();
    let mut output = io::BufReader::new(process.stdout.take().unwrap());
    let mut line = String::new();
    loop {
        assert_ne!(
            output.read_line(&mut line).unwrap(),
            0,
            "child exited before crash point"
        );
        if line.contains("REVOCATION_COMMITTED") {
            break;
        }
        line.clear();
    }
    process.kill().unwrap();
    process.wait().unwrap();
    let writer = AuthorizationWriter::open(&root).unwrap();
    assert_eq!(
        writer.read_control_state().unwrap().unwrap(),
        br#"{"phase":"active"}"#
    );
    assert_eq!(
        authorization_status(&root, &session()).unwrap(),
        Some(SessionAuthorization::Revoked { generation: 2 })
    );
    writer.register_session(&session()).unwrap();
    assert!(writer.activate_session(&session()).is_err());
}

#[test]
fn concurrent_reader_observes_only_complete_atomic_control_states() {
    let (_temp, root) = new_root();
    let writer = AuthorizationWriter::open(&root).unwrap();
    writer
        .write_control_state(&serde_json::to_vec(&json!({"payload":"a".repeat(10000)})).unwrap())
        .unwrap();
    let reader = child(&root, "state-reader").spawn().unwrap();
    for index in 0..100 {
        let character = if index % 2 == 0 { "a" } else { "b" };
        writer
            .write_control_state(
                &serde_json::to_vec(&json!({"payload":character.repeat(10000)})).unwrap(),
            )
            .unwrap();
    }
    let output = reader.wait_with_output().unwrap();
    assert!(output.status.success(), "reader process failed");
}

#[test]
fn atomic_replacement_preserves_an_already_open_reader() {
    let (_temp, root) = new_root();
    let writer = AuthorizationWriter::open(&root).unwrap();
    let old = br#"{"version":1,"phase":"old"}"#;
    let new = br#"{"version":1,"phase":"new"}"#;
    writer.write_control_state(old).unwrap();
    let mut reader = fs::File::open(root.join("control-state.json")).unwrap();
    writer.write_control_state(new).unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, old);
    assert_eq!(writer.read_control_state().unwrap().unwrap(), new);
}

#[cfg(windows)]
#[test]
fn windows_hardlinked_state_is_rejected() {
    let (temp, root) = new_root();
    let writer = AuthorizationWriter::open(&root).unwrap();
    writer.write_control_state(b"{}").unwrap();
    fs::hard_link(
        root.join("control-state.json"),
        temp.path().join("external-link"),
    )
    .unwrap();
    assert!(writer.read_control_state().is_err());
    assert!(writer.write_control_state(b"{}").is_err());
}

#[test]
fn crashed_unpublished_temporary_state_is_not_promoted() {
    let (_temp, root) = new_root();
    let writer = AuthorizationWriter::open(&root).unwrap();
    writer
        .write_control_state(br#"{"version":1,"phase":"active"}"#)
        .unwrap();
    let before = writer.read_control_state().unwrap();
    let temporary = root.join(format!(".tmp-{}", "a".repeat(64)));
    fs::write(&temporary, b"{incomplete-replacement").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).unwrap();
    }
    drop(writer);
    let writer = AuthorizationWriter::open(&root).unwrap();
    assert_eq!(writer.read_control_state().unwrap(), before);
    assert!(!temporary.exists());
}

#[test]
fn concurrent_authorization_mutations_cannot_resurrect_a_revoked_session() {
    let (_temp, root) = new_root();
    let writer = std::sync::Arc::new(active_writer(&root));
    let mut threads = Vec::new();
    for _ in 0..8 {
        let writer = writer.clone();
        threads.push(std::thread::spawn(move || {
            for _ in 0..20 {
                writer.register_session(&session()).unwrap();
                let _ = writer.activate_session(&session());
            }
        }));
    }
    writer.revoke_session(&session()).unwrap();
    for thread in threads {
        thread.join().unwrap();
    }
    assert_eq!(
        authorization_status(&root, &session()).unwrap(),
        Some(SessionAuthorization::Revoked { generation: 2 })
    );
}

#[test]
fn worker_lock_is_per_session_and_does_not_block_revocation() {
    let (_temp, root) = new_root();
    let writer = active_writer(&root);
    let first = lock_worker_session(&root, &session()).unwrap();
    let mut other = session();
    other.remote_id = SessionId::new("other-session").unwrap();
    writer.register_session(&other).unwrap();
    writer.activate_session(&other).unwrap();
    let _second = lock_worker_session(&root, &other).unwrap();
    writer.revoke_session(&session()).unwrap();
    drop(first);
    assert!(lock_worker_session(&root, &session()).is_err());
    assert_eq!(
        authorization_status(&root, &other).unwrap(),
        Some(SessionAuthorization::Active { generation: 1 })
    );
}

#[test]
fn manifest_has_exact_native_roles_and_supported_capabilities() {
    for target in ["x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"] {
        let suffix = if target.contains("windows") {
            ".exe"
        } else {
            ""
        };
        let files = ["control", "media"]
            .into_iter()
            .map(|role| PackageFile {
                path: format!("bin/{role}{suffix}"),
                sha256: "a".repeat(64),
            })
            .collect();
        let value = manifest(target, files);
        value.validate().unwrap();
        assert_eq!(value.capabilities.len(), 7);
        assert_eq!(
            value.auth_kinds.as_ref(),
            &[opennow_plugin_api::provider::AuthKind::Browser]
        );
        assert_eq!(
            value.entrypoints[target].control,
            format!("bin/control{suffix}")
        );
        assert_eq!(
            value.entrypoints[target].media,
            format!("bin/media{suffix}")
        );
    }
}

#[cfg(unix)]
#[test]
fn symlinks_hardlinks_insecure_modes_and_special_files_fail_closed() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let (temp, root) = new_root();
    let writer = AuthorizationWriter::open(&root).unwrap();
    let external = temp.path().join("external.json");
    fs::write(&external, b"{}").unwrap();
    fs::set_permissions(&external, fs::Permissions::from_mode(0o600)).unwrap();
    let state = root.join("control-state.json");
    symlink(&external, &state).unwrap();
    assert!(writer.read_control_state().is_err());
    assert!(writer.write_control_state(b"{}").is_err());
    fs::remove_file(&state).unwrap();
    fs::hard_link(&external, &state).unwrap();
    assert!(writer.read_control_state().is_err());
    assert!(writer.write_control_state(b"{}").is_err());
    fs::remove_file(&state).unwrap();
    fs::write(&state, b"{}").unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(writer.read_control_state().is_err());
    fs::remove_file(&state).unwrap();
    let cpath = std::ffi::CString::new(state.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
    assert!(writer.read_control_state().is_err());
    fs::remove_file(&state).unwrap();
    let alias = temp.path().join("alias");
    symlink(&root, &alias).unwrap();
    assert!(authorization_status(&alias, &session()).is_err());
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(authorization_status(&root, &session()).is_err());
}

#[test]
fn oversized_and_corrupt_persistent_records_fail_closed() {
    let (_temp, root) = new_root();
    let writer = active_writer(&root);
    let bootstrap = bootstrap(
        writer
            .issue_grant(&session(), &accepted(), connection(), now() + 60000)
            .unwrap(),
    );
    let filename = fs::read_dir(&root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("session-")
        })
        .unwrap();
    fs::write(&filename, vec![b' '; 32769]).unwrap();
    assert!(authorize_worker(&root, &bootstrap, now()).is_err());
    assert!(writer.register_session(&session()).is_err());
    fs::write(&filename, b"{truncated").unwrap();
    assert!(writer.activate_session(&session()).is_err());
    assert!(authorization_status(&root, &session()).is_err());
}

#[test]
fn secret_bearing_types_have_redacted_debug() {
    let connection = connection();
    assert!(!format!("{connection:?}").contains("offline"));
    let active = AuthorizedMedia {
        session: session(),
        accepted: accepted(),
        connection,
        revocation_generation: 1,
    };
    assert_eq!(format!("{active:?}"), "AuthorizedMedia([private])");
}

#[test]
fn child_process() {
    let Some(root) = std::env::var_os("BOOSTEROID_COMMON_TEST_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    match std::env::var("BOOSTEROID_COMMON_TEST_SCENARIO")
        .unwrap()
        .as_str()
    {
        "writer-excluded" => assert!(AuthorizationWriter::open(&root).is_err()),
        "worker-excluded" => assert!(lock_worker_session(&root, &session()).is_err()),
        "worker-available" => {
            let _guard = lock_worker_session(&root, &session()).unwrap();
        }
        "authorize-reader" => {
            let mut input = Vec::new();
            io::stdin()
                .take(128 * 1024)
                .read_to_end(&mut input)
                .unwrap();
            let bootstrap = serde_json::from_slice(&input).unwrap();
            let active = authorize_worker(&root, &bootstrap, now()).unwrap();
            assert!(session_authorized(&root, &active).unwrap());
        }
        "crash-after-revoke" => {
            let writer = active_writer(&root);
            writer
                .write_control_state(br#"{"phase":"active"}"#)
                .unwrap();
            writer.revoke_session(&session()).unwrap();
            println!("REVOCATION_COMMITTED");
            io::stdout().flush().unwrap();
            std::thread::sleep(Duration::from_secs(60));
            panic!("parent must kill child at committed crash point");
        }
        "state-reader" => {
            for _ in 0..1000 {
                let bytes = fs::read(root.join("control-state.json")).unwrap();
                let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                let payload = value["payload"].as_str().unwrap();
                assert_eq!(payload.len(), 10000);
                assert!(payload.bytes().all(|b| b == payload.as_bytes()[0]));
            }
        }
        _ => panic!("unknown child scenario"),
    }
}
