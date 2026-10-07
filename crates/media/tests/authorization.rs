use anyhow::Result;
use boosteroid_common::{
    AuthorizationWriter, GatewayConnection, PLUGIN_ID, authorize_worker, lock_worker_session,
    session_authorized,
};
use boosteroid_media::worker::{handshake, now_ms, read_control, write_control};
use opennow_media_protocol::{
    lease::WorkerBinding,
    wire::{ControlMessage, WorkerBootstrap},
};
use opennow_plugin_api::{
    PluginId,
    media::*,
    provider::{AttemptId, OfferId, SecretBytes, SecretString, SessionId, SessionKey, Text},
};
use std::{
    io::Write,
    process::{Command, Stdio},
    time::Duration,
};

fn accepted() -> AcceptedMedia {
    AcceptedMedia {
        offer_id: OfferId::new("test-offer").unwrap(),
        runtime_epoch: 9,
        video: VideoFormat {
            encoding: VideoEncoding::H264AnnexB,
            width: 64,
            height: 64,
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
        input: boosteroid_media::input::capabilities(),
    }
}
fn session() -> SessionKey {
    SessionKey {
        account: None,
        remote_id: SessionId::new("test-logical-session").unwrap(),
    }
}
fn connection() -> GatewayConnection {
    GatewayConnection {
        upstream_session_id: "no-service".into(),
        session_query: SecretString::new("sessionId=no-service").unwrap(),
        gateways: vec!["gateway.invalid".into()],
        home_url: None,
        peer_id: "offline-peer".into(),
        bitrate_kbps: 20000,
    }
}
fn bootstrap(grant: SecretBytes) -> WorkerBootstrap {
    WorkerBootstrap {
        version: 1,
        binding: WorkerBinding {
            lease_id: Text::new("test-lease").unwrap(),
            source_id: PluginId::new(PLUGIN_ID).unwrap(),
            session: session(),
            attempt_id: AttemptId::new("test-attempt").unwrap(),
        },
        attempt_generation: 15,
        control_port: 12345,
        authentication: SecretBytes::new(vec![1; 32]).unwrap(),
        accepted: accepted(),
        limits: MediaLimits {
            max_video_access_unit_bytes: 65536,
            max_audio_packet_bytes: 4096,
            max_buffered_video_bytes: 131072,
            max_buffered_video_frames: 2,
            max_buffered_audio_ms: 40,
            max_control_message_bytes: 65536,
            max_pending_input_events: 2,
        },
        provider_bootstrap: grant,
    }
}

#[test]
fn active_authorization_survives_owner_restart_and_grant_expiry_until_revoked() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path().join("private");
    let writer = AuthorizationWriter::open(&root)?;
    writer.register_session(&session())?;
    writer.activate_session(&session())?;
    let expires = now_ms() + 60_000;
    let grant = writer.issue_grant(&session(), &accepted(), connection(), expires)?;
    let bootstrap = bootstrap(grant);
    let active = authorize_worker(&root, &bootstrap, now_ms())?;
    assert!(!boosteroid_media::worker::remote_termination_authorized(
        &root, &active
    ));
    let lock = lock_worker_session(&root, &active.session)?;
    assert!(lock_worker_session(&root, &active.session).is_err());
    drop(writer);
    let restarted = AuthorizationWriter::open(&root)?;
    restarted.write_control_state(br#"{"epoch":2}"#)?;
    assert!(session_authorized(&root, &active)?);
    assert!(authorize_worker(&root, &bootstrap, expires + 1).is_err());
    assert!(session_authorized(&root, &active)?);
    restarted.issue_grant(&session(), &accepted(), connection(), expires + 10_000)?;
    assert!(session_authorized(&root, &active)?);
    restarted.revoke_session(&session())?;
    assert!(!session_authorized(&root, &active)?);
    assert!(boosteroid_media::worker::remote_termination_authorized(
        &root, &active
    ));
    assert!(!boosteroid_media::worker::remote_termination_authorized(
        &root.join("missing"),
        &active
    ));
    drop(lock);
    Ok(())
}

#[tokio::test]
async fn host_handshake_finishes_before_delayed_negotiation_and_stop_is_prompt() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path().join("private");
    let writer = AuthorizationWriter::open(&root)?;
    writer.register_session(&session())?;
    writer.activate_session(&session())?;
    let boot =
        bootstrap(writer.issue_grant(&session(), &accepted(), connection(), now_ms() + 60_000)?);
    let active = authorize_worker(&root, &boot, now_ms())?;
    let (mut host, mut worker) = tokio::io::duplex(65536);
    let started = std::time::Instant::now();
    let task = tokio::spawn(async move {
        handshake(&mut worker, &boot, || {
            anyhow::ensure!(session_authorized(&root, &active)?, "Revoked");
            Ok(())
        })
        .await?;
        let delayed_negotiation = tokio::time::sleep(Duration::from_secs(60));
        tokio::pin!(delayed_negotiation);
        tokio::select! {
            _=&mut delayed_negotiation=>anyhow::bail!("Unexpected delayed negotiation completion"),
            command=read_control(&mut worker,65536)=>{anyhow::ensure!(matches!(command?,ControlMessage::Stop {attempt_generation:15,sequence:1}),"Missing stop");}
        }
        Ok::<(), anyhow::Error>(())
    });
    assert!(matches!(
        read_control(&mut host, 65536).await?,
        ControlMessage::Hello {
            attempt_generation: 15,
            ..
        }
    ));
    write_control(
        &mut host,
        &ControlMessage::Attached {
            attempt_generation: 15,
        },
        65536,
    )
    .await?;
    assert!(matches!(
        read_control(&mut host, 65536).await?,
        ControlMessage::Ready {
            attempt_generation: 15,
            ..
        }
    ));
    assert!(started.elapsed() < Duration::from_secs(1));
    write_control(
        &mut host,
        &ControlMessage::Stop {
            attempt_generation: 15,
            sequence: 1,
        },
        65536,
    )
    .await?;
    tokio::time::timeout(Duration::from_millis(100), task).await???;
    Ok(())
}

#[test]
fn forged_grant_binary_exits_before_any_media_or_network() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path().join("private");
    let _writer = AuthorizationWriter::open(&root)?;
    let bootstrap = bootstrap(SecretBytes::new(b"forged offline grant".to_vec())?);
    let mut child = Command::new(env!("CARGO_BIN_EXE_boosteroid-media"))
        .env("OPENNOW_PLUGIN_DATA_DIR", &root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut encoded = serde_json::to_vec(&bootstrap)?;
    encoded.push(b'\n');
    child.stdin.take().unwrap().write_all(&encoded)?;
    let result = child.wait_with_output()?;
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&result.stderr).contains("forged offline grant"));
    Ok(())
}
