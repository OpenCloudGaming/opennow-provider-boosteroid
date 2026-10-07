use crate::{
    input::InputState,
    media::{AudioAssembler, QueuedUnit, VideoAssembler, media_queue},
    transport::Gateway,
};
use anyhow::{Result, bail, ensure};
use boosteroid_common::{
    AuthorizedMedia, authorize_worker, lock_worker_session, session_authorized,
};
use opennow_media_protocol::{
    MAX_BOOTSTRAP_BYTES, MEDIA_PROTOCOL_VERSION,
    wire::{AckKind, ControlMessage, VIDEO_TRACK_ID, WorkerBootstrap, encode_control},
};
use opennow_plugin_api::media::{RequestedVideo, VideoEncoding};
use std::{
    collections::VecDeque,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{Notify, mpsc, watch},
};
use tokio_util::sync::CancellationToken;

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_millis() as u64)
        .unwrap_or(0)
}

pub async fn read_bootstrap(reader: &mut (impl AsyncRead + Unpin)) -> Result<WorkerBootstrap> {
    let mut bytes = Vec::new();
    loop {
        ensure!(bytes.len() < MAX_BOOTSTRAP_BYTES, "Bootstrap exceeds limit");
        let byte = reader.read_u8().await?;
        if byte == b'\n' {
            break;
        }
        bytes.push(byte);
    }
    let bootstrap: WorkerBootstrap =
        serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("Invalid media bootstrap"))?;
    bootstrap
        .validate()
        .map_err(|_| anyhow::anyhow!("Invalid media bootstrap"))?;
    Ok(bootstrap)
}
pub async fn read_control(
    reader: &mut (impl AsyncRead + Unpin),
    maximum: usize,
) -> Result<ControlMessage> {
    let size = reader.read_u32_le().await? as usize;
    ensure!(
        size > 0 && size <= maximum.min(opennow_media_protocol::MAX_CONTROL_BYTES),
        "Control frame exceeds limit"
    );
    let mut bytes = vec![0; size];
    reader.read_exact(&mut bytes).await?;
    serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("Invalid host control frame"))
}
pub async fn write_control(
    writer: &mut (impl AsyncWrite + Unpin),
    message: &ControlMessage,
    maximum: usize,
) -> Result<()> {
    let bytes = encode_control(message, maximum)?;
    tokio::time::timeout(Duration::from_millis(500), writer.write_all(&bytes))
        .await
        .map_err(|_| anyhow::anyhow!("Host control write timed out"))??;
    Ok(())
}

pub async fn handshake(
    host: &mut (impl AsyncRead + AsyncWrite + Unpin),
    bootstrap: &WorkerBootstrap,
    authorize: impl FnOnce() -> Result<()>,
) -> Result<()> {
    bootstrap
        .validate()
        .map_err(|_| anyhow::anyhow!("Invalid worker bootstrap"))?;
    InputState::new(bootstrap.accepted.input.clone())?;
    let maximum = bootstrap.limits.max_control_message_bytes as usize;
    let generation = bootstrap.attempt_generation;
    write_control(
        host,
        &ControlMessage::Hello {
            version: MEDIA_PROTOCOL_VERSION,
            authentication: bootstrap.authentication.clone(),
            attempt_generation: generation,
        },
        maximum,
    )
    .await?;
    ensure!(
        matches!(tokio::time::timeout(Duration::from_secs(2),read_control(host,maximum)).await??,ControlMessage::Attached {attempt_generation} if attempt_generation==generation),
        "Host did not attach this worker attempt"
    );
    authorize()?;
    write_control(
        host,
        &ControlMessage::Ready {
            attempt_generation: generation,
            input: bootstrap.accepted.input.clone(),
        },
        maximum,
    )
    .await
}

pub async fn write_media(
    writer: &mut (impl AsyncWrite + Unpin),
    mut frames: mpsc::Receiver<QueuedUnit>,
    generation: u64,
    cancel: CancellationToken,
) -> Result<()> {
    loop {
        let frame =
            tokio::select! {_ = cancel.cancelled()=>return Ok(()),frame=frames.recv()=>frame};
        let Some(frame) = frame else { return Ok(()) };
        let write = async {
            writer
                .write_all(&frame.unit.header(generation).encode())
                .await?;
            writer.write_all(&frame.unit.bytes).await?;
            writer.flush().await
        };
        tokio::select! {_ = cancel.cancelled()=>return Ok(()), result=tokio::time::timeout(Duration::from_secs(2),write)=>{result.map_err(|_|anyhow::anyhow!("Media pipe backpressure timeout"))??;}}
    }
}

struct InputMailbox {
    pending: Mutex<VecDeque<ControlMessage>>,
    notify: Notify,
    maximum: usize,
}
impl InputMailbox {
    fn new(maximum: usize) -> Self {
        Self {
            pending: Mutex::new(VecDeque::new()),
            notify: Notify::new(),
            maximum,
        }
    }
    fn push(&self, message: ControlMessage) -> Result<()> {
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| anyhow::anyhow!("Input queue unavailable"))?;
        ensure!(pending.len() < self.maximum, "Pending input limit exceeded");
        pending.push_back(message);
        self.notify.notify_one();
        Ok(())
    }
    fn neutralize(&self, sequence: u64) -> Result<()> {
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| anyhow::anyhow!("Input queue unavailable"))?;
        pending.retain(
            |message| matches!(message,ControlMessage::Input {sequence:new,..} if *new>sequence),
        );
        Ok(())
    }
    async fn next(&self) -> Result<ControlMessage> {
        loop {
            let notified = self.notify.notified();
            if let Some(message) = self
                .pending
                .lock()
                .map_err(|_| anyhow::anyhow!("Input queue unavailable"))?
                .pop_front()
            {
                return Ok(message);
            }
            notified.await;
        }
    }
}

struct StreamChannels {
    root: PathBuf,
    commands: Arc<InputMailbox>,
    neutral: watch::Receiver<Option<(u64, bool)>>,
    replies: mpsc::Sender<ControlMessage>,
    video: crate::media::UnitSender,
    audio: crate::media::UnitSender,
    input_ready: Arc<AtomicBool>,
    keyframe: Arc<AtomicBool>,
    cancel: CancellationToken,
}

async fn stream(
    active: AuthorizedMedia,
    limits: opennow_plugin_api::media::MediaLimits,
    generation: u64,
    channels: StreamChannels,
) -> Result<()> {
    let StreamChannels {
        root,
        commands,
        mut neutral,
        replies,
        video: video_tx,
        audio: audio_tx,
        input_ready,
        keyframe,
        cancel,
    } = channels;
    let format = &active.accepted.video;
    let requested = RequestedVideo {
        width: format.width,
        height: format.height,
        encoding: Some(VideoEncoding::H264AnnexB),
        fps: Some(format.fps),
        bit_depth: format.bit_depth,
        chroma: format.chroma,
        hdr: false,
    };
    let mut input = InputState::new(active.accepted.input.clone())?;
    let mut gateway = tokio::select! {_ = cancel.cancelled()=>return Ok(()),gateway=Gateway::connect(&active.connection,&requested,cancel.clone())=>gateway?};
    gateway.start_ice();
    ensure!(
        gateway.audio == active.accepted.audio,
        "Negotiated audio differs from accepted media"
    );
    let result=async {
        for message in input.connected(now_ms())? {gateway.input(message).await?;}
        input_ready.store(true,Ordering::Release);
        let mut video=VideoAssembler::new(active.accepted.video.clone(),&limits)?;let mut audio=AudioAssembler::default();
        let mut timer=tokio::time::interval(Duration::from_millis(50));let started=Instant::now();let mut video_seen=false;let mut audio_gap=false;
        loop {
            tokio::select! {
                _=cancel.cancelled()=>break,
                changed=neutral.changed()=>{
                    changed.map_err(|_|anyhow::anyhow!("Host neutral channel closed"))?;
                    let sequence=*neutral.borrow_and_update();
                    if let Some((sequence,acknowledge))=sequence {
                        commands.neutralize(sequence)?;
                        for message in input.neutral(now_ms())? {gateway.input(message).await?;}
                        if acknowledge {replies.try_send(ControlMessage::Ack {attempt_generation:generation,sequence,kind:AckKind::Neutral}).map_err(|_|anyhow::anyhow!("Host reply queue full"))?;}
                    }
                },
                command=commands.next()=>{
                    let command=command?;
                    match command {
                        ControlMessage::Input {sequence,event,..}=>{for message in input.apply(event,now_ms())?{gateway.input(message).await?;}replies.try_send(ControlMessage::Ack {attempt_generation:generation,sequence,kind:AckKind::Input}).map_err(|_|anyhow::anyhow!("Host reply queue full"))?;},
                        ControlMessage::Neutral {sequence,..}=>{for message in input.neutral(now_ms())?{gateway.input(message).await?;}replies.try_send(ControlMessage::Ack {attempt_generation:generation,sequence,kind:AckKind::Neutral}).map_err(|_|anyhow::anyhow!("Host reply queue full"))?;},
                        ControlMessage::Keyframe {..}=>gateway.peer.request_keyframe().await?,
                        ControlMessage::FrameProgress {..}=>{},
                        _=>bail!("Unexpected media worker command"),
                    }
                },
                _=timer.tick()=>{
                    ensure!(gateway.healthy(),"Gateway transport failed");
                    ensure!(video_seen || started.elapsed()<Duration::from_secs(25),"Gateway produced no validated video");
                    video.expire(Instant::now());if video.take_keyframe_request(){gateway.peer.request_keyframe().await?;}
                    if keyframe.swap(false,Ordering::AcqRel){gateway.peer.request_keyframe().await?;}
                    gateway.announce_ready()?;
                    input_ready.store(gateway.healthy(),Ordering::Release);
                },
                message=gateway.controls.recv()=>{
                    let message=message.ok_or_else(||anyhow::anyhow!("Gateway control closed"))?;
                    gateway.handle_status(&message,&requested,active.connection.bitrate_kbps).await?;
                    if message["type"]=="controller" && message["action"]=="connected" {
                        let name=message["name"].as_str().filter(|s|s.len()<=256).ok_or_else(||anyhow::anyhow!("Invalid controller reply"))?;
                        let id=message["id"].as_u64().and_then(|id|u32::try_from(id).ok()).ok_or_else(||anyhow::anyhow!("Invalid controller id"))?;
                        for message in input.controller_connected(name,id,now_ms())?{gateway.input(message).await?;}
                    }
                    if message["type"]=="controller" && message["action"]=="rumble"
                        && let Some((controller,incarnation))=message["id"].as_u64().and_then(|id|u32::try_from(id).ok()).and_then(|id|input.rumble_target(id)) {
                            let magnitude=|key:&str|message[key].as_u64().map(|x|x.min(65535) as u16).ok_or_else(||anyhow::anyhow!("Invalid rumble magnitude"));
                            replies.try_send(ControlMessage::Rumble {attempt_generation:generation,controller,incarnation,low:magnitude("left")?,high:magnitude("right")?,duration_ms:400}).map_err(|_|anyhow::anyhow!("Host reply queue full"))?;
                    }
                },
                event=gateway.peer.packets.recv()=>{
                    let event=event.ok_or_else(||anyhow::anyhow!("Gateway media ended"))?;
                    if event.codec.mime_type.eq_ignore_ascii_case("video/h264") {
                        ensure!(event.codec.clock_rate==90000,"Invalid video clock");
                        for unit in video.push(event.packet,Instant::now(),video_tx.used_bytes())? {video_seen=true;if !video_tx.try_send(unit){video.discontinuity();}}
                    }else if event.codec.mime_type.eq_ignore_ascii_case("audio/opus"){
                        if let Some(accepted)=&active.accepted.audio {
                            ensure!(event.codec.clock_rate==accepted.sample_rate && event.codec.channels==u16::from(accepted.channels),"Negotiated audio differs from accepted format");
                            if let Some(mut unit)=audio.push(event.packet,limits.max_audio_packet_bytes as usize)? {unit.contiguous &= !audio_gap;audio_gap = !audio_tx.try_send(unit);}
                        }
                    }else {bail!("Unsupported negotiated codec")}
                }
            }
        }
        Ok(())
    }.await;
    input_ready.store(false, Ordering::Release);
    if let Ok(messages) = input.neutral(now_ms()) {
        for message in messages {
            let _ = gateway.input(message).await;
        }
    }
    gateway
        .close(remote_termination_authorized(&root, &active))
        .await;
    result
}

pub fn remote_termination_authorized(root: &std::path::Path, active: &AuthorizedMedia) -> bool {
    matches!(boosteroid_common::authorization_status(root,&active.session),Ok(Some(boosteroid_common::SessionAuthorization::Revoked {generation})) if generation>=active.revocation_generation)
}

#[derive(Default)]
struct HostSequence {
    last: Option<u64>,
}
impl HostSequence {
    fn accept(
        &mut self,
        message: &ControlMessage,
        generation: u64,
        input_ready: bool,
    ) -> Result<()> {
        match message {
            ControlMessage::Input {
                attempt_generation,
                sequence,
                ..
            }
            | ControlMessage::Neutral {
                attempt_generation,
                sequence,
            }
            | ControlMessage::Stop {
                attempt_generation,
                sequence,
            } => {
                ensure!(
                    *attempt_generation == generation
                        && self.last.is_none_or(|last| *sequence > last),
                    "Stale host sequence or generation"
                );
                if matches!(message, ControlMessage::Input { .. }) {
                    ensure!(
                        input_ready,
                        "Gameplay input arrived before the remote transport was ready"
                    );
                }
                self.last = Some(*sequence);
            }
            ControlMessage::Keyframe {
                attempt_generation,
                track_id,
            } => ensure!(
                *attempt_generation == generation && *track_id == VIDEO_TRACK_ID,
                "Invalid keyframe request"
            ),
            ControlMessage::FrameProgress { provenance, .. } => {
                provenance
                    .validate()
                    .map_err(|_| anyhow::anyhow!("Invalid frame provenance"))?;
                ensure!(
                    provenance.attempt_generation == generation
                        && matches!(provenance.track_id, 1 | 2),
                    "Stale frame progress"
                );
            }
            _ => bail!("Unexpected host control message"),
        }
        Ok(())
    }
}

pub async fn run() -> Result<()> {
    let bootstrap = tokio::time::timeout(
        Duration::from_secs(3),
        read_bootstrap(&mut tokio::io::stdin()),
    )
    .await??;
    let root = PathBuf::from(
        std::env::var_os("OPENNOW_PLUGIN_DATA_DIR")
            .ok_or_else(|| anyhow::anyhow!("Missing provider data root"))?,
    );
    let active = authorize_worker(&root, &bootstrap, now_ms())?;
    let _lock = lock_worker_session(&root, &active.session)?;
    let mut host =
        tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, bootstrap.control_port))
            .await?;
    host.set_nodelay(true)?;
    let maximum = bootstrap.limits.max_control_message_bytes as usize;
    let generation = bootstrap.attempt_generation;
    handshake(&mut host, &bootstrap, || {
        ensure!(
            session_authorized(&root, &active)?,
            "Media authorization revoked before attach"
        );
        Ok(())
    })
    .await?;
    let (mut host_read, mut host_write) = host.into_split();
    let cancel = CancellationToken::new();
    let (video_tx, audio_tx, frames) = media_queue(&bootstrap.limits);
    let writer_cancel = cancel.clone();
    let mut writer = tokio::spawn(async move {
        write_media(&mut tokio::io::stdout(), frames, generation, writer_cancel).await
    });
    let commands = Arc::new(InputMailbox::new(
        bootstrap.limits.max_pending_input_events as usize,
    ));
    let commands_tx = commands.clone();
    let (replies_tx, mut replies) = mpsc::channel(64);
    let (neutral_tx, neutral) = watch::channel(None);
    let input_ready = Arc::new(AtomicBool::new(false));
    let transport_ready = input_ready.clone();
    let keyframe = Arc::new(AtomicBool::new(false));
    let transport_keyframe = keyframe.clone();
    let transport_cancel = cancel.clone();
    let active_copy = active.clone();
    let limits = bootstrap.limits.clone();
    let transport_root = root.clone();
    let mut transport = tokio::spawn(async move {
        stream(
            active_copy,
            limits,
            generation,
            StreamChannels {
                root: transport_root,
                commands,
                neutral,
                replies: replies_tx,
                video: video_tx,
                audio: audio_tx,
                input_ready: transport_ready,
                keyframe: transport_keyframe,
                cancel: transport_cancel,
            },
        )
        .await
    });
    let (read_tx, mut incoming) = mpsc::channel(32);
    let read_cancel = cancel.clone();
    let reader = tokio::spawn(async move {
        loop {
            let message = tokio::select! {_ = read_cancel.cancelled()=>break,message=read_control(&mut host_read,maximum)=>message};
            let failed = message.is_err();
            if read_tx.send(message).await.is_err() || failed {
                break;
            }
        }
    });
    let result=async {
        let mut poll=tokio::time::interval(Duration::from_millis(250));let mut sequence=HostSequence::default();
        loop {tokio::select! {
            message=incoming.recv()=>{
                let message=message.ok_or_else(||anyhow::anyhow!("Host disconnected"))??;
                let ready=input_ready.load(Ordering::Acquire);
                sequence.accept(&message,generation,ready)?;
                match &message {
                    ControlMessage::Input {..}=>commands_tx.push(message)?,
                    ControlMessage::Neutral {sequence,..}=>{
                        commands_tx.neutralize(*sequence)?;
                        neutral_tx.send_replace(Some((*sequence,ready)));
                        if !ready {write_control(&mut host_write,&ControlMessage::Ack {attempt_generation:generation,sequence:*sequence,kind:AckKind::Neutral},maximum).await?;}
                    },
                    ControlMessage::Stop {sequence:new,..}=>{
                        cancel.cancel();write_control(&mut host_write,&ControlMessage::Ack {attempt_generation:generation,sequence:*new,kind:AckKind::Stop},maximum).await?;break;
                    },
                    ControlMessage::Keyframe {..}=>{keyframe.store(true,Ordering::Release);},
                    ControlMessage::FrameProgress {..}=>{},
                    _=>bail!("Unexpected host control message"),
                }
            },
            _=poll.tick()=>ensure!(session_authorized(&root,&active)?,"Session authorization revoked"),
            message=replies.recv()=>{let message=message.ok_or_else(||anyhow::anyhow!("Gateway control task ended"))?;write_control(&mut host_write,&message,maximum).await?;},
            result=&mut transport=>{result??;break;},
            result=&mut writer=>{result??;break;},
        }}
        Ok(())
    }.await;
    cancel.cancel();
    reader.abort();
    if !transport.is_finished() {
        let _ = tokio::time::timeout(Duration::from_millis(750), &mut transport).await;
    }
    transport.abort();
    if !writer.is_finished() {
        let _ = tokio::time::timeout(Duration::from_millis(250), &mut writer).await;
    }
    writer.abort();
    let _ = write_control(
        &mut host_write,
        &ControlMessage::Ended {
            attempt_generation: generation,
        },
        maximum,
    )
    .await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn input(sequence: u64) -> ControlMessage {
        ControlMessage::Input {
            attempt_generation: 7,
            sequence,
            captured_us: 0,
            event: opennow_media_protocol::wire::InputEvent::Key {
                virtual_key: 65,
                modifiers: 0,
                pressed: true,
            },
        }
    }

    #[tokio::test]
    async fn early_input_is_rejected_and_neutral_supersedes_only_older_pending_events() -> Result<()>
    {
        let mut sequence = HostSequence::default();
        assert!(sequence.accept(&input(0), 7, false).is_err());
        sequence.accept(
            &ControlMessage::Neutral {
                attempt_generation: 7,
                sequence: 0,
            },
            7,
            false,
        )?;
        sequence.accept(
            &ControlMessage::Stop {
                attempt_generation: 7,
                sequence: 1,
            },
            7,
            false,
        )?;
        assert!(sequence.accept(&input(1), 7, true).is_err());
        let mailbox = InputMailbox::new(2);
        mailbox.push(input(2))?;
        mailbox.push(input(4))?;
        assert!(mailbox.push(input(5)).is_err());
        mailbox.neutralize(3)?;
        assert!(matches!(
            mailbox.next().await?,
            ControlMessage::Input { sequence: 4, .. }
        ));
        mailbox.push(input(5))?;
        Ok(())
    }
}
