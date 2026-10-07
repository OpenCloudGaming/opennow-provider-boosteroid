use anyhow::{Result, bail, ensure};
use async_trait::async_trait;
use boosteroid_common::GatewayConnection;
use futures_util::{SinkExt, StreamExt};
use opennow_plugin_api::media::{AudioCodec, AudioFormat, RequestedVideo};
use rtc::{
    rtp::Packet,
    rtp_transceiver::rtp_sender::{RTCRtpCodec, RTCRtpCodecParameters, RtpCodecKind},
};
use serde_json::{Value, json};
use std::{
    collections::HashSet,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use webrtc::{
    data_channel::{DataChannel, DataChannelEvent, RTCDataChannelState},
    media_stream::track_remote::{TrackRemote, TrackRemoteEvent},
    peer_connection::{
        MediaEngine, PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler,
        RTCConfigurationBuilder, RTCIceCandidateInit, RTCIceGatheringState, RTCIceServer,
        RTCPeerConnectionIceEvent, RTCPeerConnectionState, RTCSessionDescription,
    },
    rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit},
};

const HTTP_LIMIT: usize = 512 * 1024;
const SIGNAL_TIMEOUT: Duration = Duration::from_secs(10);

pub struct ReceivedRtp {
    pub packet: Packet,
    pub codec: RTCRtpCodec,
    _budget: OwnedSemaphorePermit,
}

type VideoFeedback = Arc<Mutex<Option<(Arc<dyn TrackRemote>, u32)>>>;

struct Handler {
    packets: mpsc::Sender<ReceivedRtp>,
    candidates: mpsc::Sender<RTCIceCandidateInit>,
    gather: mpsc::Sender<()>,
    video: VideoFeedback,
    connected: Arc<AtomicBool>,
    failed: Arc<AtomicBool>,
    bytes: Arc<Semaphore>,
    cancel: CancellationToken,
}

#[async_trait]
impl PeerConnectionEventHandler for Handler {
    async fn on_ice_candidate(&self, event: RTCPeerConnectionIceEvent) {
        if let Ok(candidate) = event.candidate.to_json()
            && self.candidates.try_send(candidate).is_err()
        {
            self.failed.store(true, Ordering::Release);
        }
    }
    async fn on_ice_gathering_state_change(&self, state: RTCIceGatheringState) {
        if state == RTCIceGatheringState::Complete {
            let _ = self.gather.try_send(());
        }
    }
    async fn on_connection_state_change(&self, state: RTCPeerConnectionState) {
        self.connected.store(
            state == RTCPeerConnectionState::Connected,
            Ordering::Release,
        );
        if state == RTCPeerConnectionState::Failed {
            self.failed.store(true, Ordering::Release);
        }
    }
    async fn on_track(&self, track: Arc<dyn TrackRemote>) {
        let tx = self.packets.clone();
        let cancel = self.cancel.clone();
        let bytes = self.bytes.clone();
        let video = self.video.clone();
        let failed = self.failed.clone();
        tokio::spawn(async move {
            loop {
                let event = tokio::select! { _ = cancel.cancelled() => break, event = track.poll() => event };
                let Some(event) = event else { break };
                match event {
                    TrackRemoteEvent::OnRtpPacket(packet) => {
                        let Some(codec) = track.codec(packet.header.ssrc).await else {
                            failed.store(true, Ordering::Release);
                            break;
                        };
                        if codec.mime_type.eq_ignore_ascii_case("video/h264") {
                            *video.lock().await = Some((track.clone(), packet.header.ssrc));
                        }
                        let Ok(budget) = bytes
                            .clone()
                            .try_acquire_many_owned(packet.payload.len() as u32)
                        else {
                            continue;
                        };
                        let _ = tx.try_send(ReceivedRtp {
                            packet,
                            codec,
                            _budget: budget,
                        });
                    }
                    TrackRemoteEvent::OnError => {
                        failed.store(true, Ordering::Release);
                        break;
                    }
                    TrackRemoteEvent::OnEnded => break,
                    _ => {}
                }
            }
        });
    }
}

pub fn codec_engine() -> Result<(MediaEngine, rtc::interceptor::Registry)> {
    let mut engine = MediaEngine::default();
    for (payload_type, profile) in [(102, "42001f"), (125, "42e01f"), (123, "640032")] {
        engine.register_codec(
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: "video/H264".into(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line: format!(
                        "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id={profile}"
                    ),
                    rtcp_feedback: vec![rtc::rtp_transceiver::rtp_sender::RTCPFeedback {
                        typ: "nack".into(),
                        parameter: "pli".into(),
                    }],
                },
                payload_type,
            },
            RtpCodecKind::Video,
        )?;
    }
    engine.register_codec(
        RTCRtpCodecParameters {
            rtp_codec: RTCRtpCodec {
                mime_type: "audio/opus".into(),
                clock_rate: 48000,
                channels: 2,
                sdp_fmtp_line: "minptime=10;useinbandfec=1;stereo=1;maxaveragebitrate=128000"
                    .into(),
                rtcp_feedback: vec![],
            },
            payload_type: 111,
        },
        RtpCodecKind::Audio,
    )?;
    use rtc::peer_connection::configuration::interceptor_registry::{
        configure_nack, configure_rtcp_reports, configure_twcc_receiver_only,
    };
    let registry = configure_nack(rtc::interceptor::Registry::new(), &mut engine);
    let registry = configure_rtcp_reports(registry);
    let registry = configure_twcc_receiver_only(registry, &mut engine)?;
    Ok((engine, registry))
}

pub struct NativePeer {
    pub pc: Arc<dyn PeerConnection>,
    pub dc: Arc<dyn DataChannel>,
    pub packets: mpsc::Receiver<ReceivedRtp>,
    pub candidates: mpsc::Receiver<RTCIceCandidateInit>,
    pub gathered: mpsc::Receiver<()>,
    pub connected: Arc<AtomicBool>,
    pub failed: Arc<AtomicBool>,
    video: VideoFeedback,
    last_pli: Option<Instant>,
    cancel: CancellationToken,
}

impl NativePeer {
    pub async fn new(
        ice_servers: Vec<RTCIceServer>,
        loopback: bool,
        byte_limit: usize,
    ) -> Result<Self> {
        let (packets, packet_rx) = mpsc::channel(128);
        let (candidates, candidate_rx) = mpsc::channel(128);
        let (gather, gathered) = mpsc::channel(1);
        let connected = Arc::new(AtomicBool::new(false));
        let failed = Arc::new(AtomicBool::new(false));
        let video = Arc::new(Mutex::new(None));
        let cancel = CancellationToken::new();
        let (engine, registry) = codec_engine()?;
        let pc = PeerConnectionBuilder::new()
            .with_configuration(
                RTCConfigurationBuilder::default()
                    .with_ice_servers(ice_servers)
                    .build(),
            )
            .with_media_engine(engine)
            .with_interceptor_registry(registry)
            .with_handler(Arc::new(Handler {
                packets,
                candidates,
                gather,
                video: video.clone(),
                connected: connected.clone(),
                failed: failed.clone(),
                bytes: Arc::new(Semaphore::new(byte_limit)),
                cancel: cancel.clone(),
            }))
            .with_udp_addrs(vec![if loopback { "127.0.0.1:0" } else { "0.0.0.0:0" }])
            .with_data_channel_send_buffer_limit(64 * 1024)
            .build()
            .await?;
        for kind in [RtpCodecKind::Audio, RtpCodecKind::Video] {
            pc.add_transceiver_from_kind(
                kind,
                Some(RTCRtpTransceiverInit {
                    direction: RTCRtpTransceiverDirection::Recvonly,
                    ..Default::default()
                }),
            )
            .await?;
        }
        let dc = pc.create_data_channel("ClientDataChannel", None).await?;
        let read_dc = dc.clone();
        let stop = cancel.clone();
        tokio::spawn(async move {
            loop {
                let event =
                    tokio::select! { _ = stop.cancelled()=>break, event = read_dc.poll()=>event };
                if matches!(
                    event,
                    None | Some(DataChannelEvent::OnClose | DataChannelEvent::OnError)
                ) {
                    break;
                }
            }
        });
        Ok(Self {
            pc: Arc::new(pc),
            dc,
            packets: packet_rx,
            candidates: candidate_rx,
            gathered,
            connected,
            failed,
            video,
            last_pli: None,
            cancel,
        })
    }
    pub async fn request_keyframe(&mut self) -> Result<()> {
        let now = Instant::now();
        if self
            .last_pli
            .is_some_and(|last| now.duration_since(last) < Duration::from_millis(250))
        {
            return Ok(());
        }
        if let Some((track, ssrc)) = self.video.lock().await.as_ref() {
            tokio::time::timeout(
                Duration::from_millis(100),
                track.write_rtcp(vec![Box::new(
                    rtc::rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication {
                        sender_ssrc: 0,
                        media_ssrc: *ssrc,
                    },
                )]),
            )
            .await
            .map_err(|_| anyhow::anyhow!("Keyframe feedback timed out"))??;
            self.last_pli = Some(now);
        }
        Ok(())
    }
    pub async fn close(&self) {
        self.cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_millis(500), self.pc.close()).await;
    }
}
impl Drop for NativePeer {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

enum GatewayWrite {
    Message(Value),
    Flush(oneshot::Sender<()>),
}

pub struct Gateway {
    pub peer: NativePeer,
    pub audio: Option<AudioFormat>,
    pub controls: mpsc::Receiver<Value>,
    writer: mpsc::Sender<GatewayWrite>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    cancel: CancellationToken,
    http: reqwest::Client,
    api: url::Url,
    session: String,
    peer_id: String,
    ready_announced: bool,
}

pub fn gateway_urls(
    connection: &GatewayConnection,
    requested: &RequestedVideo,
) -> Result<(url::Url, url::Url)> {
    crate::input::validate_requested(requested)?;
    ensure!(
        connection.bitrate_kbps >= 220 && connection.bitrate_kbps <= 200_000,
        "Invalid gateway bitrate"
    );
    let raw = connection
        .gateways
        .first()
        .ok_or_else(|| anyhow::anyhow!("No authorized streaming gateway"))?;
    ensure!(
        raw.len() <= 4096 && connection.session_query.expose_secret().len() <= 32768,
        "Gateway parameters exceed limits"
    );
    let value = if raw.contains("://") {
        raw.clone()
    } else {
        format!("wss://{raw}")
    };
    let mut ws = url::Url::parse(&value).map_err(|_| anyhow::anyhow!("Invalid gateway URL"))?;
    ensure!(
        matches!(ws.scheme(), "wss" | "https")
            && ws.username().is_empty()
            && ws.password().is_none()
            && ws.query().is_none()
            && ws.fragment().is_none(),
        "Invalid gateway origin"
    );
    let host = ws
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("Missing gateway hostname"))?;
    ensure!(
        host == "boosteroid.com" || host.ends_with(".boosteroid.com"),
        "Gateway hostname is outside the supported service domain"
    );
    ws.set_scheme("wss")
        .map_err(|_| anyhow::anyhow!("Invalid gateway scheme"))?;
    ws.set_path("/");
    let query = connection
        .session_query
        .expose_secret()
        .trim_start_matches('?');
    ensure!(!query.is_empty(), "Missing gateway query");
    let mut parsed = url::form_urlencoded::parse(query.as_bytes());
    for (key, value) in &mut parsed {
        if matches!(key.as_ref(), "sessionId" | "sessionid" | "session") {
            ensure!(
                value == connection.upstream_session_id,
                "Gateway session mismatch"
            );
        }
    }
    ws.set_query(Some(query));
    ws.query_pairs_mut()
        .append_pair("x", &requested.width.to_string())
        .append_pair("y", &requested.height.to_string())
        .append_pair("lang", "en")
        .append_pair("refreshRate", &requested.fps.unwrap_or(60).to_string())
        .append_pair("rtcEngine", "webrtc")
        .append_pair("clientType", "web")
        .append_pair("devType", "desktop")
        .append_pair(
            "os",
            if cfg!(target_os = "windows") {
                "win"
            } else if cfg!(target_os = "macos") {
                "mac"
            } else {
                "lin"
            },
        )
        .append_pair("rtcAudio", "pcm");
    let mut api = ws.clone();
    api.set_scheme("https")
        .map_err(|_| anyhow::anyhow!("Invalid gateway scheme"))?;
    api.set_port(None)
        .map_err(|_| anyhow::anyhow!("Invalid gateway port"))?;
    api.set_path("/webrtc/");
    api.set_query(None);
    Ok((ws, api))
}

fn endpoint(api: &url::Url, path: &str, session: &str, peer: Option<&str>) -> Result<url::Url> {
    let mut url = api.join(path)?;
    url.query_pairs_mut().append_pair("sessionId", session);
    if let Some(peer) = peer {
        url.query_pairs_mut().append_pair("peerid", peer);
    }
    Ok(url)
}

async fn response_json(request: reqwest::RequestBuilder) -> Result<Value> {
    let response = request
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("Gateway HTTP request failed"))?;
    ensure!(
        response.status().is_success(),
        "Gateway rejected HTTP request"
    );
    ensure!(
        response
            .content_length()
            .is_none_or(|len| len <= HTTP_LIMIT as u64),
        "Gateway response exceeds limit"
    );
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| anyhow::anyhow!("Gateway response read failed"))?;
        ensure!(
            bytes.len() + chunk.len() <= HTTP_LIMIT,
            "Gateway response exceeds limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("Invalid gateway JSON"))
}

fn status(request: &RequestedVideo, bitrate: u32) -> Value {
    json!({"type":"stream","action":"status","value":"ok","params":{"type":"web","ver":"openstroid","gpu":"unknown","proto":1,"framerate_max":request.fps.unwrap_or(60),"bitrate_max":bitrate*1000,"hdr":false,"cursor_zip":false,"filler":false,"beta":0,"rtcEngine":"webrtc","rtcAudio":"pcm","network_type":"unknown"}})
}

pub fn parse_answer(value: Value) -> Result<RTCSessionDescription> {
    let answer = value
        .get("data")
        .or_else(|| value.get("answer"))
        .unwrap_or(&value);
    ensure!(
        answer["type"] == "answer",
        "Gateway did not return an SDP answer"
    );
    let sdp = answer["sdp"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing SDP answer"))?;
    ensure!(sdp.len() <= HTTP_LIMIT, "SDP exceeds limit");
    RTCSessionDescription::answer(sdp.to_owned()).map_err(|_| anyhow::anyhow!("Invalid SDP answer"))
}

pub fn negotiated_audio(answer: &RTCSessionDescription) -> Result<Option<AudioFormat>> {
    let parsed = answer
        .unmarshal()
        .map_err(|_| anyhow::anyhow!("Invalid negotiated SDP"))?;
    let mut audio = None;
    for media in parsed
        .media_descriptions
        .iter()
        .filter(|m| m.media_name.media == "audio")
    {
        if media.media_name.port.value == 0
            || media.has_attribute("inactive")
            || media.has_attribute("recvonly")
        {
            continue;
        }
        ensure!(audio.is_none(), "Multiple audio tracks are not supported");
        let codecs = media.codecs();
        let mut format = None;
        for payload in &media.media_name.formats {
            let payload = payload
                .parse::<u8>()
                .map_err(|_| anyhow::anyhow!("Invalid audio payload type"))?;
            let codec = codecs
                .get(&payload)
                .ok_or_else(|| anyhow::anyhow!("Missing audio codec mapping"))?;
            ensure!(
                codec.name.eq_ignore_ascii_case("opus") && codec.clock_rate == 48000,
                "Unsupported negotiated audio codec"
            );
            let channels = codec
                .encoding_parameters
                .parse::<u8>()
                .map_err(|_| anyhow::anyhow!("Unestablished audio channel count"))?;
            ensure!(matches!(channels, 1 | 2), "Unsupported audio channel count");
            let found = AudioFormat {
                codec: AudioCodec::Opus,
                sample_rate: 48000,
                channels,
            };
            ensure!(
                format.as_ref().is_none_or(|old| *old == found),
                "Conflicting audio codecs"
            );
            format = Some(found);
        }
        audio = Some(format.ok_or_else(|| anyhow::anyhow!("Missing negotiated audio format"))?);
    }
    Ok(audio)
}
pub fn parse_candidates(value: Value) -> Result<Vec<RTCIceCandidateInit>> {
    let values = if let Some(values) = value.as_array() {
        values.clone()
    } else if let Some(values) = value["data"].as_array() {
        values.clone()
    } else if value.get("candidate").is_some_and(Value::is_object) {
        vec![value["candidate"].clone()]
    } else {
        bail!("Unsupported candidate response")
    };
    ensure!(values.len() <= 128, "Too many ICE candidates");
    values
        .into_iter()
        .map(|v| {
            let candidate: RTCIceCandidateInit =
                serde_json::from_value(v).map_err(|_| anyhow::anyhow!("Invalid ICE candidate"))?;
            ensure!(
                candidate.candidate.len() <= 4096,
                "ICE candidate exceeds limit"
            );
            Ok(candidate)
        })
        .collect()
}

pub fn parse_ice_servers(value: Value) -> Result<Vec<RTCIceServer>> {
    let value = value
        .get("iceServers")
        .or_else(|| value.get("data"))
        .unwrap_or(&value);
    let value = value.get("iceServers").unwrap_or(value);
    let values = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Invalid ICE server response"))?;
    ensure!(values.len() <= 16, "Too many ICE servers");
    values
        .iter()
        .map(|value| {
            let mut value = value.clone();
            if let Some(single) = value["urls"].as_str() {
                value["urls"] = json!([single]);
            }
            let urls = value["urls"]
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("Invalid ICE URLs"))?;
            ensure!(
                !urls.is_empty()
                    && urls.len() <= 8
                    && urls
                        .iter()
                        .all(|url| url.as_str().is_some_and(|url| url.len() <= 2048
                            && ["stun:", "stuns:", "turn:", "turns:"]
                                .iter()
                                .any(|prefix| url.starts_with(prefix)))),
                "Unsupported ICE URL"
            );
            let optional = |key: &str| -> Result<String> {
                match value.get(key) {
                    None => Ok(String::new()),
                    Some(value) => {
                        let value = value
                            .as_str()
                            .filter(|s| s.len() <= 8192)
                            .ok_or_else(|| anyhow::anyhow!("Invalid ICE credential field"))?;
                        Ok(value.to_owned())
                    }
                }
            };
            ensure!(
                value
                    .get("credentialType")
                    .is_none_or(|value| value == "password"),
                "Unsupported ICE credential type"
            );
            let server = RTCIceServer {
                urls: urls
                    .iter()
                    .map(|v| v.as_str().unwrap_or_default().to_owned())
                    .collect(),
                username: optional("username")?,
                credential: optional("credential")?,
            };
            server
                .urls()
                .map_err(|_| anyhow::anyhow!("Invalid ICE server configuration"))?;
            Ok(server)
        })
        .collect()
}

impl Gateway {
    pub async fn connect(
        connection: &GatewayConnection,
        requested: &RequestedVideo,
        cancel: CancellationToken,
    ) -> Result<Self> {
        let (ws_url, api) = gateway_urls(connection, requested)?;
        let http = reqwest::Client::builder()
            .timeout(SIGNAL_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
            .max_message_size(Some(64 * 1024))
            .max_frame_size(Some(64 * 1024));
        let connecting = tokio::time::timeout(
            SIGNAL_TIMEOUT,
            tokio_tungstenite::connect_async_with_config(ws_url.as_str(), Some(config), true),
        );
        let (socket, _) = tokio::select!{_ = cancel.cancelled()=>bail!("Gateway connection cancelled"), result=connecting=>result}
        .map_err(|_| anyhow::anyhow!("Gateway websocket timeout"))?
        .map_err(|_| anyhow::anyhow!("Gateway websocket connection failed"))?;
        let (mut sink, mut stream) = socket.split();
        let (writer, mut writes) = mpsc::channel::<GatewayWrite>(256);
        let (controls_tx, mut controls) = mpsc::channel(128);
        let stop = CancellationToken::new();
        let write_cancel = stop.clone();
        let read_cancel = stop.clone();
        let write_task = tokio::spawn(async move {
            loop {
                let item =
                    tokio::select! {_ = write_cancel.cancelled()=>break,item=writes.recv()=>item};
                let Some(item) = item else { break };
                match item {
                    GatewayWrite::Message(item) => {
                        if sink
                            .send(tokio_tungstenite::tungstenite::Message::Text(
                                item.to_string().into(),
                            ))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    GatewayWrite::Flush(done) => {
                        if sink.flush().await.is_err() {
                            break;
                        }
                        let _ = done.send(());
                    }
                }
            }
            let _ = sink.close().await;
            write_cancel.cancel();
        });
        let read_task = tokio::spawn(async move {
            loop {
                let message = tokio::select! {_ = read_cancel.cancelled()=>break,message=stream.next()=>message};
                match message {
                    Some(Ok(tokio_tungstenite::tungstenite::Message::Text(text))) => {
                        let Ok(value) = serde_json::from_str::<Value>(&text) else {
                            break;
                        };
                        if controls_tx.try_send(value).is_err() {
                            break;
                        }
                    }
                    Some(Ok(
                        tokio_tungstenite::tungstenite::Message::Ping(_)
                        | tokio_tungstenite::tungstenite::Message::Pong(_),
                    )) => {}
                    _ => break,
                }
            }
            read_cancel.cancel();
        });
        let negotiate = async {
            loop {
                let message = controls
                    .recv()
                    .await
                    .ok_or_else(|| anyhow::anyhow!("Gateway control closed before negotiation"))?;
                if message["type"] == "stream" && message["action"] == "getstatus" {
                    writer
                        .send(GatewayWrite::Message(
                            json!({"type":"keyboard","action":"language","code":1033}),
                        ))
                        .await?;
                    writer
                        .send(GatewayWrite::Message(status(
                            requested,
                            connection.bitrate_kbps,
                        )))
                        .await?;
                }
                if message["type"] == "settings" && message["action"] == "webrtc" {
                    break;
                }
            }
            let ice = response_json(http.get(endpoint(
                &api,
                "api/getIceServers",
                &connection.upstream_session_id,
                None,
            )?))
            .await?;
            let servers = parse_ice_servers(ice)?;
            let params = response_json(http.get(endpoint(
                &api,
                "api/getParams",
                &connection.upstream_session_id,
                None,
            )?))
            .await?;
            ensure!(
                params
                    .get("codec")
                    .is_none_or(|c| c.as_str().is_some_and(|c| c.eq_ignore_ascii_case("h264"))),
                "Gateway requires unsupported codec"
            );
            let peer = NativePeer::new(servers, false, 4 * 1024 * 1024).await?;
            let result = async {
                let offer = peer.pc.create_offer(None).await?;
                peer.pc.set_local_description(offer.clone()).await?;
                let answer = parse_answer(
                    response_json(
                        http.post(endpoint(
                            &api,
                            "api/call",
                            &connection.upstream_session_id,
                            Some(&connection.peer_id),
                        )?)
                        .json(&offer),
                    )
                    .await?,
                )?;
                let audio = negotiated_audio(&answer)?;
                peer.pc.set_remote_description(answer).await?;
                Ok::<_, anyhow::Error>(audio)
            }
            .await;
            match result {
                Ok(audio) => Ok((peer, audio)),
                Err(error) => {
                    peer.close().await;
                    Err(error)
                }
            }
        };
        let result = tokio::select! {_ = cancel.cancelled()=>Err(anyhow::anyhow!("Gateway negotiation cancelled")),result=tokio::time::timeout(Duration::from_secs(25),negotiate)=>result.map_err(|_|anyhow::anyhow!("Gateway negotiation timed out"))?};
        let (peer, audio) = match result {
            Ok(result) => result,
            Err(error) => {
                stop.cancel();
                write_task.abort();
                read_task.abort();
                return Err(error);
            }
        };
        Ok(Self {
            peer,
            audio,
            controls,
            writer,
            tasks: vec![write_task, read_task],
            cancel: stop,
            http,
            api,
            session: connection.upstream_session_id.clone(),
            peer_id: connection.peer_id.clone(),
            ready_announced: false,
        })
    }

    pub fn start_ice(&mut self) {
        let (_, empty) = mpsc::channel(1);
        let mut candidates = std::mem::replace(&mut self.peer.candidates, empty);
        let http = self.http.clone();
        let api = self.api.clone();
        let session = self.session.clone();
        let peer_id = self.peer_id.clone();
        let pc = self.peer.pc.clone();
        let connected = self.peer.connected.clone();
        let failed = self.peer.failed.clone();
        let cancel = self.cancel.clone();
        self.tasks.push(tokio::spawn(async move {
            let result=async {
                let mut seen=HashSet::new();let mut timer=tokio::time::interval(Duration::from_millis(500));
                loop {tokio::select! {
                    _=cancel.cancelled()=>return Ok::<(),anyhow::Error>(()),
                    candidate=candidates.recv()=>{if let Some(candidate)=candidate {
                        let response=http.post(endpoint(&api,"api/addIceCandidate",&session,Some(&peer_id))?).json(&candidate).send().await.map_err(|_|anyhow::anyhow!("ICE submission failed"))?;
                        ensure!(response.status().is_success(),"Gateway rejected ICE candidate");
                    }},
                    _=timer.tick(),if !connected.load(Ordering::Acquire)=>{
                        for candidate in parse_candidates(response_json(http.get(endpoint(&api,"api/getIceCandidate",&session,Some(&peer_id))?)).await?)? {
                            let key=serde_json::to_string(&candidate)?;if !seen.insert(key){continue}ensure!(seen.len()<=256,"Too many remote candidates");pc.add_ice_candidate(candidate).await?;
                        }
                    }
                }}
            }.await;
            if result.is_err(){failed.store(true,Ordering::Release);cancel.cancel();}
        }));
    }
    pub fn healthy(&self) -> bool {
        !self.peer.failed.load(Ordering::Acquire) && !self.cancel.is_cancelled()
    }
    pub fn announce_ready(&mut self) -> Result<()> {
        if self.ready_announced || !self.peer.connected.load(Ordering::Acquire) {
            return Ok(());
        }
        let permits = self
            .writer
            .try_reserve_many(2)
            .map_err(|_| anyhow::anyhow!("Gateway readiness queue is full or closed"))?;
        let messages = [
            json!({"type":"settings","action":"ready"}),
            json!({"type":"stream","action":"page","is_visible":true}),
        ];
        for (permit, message) in permits.zip(messages) {
            permit.send(GatewayWrite::Message(message));
        }
        self.ready_announced = true;
        Ok(())
    }
    pub async fn send(&self, body: Value) -> Result<()> {
        self.writer
            .try_send(GatewayWrite::Message(body))
            .map_err(|_| anyhow::anyhow!("Gateway command queue is full or closed"))
    }
    pub async fn input(&self, message: crate::input::OutboundInput) -> Result<()> {
        tokio::time::timeout(Duration::from_millis(100), async {
            self.send(message.websocket).await?;
            if self.peer.dc.ready_state().await? == RTCDataChannelState::Open
                && let Some(body) = message.datachannel
            {
                self.peer
                    .dc
                    .try_send_text(&body.to_string())
                    .await
                    .map_err(|_| anyhow::anyhow!("Gateway datachannel input failed"))?;
            }
            Ok::<(), anyhow::Error>(())
        })
        .await
        .map_err(|_| anyhow::anyhow!("Input transport acceptance timed out"))?
    }
    pub async fn handle_status(
        &self,
        message: &Value,
        requested: &RequestedVideo,
        bitrate: u32,
    ) -> Result<()> {
        if message["type"] == "stream" && message["action"] == "getstatus" {
            self.send(status(requested, bitrate)).await?;
        }
        Ok(())
    }
    pub async fn close(&mut self, terminate: bool) {
        if terminate {
            let _ = self
                .send(json!({"type":"settings","action":"terminating"}))
                .await;
        }
        let (done, flushed) = oneshot::channel();
        if self.writer.try_send(GatewayWrite::Flush(done)).is_ok() {
            let _ = tokio::time::timeout(Duration::from_millis(100), flushed).await;
        }
        if terminate
            && let Ok(url) = endpoint(&self.api, "api/hangup", &self.session, Some(&self.peer_id))
        {
            let _ =
                tokio::time::timeout(Duration::from_millis(500), self.http.get(url).send()).await;
        }
        self.cancel.cancel();
        self.peer.close().await;
        for task in self.tasks.drain(..) {
            task.abort();
        }
    }
}
impl Drop for Gateway {
    fn drop(&mut self) {
        self.cancel.cancel();
        for task in &self.tasks {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn local_gateway() -> Result<(Gateway, mpsc::Receiver<GatewayWrite>)> {
        let peer = NativePeer::new(vec![], true, 65536).await?;
        let (writer, writes) = mpsc::channel(2);
        let (_, controls) = mpsc::channel(1);
        Ok((
            Gateway {
                peer,
                audio: None,
                controls,
                writer,
                tasks: vec![],
                cancel: CancellationToken::new(),
                http: reqwest::Client::new(),
                api: url::Url::parse("https://gateway.invalid/webrtc/")?,
                session: "offline-session".into(),
                peer_id: "offline-peer".into(),
                ready_announced: false,
            },
            writes,
        ))
    }

    fn take_message(writes: &mut mpsc::Receiver<GatewayWrite>) -> Value {
        match writes.try_recv().expect("Expected queued gateway message") {
            GatewayWrite::Message(message) => message,
            GatewayWrite::Flush(_) => panic!("Unexpected flush"),
        }
    }

    #[tokio::test]
    async fn readiness_is_silent_before_connected_and_announced_exactly_once() -> Result<()> {
        let (mut gateway, mut writes) = local_gateway().await?;
        gateway.announce_ready()?;
        gateway.announce_ready()?;
        assert!(writes.try_recv().is_err());
        gateway.peer.connected.store(true, Ordering::Release);
        gateway.announce_ready()?;
        gateway.announce_ready()?;
        assert_eq!(
            take_message(&mut writes),
            json!({"type":"settings","action":"ready"})
        );
        assert_eq!(
            take_message(&mut writes),
            json!({"type":"stream","action":"page","is_visible":true})
        );
        assert!(writes.try_recv().is_err());
        gateway.peer.connected.store(false, Ordering::Release);
        gateway.announce_ready()?;
        gateway.peer.connected.store(true, Ordering::Release);
        gateway.announce_ready()?;
        assert!(writes.try_recv().is_err());
        gateway.peer.close().await;
        Ok(())
    }

    #[tokio::test]
    async fn readiness_backpressure_never_enqueues_half_an_announcement() -> Result<()> {
        let (mut gateway, mut writes) = local_gateway().await?;
        gateway.send(json!({"type":"offline-test"})).await?;
        gateway.peer.connected.store(true, Ordering::Release);
        assert!(gateway.announce_ready().is_err());
        assert!(!gateway.ready_announced);
        assert_eq!(take_message(&mut writes), json!({"type":"offline-test"}));
        assert!(writes.try_recv().is_err());
        gateway.announce_ready()?;
        assert_eq!(take_message(&mut writes)["action"], "ready");
        assert_eq!(take_message(&mut writes)["action"], "page");
        assert!(writes.try_recv().is_err());
        gateway.peer.close().await;
        Ok(())
    }
}
