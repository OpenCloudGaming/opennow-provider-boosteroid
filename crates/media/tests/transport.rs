use anyhow::Result;
use boosteroid_media::{
    input::{InputState, capabilities},
    media::{AudioAssembler, VideoAssembler, inspect_sps, media_queue, opus_samples},
    transport::{NativePeer, codec_engine},
};
use bytes::Bytes;
use opennow_media_protocol::wire::{InputEvent, MediaHeader};
use opennow_plugin_api::media::*;
use rtc::{
    media_stream::MediaStreamTrack,
    rtp::{Packet, codec::h264::H264Payloader, header::Header, packetizer::Payloader},
    rtp_transceiver::rtp_sender::{
        RTCRtpCodec, RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
    },
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
use webrtc::{
    data_channel::{DataChannel, DataChannelEvent},
    media_stream::track_local::{TrackLocal, static_rtp::TrackLocalStaticRTP},
    peer_connection::{
        PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler, RTCIceGatheringState,
    },
};

const VIDEO: &[u8] = include_bytes!("fixtures/blue-64x64-bt709.h264");
const OPUS: &[u8] = include_bytes!("fixtures/silence-20ms.opus-packet");

fn limits() -> MediaLimits {
    MediaLimits {
        max_video_access_unit_bytes: 65536,
        max_audio_packet_bytes: 4096,
        max_buffered_video_bytes: 131072,
        max_buffered_video_frames: 2,
        max_buffered_audio_ms: 40,
        max_control_message_bytes: 65536,
        max_pending_input_events: 32,
    }
}
fn nals() -> Vec<&'static [u8]> {
    let mut positions = Vec::new();
    let mut i = 0;
    while i + 3 <= VIDEO.len() {
        let len = if VIDEO[i..].starts_with(&[0, 0, 0, 1]) {
            4
        } else if VIDEO[i..].starts_with(&[0, 0, 1]) {
            3
        } else {
            i += 1;
            continue;
        };
        positions.push((i, i + len));
        i += len;
    }
    positions
        .iter()
        .enumerate()
        .map(|(i, (_, start))| {
            &VIDEO[*start
                ..positions
                    .get(i + 1)
                    .map(|(end, _)| *end)
                    .unwrap_or(VIDEO.len())]
        })
        .collect()
}
fn access_units() -> Vec<Vec<u8>> {
    let mut units = Vec::new();
    let mut pending = Vec::new();
    for nal in nals() {
        pending.extend_from_slice(&[0, 0, 0, 1]);
        pending.extend_from_slice(nal);
        if matches!(nal[0] & 31, 1 | 5) {
            units.push(std::mem::take(&mut pending));
        }
    }
    units
}
fn format() -> VideoFormat {
    inspect_sps(nals().into_iter().find(|n| n[0] & 31 == 7).unwrap()).unwrap()
}
fn packets(unit: &[u8], sequence: &mut u16, timestamp: u32) -> Vec<Packet> {
    let payloads = H264Payloader::default()
        .payload(80, &Bytes::copy_from_slice(unit))
        .unwrap();
    let count = payloads.len();
    payloads
        .into_iter()
        .enumerate()
        .map(|(i, payload)| {
            let seq = *sequence;
            *sequence = sequence.wrapping_add(1);
            Packet {
                header: Header {
                    version: 2,
                    marker: i + 1 == count,
                    payload_type: 102,
                    sequence_number: seq,
                    timestamp,
                    ssrc: 0x10203040,
                    ..Default::default()
                },
                payload,
            }
        })
        .collect()
}

#[test]
fn strict_sps_and_opus_validation() {
    let format = format();
    assert_eq!((format.width, format.height, format.fps), (64, 64, 60));
    assert_eq!(format.color.primaries, Primaries::Bt709);
    assert_eq!(format.color.transfer, Transfer::Bt709);
    assert_eq!(format.color.range, ColorRange::Limited);
    assert_eq!(opus_samples(OPUS).unwrap(), 960);
    for invalid in [
        &[][..],
        &[3][..],
        &[3, 0][..],
        &[3, 63][..],
        &[2, 252][..],
        &[1, 0][..],
    ] {
        assert!(opus_samples(invalid).is_err());
    }
    let mut wrong = format.clone();
    wrong.width = 128;
    assert!(
        boosteroid_media::media::validate_sps(
            nals().into_iter().find(|n| n[0] & 31 == 7).unwrap(),
            &wrong
        )
        .is_err()
    );
}

#[test]
fn h264_reorders_wraps_and_recovers_after_loss() -> Result<()> {
    let units = access_units();
    let mut sequence = 65530;
    let mut packets = packets(&units[0], &mut sequence, u32::MAX - 1000);
    assert!(packets.len() > 4);
    let mut assembler = VideoAssembler::new(format(), &limits())?;
    let mut output = Vec::new();
    let now = Instant::now();
    output.extend(assembler.push(packets.remove(0), now, 0)?);
    packets.swap(0, 1);
    for packet in packets {
        output.extend(assembler.push(packet, now, 0)?);
    }
    assert_eq!(output.len(), 1);
    assert!(output[0].keyframe);
    assert!(!output[0].contiguous);
    assert_eq!(output[0].source.ssrc, Some(0x10203040));
    assert_eq!(output[0].source.sender_frame_id, None);
    for packet in self::packets(&units[1], &mut sequence, 499) {
        output.extend(assembler.push(packet, now, 0)?);
    }
    assert_eq!(output.len(), 2);
    assert_eq!(output[1].source.timestamp, u64::from(u32::MAX) + 500);
    assert!(output[1].contiguous);
    let broken = self::packets(&units[0], &mut sequence, 1499);
    for (index, packet) in broken.into_iter().enumerate() {
        if index != 2 {
            assert!(assembler.push(packet, now, 0)?.is_empty());
        }
    }
    assembler.expire(now + Duration::from_millis(50));
    assert!(assembler.take_keyframe_request());
    for packet in self::packets(&units[2], &mut sequence, 2499) {
        assert!(
            assembler
                .push(packet, now + Duration::from_millis(51), 0)?
                .is_empty()
        );
    }
    let mut recovered = Vec::new();
    for packet in self::packets(&units[3], &mut sequence, 3499) {
        recovered.extend(assembler.push(packet, now + Duration::from_millis(52), 0)?);
    }
    assert_eq!(recovered.len(), 1);
    assert!(recovered[0].keyframe);
    assert!(!recovered[0].contiguous);
    Ok(())
}

#[test]
fn small_nals_and_malformed_aggregates_are_distinguished() -> Result<()> {
    let mut assembler = VideoAssembler::new(format(), &limits())?;
    let packet = |payload: Bytes, seq| Packet {
        header: Header {
            version: 2,
            payload_type: 102,
            ssrc: 9,
            sequence_number: seq,
            marker: true,
            ..Default::default()
        },
        payload,
    };
    assert!(
        assembler
            .push(packet(Bytes::from_static(&[9, 0xf0]), 0), Instant::now(), 0)?
            .is_empty()
    );
    assert!(
        assembler
            .push(packet(Bytes::from_static(&[10]), 1), Instant::now(), 0)?
            .is_empty()
    );
    assert!(
        assembler
            .push(
                packet(Bytes::from_static(&[24, 0, 1, 9, 0]), 2),
                Instant::now(),
                0
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn input_preserves_source_envelopes_and_neutralizes() -> Result<()> {
    let mut input = InputState::new(capabilities())?;
    let key = input
        .apply(
            InputEvent::Key {
                virtual_key: 0xa2,
                modifiers: 2,
                pressed: true,
            },
            1000,
        )?
        .remove(0);
    assert_eq!(
        key.websocket,
        serde_json::json!({"type":"keyboard","action":"button","code":162,"isPressed":true,"id_cmd":0,"from_udp":false})
    );
    assert_eq!(key.datachannel.unwrap()["from_udp"], true);
    let button = input
        .apply(
            InputEvent::MouseButton {
                button: 3,
                pressed: true,
            },
            1000,
        )?
        .remove(0);
    assert_eq!(button.websocket["btn"], 2);
    input.apply(
        InputEvent::Text {
            paste_id: 4,
            offset: 0,
            final_chunk: false,
            utf8: "secret test text".into(),
        },
        1000,
    )?;
    let released = input.neutral(1000)?;
    assert_eq!(released.len(), 2);
    assert!(released.iter().all(|m| m.websocket["isPressed"] == false));
    assert!(
        input
            .apply(
                InputEvent::Text {
                    paste_id: 4,
                    offset: 16,
                    final_chunk: true,
                    utf8: "x".into()
                },
                1000
            )
            .is_err()
    );
    let pad = || InputEvent::Gamepad {
        controller: 0,
        bitmap: 0x101,
        buttons: 0x1000 | 1 | 8,
        left_trigger: 255,
        right_trigger: 0,
        left_x: -32768,
        left_y: 32767,
        right_x: 0,
        right_y: -32768,
        incarnation: 7,
    };
    let connected = input.apply(pad(), 1000)?.remove(0);
    let name = connected.websocket["name"].as_str().unwrap();
    let state = input.controller_connected(name, 42, 1000)?;
    assert!(
        state
            .iter()
            .any(|m| m.websocket["action"] == "pad" && m.websocket["hat"] == 3)
    );
    assert!(
        state
            .iter()
            .any(|m| m.websocket["axes"] == 2 && m.websocket["value"] == 32767)
    );
    assert!(
        state
            .iter()
            .any(|m| m.websocket["axes"] == 1 && m.websocket["value"] == -32767)
    );
    assert_eq!(input.rumble_target(42), Some((0, 7)));
    let neutral = input.neutral(1000)?;
    assert!(
        neutral
            .iter()
            .any(|m| m.websocket["button"] == 0 && m.websocket["value"] == 0)
    );
    input.apply(
        InputEvent::Gamepad {
            controller: 0,
            bitmap: 0,
            buttons: 0,
            left_trigger: 0,
            right_trigger: 0,
            left_x: 0,
            left_y: 0,
            right_x: 0,
            right_y: 0,
            incarnation: 7,
        },
        1000,
    )?;
    assert_eq!(input.rumble_target(42), None);
    Ok(())
}

#[test]
fn pointer_clipboard_and_rtt_encodings_are_exact() -> Result<()> {
    let mut input = InputState::new(capabilities())?;
    let relative = input
        .apply(InputEvent::MouseRelative { x: -3, y: 2 }, 777)?
        .remove(0)
        .websocket;
    assert_eq!(relative["offsetX"], -3);
    assert_eq!(relative["offsetY"], 2);
    assert_eq!(relative["isVisible"], false);
    let absolute = input
        .apply(
            InputEvent::MouseAbsolute {
                x: 50,
                y: 50,
                width: 100,
                height: 200,
            },
            777,
        )?
        .remove(0)
        .websocket;
    assert_eq!(absolute["X"], 0.5);
    assert_eq!(absolute["Y"], 0.25);
    assert_eq!(absolute["isVisible"], true);
    let wheel = input
        .apply(InputEvent::MouseWheel { x: 0, y: 120 }, 777)?
        .remove(0)
        .websocket;
    assert_eq!(wheel["deltaY"], -1);
    assert!(
        input
            .apply(InputEvent::MouseWheel { x: 1, y: 0 }, 777)
            .is_err()
    );
    input.apply(
        InputEvent::Text {
            paste_id: 1,
            offset: 0,
            final_chunk: false,
            utf8: "😀".into(),
        },
        777,
    )?;
    let text = input
        .apply(
            InputEvent::Text {
                paste_id: 1,
                offset: 4,
                final_chunk: true,
                utf8: "é".into(),
            },
            777,
        )?
        .remove(0);
    assert_eq!(
        text.websocket,
        serde_json::json!({"type":"clipboard","action":"paste","value":"😀é"})
    );
    assert!(text.datachannel.is_none());
    let mut input = InputState::new(capabilities())?;
    for i in 0..30 {
        let event = input
            .apply(InputEvent::MouseRelative { x: 1, y: 0 }, 777)?
            .remove(0);
        assert_eq!(event.websocket["id_cmd"], i);
        assert_eq!(event.websocket.get("time").is_some(), i == 29);
        if i == 29 {
            assert_eq!(event.websocket["time"], 777);
        }
        assert_eq!(event.datachannel.as_ref().unwrap()["id_cmd"], i);
    }
    Ok(())
}

#[test]
fn all_gamepad_masks_and_new_incarnations_are_mapped() -> Result<()> {
    let pad = |buttons, incarnation| InputEvent::Gamepad {
        controller: 0,
        bitmap: 0x101,
        buttons,
        left_trigger: 0,
        right_trigger: 255,
        left_x: 0,
        left_y: 0,
        right_x: 0,
        right_y: 0,
        incarnation,
    };
    let mut input = InputState::new(capabilities())?;
    let connected = input.apply(pad(0, 1), 0)?.remove(0);
    let name = connected.websocket["name"].as_str().unwrap();
    input.controller_connected(name, 10, 0)?;
    for (mask, button) in [
        (0x1000, 0),
        (0x2000, 1),
        (0x4000, 2),
        (0x8000, 3),
        (0x100, 4),
        (0x200, 5),
        (0x20, 6),
        (0x10, 7),
        (0x40, 8),
        (0x80, 9),
    ] {
        let events = input.apply(pad(mask, 1), 0)?;
        assert!(events.iter().any(|e| e.websocket["action"] == "button"
            && e.websocket["button"] == button
            && e.websocket["value"] == 1));
    }
    for (mask, hat) in [
        (1, 1),
        (8, 2),
        (2, 4),
        (4, 8),
        (1 | 8, 3),
        (2 | 8, 6),
        (1 | 4, 9),
        (2 | 4, 12),
        (1 | 2, 0),
    ] {
        let events = input.apply(pad(mask, 1), 0)?;
        assert!(
            events
                .iter()
                .any(|e| e.websocket["action"] == "pad" && e.websocket["hat"] == hat)
        );
    }
    let events = input.apply(pad(0, 2), 0)?;
    assert!(
        events
            .iter()
            .any(|e| e.websocket["action"] == "disconnected" && e.websocket["id"] == 10)
    );
    assert_eq!(input.rumble_target(10), None);
    Ok(())
}

struct SenderHandler {
    gather: mpsc::Sender<()>,
    input: mpsc::Sender<Vec<u8>>,
}
#[async_trait::async_trait]
impl PeerConnectionEventHandler for SenderHandler {
    async fn on_ice_gathering_state_change(&self, state: RTCIceGatheringState) {
        if state == RTCIceGatheringState::Complete {
            let _ = self.gather.try_send(());
        }
    }
    async fn on_data_channel(&self, dc: Arc<dyn DataChannel>) {
        let input = self.input.clone();
        tokio::spawn(async move {
            while let Some(event) = dc.poll().await {
                if let DataChannelEvent::OnMessage(message) = event {
                    let _ = input.try_send(message.data.to_vec());
                }
            }
        });
    }
}
fn track(mime: &str, kind: RtpCodecKind, ssrc: u32) -> Arc<TrackLocalStaticRTP> {
    let codec = RTCRtpCodec {
        mime_type: mime.into(),
        clock_rate: if kind == RtpCodecKind::Video {
            90000
        } else {
            48000
        },
        channels: if kind == RtpCodecKind::Video { 0 } else { 2 },
        sdp_fmtp_line: if kind == RtpCodecKind::Video {
            "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f"
        } else {
            "minptime=10;useinbandfec=1;stereo=1;maxaveragebitrate=128000"
        }
        .into(),
        rtcp_feedback: vec![],
    };
    Arc::new(TrackLocalStaticRTP::new(MediaStreamTrack::new(
        "fixture".into(),
        mime.into(),
        mime.into(),
        kind,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(ssrc),
                ..Default::default()
            },
            codec,
            ..Default::default()
        }],
    )))
}

#[tokio::test]
async fn real_loopback_srtp_h264_opus_and_sctp_input() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut receiver = NativePeer::new(vec![], true, 131072).await?;
        let (gather, mut gathered) = mpsc::channel(1);
        let (input, mut inputs) = mpsc::channel(2);
        let (engine, registry) = codec_engine()?;
        let sender = PeerConnectionBuilder::new()
            .with_media_engine(engine)
            .with_interceptor_registry(registry)
            .with_udp_addrs(vec!["127.0.0.1:0"])
            .with_handler(Arc::new(SenderHandler { gather, input }))
            .build()
            .await?;
        let video_track = track("video/H264", RtpCodecKind::Video, 0x10203040);
        let audio_track = track("audio/opus", RtpCodecKind::Audio, 0x50607080);
        sender.add_track(video_track.clone()).await?;
        sender.add_track(audio_track.clone()).await?;
        let offer = receiver.pc.create_offer(None).await?;
        assert!(!offer.sdp.contains("urn:ietf:params:rtp-hdrext:sdes:mid"));
        assert!(offer.sdp.contains("transport-wide-cc"));
        receiver.pc.set_local_description(offer).await?;
        receiver.gathered.recv().await.unwrap();
        sender
            .set_remote_description(receiver.pc.local_description().await.unwrap())
            .await?;
        let answer = sender.create_answer(None).await?;
        sender.set_local_description(answer).await?;
        gathered.recv().await.unwrap();
        receiver
            .pc
            .set_remote_description(sender.local_description().await.unwrap())
            .await?;
        while receiver.dc.ready_state().await? != webrtc::data_channel::RTCDataChannelState::Open {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let mut input = InputState::new(capabilities())?;
        let message = input
            .apply(
                InputEvent::Key {
                    virtual_key: 65,
                    modifiers: 0,
                    pressed: true,
                },
                1000,
            )?
            .remove(0)
            .datachannel
            .unwrap();
        receiver.dc.send_text(&message.to_string()).await?;
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&inputs.recv().await.unwrap())?,
            message
        );
        let units = access_units();
        let mut seq = 65530;
        for packet in packets(&units[0], &mut seq, 90000) {
            video_track.write_rtp(packet).await?;
        }
        audio_track
            .write_rtp(Packet {
                header: Header {
                    version: 2,
                    payload_type: 111,
                    sequence_number: 1,
                    timestamp: 48000,
                    ssrc: 0x50607080,
                    marker: true,
                    ..Default::default()
                },
                payload: Bytes::from_static(OPUS),
            })
            .await?;
        let mut video = VideoAssembler::new(format(), &limits())?;
        let mut audio = AudioAssembler::default();
        let mut video_unit = None;
        let mut audio_unit = None;
        while video_unit.is_none() || audio_unit.is_none() {
            let event = receiver.packets.recv().await.unwrap();
            if event.codec.mime_type.eq_ignore_ascii_case("video/h264") {
                for unit in video.push(event.packet, Instant::now(), 0)? {
                    video_unit = Some(unit);
                }
            } else {
                audio_unit = audio.push(event.packet, 4096)?;
            }
        }
        let video = video_unit.unwrap();
        assert_eq!(video.source.timestamp, 90000);
        assert_eq!(video.source.ssrc, Some(0x10203040));
        assert!(video.keyframe);
        assert!(
            video
                .bytes
                .ends_with(nals().into_iter().find(|nal| nal[0] & 31 == 5).unwrap())
        );
        assert!(video.bytes.windows(4).any(|w| w == [0, 0, 0, 1]));
        let header =
            MediaHeader::decode(&video.header(u64::from(u32::MAX) + 42).encode(), &limits())
                .unwrap();
        assert_eq!(header.attempt_generation, u64::from(u32::MAX) + 42);
        assert_eq!(header.source.sender_frame_id, None);
        let audio = audio_unit.unwrap();
        assert_eq!(audio.bytes.as_ref(), OPUS);
        assert_eq!(audio.audio_samples, Some(960));
        assert_eq!(audio.source.ssrc, Some(0x50607080));
        receiver.request_keyframe().await?;
        receiver.close().await;
        sender.close().await?;
        Ok::<(), anyhow::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn media_backpressure_is_bounded_and_cancellation_is_prompt() -> Result<()> {
    let (video, audio, frames) = media_queue(&limits());
    let unit = || boosteroid_media::media::EncodedUnit {
        bytes: Bytes::from_static(&[1, 2, 3]),
        source: opennow_media_protocol::SourceStamp {
            sender_frame_id: None,
            timestamp: 0,
            clock_rate_hz: 90000,
            ssrc: Some(1),
        },
        keyframe: true,
        contiguous: false,
        audio_samples: None,
    };
    assert!(video.try_send(unit()));
    assert!(video.try_send(unit()));
    assert!(!video.try_send(unit()));
    let audio_unit = || boosteroid_media::media::EncodedUnit {
        audio_samples: Some(960),
        ..unit()
    };
    assert!(audio.try_send(audio_unit()));
    assert!(audio.try_send(audio_unit()));
    assert!(!audio.try_send(audio_unit()));
    let (mut pipe, _blocked_reader) = tokio::io::duplex(1);
    let cancel = tokio_util::sync::CancellationToken::new();
    let stop = cancel.clone();
    let writer = tokio::spawn(async move {
        boosteroid_media::worker::write_media(&mut pipe, frames, 1, stop).await
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    cancel.cancel();
    tokio::time::timeout(Duration::from_millis(100), writer).await???;
    assert_eq!(video.used_bytes(), 0);
    Ok(())
}

#[test]
fn gateway_schemas_reject_unknown_and_keep_source_forms() {
    use boosteroid_media::transport::{parse_answer, parse_candidates};
    assert!(parse_answer(serde_json::json!({"type":"offer","sdp":"v=0\r\n"})).is_err());
    assert!(parse_candidates(serde_json::json!({"unexpected":[]})).is_err());
    assert!(
        parse_candidates(serde_json::json!({"data":[]}))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn negotiated_audio_dtx_and_absence_need_no_audio_packets() -> Result<()> {
    use boosteroid_media::transport::{negotiated_audio, parse_answer, parse_ice_servers};
    let session = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n";
    let audio = "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=sendonly\r\na=rtpmap:111 opus/48000/2\r\na=fmtp:111 useinbandfec=1;usedtx=1;stereo=1\r\n";
    let answer = parse_answer(
        serde_json::json!({"data":{"type":"answer","sdp":format!("{session}{audio}")}}),
    )?;
    let started = Instant::now();
    assert_eq!(
        negotiated_audio(&answer)?,
        Some(AudioFormat {
            codec: AudioCodec::Opus,
            sample_rate: 48000,
            channels: 2
        })
    );
    assert!(started.elapsed() < Duration::from_millis(100));
    for sdp in [
        session.to_owned(),
        format!("{session}{}", audio.replace("m=audio 9", "m=audio 0")),
        format!("{session}{}", audio.replace("a=sendonly", "a=inactive")),
    ] {
        let answer = parse_answer(serde_json::json!({"type":"answer","sdp":sdp}))?;
        assert_eq!(negotiated_audio(&answer)?, None);
    }
    let servers = parse_ice_servers(
        serde_json::json!({"data":{"iceServers":[{"urls":"stun:stun.example.invalid:3478"}]}}),
    )?;
    assert_eq!(servers[0].urls, vec!["stun:stun.example.invalid:3478"]);
    assert!(parse_ice_servers(serde_json::json!([{"urls":"https://invalid.invalid"}])).is_err());
    Ok(())
}
