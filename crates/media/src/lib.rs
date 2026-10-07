pub mod input;
pub mod media;
pub mod transport;
pub mod worker;

use anyhow::Result;
use boosteroid_common::GatewayConnection;
use opennow_plugin_api::{
    media::{AudioFormat, InputCapabilities, MediaLimits, VideoFormat},
    provider::StreamPreferences,
};
use tokio_util::sync::CancellationToken;

pub struct PreflightMedia {
    pub video: VideoFormat,
    pub audio: Option<AudioFormat>,
    pub input: InputCapabilities,
}

pub async fn preflight(
    connection: &GatewayConnection,
    preferences: &StreamPreferences,
    cancel: CancellationToken,
) -> Result<PreflightMedia> {
    input::validate_requested(&preferences.video)?;
    let mut connection = connection.clone();
    connection.peer_id = uuid::Uuid::new_v4().to_string();
    connection.bitrate_kbps = preferences.bitrate_kbps;
    let mut gateway = transport::Gateway::connect(&connection, &preferences.video, cancel.clone())
        .await
        .map_err(|_| anyhow::anyhow!("Native gateway negotiation failed"))?;
    let limits = MediaLimits {
        max_video_access_unit_bytes: 4 * 1024 * 1024,
        max_audio_packet_bytes: 8192,
        max_buffered_video_bytes: 8 * 1024 * 1024,
        max_buffered_video_frames: 2,
        max_buffered_audio_ms: 100,
        max_control_message_bytes: 65536,
        max_pending_input_events: 128,
    };
    let mut video = media::VideoAssembler::for_preflight(&limits)?;
    gateway.start_ice();
    let audio = gateway.audio.clone();
    let result = async {
        let mut timer = tokio::time::interval(std::time::Duration::from_millis(500));
        loop {
            tokio::select! {
                _=cancel.cancelled()=>anyhow::bail!("Media preflight cancelled"),
                _=timer.tick()=>{anyhow::ensure!(gateway.healthy(),"Preflight transport failed");gateway.announce_ready()?;gateway.peer.request_keyframe().await?;},
                message=gateway.controls.recv()=>{let message=message.ok_or_else(||anyhow::anyhow!("Preflight gateway control closed"))?;gateway.handle_status(&message,&preferences.video,connection.bitrate_kbps).await?;},
                event=gateway.peer.packets.recv()=>{
                    let event=event.ok_or_else(||anyhow::anyhow!("Preflight media transport closed"))?;
                    if event.codec.mime_type.eq_ignore_ascii_case("video/h264") {
                        anyhow::ensure!(event.codec.clock_rate==90000,"Unsupported video clock");
                        video.push(event.packet,std::time::Instant::now(),0)?;
                    } else if event.codec.mime_type.eq_ignore_ascii_case("audio/opus") {
                        anyhow::ensure!(event.codec.clock_rate==48000 && matches!(event.codec.channels,1|2),"Unsupported negotiated audio");
                        media::opus_samples(&event.packet.payload)?;
                        anyhow::ensure!(audio.as_ref().is_some_and(|audio|audio.sample_rate==event.codec.clock_rate && u16::from(audio.channels)==event.codec.channels),"Received audio differs from negotiated audio");
                    } else {anyhow::bail!("Unsupported preflight media codec")}
                    if let Some(video)=video.discovered_format() {return Ok(PreflightMedia {video:video.clone(),audio:audio.clone(),input:input::capabilities()});}
                }
            }
        }
    };
    let result = tokio::time::timeout(std::time::Duration::from_secs(20), result)
        .await
        .map_err(|_| anyhow::anyhow!("Preflight did not establish video and audio metadata"));
    gateway.close(false).await;
    result?
}
