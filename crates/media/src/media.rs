use anyhow::{Result, bail, ensure};
use bytes::Bytes;
use h264_reader::nal::{
    Nal, RefNal,
    sps::{ChromaFormat, SeqParameterSet},
};
use opennow_media_protocol::{
    SourceStamp,
    wire::{AUDIO_TRACK_ID, MediaHeader, VIDEO_TRACK_ID},
};
use opennow_plugin_api::media::{
    Chroma, ChromaLocation, ColorRange, Matrix, MediaLimits, Primaries, Transfer, VideoEncoding,
    VideoFormat,
};
use rtc::rtp::Packet;
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

const REORDER_PACKETS: usize = 128;
const REORDER_TIME: Duration = Duration::from_millis(40);

pub struct EncodedUnit {
    pub bytes: Bytes,
    pub source: SourceStamp,
    pub keyframe: bool,
    pub contiguous: bool,
    pub audio_samples: Option<u32>,
}

impl EncodedUnit {
    pub fn header(&self, generation: u64) -> MediaHeader {
        MediaHeader {
            attempt_generation: generation,
            track_id: if self.audio_samples.is_some() {
                AUDIO_TRACK_ID
            } else {
                VIDEO_TRACK_ID
            },
            payload_bytes: self.bytes.len() as u32,
            source: self.source,
            keyframe: self.keyframe,
            contiguous: self.contiguous,
        }
    }
}

#[derive(Default)]
struct Clock {
    value: Option<u64>,
}
impl Clock {
    fn extend(&mut self, raw: u32) -> Result<u64> {
        let value = match self.value {
            None => u64::from(raw),
            Some(previous) => {
                let delta = raw.wrapping_sub(previous as u32) as i32;
                previous
                    .checked_add_signed(i64::from(delta))
                    .ok_or_else(|| anyhow::anyhow!("RTP timestamp overflow"))?
            }
        };
        self.value = Some(self.value.map_or(value, |previous| previous.max(value)));
        Ok(value)
    }
}

pub struct VideoAssembler {
    format: Option<VideoFormat>,
    discovered: Option<VideoFormat>,
    parameter_sets: BTreeMap<(u8, u8), Vec<u8>>,
    formats: BTreeMap<u8, VideoFormat>,
    context: h264_reader::Context,
    first_slice: bool,
    picture: Option<(u16, Option<u32>, u8)>,
    max_bytes: usize,
    max_buffered: usize,
    max_frames: usize,
    discard_until_marker: bool,
    identity: Option<(u32, u8)>,
    next: Option<u64>,
    pending: BTreeMap<u64, Packet>,
    pending_bytes: usize,
    deadline: Option<Instant>,
    timestamp: Option<u32>,
    au: Vec<u8>,
    fu: Option<u8>,
    sps: Option<Vec<u8>>,
    pps: Option<Vec<u8>>,
    idr: bool,
    vcl: bool,
    synchronized: bool,
    continuous: bool,
    clock: Clock,
    request_keyframe: bool,
}

impl VideoAssembler {
    pub fn new(format: VideoFormat, limits: &MediaLimits) -> Result<Self> {
        ensure!(
            format.encoding == VideoEncoding::H264AnnexB
                && format.bit_depth == 8
                && format.chroma == Chroma::Yuv420,
            "Unsupported video format"
        );
        Self::with_format(Some(format), limits)
    }
    pub fn for_preflight(limits: &MediaLimits) -> Result<Self> {
        Self::with_format(None, limits)
    }
    pub fn discovered_format(&self) -> Option<&VideoFormat> {
        self.discovered.as_ref()
    }
    fn with_format(format: Option<VideoFormat>, limits: &MediaLimits) -> Result<Self> {
        limits
            .validate()
            .map_err(|_| anyhow::anyhow!("Invalid media limits"))?;
        Ok(Self {
            format,
            discovered: None,
            parameter_sets: BTreeMap::new(),
            formats: BTreeMap::new(),
            context: h264_reader::Context::default(),
            first_slice: false,
            picture: None,
            max_bytes: limits.max_video_access_unit_bytes as usize,
            max_buffered: limits.max_buffered_video_bytes as usize,
            max_frames: limits.max_buffered_video_frames as usize,
            discard_until_marker: false,
            identity: None,
            next: None,
            pending: BTreeMap::new(),
            pending_bytes: 0,
            deadline: None,
            timestamp: None,
            au: Vec::new(),
            fu: None,
            sps: None,
            pps: None,
            idr: false,
            vcl: false,
            synchronized: false,
            continuous: false,
            clock: Clock::default(),
            request_keyframe: true,
        })
    }

    pub fn take_keyframe_request(&mut self) -> bool {
        std::mem::take(&mut self.request_keyframe)
    }

    pub fn discontinuity(&mut self) {
        self.pending.clear();
        self.pending_bytes = 0;
        self.next = None;
        self.deadline = None;
        self.reset_au();
        self.synchronized = false;
        self.continuous = false;
        self.request_keyframe = true;
        self.discard_until_marker = true;
    }

    fn reset_au(&mut self) {
        self.au.clear();
        self.fu = None;
        self.timestamp = None;
        self.idr = false;
        self.vcl = false;
        self.first_slice = false;
        self.picture = None;
    }

    pub fn expire(&mut self, now: Instant) {
        if self.deadline.is_some_and(|deadline| now >= deadline) {
            self.discontinuity();
        }
    }

    pub fn push(
        &mut self,
        packet: Packet,
        now: Instant,
        queued_bytes: usize,
    ) -> Result<Vec<EncodedUnit>> {
        self.expire(now);
        ensure!(
            packet.header.version == 2 && packet.payload.len() <= self.max_bytes,
            "Invalid video RTP packet"
        );
        let identity = (packet.header.ssrc, packet.header.payload_type);
        if let Some(previous) = self.identity {
            ensure!(previous == identity, "Video RTP identity changed");
        }
        self.identity = Some(identity);
        if self.discard_until_marker {
            if packet.header.marker {
                self.discard_until_marker = false;
            }
            return Ok(vec![]);
        }
        let seq = match self.next {
            None => u64::from(packet.header.sequence_number),
            Some(next) => {
                let delta = packet.header.sequence_number.wrapping_sub(next as u16) as i16;
                if delta < 0 {
                    return Ok(vec![]);
                }
                next + delta as u64
            }
        };
        if self.pending.contains_key(&seq) {
            return Ok(vec![]);
        }
        if self.pending.len() >= REORDER_PACKETS
            || seq.saturating_sub(self.next.unwrap_or(seq)) >= REORDER_PACKETS as u64
            || self.pending_bytes + self.au.len() + packet.payload.len() + queued_bytes
                > self.max_buffered
        {
            self.discontinuity();
            return Ok(vec![]);
        }
        self.next.get_or_insert(seq);
        self.deadline.get_or_insert(now + REORDER_TIME);
        self.pending_bytes += packet.payload.len();
        self.pending.insert(seq, packet);
        let mut output = Vec::new();
        let mut output_bytes = 0;
        while let Some(next) = self.next {
            let Some(packet) = self.pending.remove(&next) else {
                break;
            };
            self.pending_bytes -= packet.payload.len();
            self.next = Some(next + 1);
            if self
                .timestamp
                .is_some_and(|ts| ts != packet.header.timestamp)
            {
                self.reset_au();
                self.synchronized = false;
                self.continuous = false;
                self.request_keyframe = true;
            }
            self.timestamp = Some(packet.header.timestamp);
            self.append(&packet.payload)?;
            if self.au.len() + self.pending_bytes + queued_bytes + output_bytes > self.max_buffered
            {
                self.discontinuity();
                return Ok(output);
            }
            if packet.header.marker {
                if self.fu.is_some() {
                    self.discontinuity();
                    return Ok(vec![]);
                }
                if self.vcl
                    && self.first_slice
                    && (self.synchronized || self.idr)
                    && self.sps.is_some()
                    && self.pps.is_some()
                {
                    let stamp = self.clock.extend(packet.header.timestamp)?;
                    let mut bytes = Vec::new();
                    if self.idr {
                        for nal in [&self.sps, &self.pps].into_iter().flatten() {
                            bytes.extend_from_slice(&[0, 0, 0, 1]);
                            bytes.extend_from_slice(nal);
                        }
                    }
                    ensure!(
                        bytes.len() + self.au.len() <= self.max_bytes,
                        "Video access unit exceeds limit"
                    );
                    bytes.extend_from_slice(&self.au);
                    if bytes.len() + output_bytes + queued_bytes > self.max_buffered
                        || output.len() >= self.max_frames
                    {
                        self.discontinuity();
                        return Ok(output);
                    }
                    output_bytes += bytes.len();
                    output.push(EncodedUnit {
                        bytes: bytes.into(),
                        source: SourceStamp {
                            sender_frame_id: None,
                            timestamp: stamp,
                            clock_rate_hz: 90_000,
                            ssrc: Some(identity.0),
                        },
                        keyframe: self.idr,
                        contiguous: self.continuous,
                        audio_samples: None,
                    });
                    self.synchronized = true;
                    self.continuous = true;
                }
                self.reset_au();
                self.deadline = if self.pending.is_empty() {
                    None
                } else {
                    Some(now + REORDER_TIME)
                };
            }
        }
        Ok(output)
    }

    fn append(&mut self, payload: &[u8]) -> Result<()> {
        ensure!(
            !payload.is_empty() && payload[0] & 0x80 == 0,
            "Malformed H264 payload"
        );
        match payload[0] & 31 {
            1..=23 => {
                ensure!(self.fu.is_none(), "Missing FU end");
                self.nal(payload)?;
            }
            24 => {
                ensure!(self.fu.is_none(), "Missing FU end");
                let mut rest = &payload[1..];
                ensure!(!rest.is_empty(), "Empty STAP");
                while !rest.is_empty() {
                    ensure!(rest.len() >= 2, "Short STAP length");
                    let size = u16::from_be_bytes([rest[0], rest[1]]) as usize;
                    rest = &rest[2..];
                    ensure!(size > 0 && size <= rest.len(), "Short STAP NAL");
                    self.nal(&rest[..size])?;
                    rest = &rest[size..];
                }
            }
            28 => {
                ensure!(
                    payload.len() >= 3 && payload[1] & 0x20 == 0,
                    "Short FU payload"
                );
                let start = payload[1] & 0x80 != 0;
                let end = payload[1] & 0x40 != 0;
                let header = (payload[0] & 0xe0) | (payload[1] & 31);
                ensure!(
                    (1..=23).contains(&(header & 31)) && !(start && end),
                    "Invalid FU header"
                );
                if start {
                    ensure!(self.fu.is_none(), "Duplicate FU start");
                    ensure!(
                        self.au.len() + payload.len() + 3 <= self.max_bytes,
                        "FU size limit"
                    );
                    self.au.extend_from_slice(&[0, 0, 0, 1, header]);
                    self.fu = Some(header);
                    self.idr |= header & 31 == 5;
                    self.vcl |= matches!(header & 31, 1..=5);
                } else {
                    ensure!(self.fu == Some(header), "FU identity mismatch");
                }
                ensure!(
                    self.au.len() + payload.len() - 2 <= self.max_bytes,
                    "FU size limit"
                );
                self.au.extend_from_slice(&payload[2..]);
                if end {
                    self.fu = None;
                    if matches!(header & 31, 1 | 5 | 7 | 8) {
                        let start = self
                            .au
                            .windows(4)
                            .rposition(|w| w == [0, 0, 0, 1])
                            .ok_or_else(|| anyhow::anyhow!("Missing FU start"))?;
                        let nal = self.au[start + 4..].to_vec();
                        self.metadata(&nal)?;
                    }
                }
            }
            _ => bail!("Unsupported H264 packetization"),
        }
        Ok(())
    }

    fn metadata(&mut self, nal: &[u8]) -> Result<()> {
        match nal[0] & 31 {
            7 => {
                ensure!(nal.len() <= 4096, "SPS too large");
                let format = inspect_sps(nal)?;
                if let Some(expected) = &self.format {
                    ensure!(*expected == format, "SPS differs from accepted format");
                }
                let sps = SeqParameterSet::from_bits(RefNal::new(nal, &[], true).rbsp_bits())
                    .map_err(|_| anyhow::anyhow!("Malformed SPS"))?;
                let id = sps.seq_parameter_set_id.id();
                self.formats.insert(id, format);
                self.parameter_sets.insert((7, id), nal.to_vec());
                self.context.put_seq_param_set(sps);
            }
            8 => {
                ensure!(nal.len() <= 4096, "PPS too large");
                let pps = h264_reader::nal::pps::PicParameterSet::from_bits(
                    &self.context,
                    RefNal::new(nal, &[], true).rbsp_bits(),
                )
                .map_err(|_| anyhow::anyhow!("PPS does not reference a validated SPS"))?;
                self.parameter_sets
                    .insert((8, pps.pic_parameter_set_id.id()), nal.to_vec());
                self.context.put_pic_param_set(pps);
            }
            1 | 5 => {
                if !self.parameter_sets.keys().any(|(kind, _)| *kind == 8) {
                    return Ok(());
                }
                let nal = RefNal::new(nal, &[], true);
                let mut bits = nal.rbsp_bits();
                let (slice, sps, pps) = h264_reader::nal::slice::SliceHeader::from_bits(
                    &self.context,
                    &mut bits,
                    nal.header()
                        .map_err(|_| anyhow::anyhow!("Invalid slice NAL"))?,
                    None,
                )
                .map_err(|_| anyhow::anyhow!("Invalid slice header or parameter-set reference"))?;
                let pps_id = pps.pic_parameter_set_id.id();
                let sps_id = sps.seq_parameter_set_id.id();
                let picture = (slice.frame_num, slice.idr_pic_id, pps_id);
                ensure!(
                    self.picture.is_none_or(|old| old == picture),
                    "Conflicting pictures in one RTP timestamp"
                );
                self.picture = Some(picture);
                self.first_slice |= slice.first_mb_in_slice == 0;
                self.sps = self.parameter_sets.get(&(7, sps_id)).cloned();
                self.pps = self.parameter_sets.get(&(8, pps_id)).cloned();
                self.discovered = self.formats.get(&sps_id).cloned();
            }
            _ => {}
        }
        ensure!(
            self.parameter_sets.len() <= 64,
            "H264 parameter set count exceeds bound"
        );
        Ok(())
    }

    fn nal(&mut self, nal: &[u8]) -> Result<()> {
        ensure!(
            !nal.is_empty() && nal[0] & 0x80 == 0 && (1..=23).contains(&(nal[0] & 31)),
            "Invalid H264 NAL"
        );
        ensure!(
            self.au.len() + nal.len() + 4 <= self.max_bytes,
            "NAL size limit"
        );
        self.metadata(nal)?;
        self.idr |= nal[0] & 31 == 5;
        self.vcl |= matches!(nal[0] & 31, 1..=5);
        self.au.extend_from_slice(&[0, 0, 0, 1]);
        self.au.extend_from_slice(nal);
        Ok(())
    }
}

pub fn validate_sps(nal: &[u8], expected: &VideoFormat) -> Result<()> {
    ensure!(
        inspect_sps(nal)? == *expected,
        "SPS differs from accepted format"
    );
    Ok(())
}

pub fn inspect_sps(nal: &[u8]) -> Result<VideoFormat> {
    ensure!(
        !nal.is_empty() && nal.len() <= 4096 && nal[0] & 31 == 7,
        "Invalid SPS"
    );
    let sps = SeqParameterSet::from_bits(RefNal::new(nal, &[], true).rbsp_bits())
        .map_err(|_| anyhow::anyhow!("Malformed SPS"))?;
    let dimensions = sps
        .pixel_dimensions()
        .map_err(|_| anyhow::anyhow!("Invalid SPS dimensions"))?;
    ensure!(
        matches!(
            sps.frame_mbs_flags,
            h264_reader::nal::sps::FrameMbsFlags::Frames
        ),
        "Interlaced H264 is not supported"
    );
    ensure!(
        sps.chroma_info.chroma_format == ChromaFormat::YUV420
            && sps.chroma_info.bit_depth_luma_minus8 == 0
            && sps.chroma_info.bit_depth_chroma_minus8 == 0,
        "SPS format differs from accepted media"
    );
    let vui = sps
        .vui_parameters
        .ok_or_else(|| anyhow::anyhow!("SPS does not establish color metadata"))?;
    let signal = vui
        .video_signal_type
        .ok_or_else(|| anyhow::anyhow!("SPS does not establish color range"))?;
    let color = signal
        .colour_description
        .ok_or_else(|| anyhow::anyhow!("SPS does not establish color description"))?;
    let primaries = match color.colour_primaries {
        1 => Primaries::Bt709,
        9 => Primaries::Bt2020,
        _ => bail!("Unsupported color primaries"),
    };
    let transfer = match color.transfer_characteristics {
        1 => Transfer::Bt709,
        13 => Transfer::Srgb,
        _ => bail!("Unsupported SDR transfer"),
    };
    let matrix = match color.matrix_coefficients {
        1 => Matrix::Bt709,
        5 | 6 => Matrix::Bt601,
        9 => Matrix::Bt2020NonConstant,
        _ => bail!("Unsupported matrix"),
    };
    let range = if signal.video_full_range_flag {
        ColorRange::Full
    } else {
        ColorRange::Limited
    };
    let chroma_location = match vui.chroma_loc_info {
        None => ChromaLocation::Left,
        Some(loc)
            if loc.chroma_sample_loc_type_top_field == 0
                && loc.chroma_sample_loc_type_bottom_field == 0 =>
        {
            ChromaLocation::Left
        }
        Some(loc)
            if loc.chroma_sample_loc_type_top_field == 1
                && loc.chroma_sample_loc_type_bottom_field == 1 =>
        {
            ChromaLocation::Center
        }
        _ => bail!("Unsupported chroma location"),
    };
    let timing = vui
        .timing_info
        .ok_or_else(|| anyhow::anyhow!("SPS does not establish frame rate"))?;
    ensure!(
        timing.fixed_frame_rate_flag,
        "SPS does not establish a fixed frame rate"
    );
    let divisor = u64::from(timing.num_units_in_tick) * 2;
    ensure!(
        divisor > 0 && u64::from(timing.time_scale).is_multiple_of(divisor),
        "SPS frame rate is not an exact supported integer"
    );
    let fps = u32::try_from(u64::from(timing.time_scale) / divisor)?;
    let format = VideoFormat {
        encoding: VideoEncoding::H264AnnexB,
        width: dimensions.0,
        height: dimensions.1,
        fps,
        bit_depth: 8,
        chroma: Chroma::Yuv420,
        color: opennow_plugin_api::media::ColorDescription {
            range,
            primaries,
            transfer,
            matrix,
            chroma_location,
        },
    };
    format
        .validate()
        .map_err(|_| anyhow::anyhow!("Unsupported SPS format"))?;
    Ok(format)
}

pub fn opus_samples(packet: &[u8]) -> Result<u32> {
    ensure!(!packet.is_empty(), "Empty Opus packet");
    let toc = packet[0];
    let frame_samples = if toc & 0x80 != 0 {
        120 << ((toc >> 3) & 3)
    } else if toc & 0x60 == 0x60 {
        if toc & 8 != 0 { 960 } else { 480 }
    } else {
        match (toc >> 3) & 3 {
            3 => 2880,
            shift => 480 << shift,
        }
    };
    let mut offset = 1;
    let read_size = |offset: &mut usize| -> Result<usize> {
        ensure!(*offset < packet.len(), "Short Opus length");
        let first = packet[*offset] as usize;
        *offset += 1;
        if first < 252 {
            Ok(first)
        } else {
            ensure!(*offset < packet.len(), "Short Opus length");
            let result = first + 4 * packet[*offset] as usize;
            *offset += 1;
            Ok(result)
        }
    };
    let count = match toc & 3 {
        0 => {
            ensure!(packet.len() - 1 <= 1275, "Oversized Opus frame");
            1
        }
        1 => {
            ensure!(
                (packet.len() - 1).is_multiple_of(2) && (packet.len() - 1) / 2 <= 1275,
                "Invalid Opus CBR"
            );
            2
        }
        2 => {
            let first = read_size(&mut offset)?;
            ensure!(
                first <= 1275
                    && first <= packet.len() - offset
                    && packet.len() - offset - first <= 1275,
                "Invalid Opus VBR"
            );
            2
        }
        _ => {
            ensure!(offset < packet.len(), "Short Opus frame count");
            let flags = packet[offset];
            offset += 1;
            let count = usize::from(flags & 63);
            ensure!((1..=48).contains(&count), "Invalid Opus frame count");
            let mut padding = 0usize;
            if flags & 64 != 0 {
                loop {
                    ensure!(offset < packet.len(), "Short Opus padding");
                    let byte = packet[offset];
                    offset += 1;
                    padding += if byte == 255 { 254 } else { byte as usize };
                    ensure!(padding <= packet.len() - offset, "Invalid Opus padding");
                    if byte != 255 {
                        break;
                    }
                }
            }
            let end = packet.len() - padding;
            if flags & 128 == 0 {
                ensure!(
                    (end - offset).is_multiple_of(count) && (end - offset) / count <= 1275,
                    "Invalid Opus CBR"
                );
            } else {
                let mut total = 0usize;
                for _ in 1..count {
                    let length = read_size(&mut offset)?;
                    ensure!(length <= 1275, "Oversized Opus frame");
                    total += length;
                }
                ensure!(
                    offset <= end && total <= end - offset && end - offset - total <= 1275,
                    "Invalid Opus VBR"
                );
            }
            count as u32
        }
    };
    ensure!(
        count * frame_samples <= 5760,
        "Opus duration exceeds 120 ms"
    );
    Ok(count * frame_samples)
}

#[derive(Default)]
pub struct AudioAssembler {
    identity: Option<(u32, u8)>,
    sequence: Option<u16>,
    clock: Clock,
}
impl AudioAssembler {
    pub fn push(&mut self, packet: Packet, max_bytes: usize) -> Result<Option<EncodedUnit>> {
        ensure!(
            packet.header.version == 2 && packet.payload.len() <= max_bytes,
            "Invalid audio RTP packet"
        );
        let id = (packet.header.ssrc, packet.header.payload_type);
        if let Some(old) = self.identity {
            ensure!(old == id, "Audio RTP identity changed");
        }
        self.identity = Some(id);
        let contiguous = self
            .sequence
            .is_some_and(|s| packet.header.sequence_number == s.wrapping_add(1));
        if self
            .sequence
            .is_some_and(|s| packet.header.sequence_number.wrapping_sub(s) as i16 <= 0)
        {
            return Ok(None);
        }
        let samples = opus_samples(&packet.payload)?;
        let timestamp = self.clock.extend(packet.header.timestamp)?;
        self.sequence = Some(packet.header.sequence_number);
        Ok(Some(EncodedUnit {
            bytes: packet.payload,
            source: SourceStamp {
                sender_frame_id: None,
                timestamp,
                clock_rate_hz: 48000,
                ssrc: Some(id.0),
            },
            keyframe: false,
            contiguous,
            audio_samples: Some(samples),
        }))
    }
}

pub struct QueuedUnit {
    pub unit: EncodedUnit,
    _bytes: OwnedSemaphorePermit,
    _slots: OwnedSemaphorePermit,
}
#[derive(Clone)]
pub struct UnitSender {
    sender: mpsc::Sender<QueuedUnit>,
    bytes: Arc<Semaphore>,
    slots: Arc<Semaphore>,
    maximum: usize,
}
impl UnitSender {
    pub fn used_bytes(&self) -> usize {
        self.maximum - self.bytes.available_permits()
    }
    pub fn try_send(&self, unit: EncodedUnit) -> bool {
        let size = unit.bytes.len();
        let slots = unit.audio_samples.unwrap_or(1);
        let Ok(bytes) = self.bytes.clone().try_acquire_many_owned(size as u32) else {
            return false;
        };
        let Ok(slots) = self.slots.clone().try_acquire_many_owned(slots) else {
            return false;
        };
        self.sender
            .try_send(QueuedUnit {
                unit,
                _bytes: bytes,
                _slots: slots,
            })
            .is_ok()
    }
}
pub fn media_queue(limits: &MediaLimits) -> (UnitSender, UnitSender, mpsc::Receiver<QueuedUnit>) {
    let (sender, receiver) = mpsc::channel(64);
    let video = UnitSender {
        sender: sender.clone(),
        bytes: Arc::new(Semaphore::new(limits.max_buffered_video_bytes as usize)),
        slots: Arc::new(Semaphore::new(limits.max_buffered_video_frames as usize)),
        maximum: limits.max_buffered_video_bytes as usize,
    };
    let audio_bytes = limits.max_audio_packet_bytes as usize * 40;
    let audio = UnitSender {
        sender,
        bytes: Arc::new(Semaphore::new(audio_bytes)),
        slots: Arc::new(Semaphore::new(limits.max_buffered_audio_ms as usize * 48)),
        maximum: audio_bytes,
    };
    (video, audio, receiver)
}
