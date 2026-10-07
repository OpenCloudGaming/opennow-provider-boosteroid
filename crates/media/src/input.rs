use anyhow::{Result, bail, ensure};
use opennow_media_protocol::wire::InputEvent;
use opennow_plugin_api::media::InputCapabilities;
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub fn capabilities() -> InputCapabilities {
    InputCapabilities {
        keyboard: true,
        relative_mouse: true,
        absolute_mouse: true,
        text: true,
        gamepad_slots: 4,
        rumble: true,
    }
}

pub struct OutboundInput {
    pub websocket: Value,
    pub datachannel: Option<Value>,
}
struct Paste {
    id: u64,
    bytes: String,
}
#[derive(Clone, Default)]
struct Pad {
    incarnation: u64,
    server_id: Option<u32>,
    buttons: u16,
    axes: [i32; 6],
    name: String,
}

pub struct InputState {
    accepted: InputCapabilities,
    command: u64,
    rtt_count: u8,
    keys: BTreeSet<u16>,
    buttons: BTreeSet<u8>,
    position: (f64, f64),
    paste: Option<Paste>,
    pads: [Option<Pad>; 4],
}

impl InputState {
    pub fn new(accepted: InputCapabilities) -> Result<Self> {
        ensure!(
            accepted.is_subset_of(&capabilities()),
            "Unsupported input capability"
        );
        Ok(Self {
            accepted,
            command: 0,
            rtt_count: 0,
            keys: BTreeSet::new(),
            buttons: BTreeSet::new(),
            position: (0.5, 0.5),
            paste: None,
            pads: std::array::from_fn(|_| None),
        })
    }

    fn envelope(&mut self, mut body: Value, now_ms: u64, rtt: bool) -> Result<OutboundInput> {
        let external = matches!(
            body["type"].as_str(),
            Some("keyboard" | "mouse" | "controller" | "finger")
        );
        if rtt && external {
            self.rtt_count += 1;
            if self.rtt_count == 30 {
                body["time"] = now_ms.into();
                self.rtt_count = 0;
            }
        }
        if external {
            ensure!(self.command < (1u64 << 53), "Input command range exhausted");
            body["id_cmd"] = self.command.into();
            self.command += 1;
            body["from_udp"] = false.into();
            let mut dc = body.clone();
            dc["from_udp"] = true.into();
            Ok(OutboundInput {
                websocket: body,
                datachannel: Some(dc),
            })
        } else {
            Ok(OutboundInput {
                websocket: body,
                datachannel: None,
            })
        }
    }

    pub fn connected(&mut self, now: u64) -> Result<Vec<OutboundInput>> {
        let mut messages = vec![];
        if self.accepted.keyboard {
            messages.push(json!({"type":"keyboard","action":"connected"}));
        }
        if self.accepted.relative_mouse || self.accepted.absolute_mouse {
            messages.push(json!({"type":"cursor","action":"missed"}));
            messages.push(json!({"type":"mouse","action":"connected","LeftBtnState":false,"MiddleBtnState":false,"RightBtnState":false}));
        }
        messages
            .into_iter()
            .map(|m| self.envelope(m, now, false))
            .collect()
    }

    pub fn apply(&mut self, event: InputEvent, now_ms: u64) -> Result<Vec<OutboundInput>> {
        let mut messages = Vec::new();
        match event {
            InputEvent::Key {
                virtual_key,
                pressed,
                modifiers: _,
            } => {
                ensure!(
                    self.accepted.keyboard && (1..=255).contains(&virtual_key),
                    "Unsupported keyboard event"
                );
                if pressed {
                    if !self.keys.insert(virtual_key) {
                        return Ok(vec![]);
                    }
                } else {
                    self.keys.remove(&virtual_key);
                }
                messages.push(json!({"type":"keyboard","action":"button","code":virtual_key,"isPressed":pressed}));
            }
            InputEvent::MouseRelative { x, y } => {
                ensure!(
                    self.accepted.relative_mouse,
                    "Relative mouse is not accepted"
                );
                messages.push(json!({"type":"mouse","action":"move","X":self.position.0,"Y":self.position.1,"offsetX":x,"offsetY":y,"isVisible":false}));
            }
            InputEvent::MouseAbsolute {
                x,
                y,
                width,
                height,
            } => {
                ensure!(
                    self.accepted.absolute_mouse
                        && width > 0
                        && height > 0
                        && x <= width
                        && y <= height,
                    "Invalid absolute mouse event"
                );
                self.position = (
                    f64::from(x) / f64::from(width),
                    f64::from(y) / f64::from(height),
                );
                messages.push(json!({"type":"mouse","action":"move","X":self.position.0,"Y":self.position.1,"offsetX":0,"offsetY":0,"isVisible":true}));
            }
            InputEvent::MouseButton { button, pressed } => {
                ensure!(
                    (self.accepted.relative_mouse || self.accepted.absolute_mouse)
                        && (1..=5).contains(&button),
                    "Invalid mouse button"
                );
                if pressed {
                    self.buttons.insert(button);
                } else {
                    self.buttons.remove(&button);
                }
                messages.push(
                    json!({"type":"mouse","action":"button","btn":button-1,"isPressed":pressed}),
                );
            }
            InputEvent::MouseWheel { x, y } => {
                ensure!(
                    self.accepted.relative_mouse || self.accepted.absolute_mouse,
                    "Mouse input is not accepted"
                );
                ensure!(
                    x == 0,
                    "Horizontal wheel is not supported by the gateway protocol"
                );
                if y != 0 {
                    messages.push(json!({"type":"mouse","action":"wheel","deltaY":-y.signum()}));
                }
            }
            InputEvent::Text {
                paste_id,
                offset,
                final_chunk,
                utf8,
            } => {
                ensure!(
                    self.accepted.text && utf8.len() <= 8192,
                    "Invalid text chunk"
                );
                if offset == 0 {
                    ensure!(self.paste.is_none(), "Another paste is incomplete");
                    self.paste = Some(Paste {
                        id: paste_id,
                        bytes: String::new(),
                    });
                }
                let paste = self
                    .paste
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("Missing paste start"))?;
                ensure!(
                    paste.id == paste_id
                        && paste.bytes.len() == offset as usize
                        && paste.bytes.len() + utf8.len() <= 65536,
                    "Invalid paste sequence"
                );
                paste.bytes.push_str(&utf8);
                if final_chunk {
                    let paste = self
                        .paste
                        .take()
                        .ok_or_else(|| anyhow::anyhow!("Missing paste"))?;
                    messages.push(json!({"type":"clipboard","action":"paste","value":paste.bytes}));
                }
            }
            InputEvent::Gamepad {
                controller,
                bitmap,
                buttons,
                left_trigger,
                right_trigger,
                left_x,
                left_y,
                right_x,
                right_y,
                incarnation,
            } => {
                ensure!(
                    controller < self.accepted.gamepad_slots
                        && incarnation != 0
                        && buttons & 0x0c00 == 0,
                    "Invalid controller event"
                );
                let slot = controller as usize;
                let connected = bitmap & (1 << controller) != 0;
                let old = self.pads[slot].take();
                let mut pad = match old {
                    Some(old) if connected && old.incarnation == incarnation => old,
                    other => {
                        if let Some(old) = other {
                            messages.extend(neutral_pad(&old));
                            if let Some(id) = old.server_id {
                                messages.push(
                                    json!({"type":"controller","action":"disconnected","id":id}),
                                );
                            }
                        }
                        if !connected {
                            return messages
                                .into_iter()
                                .map(|m| self.envelope(m, now_ms, true))
                                .collect();
                        }
                        let name = format!("OpenNOW-controller-{controller}-{incarnation}");
                        messages
                            .push(json!({"type":"controller","action":"connected","name":name}));
                        Pad {
                            incarnation,
                            name,
                            axes: [0, 0, -32767, 0, 0, -32767],
                            ..Pad::default()
                        }
                    }
                };
                let trigger =
                    |value: u8| ((f64::from(value) / 255.0 * 65534.0).round() as i32) - 32767;
                let axis = |value: i16| i32::from(value).clamp(-32767, 32767);
                let axes = [
                    axis(left_x),
                    -axis(left_y),
                    trigger(left_trigger),
                    axis(right_x),
                    -axis(right_y),
                    trigger(right_trigger),
                ];
                if let Some(id) = pad.server_id {
                    for (mask, index) in button_map() {
                        if (pad.buttons ^ buttons) & mask != 0 {
                            messages.push(json!({"type":"controller","action":"button","id":id,"button":index,"value":u8::from(buttons & mask != 0)}));
                        }
                    }
                    if hat(pad.buttons) != hat(buttons) {
                        messages.push(
                            json!({"type":"controller","action":"pad","id":id,"hat":hat(buttons)}),
                        );
                    }
                    for (index, value) in axes.iter().enumerate() {
                        if pad.axes[index] != *value {
                            messages.push(json!({"type":"controller","action":"axes","id":id,"axes":index,"value":value}));
                        }
                    }
                }
                pad.buttons = buttons;
                pad.axes = axes;
                self.pads[slot] = Some(pad);
            }
        }
        messages
            .into_iter()
            .map(|m| self.envelope(m, now_ms, true))
            .collect()
    }

    pub fn controller_connected(
        &mut self,
        name: &str,
        id: u32,
        now: u64,
    ) -> Result<Vec<OutboundInput>> {
        ensure!(
            self.pads
                .iter()
                .flatten()
                .all(|p| p.server_id != Some(id) || p.name == name),
            "Conflicting gateway controller id"
        );
        let Some(pad) = self.pads.iter_mut().flatten().find(|p| p.name == name) else {
            return Ok(vec![]);
        };
        if pad.server_id == Some(id) {
            return Ok(vec![]);
        }
        ensure!(pad.server_id.is_none(), "Gateway controller id changed");
        pad.server_id = Some(id);
        let mut messages = Vec::new();
        for (mask, index) in button_map() {
            messages.push(json!({"type":"controller","action":"button","id":id,"button":index,"value":u8::from(pad.buttons & mask != 0)}));
        }
        messages.push(json!({"type":"controller","action":"pad","id":id,"hat":hat(pad.buttons)}));
        for (index, value) in pad.axes.iter().enumerate() {
            messages.push(
                json!({"type":"controller","action":"axes","id":id,"axes":index,"value":value}),
            );
        }
        messages
            .into_iter()
            .map(|m| self.envelope(m, now, false))
            .collect()
    }

    pub fn rumble_target(&self, id: u32) -> Option<(u8, u64)> {
        if !self.accepted.rumble {
            return None;
        }
        self.pads.iter().enumerate().find_map(|(slot, pad)| {
            pad.as_ref()
                .filter(|p| p.server_id == Some(id))
                .map(|p| (slot as u8, p.incarnation))
        })
    }

    pub fn neutral(&mut self, now: u64) -> Result<Vec<OutboundInput>> {
        let mut messages = Vec::new();
        self.paste = None;
        for code in std::mem::take(&mut self.keys) {
            messages
                .push(json!({"type":"keyboard","action":"button","code":code,"isPressed":false}));
        }
        for button in std::mem::take(&mut self.buttons) {
            messages
                .push(json!({"type":"mouse","action":"button","btn":button-1,"isPressed":false}));
        }
        for pad in self.pads.iter_mut().flatten() {
            messages.extend(neutral_pad(pad));
            pad.buttons = 0;
            pad.axes = [0, 0, -32767, 0, 0, -32767];
        }
        messages
            .into_iter()
            .map(|m| self.envelope(m, now, true))
            .collect()
    }
}

fn button_map() -> [(u16, u8); 10] {
    [
        (0x1000, 0),
        (0x2000, 1),
        (0x4000, 2),
        (0x8000, 3),
        (0x0100, 4),
        (0x0200, 5),
        (0x0020, 6),
        (0x0010, 7),
        (0x0040, 8),
        (0x0080, 9),
    ]
}
fn hat(buttons: u16) -> u8 {
    let up = buttons & 1 != 0;
    let down = buttons & 2 != 0;
    let left = buttons & 4 != 0;
    let right = buttons & 8 != 0;
    if (up && down) || (left && right) {
        0
    } else {
        u8::from(up) | (u8::from(right) << 1) | (u8::from(down) << 2) | (u8::from(left) << 3)
    }
}
fn neutral_pad(pad: &Pad) -> Vec<Value> {
    let Some(id) = pad.server_id else {
        return vec![];
    };
    let mut result: Vec<_> = button_map().iter().filter(|(mask,_)| pad.buttons & mask != 0).map(|(_,index)| json!({"type":"controller","action":"button","id":id,"button":index,"value":0})).collect();
    result.push(json!({"type":"controller","action":"pad","id":id,"hat":0}));
    for (index, value) in [0, 0, -32767, 0, 0, -32767].iter().enumerate() {
        result
            .push(json!({"type":"controller","action":"axes","id":id,"axes":index,"value":value}));
    }
    result
}

pub fn validate_requested(request: &opennow_plugin_api::media::RequestedVideo) -> Result<()> {
    use opennow_plugin_api::media::{Chroma, VideoEncoding};
    request
        .validate()
        .map_err(|_| anyhow::anyhow!("Invalid video request"))?;
    if request.hdr
        || request.bit_depth != 8
        || request.chroma != Chroma::Yuv420
        || request
            .encoding
            .is_some_and(|c| c != VideoEncoding::H264AnnexB)
    {
        bail!("Only SDR 8-bit YUV420 H264 is implemented");
    }
    ensure!(
        request.fps.is_none_or(|fps| matches!(fps, 60 | 120)),
        "Only sourced 60 or 120 FPS requests are supported"
    );
    Ok(())
}
