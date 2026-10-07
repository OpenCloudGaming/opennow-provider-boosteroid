# Native Boosteroid media worker

This crate contains `boosteroid-media`, the headless media role, and the shared native preflight library. It uses the OpenNOW SDK at `683eaa0ecfb60738388def065944c7284154be5c`, webrtc/rtc 0.21.0, and the service protocol traced from OpenStroid at `c27c4f54974bf2d0a58c625c3f219dcb05bd0fd2`.

It contains no browser, decoder, presenter, account login, allocation, credential refresh, or generated production media. Qt owns playback and input capture. Test fixtures are only included by test targets.

## Call preflight from control

```rust,ignore
let observed = boosteroid_media::preflight(
    &gateway_connection,
    &persisted_create.preferences,
    cancellation,
).await?;
```

`PreflightMedia` returns `video: VideoFormat`, `audio: Option<AudioFormat>`, and `input: InputCapabilities`. Control must intersect those values with the current `NativeOffer` before issuing a grant. The preflight requests the persisted resolution, FPS and bitrate, uses a fresh temporary peer ID, receives authenticated native RTP, and parses the active slice/PPS/SPS/VUI relationship. It requires explicit color description and fixed integer frame-rate evidence. H264's specified absent-chroma-location default is left; color primaries, transfer and range are never guessed.

Opus sample rate and channel count come from the accepted SDP answer, not a requirement to receive an audio packet. Silence/DTX cannot hold preflight open waiting for Opus. An absent, rejected, inactive or receive-only audio section returns `None`. An unsupported active audio codec fails explicitly. Any received audio must agree with negotiation. Preflight closes only its temporary peer/local sockets, never `terminating`, hangup or dequeue. Its WSS connection deadline is ten seconds, negotiation deadline 25 seconds and metadata deadline 20 seconds; cancellation interrupts each phase. Native peer close is bounded to 500 ms.

Preflight and the worker share `Gateway::announce_ready`. After the native peer becomes Connected, it queues the sourced `settings/ready` and `stream/page` messages exactly once. Both queue slots are reserved together, so backpressure cannot send half an announcement. This service readiness announcement is separate from the host's local Ready handshake and does not introduce gameplay input into preflight.

## Run the worker

Only the verified host should launch the executable. It accepts no CLI arguments. It reads the SDK's bounded private `WorkerBootstrap` from stdin and the host-owned `OPENNOW_PLUGIN_DATA_DIR` environment variable. It validates the common grant before networking, takes the common per-session RAII lock, and performs Hello/Attached/Ready over the authenticated loopback control channel.

Ready means local attachment and implemented input capabilities, not successful service playback. It is sent before potentially slow remote negotiation to meet the host's three-second startup deadline. Gameplay input before the remote WSS input path is usable fails explicitly and retires the worker; it is neither acknowledged as delivered nor accumulated for later replay. Neutral can be accepted locally during startup. During streaming, a bounded mailbox preserves order, Neutral supersedes older pending gameplay, and Stop independently cancels transport and pipe tasks. No media is emitted until its actual format matches the accepted format.

The control process remains the only durable writer. An active worker reads the durable authorization every 250 ms, without a writer lock or heartbeat. Control epoch changes, grant expiry after attachment and attach-token rotation do not revoke it. Explicit revocation does. Unreadable/corrupt authorization closes locally. Only a freshly verified `Revoked` state for the exact owned session permits best-effort `settings/terminating` and exact-peer hangup. Native Stop, host disconnect, decode/format mismatch and transport failure with Active authorization do not authorize remote termination. No outcome here claims the remote VM ended.

## Transport and bounds

`transport.rs` implements the sourced WSS handshake and HTTPS getParams/getIceServers/call/addIceCandidate/getIceCandidate protocol. Browser-shaped ICE URL strings or arrays are normalized into the native API. HTTPS redirects are disabled. Only returned `boosteroid.com` hostnames or subdomains are currently supported, with normal TLS validation; unestablished gateway domains fail explicitly. Gateway, SDP, ICE, JSON, command and packet queues have fixed limits. No URL, credential, SDP, candidate, packet content, pasted text or raw upstream error is logged.

H264 packetization mode 1 supports complete single NALs, STAP-A and FU-A, including valid one-/two-byte non-VCL NALs. It validates complete slice headers against parsed PPS/SPS before emission. The reorder window is 128 packets with a 40 ms incomplete-unit deadline. The negotiated host byte limits bound aggregation and output; output permits remain held while stdout blocks. Loss, timeout and output rejection cause discontinuity and rate-limited PLI. No partial access unit reaches Qt. Opus framing and duration are validated and its output queue is bounded by encoded packet size and audio duration.

Video provenance uses original extended RTP timestamps, original primary SSRC and a 90 kHz clock; Opus uses 48 kHz. Sender frame ID is absent, never invented from packet counters. Host attempt generation stays full-width. No RTX, RED, FEC, AV1, HDR, microphone or rendering is advertised. Selective RTCP/NACK/TWCC interceptors preserve supported TWCC while avoiding OpenStroid's specifically stripped MID/RID/audio-level/orientation extensions.

`input.rs` implements source-shaped keyboard, relative/absolute mouse, buttons, vertical wheel, bounded UTF-8 clipboard, four gamepads and rumble mapping. Native button masks/axis directions are converted explicitly. Controller IDs come from matching gateway connection replies and are bound to host incarnations. Device events retain the same `id_cmd` across WSS and SCTP, with their distinct `from_udp` values. Input acknowledgements mean bounded local transport acceptance, not remote execution. Horizontal wheel is explicitly unsupported. Server-driven cursor images/capture-mode parity are not implemented and no host UI ownership is moved into this crate.

## Verify offline

From this crate directory, with the sibling common crate present:

```sh
cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked --bin boosteroid-media
```

After the initial dependency fetch, add `--offline` to Cargo test/clippy/build. The tests do not contact Boosteroid or any STUN/TURN server.

The suite exercises real loopback ICE/DTLS/SRTP H264 and Opus ingress, SCTP input, source provenance, wrap/reorder/loss recovery, malformed framing, metadata rejection, DTX/no-audio negotiation, bounded stdout cancellation, input neutralization and admission, authentic common grants across control restarts/expiry/rotation/revocation, process rejection of a forged grant, and the actual host handshake with a delayed negotiation task. The delayed-negotiation test isolates the host protocol; it does not pretend to be a live gateway.

No live-account compatibility, real gateway SDP profile, TURN traversal, double negotiation, Windows build or end-to-end Qt playback has been verified. In particular, some real gateways may reject a temporary preflight followed by another attach, omit required VUI timing/color evidence, or use another hostname/SSRC convention. Those remain explicit integration gates rather than fallback success paths.

## Protocol source map

- OpenStroid `src/stream/OpenStroidStreamClient.ts:729-839,1680-1797,1843-1952`: WSS, status, SDP constraints and HTTP signaling.
- The same file `:1353-1440,1954-1976,2036-2063`: pointer/key JSON, command IDs, duplicate WSS/SCTP routing and RTT timestamps.
- OpenStroid `src/stream/GamepadController.ts:153-166,226-277,307-467`: gateway IDs, buttons, axes, hats and rumble.
- OpenNOW `native/opennow-streamer/crates/opennow-streamer-platform/src/output.rs:1075-1146,1506-1527,2120-2129`: native bitmap, button masks, Y inversion and pointer numbering.
- OpenNOW `native/opennow-media-protocol/src/wire.rs` and `examples/provider-media-worker`: host framing and worker lifecycle only. No example-generated media is used in production.
