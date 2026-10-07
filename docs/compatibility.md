# OpenNOW compatibility

The implementation targets the provider SDK in OpenNOW commit
`683eaa0ecfb60738388def065944c7284154be5c`, on
[PR #1129](https://github.com/OpenCloudGaming/OpenNOW/pull/1129).

The application version string alone does not establish compatibility. Use an
OpenNOW build that includes the provider-v2 changes from that pull request.

| Boundary | Version |
| --- | --- |
| Provider manifest and control protocol | 2 |
| Encoded-media worker protocol | 1 |
| OpenNOW core protocol | 5, with `sources.v2` |
| Native runtime JSON | 8 |
| Native C ABI | 12 |

The plugin imports `opennow-plugin-api` and `opennow-media-protocol` from the same
pinned Git revision. These are source dependencies, not published stable SDK
packages. Build and package the control and media executables for the same
operating system and architecture as OpenNOW.

The host negotiates the actual supported video, audio, and input formats. The
external media contract currently excludes HDR and microphone input. A service
format that the host cannot accept must fail explicitly; it must not be relabeled
as a different format.

OpenNOW owns decoding, rendering, audio output, input capture, overlays, and
recording. The plugin owns Boosteroid authentication, catalogs, remote-session
operations, and the service's network transport. Neither executable may launch
the official Boosteroid application or an embedded browser as a substitute for
the native worker.

Local compilation and synthetic protocol tests do not prove live Boosteroid
compatibility. Live verification requires an authorized account and must check
actual displayed frames, audio, input, and remote-session cleanup separately.
