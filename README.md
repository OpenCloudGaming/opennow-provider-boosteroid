# Boosteroid provider for OpenNOW

A standalone native provider plugin targeting the provider-v2 SDK in
[OpenNOW PR #1129](https://github.com/OpenCloudGaming/OpenNOW/pull/1129).

This is an experimental implementation, not a verified live-playback release.
It builds native `.opennow-plugin` packages. Live Boosteroid authentication,
gameplay, and remote-session cleanup still require account-based verification.

The plugin contains a control executable for authentication, catalogs, and
remote sessions, plus a headless media worker for Boosteroid's streaming transport.
OpenNOW retains its Qt interface, decoding, audio output, input capture, overlays,
and recording. The plugin does not embed a browser or launch the official client.

The compatibility baseline is OpenNOW commit
`683eaa0ecfb60738388def065944c7284154be5c`. Live authentication and playback require
an authorized Boosteroid account and are separate from offline protocol tests.
See [compatibility](docs/compatibility.md) for the protocol and player boundaries.
See [build a native package](docs/build.md) for repeatable offline checks and packaging.
See [verification scope](docs/verification.md) for measured results and remaining live-service gates.

Protocol research references:

- [OpenStroid](https://github.com/OpenCloudGaming/OpenStroid), commit
  `c27c4f54974bf2d0a58c625c3f219dcb05bd0fd2`, under Apache-2.0.
- [boosteroid-steamos](https://github.com/bschelst/boosteroid-steamos), commit
  `aba920858ec67658862c2bccfd0c2a911a952b91`, for deployment research only.

No proprietary Boosteroid client binaries are included. Do not put credentials,
authentication responses, session tickets, or unredacted network captures in
issues, logs, or this repository.
