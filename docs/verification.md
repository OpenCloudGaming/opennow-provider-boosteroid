# Verification scope

The native package has offline and host-integration evidence. It does not yet
have evidence of live Boosteroid authentication or gameplay.

## Checked on October 7, 2026

The SDK and host core use OpenNOW commit
`683eaa0ecfb60738388def065944c7284154be5c`. Builds use Rust 1.99.0.

| Check | Result |
| --- | --- |
| Linux x86_64 workspace tests | 65 passed |
| Windows x86_64 MSVC workspace tests | 68 passed |
| Python notice-validation tests | 5 passed on each platform |
| Formatting and strict workspace Clippy | Passed on Linux and Windows |
| Modified vendored H264 parser library tests | 125 passed on Linux |
| Real host package inspection and consent | Passed on Linux and Windows |
| Disabled-by-default install, enable, native control startup | Passed on Linux and Windows |
| Signed-out authentication and empty account projection | Passed on Linux and Windows |
| Disablement and uninstall | Passed on Linux and Windows |

Host checks use isolated temporary profiles and the actual core executable.
They do not alter an existing OpenNOW profile. Media tests use loopback DTLS-SRTP
and SCTP with documented test fixtures. These tests do not connect to Boosteroid.

The Windows release package is `boosteroid-windows-x86_64.opennow-plugin`,
8,249,932 bytes, SHA-256:

```text
d21655ff0374bc24bd16ba03ee0d39d5e38287cadf0e8ea519e0ecdfda027224
```

## Not established

Live verification must cover browser approval, token refresh, service response
schemas, queue-to-seat correlation, preflight followed by actual attachment,
TURN routing, displayed video, audible sound, gameplay input, and authoritative
remote-session termination. A worker exit or hangup is not termination evidence.

The Windows package was tested on Windows 11 with NTFS. Atomic state replacement
requires Windows 10 1607 or later and filesystem support. Unsupported operations
fail rather than fall back to non-atomic writes. macOS runtime behavior and
hardware power-loss recovery have not been tested.

See [build.md](build.md) for commands that reproduce the package and host checks.
