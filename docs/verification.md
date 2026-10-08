# Verification scope

The native package has offline, host-integration, and live Windows authentication
and library evidence. Live gameplay remains unverified.

## Version 0.1.2 library and Windows persistence correction

Live requests proved that Boosteroid rejects `paginate=40` with HTTP 422 and
accepts `paginate=50`. The provider now maps host pages onto fixed 50-item service
pages, preserving the requested item limit without skipping or duplicating items
at page boundaries. A loopback regression covers three 40-item pages over 105 games.

Boosteroid artwork URLs include image-transform queries. The original image was
verified accessible without authentication or a query. The provider removes
queries only on Boosteroid-owned hosts before projecting credential-free public
artwork URLs. Both the pagination and artwork regressions failed before the fixes.

Windows Credential Manager limits each secret blob to 2560 bytes. A live login
produced 2619 UTF-8 bytes, or 5238 bytes under the previous UTF-16 password encoding,
which forced temporary storage. Windows now stores bounded UTF-8 chunks in the
OS credential store and publishes a length-and-digest manifest last. Legacy UTF-16
records remain readable. Partial writes are rolled back; incomplete or corrupt
records never yield credentials. No plaintext credential files are created.
Termination or persistent OS cleanup failures can leave protected orphan chunks;
removal retries all bounded chunk names for that reference without scanning other
credentials. Linux and macOS storage behavior is unchanged.

Verification on October 7, 2026:

- 85 Linux and 88 Windows Rust tests passed, including 15 credential-store tests.
- Five Python tests, formatting, and strict workspace Clippy passed on Windows;
  formatting and strict workspace Clippy also passed on Linux.
- The actual Windows core installed the release package in an isolated profile,
  completed browser authentication with durable persistence, and returned five
  library items with five public artwork URLs through `sources.library.page`.
- Disabling and re-enabling the provider preserved login and returned the same
  five library items. The isolated account and credentials were then removed.
- Native OS-store probes passed process-restart round trips at 2619 and 327680
  bytes, plus legacy Unicode reads and cleanup. The ordinary write took 23 ms;
  the maximum-size write took 3662 ms. Actual host auth completion took 33 ms.

The Windows package is `boosteroid-windows-x86_64-0.1.2.opennow-plugin`,
8,255,514 bytes, SHA-256:

```text
37b04d90c6aec812e2dfad44e829f7f74579418eac5a7bc46cb7e61c8d55d2f1
```

Existing temporary logins require browser approval again after replacing the
plugin. These checks did not start a game, refresh or revoke a token, log out a
remote account, or request remote termination. The existing Qt test profile was
not modified by the isolated verification.

## Version 0.1.1 authentication correction

QR login can return the opaque authorization data directly in `user_data`.
Version 0.1.1 preserves that string and sends it as `Authorization-Data` during
the authenticated account lookup. The supported object forms remain valid.
Refresh replaces or retains the value as appropriate, with the same size bounds.

A loopback HTTP regression returns 401 when this header is absent. It failed
with `AuthRequired` before the fix and passes afterward. The full suite passes
68 Rust tests on Linux and 71 on Windows, plus the five Python tests, formatting,
strict Clippy, and the real Windows core installation/startup/uninstall check.
Subsequent live testing confirmed browser approval and account lookup. The
remaining library and Windows persistence defects are corrected in 0.1.2 above.

The Windows package is `boosteroid-windows-x86_64-0.1.1.opennow-plugin`,
8,250,068 bytes, SHA-256:

```text
51f68812220d6e06a81b0cd6c1b358fd66d4ef905110d3fd1e3e5d30a6bb15f3
```

## Version 0.1.0 baseline, October 7, 2026

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

Live verification must still cover token refresh, remaining service response
schemas, queue-to-seat correlation, preflight followed by actual attachment,
TURN routing, displayed video, audible sound, gameplay input, and authoritative
remote-session termination. A worker exit or hangup is not termination evidence.

The Windows package was tested on Windows 11 with NTFS. Atomic state replacement
requires Windows 10 1607 or later and filesystem support. Unsupported operations
fail rather than fall back to non-atomic writes. macOS runtime behavior and
hardware power-loss recovery have not been tested.

See [build.md](build.md) for commands that reproduce the package and host checks.
