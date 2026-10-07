# Boosteroid control executable

This is the native provider-v2 control role. It uses the OpenNOW SDK pinned by the workspace and the sibling common/media crates. It does not load Electron, a web view, a decoder, or a presenter.

## Ownership

- `dispatcher.rs` reads bounded NDJSON, binds the process epoch, reserves separate receipt/stop and session capacity, and cancels read requests without discarding allocation obligations. Stdout contains protocol frames only.
- `service.rs` implements native HTTPS requests derived from OpenStroid commit `c27c4f54974bf2d0a58c625c3f219dcb05bd0fd2`. It rejects redirects, caps bodies, disables automatic retries and parses conservative response shapes. Unknown JSON is not an empty successful catalog or session result.
- `state.rs` stores account metadata, exact logical-session ownership, receipt decisions and possible-dispatch stages through `AuthorizationWriter`. Credentials and connection secrets are not stored in this journal.
- `vault.rs` uses the operating system's credential store. Unavailable durable storage produces an explicit temporary account. Temporary credentials support browsing but cannot launch: remote cleanup credentials must survive a control restart.
- `lib.rs` coordinates auth, catalog and session operations. Token rotation runs independently of a cancelled read request. An interrupted rotation has a durable marker and requires reauthentication after restart rather than automatically replaying the old refresh token. Blocking credential-store jobs have an independent capacity limit that remains held after caller cancellation.
- `native_environment.rs` discovers only the current user's owner-validated Linux session-bus socket, before Tokio or background threads start. This supports Secret Service when the host strips inherited environment variables. It does not access another user's bus or weaken storage protection.

## Session behavior

Create durably allocates a provider-owned logical session and receipt, initially `Allocating`, without a remote request. Only durable receipt acceptance starts the bounded background workflow. Enqueue/start each record possible dispatch before I/O. Lost or unrecognized outcomes remain `Unknown` and are never automatically replayed. Later service seat IDs are private mappings; the logical SDK session key never changes. Poll is read-only.

The workflow can follow an exact token or seat supplied directly by its original enqueue/start response. It deliberately does not infer ownership from the newest same-game session, arbitrary recursive JSON matches, or an empty active-session list. Queue responses without proven correlation therefore fail closed until their actual service schema is established.

After binding a seat, native preflight obtains real video/audio metadata through the media crate. Only observed, supported media makes a session ready. Preparation rechecks the stream, intersects the fresh native offer and input capabilities, and issues a common private grant. The common per-session worker lock excludes a probe while an existing worker is active. Recovered healthy media is not re-probed or revoked just because control restarted.

Stop irrevocably revokes that exact session's local media authorization before updating its control record. Local no-dispatch sessions can finish immediately. Dispatched sessions retain unresolved remote cleanup until authenticated details name the recorded upstream seat and a supported explicit terminal status. Poll, stop and reconciliation can consume that evidence. Neither worker retirement, an empty discovery list, a 404 nor WebRTC hangup proves that Boosteroid destroyed the seat. There is no account-wide dequeue shortcut or fabricated successful stop.

## Verification and limits

From the workspace root:

```sh
cargo fmt -p boosteroid-control --check
cargo test -p boosteroid-control
cargo clippy -p boosteroid-control --all-targets --no-deps -- -D warnings
```

Tests use explicitly synthetic loopback HTTP responses, durable-state fixtures, and the real NDJSON executable. They never contact a production service or use real credentials. Media transport tests belong to `boosteroid-media`.

No live Boosteroid login or gameplay has been validated here. Remaining account-dependent checks include the unofficial QR client identity, actual envelopes/pagination, queue correlation, safe reconnect after preflight, and authoritative exact-seat termination. Production has no fake login, catalog, media stream, token-import shortcut, or fallback that claims those checks passed.
