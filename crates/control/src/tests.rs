use super::*;
use opennow_plugin_api::media::*;
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn common_private_store_accepts_control_state() {
    let root = tempfile::tempdir().unwrap();
    let writer =
        boosteroid_common::AuthorizationWriter::open(&root.path().join("private")).unwrap();
    assert!(writer.read_control_state().unwrap().is_none());
    writer.write_control_state(b"{\"version\":1}").unwrap();
}

async fn server(
    responses: Vec<(u16, serde_json::Value)>,
) -> (
    BoosteroidClient,
    Arc<AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = BoosteroidClient::fixture(
        reqwest::Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap(),
    )
    .unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let requests = count.clone();
    let task = tokio::spawn(async move {
        for (status, data) in responses {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = vec![0; 16_384];
            let _ = socket.read(&mut bytes).await.unwrap();
            requests.fetch_add(1, Ordering::SeqCst);
            if status == 0 {
                drop(socket);
                continue;
            }
            let body = serde_json::to_vec(&data).unwrap();
            let header = format!(
                "HTTP/1.1 {status} fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            socket.write_all(header.as_bytes()).await.unwrap();
            socket.write_all(&body).await.unwrap();
        }
    });
    (client, count, task)
}

fn account() -> AccountKey {
    AccountKey {
        authority: AuthorityId::new("boosteroid").unwrap(),
        account: AccountId::new("12345").unwrap(),
    }
}

fn account_setup(provider: &Provider, vault: &dyn Vault) {
    let credentials = Credentials {
        access: SecretString::new("fixture-access").unwrap(),
        refresh: SecretString::new("fixture-refresh").unwrap(),
        authorization_data: None,
    };
    vault
        .put(
            "fixture-credential",
            &serde_json::to_string(&credentials).unwrap(),
        )
        .unwrap();
    let mut store = provider.store().unwrap();
    let mut state = store.state.clone();
    state.accounts.push(Account {
        public: PublicAccount {
            key: account(),
            name: text("Fixture").unwrap(),
            persistence: Persistence::Durable,
            reauthentication_required: false,
            pin_locked: false,
        },
        credential: "fixture-credential".into(),
        refresh_pending: false,
    });
    state.selected = Some(account());
    store.save(state).unwrap();
}

fn offer() -> NativeOffer {
    NativeOffer {
        version: 1,
        offer_id: OfferId::new("offer-1").unwrap(),
        runtime_epoch: 1,
        expires_at_ms: now_ms() + 300_000,
        video_formats: List::new(vec![VideoSupport {
            encoding: VideoEncoding::H264AnnexB,
            bit_depth: 8,
            chroma: Chroma::Yuv420,
            dynamic_range: DynamicRange::Sdr,
            max_width: 1920,
            max_height: 1080,
            max_fps: 60,
        }])
        .unwrap(),
        audio_formats: List::new(vec![AudioFormat {
            codec: AudioCodec::Opus,
            sample_rate: 48000,
            channels: 2,
        }])
        .unwrap(),
        input: InputCapabilities {
            keyboard: true,
            relative_mouse: false,
            absolute_mouse: false,
            text: false,
            gamepad_slots: 1,
            rumble: false,
        },
        limits: MediaLimits {
            max_video_access_unit_bytes: 1_000_000,
            max_audio_packet_bytes: 4096,
            max_buffered_video_bytes: 2_000_000,
            max_buffered_video_frames: 2,
            max_buffered_audio_ms: 100,
            max_control_message_bytes: 16384,
            max_pending_input_events: 64,
        },
    }
}

fn create_request() -> CreateSession {
    let scope = AccountScope {
        account: account(),
        revision: 1,
    };
    CreateSession {
        scope: Some(scope.clone()),
        operation: OperationId::new("operation-1").unwrap(),
        target: LaunchTarget {
            game: GameId::new("45").unwrap(),
            variant: VariantId::new("default").unwrap(),
        },
        catalog_revision: catalog_revision(&scope).unwrap(),
        settings_revision: 1,
        preferences: StreamPreferences {
            video: RequestedVideo {
                width: 1920,
                height: 1080,
                encoding: Some(VideoEncoding::H264AnnexB),
                fps: Some(60),
                bit_depth: 8,
                chroma: Chroma::Yuv420,
                hdr: false,
            },
            bitrate_kbps: 20000,
        },
        offer: offer(),
    }
}

#[tokio::test]
async fn create_is_local_idempotent_and_rejection_never_dispatches() {
    let root = tempfile::tempdir().unwrap();
    let (client, count, server) = server(vec![(200, json!({}))]).await;
    let vault = Arc::new(TemporaryVault::default());
    let provider =
        Provider::with_client(root.path().join("private").as_path(), client, vault.clone())
            .unwrap();
    account_setup(&provider, vault.as_ref());
    let request = create_request();
    let first = provider.create(request.clone()).unwrap();
    let ticket = first.allocation.unwrap();
    let second = provider.create(request.clone()).unwrap();
    assert_eq!(second.allocation.as_ref().unwrap(), &ticket);
    assert_eq!(count.load(Ordering::SeqCst), 0);
    let mut conflicting = request;
    conflicting.target.game = GameId::new("46").unwrap();
    assert!(provider.create(conflicting).is_err());
    provider
        .resolve(ResolveAllocation {
            operation: ticket.operation.clone(),
            receipt: ticket.receipt.clone(),
            decision: Acceptance::Rejected,
        })
        .unwrap();
    assert!(
        provider
            .store()
            .unwrap()
            .state
            .session(&ticket.session)
            .unwrap()
            .terminal()
    );
    assert_eq!(count.load(Ordering::SeqCst), 0);
    assert!(
        provider
            .resolve(ResolveAllocation {
                operation: ticket.operation,
                receipt: ticket.receipt,
                decision: Acceptance::Accepted
            })
            .is_err()
    );
    server.abort();
}

#[tokio::test]
async fn accepted_enqueue_response_loss_is_unknown_across_restart_and_never_replayed() {
    let root = tempfile::tempdir().unwrap();
    let (client, count, task) = server(vec![(0, Value::Null)]).await;
    let vault = Arc::new(TemporaryVault::default());
    let provider = Provider::with_client(
        root.path().join("private").as_path(),
        client.clone(),
        vault.clone(),
    )
    .unwrap();
    account_setup(&provider, vault.as_ref());
    let request = create_request();
    let ticket = provider
        .create(request.clone())
        .unwrap()
        .allocation
        .unwrap();
    provider
        .resolve(ResolveAllocation {
            operation: ticket.operation.clone(),
            receipt: ticket.receipt.clone(),
            decision: Acceptance::Accepted,
        })
        .unwrap();
    task.await.unwrap();
    for _ in 0..100 {
        if provider.workflows.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    assert_eq!(count.load(Ordering::SeqCst), 1);
    let query = ReconcileSession {
        scope: request.scope.clone(),
        operation: ticket.operation.clone(),
        session: Some(ticket.session.clone()),
    };
    assert!(matches!(
        provider.reconcile(query.clone()).unwrap(),
        Reconciliation::Unknown { .. }
    ));
    drop(provider);
    let provider =
        Provider::with_client(root.path().join("private").as_path(), client, vault).unwrap();
    provider.resume().unwrap();
    assert!(matches!(
        provider.reconcile(query).unwrap(),
        Reconciliation::Unknown { .. }
    ));
    assert_eq!(
        provider.create(request).unwrap().allocation.unwrap(),
        ticket
    );
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn revoked_authorization_wins_over_older_control_journal() {
    let root = tempfile::tempdir().unwrap();
    let vault = Arc::new(TemporaryVault::default());
    let client = BoosteroidClient::production().unwrap();
    let provider = Provider::with_client(
        root.path().join("private").as_path(),
        client.clone(),
        vault.clone(),
    )
    .unwrap();
    account_setup(&provider, vault.as_ref());
    let request = create_request();
    let ticket = provider
        .create(request.clone())
        .unwrap()
        .allocation
        .unwrap();
    {
        let mut store = provider.store().unwrap();
        let mut next = store.state.clone();
        next.sessions[0].decision = Some(Acceptance::Accepted);
        store.save(next).unwrap();
        store.writer.activate_session(&ticket.session).unwrap();
        store.writer.revoke_session(&ticket.session).unwrap();
    }
    drop(provider);
    let provider =
        Provider::with_client(root.path().join("private").as_path(), client, vault).unwrap();
    let store = provider.store().unwrap();
    let session = store.state.session(&ticket.session).unwrap();
    assert!(session.revoked && session.terminal());
    assert!(matches!(
        authorization_status(root.path().join("private").as_path(), &ticket.session).unwrap(),
        Some(SessionAuthorization::Revoked { .. })
    ));
}

#[tokio::test]
async fn approval_requires_explicit_completion_and_journal_has_no_secrets() {
    let root = tempfile::tempdir().unwrap();
    let (client, _, task) = server(vec![
        (
            200,
            json!({"data":{"access_token":"fixture-access","refresh_token":"fixture-refresh"}}),
        ),
        (200, json!({"data":{"id":12345,"name":"Fixture user"}})),
    ])
    .await;
    let provider = Provider::with_client(
        root.path().join("private").as_path(),
        client,
        Arc::new(TemporaryVault::default()),
    )
    .unwrap();
    let state = provider
        .begin_auth(BeginAuth {
            authority: None,
            kind: AuthKind::Browser,
            remember: true,
        })
        .await
        .unwrap();
    let AuthState::Pending {
        challenge: AuthChallenge::Browser { attempt, .. },
    } = state
    else {
        panic!("browser challenge missing")
    };
    assert!(matches!(
        provider
            .poll_auth(AuthAttempt {
                attempt: attempt.clone()
            })
            .await
            .unwrap(),
        AuthState::Authorized { .. }
    ));
    assert!(matches!(
        provider.auth_state().unwrap(),
        AuthState::SignedOut
    ));
    provider
        .complete_auth(CompleteAuth {
            attempt,
            proof: None,
        })
        .await
        .unwrap();
    assert!(matches!(
        provider.auth_state().unwrap(),
        AuthState::SignedIn { .. }
    ));
    let bytes = provider
        .store()
        .unwrap()
        .writer
        .read_control_state()
        .unwrap()
        .unwrap();
    let text = String::from_utf8(bytes).unwrap();
    assert!(!text.contains("fixture-access") && !text.contains("fixture-refresh"));
    task.await.unwrap();
}

#[tokio::test]
async fn unknown_discovery_never_means_not_allocated() {
    let root = tempfile::tempdir().unwrap();
    let provider = Provider::with_client(
        root.path().join("private").as_path(),
        BoosteroidClient::production().unwrap(),
        Arc::new(TemporaryVault::default()),
    )
    .unwrap();
    assert!(matches!(
        provider
            .reconcile(ReconcileSession {
                scope: None,
                operation: OperationId::new("unknown").unwrap(),
                session: None
            })
            .unwrap(),
        Reconciliation::Unknown { .. }
    ));
}

#[tokio::test]
async fn late_seat_after_stop_is_retained_without_reactivation() {
    let root = tempfile::tempdir().unwrap();
    let vault = Arc::new(TemporaryVault::default());
    let provider = Provider::with_client(
        root.path().join("private").as_path(),
        BoosteroidClient::production().unwrap(),
        vault.clone(),
    )
    .unwrap();
    account_setup(&provider, vault.as_ref());
    let ticket = provider
        .create(create_request())
        .unwrap()
        .allocation
        .unwrap();
    {
        let mut store = provider.store().unwrap();
        let mut next = store.state.clone();
        next.sessions[0].decision = Some(Acceptance::Accepted);
        next.sessions[0].remote = Remote::EnqueueDispatching;
        store.save(next).unwrap();
        store.writer.activate_session(&ticket.session).unwrap();
    }
    let stopped = provider
        .stop(StopSession {
            session: ticket.session.clone(),
            operation: OperationId::new("stop-1").unwrap(),
        })
        .unwrap();
    assert!(matches!(stopped, CleanupState::Unknown { .. }));
    provider
        .bind_seat(
            &ticket.session,
            "6f43f953-df4d-4e09-b920-7f086a8d2db0".into(),
        )
        .unwrap();
    let store = provider.store().unwrap();
    let session = store.state.session(&ticket.session).unwrap();
    assert!(session.revoked && matches!(session.remote, Remote::Seat { .. }));
    assert!(matches!(
        authorization_status(root.path().join("private").as_path(), &ticket.session).unwrap(),
        Some(SessionAuthorization::Revoked { .. })
    ));
}

use serde_json::Value;

#[tokio::test]
async fn cleanup_converges_only_on_exact_seat_terminal_details() {
    let expected = "6f43f953-df4d-4e09-b920-7f086a8d2db0";
    let other = "6636c3e0-cef8-4cac-a9eb-16b06d10aa79";
    let cases = [
        (
            200,
            json!({"data":{"sessionId":other,"status":"ENDED"}}),
            false,
        ),
        (
            200,
            json!({"data":{"sessionId":expected,"status":"READY"}}),
            false,
        ),
        (
            200,
            json!({"data":{"sessionId":expected,"status":"UNKNOWN_NEW_STATUS"}}),
            false,
        ),
        (200, json!({"data":[]}), false),
        (
            404,
            json!({"data":{"sessionId":expected,"status":"ENDED"}}),
            false,
        ),
        (
            200,
            json!({"data":{"sessionId":expected,"status":"ENDED","stage":"RUNNING"}}),
            false,
        ),
        (
            200,
            json!({"data":{"sessionId":expected,"status":"ENDED"}}),
            true,
        ),
        (
            200,
            json!({"data":{"sessionId":expected,"status":"EXPIRED"}}),
            true,
        ),
    ];
    for (status, body, terminal) in cases {
        let root = tempfile::tempdir().unwrap();
        let (client, count, task) = server(vec![(status, body)]).await;
        let vault = Arc::new(TemporaryVault::default());
        let provider = Provider::with_client(
            root.path().join("private").as_path(),
            client.clone(),
            vault.clone(),
        )
        .unwrap();
        account_setup(&provider, vault.as_ref());
        let create = create_request();
        let ticket = provider.create(create.clone()).unwrap().allocation.unwrap();
        {
            let mut store = provider.store().unwrap();
            let mut next = store.state.clone();
            next.sessions[0].decision = Some(Acceptance::Accepted);
            next.sessions[0].remote = Remote::Seat {
                id: expected.into(),
                connection_reference: None,
            };
            store.save(next).unwrap();
            store.writer.activate_session(&ticket.session).unwrap();
        }
        let result = provider
            .stop_observed(StopSession {
                session: ticket.session.clone(),
                operation: OperationId::new("stop-1").unwrap(),
            })
            .await
            .unwrap();
        assert_eq!(matches!(result, CleanupState::Resolved), terminal);
        assert_eq!(
            provider
                .store()
                .unwrap()
                .state
                .session(&ticket.session)
                .unwrap()
                .terminal(),
            terminal
        );
        assert_eq!(count.load(Ordering::SeqCst), 1);
        task.await.unwrap();
        drop(provider);
        let provider =
            Provider::with_client(root.path().join("private").as_path(), client, vault).unwrap();
        let state = provider
            .reconcile(ReconcileSession {
                scope: create.scope,
                operation: ticket.operation,
                session: Some(ticket.session.clone()),
            })
            .unwrap();
        assert_eq!(matches!(state, Reconciliation::Terminal { .. }), terminal);
        if terminal {
            assert!(
                matches!(&provider.store().unwrap().state.session(&ticket.session).unwrap().remote,Remote::Terminal { upstream_id:Some(id),.. } if id == expected)
            );
        } else {
            assert!(matches!(state, Reconciliation::Unknown { .. }));
        }
    }
}

#[tokio::test]
async fn cancelled_callers_cannot_unbound_blocking_credential_jobs() {
    let root = tempfile::tempdir().unwrap();
    let provider = Provider::with_client(
        root.path().join("private").as_path(),
        BoosteroidClient::production().unwrap(),
        Arc::new(TemporaryVault::default()),
    )
    .unwrap();
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let spawn = || {
        let provider = provider.clone();
        let active = active.clone();
        let peak = peak.clone();
        tokio::spawn(async move {
            provider
                .vault_io(move || {
                    let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(current, Ordering::SeqCst);
                    std::thread::sleep(std::time::Duration::from_millis(150));
                    active.fetch_sub(1, Ordering::SeqCst);
                    Ok(())
                })
                .await
        })
    };
    let first = (0..8).map(|_| spawn()).collect::<Vec<_>>();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while active.load(Ordering::SeqCst) < 4 {
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
    for task in first {
        task.abort();
    }
    let second = (0..8).map(|_| spawn()).collect::<Vec<_>>();
    for task in second {
        task.await.unwrap().unwrap();
    }
    assert_eq!(peak.load(Ordering::SeqCst), 4);
    assert_eq!(active.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn cancellation_does_not_drop_a_refresh_rotation_response() {
    let root = tempfile::tempdir().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = BoosteroidClient::fixture(
        reqwest::Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap(),
    )
    .unwrap();
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let server_started = started.clone();
    let server_release = release.clone();
    let task = tokio::spawn(async move {
        for (index,data) in [json!({"data":{"access_token":"cancel-rotated-access","refresh_token":"cancel-rotated-refresh"}}),json!({"data":{"id":12345}})].into_iter().enumerate() {
            let (mut socket,_) = listener.accept().await.unwrap();
            let mut bytes = [0;8192];
            let received = socket.read(&mut bytes).await.unwrap();
            assert!(received > 0);
            if index == 0 { server_started.notify_one(); server_release.notified().await; }
            let body = serde_json::to_string(&data).unwrap();
            socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
        }
    });
    let vault = Arc::new(TemporaryVault::default());
    let provider =
        Provider::with_client(root.path().join("private").as_path(), client, vault.clone())
            .unwrap();
    account_setup(&provider, vault.as_ref());
    let failed = provider.credential(&account()).await.unwrap();
    let caller = {
        let provider = provider.clone();
        tokio::spawn(async move { provider.refresh(&account(), &failed).await })
    };
    started.notified().await;
    assert!(
        provider
            .store()
            .unwrap()
            .state
            .account(&account())
            .unwrap()
            .refresh_pending
    );
    caller.abort();
    release.notify_one();
    task.await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while provider
            .store()
            .unwrap()
            .state
            .account(&account())
            .unwrap()
            .refresh_pending
        {
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        provider
            .credential(&account())
            .await
            .unwrap()
            .refresh
            .expose_secret(),
        "cancel-rotated-refresh"
    );
}

#[tokio::test]
async fn crash_during_refresh_requires_reauthentication_instead_of_retrying_old_token() {
    let root = tempfile::tempdir().unwrap();
    let vault = Arc::new(TemporaryVault::default());
    let provider = Provider::with_client(
        root.path().join("private").as_path(),
        BoosteroidClient::production().unwrap(),
        vault.clone(),
    )
    .unwrap();
    account_setup(&provider, vault.as_ref());
    {
        let mut store = provider.store().unwrap();
        let mut next = store.state.clone();
        next.accounts[0].refresh_pending = true;
        store.save(next).unwrap();
    }
    drop(provider);
    let provider = Provider::with_client(
        root.path().join("private").as_path(),
        BoosteroidClient::production().unwrap(),
        vault,
    )
    .unwrap();
    assert!(
        provider
            .store()
            .unwrap()
            .state
            .account(&account())
            .unwrap()
            .public
            .reauthentication_required
    );
    assert!(matches!(
        provider.credential(&account()).await,
        Err(Error {
            code: ProviderErrorCode::AuthRequired,
            ..
        })
    ));
}

#[tokio::test]
async fn empty_remote_discovery_does_not_clear_a_known_owned_seat() {
    let root = tempfile::tempdir().unwrap();
    let (client, _, task) = server(vec![(200, json!({"data":[]}))]).await;
    let vault = Arc::new(TemporaryVault::default());
    let provider =
        Provider::with_client(root.path().join("private").as_path(), client, vault.clone())
            .unwrap();
    account_setup(&provider, vault.as_ref());
    let request = create_request();
    let ticket = provider
        .create(request.clone())
        .unwrap()
        .allocation
        .unwrap();
    {
        let mut store = provider.store().unwrap();
        let mut next = store.state.clone();
        next.sessions[0].decision = Some(Acceptance::Accepted);
        next.sessions[0].remote = Remote::Seat {
            id: "6f43f953-df4d-4e09-b920-7f086a8d2db0".into(),
            connection_reference: None,
        };
        store.save(next).unwrap();
    }
    assert!(matches!(
        provider
            .discover(DiscoverSessions {
                scope: request.scope
            })
            .await,
        Err(Error {
            code: ProviderErrorCode::OutcomeUnknown,
            ..
        })
    ));
    assert!(
        !provider
            .store()
            .unwrap()
            .state
            .session(&ticket.session)
            .unwrap()
            .terminal()
    );
    task.await.unwrap();
}

#[test]
fn media_admission_preserves_observed_color_and_intersects_real_capabilities() {
    let offer = offer();
    let facts = MediaFacts {
        video: VideoFormat {
            encoding: VideoEncoding::H264AnnexB,
            width: 1920,
            height: 1080,
            fps: 60,
            bit_depth: 8,
            chroma: Chroma::Yuv420,
            color: ColorDescription {
                range: ColorRange::Full,
                primaries: Primaries::Bt709,
                transfer: Transfer::Srgb,
                matrix: Matrix::Bt709,
                chroma_location: ChromaLocation::Center,
            },
        },
        audio: Some(AudioFormat {
            codec: AudioCodec::Opus,
            sample_rate: 48000,
            channels: 2,
        }),
        input: boosteroid_media::input::capabilities(),
    };
    let accepted = admit_media(&offer, facts.clone()).unwrap();
    assert_eq!(accepted.video, facts.video);
    assert_eq!(accepted.input.gamepad_slots, 1);
    assert!(!accepted.input.rumble && !accepted.input.text && !accepted.input.relative_mouse);
    assert_eq!(accepted.audio, facts.audio);
    let mut oversized = facts.clone();
    oversized.video.width = 4096;
    assert!(admit_media(&offer, oversized).is_err());
    let mut non_worker_rate = facts;
    non_worker_rate.video.fps = 50;
    assert!(admit_media(&offer, non_worker_rate).is_err());
}

#[tokio::test]
async fn healthy_media_authorization_survives_control_restart_and_blocks_preflight_reentry() {
    let root = tempfile::tempdir().unwrap();
    let vault = Arc::new(TemporaryVault::default());
    let client = BoosteroidClient::production().unwrap();
    let provider = Provider::with_client(
        root.path().join("private").as_path(),
        client.clone(),
        vault.clone(),
    )
    .unwrap();
    account_setup(&provider, vault.as_ref());
    let ticket = provider
        .create(create_request())
        .unwrap()
        .allocation
        .unwrap();
    {
        let mut store = provider.store().unwrap();
        let mut next = store.state.clone();
        let session = &mut next.sessions[0];
        session.decision = Some(Acceptance::Accepted);
        session.remote = Remote::Seat {
            id: "6f43f953-df4d-4e09-b920-7f086a8d2db0".into(),
            connection_reference: Some("fixture-private-reference".into()),
        };
        session.media = Some(MediaFacts {
            video: VideoFormat {
                encoding: VideoEncoding::H264AnnexB,
                width: 1920,
                height: 1080,
                fps: 60,
                bit_depth: 8,
                chroma: Chroma::Yuv420,
                color: ColorDescription {
                    range: ColorRange::Limited,
                    primaries: Primaries::Bt709,
                    transfer: Transfer::Bt709,
                    matrix: Matrix::Bt709,
                    chroma_location: ChromaLocation::Left,
                },
            },
            audio: None,
            input: offer().input,
        });
        store.save(next).unwrap();
        store.writer.activate_session(&ticket.session).unwrap();
    }
    let worker =
        lock_worker_session(root.path().join("private").as_path(), &ticket.session).unwrap();
    drop(provider);
    let provider =
        Provider::with_client(root.path().join("private").as_path(), client, vault).unwrap();
    provider.resume().unwrap();
    assert!(provider.workflows.lock().unwrap().is_empty());
    assert!(matches!(
        authorization_status(root.path().join("private").as_path(), &ticket.session).unwrap(),
        Some(SessionAuthorization::Active { .. })
    ));
    assert!(matches!(
        provider
            .prepare(PrepareSession {
                session: ticket.session,
                offer: offer()
            })
            .await,
        Err(Error {
            code: ProviderErrorCode::BusyBeforeDispatch,
            ..
        })
    ));
    drop(worker);
}

#[tokio::test]
async fn readonly_library_refreshes_once_and_persists_rotation_outside_journal() {
    let root = tempfile::tempdir().unwrap();
    let (client,count,task) = server(vec![
        (401,json!({"message":"expired"})),
        (200,json!({"data":{"access_token":"rotated-access","refresh_token":"rotated-refresh"}})),
        (200,json!({"data":{"id":12345,"name":"Fixture user"}})),
        (200,json!({"data":[{"id":45,"name":"Fixture game","cover":"https://cdn.boosteroid.com/game.png"}]})),
    ]).await;
    let vault = Arc::new(TemporaryVault::default());
    let provider =
        Provider::with_client(root.path().join("private").as_path(), client, vault.clone())
            .unwrap();
    account_setup(&provider, vault.as_ref());
    let page = provider
        .library(CatalogRequest {
            scope: CatalogScope::Account {
                scope: AccountScope {
                    account: account(),
                    revision: 1,
                },
            },
            query: opennow_plugin_api::CatalogQuery::default(),
        })
        .await
        .unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].id.as_str(), "45");
    assert_eq!(page.coverage, Coverage::Unknown);
    assert_eq!(count.load(Ordering::SeqCst), 4);
    assert_eq!(
        provider
            .credential(&account())
            .await
            .unwrap()
            .access
            .expose_secret(),
        "rotated-access"
    );
    assert!(vault.get("fixture-credential").is_err());
    let bytes = provider
        .store()
        .unwrap()
        .writer
        .read_control_state()
        .unwrap()
        .unwrap();
    let content = String::from_utf8(bytes).unwrap();
    assert!(!content.contains("rotated-access") && !content.contains("rotated-refresh"));
    task.await.unwrap();
}

#[tokio::test]
async fn temporary_credentials_are_truthful_and_cannot_allocate_without_recovery_storage() {
    struct Unavailable;
    impl Vault for Unavailable {
        fn put(&self, _: &str, _: &str) -> Result<()> {
            Err(Error::new(ProviderErrorCode::ServiceUnavailable))
        }
        fn get(&self, _: &str) -> Result<Zeroizing<String>> {
            Err(Error::new(ProviderErrorCode::AuthRequired))
        }
        fn remove(&self, _: &str) -> Result<()> {
            Ok(())
        }
    }
    let root = tempfile::tempdir().unwrap();
    let provider = Provider::with_client(
        root.path().join("private").as_path(),
        BoosteroidClient::production().unwrap(),
        Arc::new(Unavailable),
    )
    .unwrap();
    let id = AttemptId::new("fixture-attempt").unwrap();
    provider.approvals.lock().await.insert(
        id.as_str().to_owned(),
        Approval {
            expires: now_ms() + 60_000,
            next_poll: 0,
            remember: true,
            state: ApprovalState::Authorized {
                credentials: Credentials {
                    access: SecretString::new("temporary-access").unwrap(),
                    refresh: SecretString::new("temporary-refresh").unwrap(),
                    authorization_data: None,
                },
                account: service::User {
                    id: "12345".into(),
                    name: "Fixture".into(),
                },
            },
        },
    );
    let completion = provider
        .complete_auth(CompleteAuth {
            attempt: id,
            proof: None,
        })
        .await
        .unwrap();
    let ProviderReply::AuthComplete(AuthState::SignedIn { account, revision }) = completion.reply
    else {
        panic!("completion shape")
    };
    assert_eq!(account.persistence, Persistence::Temporary);
    let mut request = create_request();
    request.scope.as_mut().unwrap().revision = revision;
    request.catalog_revision = catalog_revision(request.scope.as_ref().unwrap()).unwrap();
    let operation = request.operation.clone();
    let scope = request.scope.clone();
    assert!(matches!(
        provider.create(request),
        Err(Error {
            code: ProviderErrorCode::AuthRequired,
            ..
        })
    ));
    assert!(matches!(
        provider
            .reconcile(ReconcileSession {
                scope,
                operation,
                session: None
            })
            .unwrap(),
        Reconciliation::NotAllocated { .. }
    ));
}

#[tokio::test]
async fn queued_token_and_upstream_seat_never_replace_logical_identity() {
    let root = tempfile::tempdir().unwrap();
    let (client, count, task) = server(vec![
        (200, json!({"data":{"sessionToken":"fixture-queue-token"}})),
        (
            200,
            json!({"data":{"sessionId":"6f43f953-df4d-4e09-b920-7f086a8d2db0"}}),
        ),
    ])
    .await;
    let vault = Arc::new(TemporaryVault::default());
    let provider =
        Provider::with_client(root.path().join("private").as_path(), client, vault.clone())
            .unwrap();
    account_setup(&provider, vault.as_ref());
    let ticket = provider
        .create(create_request())
        .unwrap()
        .allocation
        .unwrap();
    provider
        .resolve(ResolveAllocation {
            operation: ticket.operation.clone(),
            receipt: ticket.receipt.clone(),
            decision: Acceptance::Accepted,
        })
        .unwrap();
    task.await.unwrap();
    for _ in 0..100 {
        if provider.workflows.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    assert_eq!(count.load(Ordering::SeqCst), 2);
    let store = provider.store().unwrap();
    let session = store.state.session(&ticket.session).unwrap();
    assert_eq!(session.key, ticket.session);
    assert!(
        matches!(&session.remote,Remote::Seat { id,.. } if id == "6f43f953-df4d-4e09-b920-7f086a8d2db0")
    );
    assert!(matches!(
        session.view().state,
        RemoteSessionState::Allocating
    ));
    let content = String::from_utf8(store.writer.read_control_state().unwrap().unwrap()).unwrap();
    assert!(!content.contains("fixture-queue-token"));
}

#[tokio::test]
async fn ndjson_receipt_lane_and_cancellation_work_while_catalog_io_is_saturated() {
    use std::num::NonZeroU64;
    let root = tempfile::tempdir().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = BoosteroidClient::fixture(
        reqwest::Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap(),
    )
    .unwrap();
    let received = Arc::new(AtomicUsize::new(0));
    let count = received.clone();
    let blocked = tokio::spawn(async move {
        let mut sockets = Vec::new();
        for _ in 0..8 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = vec![0; 8192];
            let _ = socket.read(&mut bytes).await.unwrap();
            count.fetch_add(1, Ordering::SeqCst);
            sockets.push(socket);
        }
        std::future::pending::<()>().await;
    });
    let vault = Arc::new(TemporaryVault::default());
    let provider =
        Provider::with_client(root.path().join("private").as_path(), client, vault.clone())
            .unwrap();
    account_setup(&provider, vault.as_ref());
    let ticket = provider
        .create(create_request())
        .unwrap()
        .allocation
        .unwrap();
    let (parent, child) = tokio::io::duplex(2 * 1024 * 1024);
    let (input, output) = tokio::io::split(child);
    let driver = tokio::spawn(dispatcher::run(
        provider,
        tokio::io::BufReader::new(input),
        output,
    ));
    let (read, mut write) = tokio::io::split(parent);
    let mut read = tokio::io::BufReader::new(read);
    async fn send(
        write: &mut tokio::io::WriteHalf<tokio::io::DuplexStream>,
        message: HostMessageV2,
    ) {
        let mut data = serde_json::to_vec(&message).unwrap();
        data.push(b'\n');
        write.write_all(&data).await.unwrap();
    }
    fn request(id: &str, request: ProviderRequest) -> HostMessageV2 {
        HostMessageV2::Request(Box::new(HostRequestV2 {
            v: Version2,
            epoch: NonZeroU64::new(1).unwrap(),
            id: text(id).unwrap(),
            timeout_ms: 30_000,
            request,
        }))
    }
    send(
        &mut write,
        request(
            "hello",
            ProviderRequest::Hello(ProviderHello {
                plugin_id: PluginId::new(PLUGIN_ID).unwrap(),
                version: text(VERSION).unwrap(),
                capabilities: List::new(capabilities()).unwrap(),
            }),
        ),
    )
    .await;
    dispatcher::read_frame(&mut read).await.unwrap().unwrap();
    for index in 0..8 {
        send(
            &mut write,
            request(
                &format!("catalog-{index}"),
                ProviderRequest::CatalogLibrary(CatalogRequest {
                    scope: CatalogScope::Account {
                        scope: AccountScope {
                            account: account(),
                            revision: 1,
                        },
                    },
                    query: opennow_plugin_api::CatalogQuery::default(),
                }),
            ),
        )
        .await;
    }
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while received.load(Ordering::SeqCst) != 8 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    send(
        &mut write,
        request(
            "receipt",
            ProviderRequest::SessionResolveAllocation(ResolveAllocation {
                operation: ticket.operation,
                receipt: ticket.receipt,
                decision: Acceptance::Rejected,
            }),
        ),
    )
    .await;
    let frame = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        dispatcher::read_frame(&mut read),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    let PluginMessageV2::Response(response) = serde_json::from_slice(&frame).unwrap();
    assert_eq!(response.id.as_str(), "receipt");
    assert!(matches!(response.outcome, ProviderOutcome::Success { .. }));
    for index in 0..8 {
        send(
            &mut write,
            HostMessageV2::Cancel {
                v: Version2,
                epoch: NonZeroU64::new(1).unwrap(),
                id: text(format!("catalog-{index}")).unwrap(),
            },
        )
        .await;
    }
    for _ in 0..8 {
        let frame = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            dispatcher::read_frame(&mut read),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        let PluginMessageV2::Response(response) = serde_json::from_slice(&frame).unwrap();
        assert!(matches!(
            response.outcome,
            ProviderOutcome::Failure {
                error: ProviderError {
                    code: ProviderErrorCode::Cancelled,
                    ..
                }
            }
        ));
    }
    send(
        &mut write,
        request("shutdown", ProviderRequest::Shutdown(Empty {})),
    )
    .await;
    dispatcher::read_frame(&mut read).await.unwrap().unwrap();
    driver.await.unwrap().unwrap();
    blocked.abort();
}
