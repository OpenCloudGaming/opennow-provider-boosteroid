use crate::{Completion, Error, Provider, Result};
use opennow_plugin_api::MAX_FRAME_BYTES;
use opennow_plugin_api::provider::*;
use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, Semaphore, mpsc};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

pub async fn read_frame<R: AsyncBufRead + Unpin>(reader: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    loop {
        let buffer = reader.fill_buf().await?;
        if buffer.is_empty() {
            return if bytes.is_empty() {
                Ok(None)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Incomplete protocol frame",
                ))
            };
        }
        let newline = buffer.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(buffer.len(), |index| index + 1);
        if bytes.len().saturating_add(consumed) > MAX_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Oversized protocol frame",
            ));
        }
        bytes.extend_from_slice(&buffer[..consumed]);
        reader.consume(consumed);
        if newline.is_some() {
            return Ok(Some(bytes));
        }
    }
}

fn response(request: &HostRequestV2, completion: Result<Completion>) -> ProviderResponseV2 {
    let (outcome, effects, allocation) = match completion {
        Ok(completion) => (
            ProviderOutcome::success(completion.reply),
            List::new(completion.effects).unwrap_or_default(),
            completion.allocation,
        ),
        Err(error) => (
            ProviderOutcome::Failure {
                error: error.public(),
            },
            List::default(),
            None,
        ),
    };
    let reply = ProviderResponseV2 {
        v: Version2,
        epoch: request.epoch,
        id: request.id.clone(),
        outcome,
        effects,
        allocation,
    };
    if reply.validate_for(request).is_err() {
        return ProviderResponseV2 {
            v: Version2,
            epoch: request.epoch,
            id: request.id.clone(),
            outcome: ProviderOutcome::Failure {
                error: Error::internal().public(),
            },
            effects: List::default(),
            allocation: None,
        };
    }
    reply
}

fn receipt(request: &ProviderRequest) -> bool {
    matches!(
        request,
        ProviderRequest::SessionResolveAllocation(_) | ProviderRequest::SessionStop(_)
    )
}

fn session(request: &ProviderRequest) -> bool {
    matches!(
        request,
        ProviderRequest::SessionCreate(_)
            | ProviderRequest::SessionReconcile(_)
            | ProviderRequest::SessionPoll(_)
            | ProviderRequest::SessionPrepare(_)
            | ProviderRequest::SessionClaim(_)
            | ProviderRequest::SessionDiscover(_)
    )
}

fn cancellable(request: &ProviderRequest) -> bool {
    matches!(
        request,
        ProviderRequest::AuthPoll(_)
            | ProviderRequest::CatalogLibrary(_)
            | ProviderRequest::CatalogDetails(_)
            | ProviderRequest::LaunchInspect(_)
            | ProviderRequest::SessionPoll(_)
            | ProviderRequest::SessionDiscover(_)
            | ProviderRequest::SessionPrepare(_)
            | ProviderRequest::AuthStatus(_)
            | ProviderRequest::AccountsList(_)
    )
}

pub async fn run<R, W>(provider: Arc<Provider>, mut input: R, mut output: W) -> io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let first = read_frame(&mut input)
        .await?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "Hello required"))?;
    let HostMessageV2::Request(first) = HostMessageV2::decode(&first)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid hello"))?
    else {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Hello required"));
    };
    if !matches!(first.request, ProviderRequest::Hello(_)) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Hello required"));
    }
    let hello = provider.handle(first.request.clone()).await;
    let approved = hello.is_ok();
    let bytes = serde_json::to_vec(&PluginMessageV2::Response(response(&first, hello)))
        .map_err(io::Error::other)?;
    output.write_all(&bytes).await?;
    output.write_all(b"\n").await?;
    output.flush().await?;
    if !approved {
        return Ok(());
    }
    provider
        .resume()
        .map_err(|_| io::Error::other("Provider recovery failed"))?;
    let epoch = first.epoch;
    let lanes = [
        Arc::new(Semaphore::new(8)),
        Arc::new(Semaphore::new(4)),
        Arc::new(Semaphore::new(4)),
    ];
    let inflight = Arc::new(Mutex::new(HashMap::<String, CancellationToken>::new()));
    let (send, mut receive) = mpsc::channel::<ProviderResponseV2>(32);
    let writer = tokio::spawn(async move {
        while let Some(response) = receive.recv().await {
            let bytes = serde_json::to_vec(&PluginMessageV2::Response(response))
                .map_err(io::Error::other)?;
            if bytes.len() >= MAX_FRAME_BYTES {
                return Err(io::Error::other("Response limit exceeded"));
            }
            output.write_all(&bytes).await?;
            output.write_all(b"\n").await?;
            output.flush().await?;
        }
        Ok::<(), io::Error>(())
    });
    let mut tasks = JoinSet::new();
    let mut read_error = None;
    loop {
        while tasks.try_join_next().is_some() {}
        let frame = match read_frame(&mut input).await {
            Ok(Some(frame)) => frame,
            Ok(None) => break,
            Err(error) => {
                read_error = Some(error);
                break;
            }
        };
        let message = match HostMessageV2::decode(&frame) {
            Ok(message) => message,
            Err(_) => {
                read_error = Some(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid protocol frame",
                ));
                break;
            }
        };
        match message {
            HostMessageV2::Cancel {
                epoch: cancel_epoch,
                id,
                ..
            } => {
                if cancel_epoch != epoch {
                    continue;
                }
                if let Some(cancel) = inflight.lock().await.get(id.as_str()) {
                    cancel.cancel();
                }
            }
            HostMessageV2::Request(request) => {
                if request.epoch != epoch || matches!(request.request, ProviderRequest::Hello(_)) {
                    read_error = Some(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Process epoch mismatch",
                    ));
                    break;
                }
                if matches!(request.request, ProviderRequest::Shutdown(_)) {
                    provider.shutdown();
                    let _ = send
                        .send(response(
                            &request,
                            provider.handle(request.request.clone()).await,
                        ))
                        .await;
                    break;
                }
                let lane = if receipt(&request.request) {
                    2
                } else if session(&request.request) {
                    1
                } else {
                    0
                };
                let permit = match lanes[lane].clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        if send
                            .send(response(
                                &request,
                                Err(Error::new(ProviderErrorCode::BusyBeforeDispatch)),
                            ))
                            .await
                            .is_err()
                        {
                            break;
                        }
                        continue;
                    }
                };
                let cancellation = CancellationToken::new();
                {
                    let mut active = inflight.lock().await;
                    if active.contains_key(request.id.as_str()) {
                        read_error = Some(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Duplicate request ID",
                        ));
                        break;
                    }
                    active.insert(request.id.as_str().to_owned(), cancellation.clone());
                }
                let active = inflight.clone();
                let target = send.clone();
                let provider = provider.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let result = if cancellable(&request.request) {
                        tokio::select! {
                            _ = cancellation.cancelled() => Err(Error::new(ProviderErrorCode::Cancelled)),
                            _ = tokio::time::sleep(Duration::from_millis(u64::from(request.timeout_ms))) => Err(Error::new(ProviderErrorCode::Cancelled)),
                            result = provider.handle(request.request.clone()) => result,
                        }
                    } else { provider.handle(request.request.clone()).await };
                    let _ = target.send(response(&request, result)).await;
                    active.lock().await.remove(request.id.as_str());
                });
            }
        }
    }
    provider.shutdown();
    for cancel in inflight.lock().await.values() {
        cancel.cancel();
    }
    let drained = tokio::time::timeout(Duration::from_secs(35), async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        tasks.abort_all();
    }
    drop(send);
    let written = tokio::time::timeout(Duration::from_secs(2), writer).await;
    if let Some(error) = read_error {
        return Err(error);
    }
    match written {
        Ok(Ok(result)) => result,
        _ => Err(io::Error::other("Protocol writer did not finish")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    #[tokio::test]
    async fn framing_is_bounded_and_rejects_partial_eof() {
        let mut input = BufReader::new(&b"one\ntwo\n"[..]);
        assert_eq!(read_frame(&mut input).await.unwrap().unwrap(), b"one\n");
        assert_eq!(read_frame(&mut input).await.unwrap().unwrap(), b"two\n");
        assert!(read_frame(&mut input).await.unwrap().is_none());
        assert!(
            read_frame(&mut BufReader::new(&b"partial"[..]))
                .await
                .is_err()
        );
        let bytes = vec![b'x'; MAX_FRAME_BYTES + 1];
        assert!(
            read_frame(&mut BufReader::new(bytes.as_slice()))
                .await
                .is_err()
        );
    }

    #[test]
    fn receipt_and_cleanup_requests_never_share_catalog_capacity() {
        let key = SessionKey {
            account: None,
            remote_id: SessionId::new("session").unwrap(),
        };
        assert!(receipt(&ProviderRequest::SessionStop(StopSession {
            session: key,
            operation: OperationId::new("stop").unwrap()
        })));
        assert!(!receipt(&ProviderRequest::AuthStatus(Empty {})));
        assert!(!cancellable(&ProviderRequest::SessionResolveAllocation(
            ResolveAllocation {
                operation: OperationId::new("op").unwrap(),
                receipt: ReceiptId::new("receipt").unwrap(),
                decision: Acceptance::Rejected
            }
        )));
    }
}
