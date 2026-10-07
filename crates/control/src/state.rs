use crate::{Error, Result};
use boosteroid_common::AuthorizationWriter;
use opennow_plugin_api::media::{AudioFormat, InputCapabilities, VideoFormat};
use opennow_plugin_api::provider::*;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const MAX_SESSIONS: usize = 64;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Account {
    pub public: PublicAccount,
    pub credential: String,
    #[serde(default)]
    pub refresh_pending: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "phase", deny_unknown_fields)]
pub enum Remote {
    NotDispatched,
    EnqueueDispatching,
    Enqueued {
        token_reference: String,
    },
    StartDispatching,
    Seat {
        id: String,
        connection_reference: Option<String>,
    },
    Unknown,
    Terminal {
        reason: TerminalReason,
        #[serde(default)]
        upstream_id: Option<String>,
    },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Session {
    pub request: CreateSession,
    pub key: SessionKey,
    pub receipt: ReceiptId,
    pub decision: Option<Acceptance>,
    pub remote: Remote,
    pub stop_operations: Vec<OperationId>,
    pub revoked: bool,
    #[serde(default)]
    pub media: Option<MediaFacts>,
    #[serde(default)]
    pub preparation_error: Option<ProviderErrorCode>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaFacts {
    pub video: VideoFormat,
    pub audio: Option<AudioFormat>,
    pub input: InputCapabilities,
}

impl Session {
    pub fn view(&self) -> SessionView {
        let state = match &self.remote {
            Remote::Seat { .. } if self.media.is_some() && !self.revoked => {
                RemoteSessionState::Ready
            }
            Remote::Enqueued { .. } => RemoteSessionState::Queued {
                position: None,
                wait_seconds: None,
            },
            Remote::Terminal { reason, .. } => RemoteSessionState::Finished { reason: *reason },
            _ => RemoteSessionState::Allocating,
        };
        SessionView {
            key: self.key.clone(),
            target: self.request.target.clone(),
            state,
        }
    }

    pub fn ticket(&self) -> AllocationTicket {
        AllocationTicket {
            operation: self.request.operation.clone(),
            receipt: self.receipt.clone(),
            session: self.key.clone(),
        }
    }

    pub fn terminal(&self) -> bool {
        matches!(self.remote, Remote::Terminal { .. })
    }

    pub fn ambiguous(&self) -> bool {
        matches!(
            self.remote,
            Remote::Unknown | Remote::EnqueueDispatching | Remote::StartDispatching
        )
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rejected {
    pub request: CreateSession,
    pub code: ProviderErrorCode,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    version: u32,
    pub revision: u64,
    pub selected: Option<AccountKey>,
    pub accounts: Vec<Account>,
    pub sessions: Vec<Session>,
    pub rejected: Vec<Rejected>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            version: 1,
            revision: 1,
            selected: None,
            accounts: vec![],
            sessions: vec![],
            rejected: vec![],
        }
    }
}

impl State {
    fn validate(&self) -> Result<()> {
        if self.version != 1
            || self.revision > MAX_PUBLIC_REVISION
            || self.accounts.len() > 64
            || self.sessions.len() > MAX_SESSIONS
            || self.rejected.len() > 128
        {
            return Err(Error::internal());
        }
        for (index, account) in self.accounts.iter().enumerate() {
            if self.accounts[..index]
                .iter()
                .any(|a| a.public.key == account.public.key)
            {
                return Err(Error::internal());
            }
        }
        for (index, session) in self.sessions.iter().enumerate() {
            session
                .request
                .offer
                .validate()
                .map_err(|_| Error::internal())?;
            if session.key.account != session.request.scope.as_ref().map(|s| s.account.clone())
                || session.stop_operations.len() > 64
                || self.sessions[..index].iter().any(|s| {
                    s.key == session.key
                        || s.request.operation == session.request.operation
                        || s.receipt == session.receipt
                })
                || self
                    .rejected
                    .iter()
                    .any(|r| r.request.operation == session.request.operation)
            {
                return Err(Error::internal());
            }
            if let Some(media) = &session.media {
                media.video.validate().map_err(|_| Error::internal())?;
                if let Some(audio) = &media.audio {
                    audio.validate().map_err(|_| Error::internal())?;
                }
                if media.input.gamepad_slots > 4
                    || !matches!(
                        session.remote,
                        Remote::Seat {
                            connection_reference: Some(_),
                            ..
                        }
                    )
                {
                    return Err(Error::internal());
                }
            }
        }
        Ok(())
    }

    pub fn account(&self, key: &AccountKey) -> Result<&Account> {
        self.accounts
            .iter()
            .find(|a| &a.public.key == key)
            .ok_or_else(|| Error::new(ProviderErrorCode::AuthRequired))
    }

    pub fn scope(&self, scope: Option<&AccountScope>) -> Result<&Account> {
        let scope = scope.ok_or_else(|| Error::new(ProviderErrorCode::AuthRequired))?;
        if scope.revision != self.revision || self.selected.as_ref() != Some(&scope.account) {
            return Err(Error::new(ProviderErrorCode::ScopeChanged));
        }
        let account = self.account(&scope.account)?;
        if account.public.reauthentication_required {
            return Err(Error::new(ProviderErrorCode::AuthRequired));
        }
        Ok(account)
    }

    pub fn session(&self, key: &SessionKey) -> Result<&Session> {
        self.sessions
            .iter()
            .find(|s| &s.key == key)
            .ok_or_else(|| Error::new(ProviderErrorCode::SessionNotFound))
    }

    pub fn occupied(&self, key: &AccountKey) -> bool {
        self.sessions
            .iter()
            .any(|s| s.key.account.as_ref() == Some(key) && !s.terminal())
    }

    pub fn advance_revision(&mut self) -> Result<()> {
        if self.revision >= MAX_PUBLIC_REVISION {
            return Err(Error::internal());
        }
        self.revision += 1;
        Ok(())
    }
}

pub struct Store {
    pub state: State,
    pub writer: AuthorizationWriter,
    pub root: PathBuf,
}

impl Store {
    pub fn open(root: &Path) -> Result<Self> {
        let writer = AuthorizationWriter::open(root).map_err(|_| Error::internal())?;
        let state = match writer.read_control_state().map_err(|_| Error::internal())? {
            Some(bytes) => {
                serde_json::from_slice::<State>(&bytes).map_err(|_| Error::internal())?
            }
            None => State::default(),
        };
        state.validate()?;
        Ok(Self {
            state,
            writer,
            root: root.to_owned(),
        })
    }

    pub fn save(&mut self, next: State) -> Result<()> {
        next.validate()?;
        let bytes = serde_json::to_vec(&next).map_err(|_| Error::internal())?;
        self.writer
            .write_control_state(&bytes)
            .map_err(|_| Error::internal())?;
        self.state = next;
        Ok(())
    }
}
