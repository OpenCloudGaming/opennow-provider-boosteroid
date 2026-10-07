pub mod dispatcher;
pub mod service;
mod state;
pub mod vault;

use boosteroid_common::{
    GatewayConnection, PLUGIN_ID, SessionAuthorization, VERSION, authorization_status,
    lock_worker_session,
};
use opennow_plugin_api::provider::*;
use opennow_plugin_api::{Coverage, PluginId};
use serde::{Deserialize, Serialize};
use service::{Application, BoosteroidClient, Credentials};
use sha2::{Digest, Sha256};
use state::{Account, MAX_SESSIONS, MediaFacts, Rejected, Remote, Session, Store};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex as AsyncMutex, Semaphore};
use tokio_util::sync::CancellationToken;
use vault::{CredentialVault, TemporaryVault, Vault};
use zeroize::Zeroizing;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    pub code: ProviderErrorCode,
    pub retry_after_ms: Option<u32>,
}

impl Error {
    pub fn new(code: ProviderErrorCode) -> Self {
        Self {
            code,
            retry_after_ms: None,
        }
    }
    pub fn internal() -> Self {
        Self::new(ProviderErrorCode::InternalError)
    }
    pub fn invalid() -> Self {
        Self::new(ProviderErrorCode::InvalidRequest)
    }
    pub fn schema() -> Self {
        Self::new(ProviderErrorCode::OutcomeUnknown)
    }
    pub fn public(self) -> ProviderError {
        ProviderError {
            code: self.code,
            retry_after_ms: self.retry_after_ms,
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
fn random(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4())
}
fn text<const N: usize>(value: impl Into<String>) -> Result<Text<N>> {
    Text::new(value).map_err(|_| Error::invalid())
}

pub fn capabilities() -> Vec<Capability> {
    vec![
        Capability::AuthBrowser,
        Capability::Accounts,
        Capability::LibraryCatalog,
        Capability::CatalogDetails,
        Capability::Launch,
        Capability::Sessions,
        Capability::MediaWorker,
    ]
}

enum ApprovalState {
    Pending {
        code: SecretString,
    },
    Authorized {
        credentials: Credentials,
        account: service::User,
    },
}

struct Approval {
    expires: u64,
    next_poll: u64,
    remember: bool,
    state: ApprovalState,
}

pub struct Provider {
    store: Mutex<Store>,
    client: BoosteroidClient,
    durable: Arc<dyn Vault>,
    temporary: Arc<TemporaryVault>,
    approvals: AsyncMutex<HashMap<String, Approval>>,
    refresh_locks: Mutex<HashMap<String, Arc<AsyncMutex<()>>>>,
    workflows: Mutex<HashMap<String, CancellationToken>>,
    identity_mutation: AsyncMutex<()>,
    vault_slots: Arc<Semaphore>,
    shutdown: CancellationToken,
}

pub struct Completion {
    pub reply: ProviderReply,
    pub allocation: Option<AllocationTicket>,
    pub effects: Vec<ProviderEffect>,
}

impl Completion {
    fn reply(reply: ProviderReply) -> Self {
        Self {
            reply,
            allocation: None,
            effects: vec![],
        }
    }
}

impl Provider {
    pub fn open(root: &Path) -> Result<Arc<Self>> {
        Self::with_client(
            root,
            BoosteroidClient::production()?,
            Arc::new(CredentialVault),
        )
    }

    fn with_client(
        root: &Path,
        client: BoosteroidClient,
        durable: Arc<dyn Vault>,
    ) -> Result<Arc<Self>> {
        let provider = Arc::new(Self {
            store: Mutex::new(Store::open(root)?),
            client,
            durable,
            temporary: Arc::new(TemporaryVault::default()),
            approvals: AsyncMutex::new(HashMap::new()),
            refresh_locks: Mutex::new(HashMap::new()),
            workflows: Mutex::new(HashMap::new()),
            identity_mutation: AsyncMutex::new(()),
            vault_slots: Arc::new(Semaphore::new(4)),
            shutdown: CancellationToken::new(),
        });
        provider.recover()?;
        Ok(provider)
    }

    fn store(&self) -> Result<MutexGuard<'_, Store>> {
        self.store.lock().map_err(|_| Error::internal())
    }

    fn recover(&self) -> Result<()> {
        let mut store = self.store()?;
        let mut next = store.state.clone();
        let mut auth_changed = false;
        for account in &mut next.accounts {
            if (account.public.persistence != Persistence::Durable || account.refresh_pending)
                && !account.public.reauthentication_required
            {
                account.public.reauthentication_required = true;
                auth_changed = true;
            }
        }
        if auth_changed {
            next.advance_revision()?;
        }
        for session in &mut next.sessions {
            match authorization_status(&store.root, &session.key).map_err(|_| Error::internal())? {
                Some(SessionAuthorization::Revoked { .. }) => {
                    session.revoked = true;
                    if session.remote == Remote::NotDispatched {
                        session.remote = Remote::Terminal {
                            reason: TerminalReason::UserStopped,
                            upstream_id: None,
                        };
                    }
                }
                Some(SessionAuthorization::Pending { .. })
                    if session.decision == Some(Acceptance::Accepted) && !session.revoked =>
                {
                    store
                        .writer
                        .activate_session(&session.key)
                        .map_err(|_| Error::internal())?;
                }
                Some(_) => {}
                None => return Err(Error::internal()),
            }
            if matches!(
                session.remote,
                Remote::EnqueueDispatching | Remote::StartDispatching
            ) {
                session.remote = Remote::Unknown;
            }
        }
        store.save(next)
    }

    pub fn resume(self: &Arc<Self>) -> Result<()> {
        let keys = self
            .store()?
            .state
            .sessions
            .iter()
            .filter(|s| {
                s.decision == Some(Acceptance::Accepted)
                    && !s.revoked
                    && !s.terminal()
                    && !s.ambiguous()
                    && s.media.is_none()
            })
            .map(|s| s.key.clone())
            .collect::<Vec<_>>();
        for key in keys {
            self.schedule(key)?;
        }
        Ok(())
    }

    pub fn shutdown(&self) {
        self.shutdown.cancel();
    }

    fn vault_for(&self, persistence: Persistence) -> Arc<dyn Vault> {
        if persistence == Persistence::Durable {
            self.durable.clone()
        } else {
            self.temporary.clone()
        }
    }

    async fn vault_io<T: Send + 'static>(
        &self,
        operation: impl FnOnce() -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let permit = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            self.vault_slots.clone().acquire_owned(),
        )
        .await
        .map_err(|_| Error::new(ProviderErrorCode::ServiceUnavailable))?
        .map_err(|_| Error::internal())?;
        let work = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            operation()
        });
        tokio::time::timeout(std::time::Duration::from_secs(15), work)
            .await
            .map_err(|_| Error::new(ProviderErrorCode::ServiceUnavailable))?
            .map_err(|_| Error::internal())?
    }

    async fn credential(&self, key: &AccountKey) -> Result<Credentials> {
        let account = self.store()?.state.account(key)?.clone();
        self.credential_record(account).await
    }

    async fn credential_record(&self, account: Account) -> Result<Credentials> {
        if account.public.reauthentication_required {
            return Err(Error::new(ProviderErrorCode::AuthRequired));
        }
        let vault = self.vault_for(account.public.persistence);
        let data = self
            .vault_io(move || vault.get(&account.credential))
            .await?;
        serde_json::from_str(&data).map_err(|_| Error::new(ProviderErrorCode::AuthRequired))
    }

    async fn refresh(
        self: &Arc<Self>,
        key: &AccountKey,
        failed: &Credentials,
    ) -> Result<Credentials> {
        let lock = {
            let mut locks = self.refresh_locks.lock().map_err(|_| Error::internal())?;
            locks
                .entry(key.account.as_str().to_owned())
                .or_insert_with(|| Arc::new(AsyncMutex::new(())))
                .clone()
        };
        let guard = lock.lock_owned().await;
        let old = self.store()?.state.account(key)?.clone();
        let provider = self.clone();
        let key = key.clone();
        let failed = failed.clone();
        let (send, receive) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let _guard = guard;
            let result = provider.rotate_credentials(&key, &failed, &old).await;
            if result.is_err() {
                let _ = provider.mark_reauthentication(&key, &old.credential);
            }
            let _ = send.send(result);
        });
        receive
            .await
            .map_err(|_| Error::new(ProviderErrorCode::AuthRequired))?
    }

    fn mark_reauthentication(&self, key: &AccountKey, expected_reference: &str) -> Result<()> {
        let mut store = self.store()?;
        let mut next = store.state.clone();
        let account = next
            .accounts
            .iter_mut()
            .find(|account| &account.public.key == key)
            .ok_or_else(|| Error::new(ProviderErrorCode::AuthRequired))?;
        if account.credential == expected_reference && !account.public.reauthentication_required {
            account.public.reauthentication_required = true;
            next.advance_revision()?;
            store.save(next)?;
        }
        Ok(())
    }

    async fn rotate_credentials(
        &self,
        key: &AccountKey,
        failed: &Credentials,
        old: &Account,
    ) -> Result<Credentials> {
        let current = self.credential_record(old.clone()).await?;
        if current.access != failed.access {
            return Ok(current);
        }
        {
            let mut store = self.store()?;
            let mut next = store.state.clone();
            let account = next
                .accounts
                .iter_mut()
                .find(|account| &account.public.key == key)
                .ok_or_else(|| Error::new(ProviderErrorCode::AuthRequired))?;
            if account.credential != old.credential {
                return Err(Error::new(ProviderErrorCode::ScopeChanged));
            }
            if account.refresh_pending {
                return Err(Error::new(ProviderErrorCode::AuthRequired));
            }
            account.refresh_pending = true;
            store.save(next)?;
        }
        let credentials = self.client.refresh(&current).await?;
        let identity = self.client.user(&credentials).await?;
        if identity.id != key.account.as_str() {
            return Err(Error::new(ProviderErrorCode::AuthenticationFailed));
        }
        let reference = random("credential");
        let data =
            Zeroizing::new(serde_json::to_string(&credentials).map_err(|_| Error::internal())?);
        let vault = self.vault_for(old.public.persistence);
        let target = reference.clone();
        self.vault_io(move || vault.put(&target, &data)).await?;
        {
            let mut store = self.store()?;
            let mut next = store.state.clone();
            let account = next
                .accounts
                .iter_mut()
                .find(|a| a.public.key == *key)
                .ok_or_else(|| Error::new(ProviderErrorCode::AuthRequired))?;
            if account.credential != old.credential {
                return Err(Error::new(ProviderErrorCode::ScopeChanged));
            }
            account.credential = reference;
            account.refresh_pending = false;
            store.save(next)?;
        }
        let vault = self.vault_for(old.public.persistence);
        let old_reference = old.credential.clone();
        let _ = self.vault_io(move || vault.remove(&old_reference)).await;
        Ok(credentials)
    }

    fn scope(&self, scope: &CatalogScope) -> Result<AccountScope> {
        let CatalogScope::Account { scope } = scope else {
            return Err(Error::new(ProviderErrorCode::AuthRequired));
        };
        self.store()?.state.scope(Some(scope))?;
        Ok(scope.clone())
    }

    fn auth_state(&self) -> Result<AuthState> {
        let store = self.store()?;
        let Some(key) = &store.state.selected else {
            return Ok(AuthState::SignedOut);
        };
        let account = store.state.account(key)?;
        Ok(AuthState::SignedIn {
            account: account.public.clone(),
            revision: store.state.revision,
        })
    }

    pub async fn handle(self: &Arc<Self>, request: ProviderRequest) -> Result<Completion> {
        use ProviderReply as R;
        use ProviderRequest as Q;
        let _identity_guard = if matches!(
            request,
            Q::AuthComplete(_)
                | Q::AuthLogout(_)
                | Q::AccountsRemove(_)
                | Q::AccountsSelect(_)
                | Q::SessionCreate(_)
        ) {
            Some(self.identity_mutation.lock().await)
        } else {
            None
        };
        let reply = match request {
            Q::Hello(hello) => {
                if hello.plugin_id.as_str() != PLUGIN_ID
                    || hello.version.as_str() != VERSION
                    || hello.capabilities.len() != capabilities().len()
                    || hello
                        .capabilities
                        .iter()
                        .any(|c| !capabilities().contains(c))
                {
                    return Err(Error::invalid());
                }
                R::Hello(ProviderHelloReply {
                    plugin_id: PluginId::new(PLUGIN_ID).map_err(|_| Error::internal())?,
                    version: text(VERSION)?,
                    protocol_version: 2,
                    capabilities: List::new(capabilities()).map_err(|_| Error::internal())?,
                    auth_kinds: List::new(vec![AuthKind::Browser])
                        .map_err(|_| Error::internal())?,
                })
            }
            Q::Shutdown(_) => {
                self.shutdown();
                R::Shutdown(Empty {})
            }
            Q::AuthAuthorities(_) => R::AuthAuthorities(
                List::new(vec![Authority {
                    id: AuthorityId::new("boosteroid").map_err(|_| Error::internal())?,
                    name: text("Boosteroid")?,
                }])
                .map_err(|_| Error::internal())?,
            ),
            Q::AuthStatus(_) => R::AuthStatus(self.auth_state()?),
            Q::AuthBegin(begin) => R::AuthBegin(self.begin_auth(begin).await?),
            Q::AuthPoll(attempt) => R::AuthPoll(self.poll_auth(attempt).await?),
            Q::AuthComplete(complete) => return self.complete_auth(complete).await,
            Q::AuthCancel(attempt) => {
                self.approvals.lock().await.remove(attempt.attempt.as_str());
                R::AuthCancel(Empty {})
            }
            Q::AccountsList(_) => R::AccountsList(self.accounts()?),
            Q::AccountsSelect(select) => {
                if select.pin.is_some() {
                    return Err(Error::new(ProviderErrorCode::UnsupportedFeature));
                }
                let mut store = self.store()?;
                store.state.account(&select.account)?;
                let mut next = store.state.clone();
                next.selected = Some(select.account);
                next.advance_revision()?;
                store.save(next)?;
                drop(store);
                return self.account_completion(R::AccountsSelect(self.auth_state()?));
            }
            Q::AccountsRemove(key) => {
                self.remove_account(&key, false).await?;
                return self.account_completion(R::AccountsRemove(self.accounts()?));
            }
            Q::AuthLogout(key) => {
                self.remove_account(&key, true).await?;
                return self.account_completion(R::AuthLogout(self.auth_state()?));
            }
            Q::CatalogLibrary(query) => R::CatalogLibrary(self.library(query).await?),
            Q::CatalogDetails(query) => R::CatalogDetails(self.details(query).await?),
            Q::LaunchInspect(query) => R::LaunchInspect(self.inspect(query).await?),
            Q::SessionCreate(create) => return self.create(create),
            Q::SessionResolveAllocation(resolve) => return self.resolve(resolve),
            Q::SessionPoll(key) => R::SessionPoll(self.poll_session(&key).await?),
            Q::SessionDiscover(query) => R::SessionDiscover(self.discover(query).await?),
            Q::SessionClaim(query) => R::SessionClaim(self.claim(query)?),
            Q::SessionReconcile(query) => {
                R::SessionReconcile(self.reconcile_observed(query).await?)
            }
            Q::SessionStop(stop) => R::SessionStop(self.stop_observed(stop).await?),
            Q::SessionPrepare(prepare) => R::SessionPrepare(self.prepare(prepare).await?),
            _ => return Err(Error::new(ProviderErrorCode::UnsupportedFeature)),
        };
        Ok(Completion::reply(reply))
    }

    async fn begin_auth(&self, begin: BeginAuth) -> Result<AuthState> {
        if begin.kind != AuthKind::Browser
            || begin
                .authority
                .as_ref()
                .is_some_and(|a| a.as_str() != "boosteroid")
        {
            return Err(Error::new(ProviderErrorCode::UnsupportedFeature));
        }
        let mut attempts = self.approvals.lock().await;
        attempts.retain(|_, a| a.expires > now_ms());
        if attempts.len() >= 8 {
            return Err(Error::new(ProviderErrorCode::BusyBeforeDispatch));
        }
        let id = random("auth");
        let code = uuid::Uuid::new_v4().to_string();
        let url = self.client.approval_url(&code)?;
        let expires = now_ms().saturating_add(300_000);
        attempts.insert(
            id.clone(),
            Approval {
                expires,
                next_poll: 0,
                remember: begin.remember,
                state: ApprovalState::Pending {
                    code: SecretString::new(code).map_err(|_| Error::internal())?,
                },
            },
        );
        Ok(AuthState::Pending {
            challenge: AuthChallenge::Browser {
                attempt: AttemptId::new(id).map_err(|_| Error::internal())?,
                authorization: SecretString::new(url).map_err(|_| Error::internal())?,
                expires_at_ms: expires,
                poll_after_ms: 3000,
            },
        })
    }

    async fn poll_auth(&self, query: AuthAttempt) -> Result<AuthState> {
        let (code, expires) = {
            let mut attempts = self.approvals.lock().await;
            let attempt = attempts
                .get_mut(query.attempt.as_str())
                .ok_or_else(Error::invalid)?;
            if attempt.expires <= now_ms() {
                attempts.remove(query.attempt.as_str());
                return Err(Error::new(ProviderErrorCode::AuthenticationFailed));
            }
            if matches!(attempt.state, ApprovalState::Authorized { .. }) {
                return Ok(AuthState::Authorized {
                    attempt: query.attempt,
                });
            }
            if attempt.next_poll > now_ms() {
                return Err(Error {
                    code: ProviderErrorCode::RateLimited,
                    retry_after_ms: Some(3000),
                });
            }
            attempt.next_poll = now_ms().saturating_add(3000);
            let ApprovalState::Pending { code } = &attempt.state else {
                return Err(Error::internal());
            };
            (code.clone(), attempt.expires)
        };
        let credentials = self.client.poll_auth(code.expose_secret()).await?;
        let Some(credentials) = credentials else {
            let attempts = self.approvals.lock().await;
            if !attempts.contains_key(query.attempt.as_str()) {
                return Err(Error::new(ProviderErrorCode::Cancelled));
            }
            return Ok(AuthState::Pending {
                challenge: AuthChallenge::Browser {
                    attempt: query.attempt,
                    authorization: SecretString::new(
                        self.client.approval_url(code.expose_secret())?,
                    )
                    .map_err(|_| Error::internal())?,
                    expires_at_ms: expires,
                    poll_after_ms: 3000,
                },
            });
        };
        let account = self.client.user(&credentials).await?;
        let mut attempts = self.approvals.lock().await;
        let attempt = attempts
            .get_mut(query.attempt.as_str())
            .ok_or_else(|| Error::new(ProviderErrorCode::Cancelled))?;
        if attempt.expires != expires || expires <= now_ms() {
            return Err(Error::new(ProviderErrorCode::AuthenticationFailed));
        }
        attempt.state = ApprovalState::Authorized {
            credentials,
            account,
        };
        Ok(AuthState::Authorized {
            attempt: query.attempt,
        })
    }

    async fn complete_auth(&self, complete: CompleteAuth) -> Result<Completion> {
        if complete.proof.is_some() {
            return Err(Error::invalid());
        }
        let attempt = self
            .approvals
            .lock()
            .await
            .remove(complete.attempt.as_str())
            .ok_or_else(Error::invalid)?;
        if attempt.expires <= now_ms() {
            return Err(Error::new(ProviderErrorCode::AuthenticationFailed));
        }
        let ApprovalState::Authorized {
            credentials,
            account,
        } = attempt.state
        else {
            return Err(Error::new(ProviderErrorCode::AuthenticationFailed));
        };
        let key = AccountKey {
            authority: AuthorityId::new("boosteroid").map_err(|_| Error::internal())?,
            account: AccountId::new(account.id).map_err(|_| Error::schema())?,
        };
        let reference = random("credential");
        let data =
            Zeroizing::new(serde_json::to_string(&credentials).map_err(|_| Error::internal())?);
        let vault = self.durable.clone();
        let target = reference.clone();
        let saved = if attempt.remember {
            let data = data.clone();
            self.vault_io(move || vault.put(&target, &data))
                .await
                .is_ok()
        } else {
            false
        };
        let persistence = if saved {
            Persistence::Durable
        } else {
            self.temporary.put(&reference, &data)?;
            Persistence::Temporary
        };
        let public = PublicAccount {
            key: key.clone(),
            name: text(account.name)?,
            persistence,
            reauthentication_required: false,
            pin_locked: false,
        };
        let revision = {
            let mut store = self.store()?;
            let mut next = store.state.clone();
            if let Some(existing) = next.accounts.iter_mut().find(|a| a.public.key == key) {
                *existing = Account {
                    public: public.clone(),
                    credential: reference,
                    refresh_pending: false,
                };
            } else {
                if next.accounts.len() >= 64 {
                    return Err(Error::new(ProviderErrorCode::BusyBeforeDispatch));
                }
                next.accounts.push(Account {
                    public: public.clone(),
                    credential: reference,
                    refresh_pending: false,
                });
            }
            next.selected = Some(key);
            next.advance_revision()?;
            let revision = next.revision;
            store.save(next)?;
            revision
        };
        Ok(Completion {
            reply: ProviderReply::AuthComplete(AuthState::SignedIn {
                account: public,
                revision,
            }),
            allocation: None,
            effects: vec![ProviderEffect::AuthChanged { revision }],
        })
    }

    fn accounts(&self) -> Result<Accounts> {
        let store = self.store()?;
        Ok(Accounts {
            accounts: List::new(
                store
                    .state
                    .accounts
                    .iter()
                    .map(|a| a.public.clone())
                    .collect(),
            )
            .map_err(|_| Error::internal())?,
            selected: store.state.selected.clone(),
            revision: store.state.revision,
        })
    }

    fn account_completion(&self, reply: ProviderReply) -> Result<Completion> {
        let revision = self.store()?.state.revision;
        Ok(Completion {
            reply,
            allocation: None,
            effects: vec![ProviderEffect::AuthChanged { revision }],
        })
    }

    async fn remove_account(&self, key: &AccountKey, logout: bool) -> Result<()> {
        let account = {
            let store = self.store()?;
            if store.state.occupied(key) {
                return Err(Error::new(ProviderErrorCode::CleanupRequired));
            }
            store.state.account(key)?.clone()
        };
        if logout {
            let credentials = self.credential(key).await?;
            self.client.logout(&credentials).await?;
        }
        {
            let mut store = self.store()?;
            if store.state.occupied(key) {
                return Err(Error::new(ProviderErrorCode::CleanupRequired));
            }
            let mut next = store.state.clone();
            next.accounts.retain(|a| a.public.key != *key);
            if next.selected.as_ref() == Some(key) {
                next.selected = None;
            }
            next.advance_revision()?;
            store.save(next)?;
        }
        let vault = self.vault_for(account.public.persistence);
        self.vault_io(move || vault.remove(&account.credential))
            .await?;
        self.refresh_locks
            .lock()
            .map_err(|_| Error::internal())?
            .remove(key.account.as_str());
        Ok(())
    }

    async fn library(self: &Arc<Self>, request: CatalogRequest) -> Result<GamePage> {
        let scope = self.scope(&request.scope)?;
        let page = match &request.query.cursor {
            Some(cursor) => {
                let cursor: Cursor = serde_json::from_str(cursor).map_err(|_| Error::invalid())?;
                if cursor.scope != scope
                    || cursor.query != request.query.query
                    || cursor.limit != request.query.limit
                    || !(2..=10_000).contains(&cursor.page)
                {
                    return Err(Error::new(ProviderErrorCode::ScopeChanged));
                }
                cursor.page
            }
            None => 1,
        };
        let auth = self.credential(&scope.account).await?;
        let apps = match self.client.library(&auth, page, request.query.limit).await {
            Err(error) if error.code == ProviderErrorCode::AuthRequired => {
                let auth = self.refresh(&scope.account, &auth).await?;
                self.client
                    .library(&auth, page, request.query.limit)
                    .await?
            }
            result => result?,
        };
        self.store()?.state.scope(Some(&scope))?;
        let full = apps.len() == usize::from(request.query.limit);
        let next_cursor = if full && page < 10_000 {
            Some(text(
                serde_json::to_string(&Cursor {
                    scope: scope.clone(),
                    query: request.query.query.clone(),
                    limit: request.query.limit,
                    page: page + 1,
                })
                .map_err(|_| Error::internal())?,
            )?)
        } else {
            None
        };
        let needle = request.query.query.to_lowercase();
        let summaries = apps
            .into_iter()
            .filter(|app| app.title.to_lowercase().contains(&needle))
            .map(summary)
            .collect::<Result<Vec<_>>>()?;
        let revision = catalog_revision(&scope)?;
        Ok(GamePage {
            items: List::new(summaries).map_err(|_| Error::schema())?,
            next_cursor,
            coverage: Coverage::Unknown,
            revision,
            scope: request.scope,
        })
    }

    async fn details(self: &Arc<Self>, request: GameRequest) -> Result<GameDetails> {
        let scope = self.scope(&request.scope)?;
        let id = app_id(&request.game)?;
        let auth = self.credential(&scope.account).await?;
        let app = match self.client.application(&auth, id).await {
            Err(error) if error.code == ProviderErrorCode::AuthRequired => {
                let auth = self.refresh(&scope.account, &auth).await?;
                self.client.application(&auth, id).await?
            }
            result => result?,
        };
        self.store()?.state.scope(Some(&scope))?;
        let description = app.description.clone().map(text).transpose()?;
        Ok(GameDetails {
            game: summary(app)?,
            description,
            variants: List::new(vec![GameVariant {
                id: VariantId::new("default").map_err(|_| Error::internal())?,
                label: text("Boosteroid")?,
                availability: Availability::Unknown,
            }])
            .map_err(|_| Error::internal())?,
            revision: catalog_revision(&scope)?,
            scope: request.scope,
        })
    }

    async fn inspect(self: &Arc<Self>, request: InspectLaunch) -> Result<LaunchDecision> {
        let scope = request
            .scope
            .ok_or_else(|| Error::new(ProviderErrorCode::AuthRequired))?;
        if request.target.variant.as_str() != "default"
            || request.catalog_revision != catalog_revision(&scope)?
        {
            return Err(Error::new(ProviderErrorCode::ScopeChanged));
        }
        self.details(GameRequest {
            scope: CatalogScope::Account {
                scope: scope.clone(),
            },
            game: request.target.game.clone(),
        })
        .await?;
        let account = self.store()?.state.scope(Some(&scope))?.clone();
        if account.public.persistence != Persistence::Durable {
            return Ok(LaunchDecision::Blocked {
                reason: Availability::Unavailable,
                message: text(
                    "Remember this account using secure operating-system storage before launching. Cleanup credentials must survive a restart.",
                )?,
            });
        }
        Ok(LaunchDecision::Ready {
            target: request.target,
            revision: request.catalog_revision,
        })
    }

    fn create(&self, request: CreateSession) -> Result<Completion> {
        let mut store = self.store()?;
        if let Some(session) = store
            .state
            .sessions
            .iter()
            .find(|s| s.request.operation == request.operation)
        {
            if session.request != request {
                return Err(Error::invalid());
            }
            return Ok(created(session));
        }
        if let Some(rejected) = store
            .state
            .rejected
            .iter()
            .find(|r| r.request.operation == request.operation)
        {
            if rejected.request != request {
                return Err(Error::invalid());
            }
            return Err(Error::new(rejected.code));
        }
        let preflight = (|| {
            let account = store.state.scope(request.scope.as_ref())?;
            if account.public.persistence != Persistence::Durable {
                return Err(Error::new(ProviderErrorCode::AuthRequired));
            }
            let scope = request.scope.as_ref().ok_or_else(Error::invalid)?;
            if request.catalog_revision != catalog_revision(scope)?
                || request.target.variant.as_str() != "default"
            {
                return Err(Error::new(ProviderErrorCode::ScopeChanged));
            }
            app_id(&request.target.game)?;
            request.offer.validate().map_err(|_| Error::invalid())?;
            boosteroid_media::input::validate_requested(&request.preferences.video)
                .map_err(|_| Error::new(ProviderErrorCode::UnsupportedFeature))?;
            let video = &request.preferences.video;
            if !request.offer.video_formats.iter().any(|support| {
                support.encoding == opennow_plugin_api::media::VideoEncoding::H264AnnexB
                    && support.bit_depth == video.bit_depth
                    && support.chroma == video.chroma
                    && support.max_width >= video.width
                    && support.max_height >= video.height
                    && support.max_fps >= video.fps.unwrap_or(60)
            }) {
                return Err(Error::new(ProviderErrorCode::UnsupportedFeature));
            }
            if !(220..=200_000).contains(&request.preferences.bitrate_kbps) {
                return Err(Error::new(ProviderErrorCode::UnsupportedFeature));
            }
            if request.offer.expires_at_ms <= now_ms() || request.preferences.video.hdr {
                return Err(Error::new(ProviderErrorCode::UnsupportedFeature));
            }
            if store.state.sessions.len() >= MAX_SESSIONS
                || store.state.sessions.iter().any(|s| !s.terminal())
            {
                return Err(Error::new(ProviderErrorCode::BusyBeforeDispatch));
            }
            Ok(account.public.key.clone())
        })();
        let account = match preflight {
            Ok(account) => account,
            Err(error) => {
                if store.state.rejected.len() >= 128 {
                    return Err(Error::new(ProviderErrorCode::OutcomeUnknown));
                }
                let mut next = store.state.clone();
                next.rejected.push(Rejected {
                    request,
                    code: error.code,
                });
                store.save(next)?;
                return Err(error);
            }
        };
        let session = Session {
            request,
            key: SessionKey {
                account: Some(account),
                remote_id: SessionId::new(random("boosteroid-session"))
                    .map_err(|_| Error::internal())?,
            },
            receipt: ReceiptId::new(random("receipt")).map_err(|_| Error::internal())?,
            decision: None,
            remote: Remote::NotDispatched,
            stop_operations: vec![],
            revoked: false,
            media: None,
            preparation_error: None,
        };
        store
            .writer
            .register_session(&session.key)
            .map_err(|_| Error::internal())?;
        let result = created(&session);
        let mut next = store.state.clone();
        next.sessions.push(session);
        store.save(next)?;
        Ok(result)
    }

    fn resolve(self: &Arc<Self>, request: ResolveAllocation) -> Result<Completion> {
        let key = {
            let mut store = self.store()?;
            let index = store
                .state
                .sessions
                .iter()
                .position(|s| {
                    s.request.operation == request.operation && s.receipt == request.receipt
                })
                .ok_or_else(Error::invalid)?;
            let old = &store.state.sessions[index];
            if old.decision.is_some_and(|d| d != request.decision) {
                return Err(Error::invalid());
            }
            let mut next = store.state.clone();
            let session = &mut next.sessions[index];
            session.decision = Some(request.decision);
            if request.decision == Acceptance::Rejected {
                store
                    .writer
                    .revoke_session(&session.key)
                    .map_err(|_| Error::internal())?;
                session.revoked = true;
                if session.remote == Remote::NotDispatched {
                    session.remote = Remote::Terminal {
                        reason: TerminalReason::AllocationRejected,
                        upstream_id: None,
                    };
                }
            }
            let key = session.key.clone();
            store.save(next)?;
            if request.decision == Acceptance::Accepted && !store.state.session(&key)?.revoked {
                store
                    .writer
                    .activate_session(&key)
                    .map_err(|_| Error::new(ProviderErrorCode::CleanupRequired))?;
            }
            key
        };
        if request.decision == Acceptance::Accepted && !self.store()?.state.session(&key)?.revoked {
            self.schedule(key.clone())?;
        }
        let store = self.store()?;
        let session = store.state.session(&key)?;
        let cleanup = if request.decision == Acceptance::Accepted || session.terminal() {
            CleanupState::Resolved
        } else {
            CleanupState::Unknown {
                operation: request.operation,
            }
        };
        Ok(Completion::reply(ProviderReply::SessionResolveAllocation(
            cleanup,
        )))
    }

    fn schedule(self: &Arc<Self>, key: SessionKey) -> Result<()> {
        if self.store()?.state.session(&key)?.media.is_some() {
            return Ok(());
        }
        let id = key.remote_id.as_str().to_owned();
        let mut workflows = self.workflows.lock().map_err(|_| Error::internal())?;
        if workflows.len() >= MAX_SESSIONS || workflows.contains_key(&id) {
            return Ok(());
        }
        let cancel = self.shutdown.child_token();
        workflows.insert(id.clone(), cancel.clone());
        let provider = self.clone();
        tokio::spawn(async move {
            let _ = provider.workflow(key, cancel).await;
            if let Ok(mut workflows) = provider.workflows.lock() {
                workflows.remove(&id);
            }
        });
        Ok(())
    }

    fn transition(&self, key: &SessionKey, expected: &Remote, next_remote: Remote) -> Result<()> {
        let mut store = self.store()?;
        let mut next = store.state.clone();
        let session = next
            .sessions
            .iter_mut()
            .find(|s| &s.key == key)
            .ok_or_else(|| Error::new(ProviderErrorCode::SessionNotFound))?;
        if session.remote != *expected
            || session.revoked
            || session.decision != Some(Acceptance::Accepted)
        {
            return Err(Error::new(ProviderErrorCode::CleanupRequired));
        }
        session.remote = next_remote;
        store.save(next)
    }

    async fn workflow(self: &Arc<Self>, key: SessionKey, cancel: CancellationToken) -> Result<()> {
        loop {
            if cancel.is_cancelled() {
                return Ok(());
            }
            let session = self.store()?.state.session(&key)?.clone();
            if session.revoked || session.terminal() || session.ambiguous() {
                return Ok(());
            }
            let account = key.account.as_ref().ok_or_else(Error::invalid)?;
            let auth = self.credential(account).await?;
            let app = app_id(&session.request.target.game)?;
            match &session.remote {
                Remote::NotDispatched => {
                    self.transition(&key, &Remote::NotDispatched, Remote::EnqueueDispatching)?;
                    let result = self.client.enqueue(&auth, app).await;
                    let data = match result {
                        Ok(data) => data,
                        Err(_) => {
                            self.mark_unknown(&key)?;
                            return Ok(());
                        }
                    };
                    if let Ok(id) = service::seat_id(&data) {
                        self.bind_seat(&key, id)?;
                    } else if let Ok(token) = service::queue_token(&data) {
                        let reference = random("queue");
                        let vault = self.durable.clone();
                        let target = reference.clone();
                        let saved = self
                            .vault_io(move || vault.put(&target, token.expose_secret()))
                            .await;
                        if saved.is_err() {
                            self.mark_unknown(&key)?;
                            return Ok(());
                        }
                        self.finish_mutation(
                            &key,
                            Remote::Enqueued {
                                token_reference: reference,
                            },
                        )?;
                    } else {
                        self.mark_unknown(&key)?;
                        return Ok(());
                    }
                }
                Remote::Enqueued { token_reference } => {
                    let vault = self.durable.clone();
                    let reference = token_reference.clone();
                    let raw = self.vault_io(move || vault.get(&reference)).await?;
                    let token = SecretString::new(raw.as_str()).map_err(|_| Error::internal())?;
                    self.transition(&key, &session.remote, Remote::StartDispatching)?;
                    match self
                        .client
                        .start(&auth, app, &token)
                        .await
                        .and_then(|data| service::seat_id(&data))
                    {
                        Ok(id) => self.bind_seat(&key, id)?,
                        Err(_) => {
                            self.mark_unknown(&key)?;
                            return Ok(());
                        }
                    }
                }
                Remote::Seat { .. } => {
                    let result = self.establish_media(&key, cancel.clone()).await;
                    if !cancel.is_cancelled() {
                        let mut store = self.store()?;
                        let mut next = store.state.clone();
                        if let Some(session) = next
                            .sessions
                            .iter_mut()
                            .find(|session| session.key == key && !session.revoked)
                        {
                            session.preparation_error = result.err().map(|error| error.code);
                            store.save(next)?;
                        }
                    }
                    return Ok(());
                }
                _ => return Ok(()),
            }
        }
    }

    fn bind_seat(&self, key: &SessionKey, id: String) -> Result<()> {
        self.finish_mutation(
            key,
            Remote::Seat {
                id,
                connection_reference: None,
            },
        )
    }

    fn mark_unknown(&self, key: &SessionKey) -> Result<()> {
        self.finish_mutation(key, Remote::Unknown)
    }

    fn finish_mutation(&self, key: &SessionKey, remote: Remote) -> Result<()> {
        let mut store = self.store()?;
        let mut next = store.state.clone();
        let session = next
            .sessions
            .iter_mut()
            .find(|s| &s.key == key)
            .ok_or_else(|| Error::new(ProviderErrorCode::SessionNotFound))?;
        if !matches!(
            session.remote,
            Remote::EnqueueDispatching | Remote::StartDispatching | Remote::Unknown
        ) {
            return Err(Error::new(ProviderErrorCode::OutcomeUnknown));
        }
        session.remote = remote;
        store.save(next)
    }

    async fn poll_session(self: &Arc<Self>, key: &SessionKey) -> Result<SessionView> {
        let session = self.store()?.state.session(key)?.clone();
        if session.ambiguous() || session.revoked && !session.terminal() {
            return Err(Error::new(ProviderErrorCode::OutcomeUnknown));
        }
        if let Some(code) = session.preparation_error {
            return Err(Error::new(code));
        }
        if let Remote::Seat { id, .. } = &session.remote {
            let auth = self
                .credential(key.account.as_ref().ok_or_else(Error::invalid)?)
                .await?;
            let data = match self.client.details(&auth, id).await {
                Err(error) if error.code == ProviderErrorCode::AuthRequired => {
                    let auth = self
                        .refresh(key.account.as_ref().ok_or_else(Error::invalid)?, &auth)
                        .await?;
                    self.client.details(&auth, id).await?
                }
                result => result?,
            };
            if let Some(reason) = service::terminal_reason(&data, id)? {
                self.record_terminal(key, id, reason)?;
                return Ok(self.store()?.state.session(key)?.view());
            }
        }
        Ok(session.view())
    }

    fn record_terminal(
        &self,
        key: &SessionKey,
        expected_seat: &str,
        reason: TerminalReason,
    ) -> Result<()> {
        let mut store = self.store()?;
        let session = store.state.session(key)?;
        if !matches!(&session.remote,Remote::Seat { id,.. } if id == expected_seat) {
            return Err(Error::new(ProviderErrorCode::OutcomeUnknown));
        }
        store
            .writer
            .revoke_session(key)
            .map_err(|_| Error::internal())?;
        if let Some(cancel) = self
            .workflows
            .lock()
            .map_err(|_| Error::internal())?
            .get(key.remote_id.as_str())
        {
            cancel.cancel();
        }
        let mut next = store.state.clone();
        let session = next
            .sessions
            .iter_mut()
            .find(|session| &session.key == key)
            .ok_or_else(Error::invalid)?;
        session.remote = Remote::Terminal {
            reason,
            upstream_id: Some(expected_seat.to_owned()),
        };
        session.revoked = true;
        session.media = None;
        session.preparation_error = None;
        store.save(next)
    }

    async fn observe_terminal(self: &Arc<Self>, key: &SessionKey) -> Result<()> {
        let session = self.store()?.state.session(key)?.clone();
        let Remote::Seat { id, .. } = session.remote else {
            return Ok(());
        };
        let account = key.account.as_ref().ok_or_else(Error::invalid)?;
        let auth = self.credential(account).await?;
        let data = match self.client.details(&auth, &id).await {
            Err(error) if error.code == ProviderErrorCode::AuthRequired => {
                let auth = self.refresh(account, &auth).await?;
                self.client.details(&auth, &id).await?
            }
            result => result?,
        };
        if let Some(reason) = service::terminal_reason(&data, &id)? {
            self.record_terminal(key, &id, reason)?;
        }
        Ok(())
    }

    async fn reconcile_observed(
        self: &Arc<Self>,
        query: ReconcileSession,
    ) -> Result<Reconciliation> {
        let initial = self.reconcile(query.clone())?;
        let key = self
            .store()?
            .state
            .sessions
            .iter()
            .find(|session| session.request.operation == query.operation)
            .map(|session| session.key.clone());
        if let Some(key) = key {
            if self.observe_terminal(&key).await.is_err() {
                return Ok(Reconciliation::Unknown {
                    operation: query.operation,
                });
            }
            return self.reconcile(query);
        }
        Ok(initial)
    }

    async fn stop_observed(self: &Arc<Self>, request: StopSession) -> Result<CleanupState> {
        let initial = self.stop(request.clone())?;
        if matches!(initial, CleanupState::Resolved) {
            return Ok(initial);
        }
        if self.observe_terminal(&request.session).await.is_ok()
            && self.store()?.state.session(&request.session)?.terminal()
        {
            return Ok(CleanupState::Resolved);
        }
        Ok(initial)
    }

    async fn discover(self: &Arc<Self>, query: DiscoverSessions) -> Result<List<SessionView, 32>> {
        let account = self
            .store()?
            .state
            .scope(query.scope.as_ref())?
            .public
            .key
            .clone();
        let auth = self.credential(&account).await?;
        let response = match self.client.active(&auth).await {
            Err(error) if error.code == ProviderErrorCode::AuthRequired => {
                let auth = self.refresh(&account, &auth).await?;
                self.client.active(&auth).await?
            }
            result => result?,
        };
        let remote = response
            .as_array()
            .filter(|entries| entries.len() <= 32)
            .ok_or_else(Error::schema)?;
        let ids = remote
            .iter()
            .map(service::seat_id)
            .collect::<Result<Vec<_>>>()?;
        let store = self.store()?;
        store.state.scope(query.scope.as_ref())?;
        let sessions = store
            .state
            .sessions
            .iter()
            .filter(|s| s.key.account.as_ref() == Some(&account) && !s.terminal())
            .collect::<Vec<_>>();
        if ids.iter().any(|id| {
            !sessions
                .iter()
                .any(|s| matches!(&s.remote,Remote::Seat { id:known,.. } if known == id))
        }) {
            return Err(Error::new(ProviderErrorCode::OutcomeUnknown));
        }
        let mut views = Vec::new();
        for session in sessions {
            if session.ambiguous()
                || session.revoked
                || matches!(&session.remote,Remote::Seat { id,.. } if !ids.contains(id))
            {
                return Err(Error::new(ProviderErrorCode::OutcomeUnknown));
            }
            views.push(session.view());
        }
        List::new(views).map_err(|_| Error::internal())
    }

    fn claim(&self, query: ClaimSession) -> Result<SessionView> {
        let store = self.store()?;
        let account = store.state.scope(query.scope.as_ref())?;
        if query.session.account.as_ref() != Some(&account.public.key) {
            return Err(Error::invalid());
        }
        let session = store.state.session(&query.session)?;
        if session.decision != Some(Acceptance::Accepted)
            || session.revoked
            || session.ambiguous()
            || session.terminal()
        {
            return Err(Error::new(ProviderErrorCode::SessionNotReady));
        }
        Ok(session.view())
    }

    fn reconcile(&self, query: ReconcileSession) -> Result<Reconciliation> {
        let store = self.store()?;
        let account = query.scope.as_ref().map(|s| &s.account);
        let Some(session) = store
            .state
            .sessions
            .iter()
            .find(|s| s.request.operation == query.operation)
        else {
            if query.session.is_none()
                && store.state.rejected.iter().any(|r| {
                    r.request.operation == query.operation
                        && r.request.scope.as_ref().map(|s| &s.account) == account
                })
            {
                return Ok(Reconciliation::NotAllocated {
                    operation: query.operation,
                });
            }
            return Ok(Reconciliation::Unknown {
                operation: query.operation,
            });
        };
        if session.key.account.as_ref() != account
            || query
                .session
                .as_ref()
                .is_some_and(|key| key != &session.key)
        {
            return Err(Error::invalid());
        }
        if let Remote::Terminal { reason, .. } = session.remote {
            return Ok(Reconciliation::Terminal {
                session: session.key.clone(),
                reason,
            });
        }
        if session.decision.is_none() {
            return Ok(Reconciliation::PendingAllocation {
                session: session.view(),
                ticket: session.ticket(),
            });
        }
        if session.revoked || session.ambiguous() {
            return Ok(Reconciliation::Unknown {
                operation: query.operation,
            });
        }
        Ok(Reconciliation::Active {
            session: session.view(),
        })
    }

    fn stop(&self, request: StopSession) -> Result<CleanupState> {
        let mut store = self.store()?;
        store.state.session(&request.session)?;
        if store
            .state
            .sessions
            .iter()
            .any(|s| s.key != request.session && s.stop_operations.contains(&request.operation))
        {
            return Err(Error::invalid());
        }
        store
            .writer
            .revoke_session(&request.session)
            .map_err(|_| Error::internal())?;
        if let Some(cancel) = self
            .workflows
            .lock()
            .map_err(|_| Error::internal())?
            .get(request.session.remote_id.as_str())
        {
            cancel.cancel();
        }
        let mut next = store.state.clone();
        let session = next
            .sessions
            .iter_mut()
            .find(|s| s.key == request.session)
            .ok_or_else(Error::invalid)?;
        if !session.stop_operations.contains(&request.operation) {
            if session.stop_operations.len() >= 64 {
                return Err(Error::new(ProviderErrorCode::OutcomeUnknown));
            }
            session.stop_operations.push(request.operation.clone());
        }
        session.revoked = true;
        if session.remote == Remote::NotDispatched {
            session.remote = Remote::Terminal {
                reason: TerminalReason::UserStopped,
                upstream_id: None,
            };
        }
        let result = if session.terminal() {
            CleanupState::Resolved
        } else {
            CleanupState::Unknown {
                operation: request.operation,
            }
        };
        store.save(next)?;
        Ok(result)
    }

    async fn prepare(
        self: &Arc<Self>,
        request: PrepareSession,
    ) -> Result<opennow_plugin_api::media::PreparedWorker> {
        request.offer.validate().map_err(|_| Error::invalid())?;
        if request.offer.expires_at_ms <= now_ms() {
            return Err(Error::new(ProviderErrorCode::SessionNotReady));
        }
        let cancel = self.shutdown.child_token();
        let _cancel_on_drop = cancel.clone().drop_guard();
        let (connection, facts) = self.establish_media(&request.session, cancel).await?;
        let accepted = admit_media(&request.offer, facts)?;
        let store = self.store()?;
        let session = store.state.session(&request.session)?;
        if session.revoked || session.decision != Some(Acceptance::Accepted) {
            return Err(Error::new(ProviderErrorCode::CleanupRequired));
        }
        let expiry = request
            .offer
            .expires_at_ms
            .min(now_ms().saturating_add(30_000));
        let bootstrap = store
            .writer
            .issue_grant(&request.session, &accepted, connection, expiry)
            .map_err(|_| Error::new(ProviderErrorCode::CleanupRequired))?;
        Ok(opennow_plugin_api::media::PreparedWorker {
            accepted,
            bootstrap,
        })
    }

    async fn establish_media(
        self: &Arc<Self>,
        key: &SessionKey,
        cancel: CancellationToken,
    ) -> Result<(GatewayConnection, MediaFacts)> {
        let cancel = cancel.child_token();
        let (session, root) = {
            let store = self.store()?;
            let session = store.state.session(key)?.clone();
            if session.revoked || session.decision != Some(Acceptance::Accepted) {
                return Err(Error::new(ProviderErrorCode::CleanupRequired));
            }
            (session, store.root.clone())
        };
        let Remote::Seat { id, .. } = &session.remote else {
            return Err(Error::new(ProviderErrorCode::SessionNotReady));
        };
        let _worker_exclusion = lock_worker_session(&root, key)
            .map_err(|_| Error::new(ProviderErrorCode::BusyBeforeDispatch))?;
        let auth = self
            .credential(key.account.as_ref().ok_or_else(Error::invalid)?)
            .await?;
        let _cancel_on_drop = cancel.clone().drop_guard();
        let connect = self
            .client
            .connection(&auth, id, session.request.preferences.bitrate_kbps);
        let connection_result = tokio::select! {
            _ = cancel.cancelled() => return Err(Error::new(ProviderErrorCode::Cancelled)),
            connection = connect => connection,
        };
        let connection = match connection_result {
            Err(error) if error.code == ProviderErrorCode::AuthRequired => {
                let auth = self
                    .refresh(key.account.as_ref().ok_or_else(Error::invalid)?, &auth)
                    .await?;
                tokio::select! {
                    _ = cancel.cancelled() => return Err(Error::new(ProviderErrorCode::Cancelled)),
                    connection = self.client.connection(&auth,id,session.request.preferences.bitrate_kbps) => connection?,
                }
            }
            result => result?,
        };
        let reference = random("connection");
        let target = reference.clone();
        let data =
            Zeroizing::new(serde_json::to_string(&connection).map_err(|_| Error::internal())?);
        let vault = self.durable.clone();
        self.vault_io(move || vault.put(&target, &data)).await?;
        {
            let mut store = self.store()?;
            let mut next = store.state.clone();
            let session = next
                .sessions
                .iter_mut()
                .find(|session| &session.key == key)
                .ok_or_else(Error::invalid)?;
            if session.revoked {
                return Err(Error::new(ProviderErrorCode::CleanupRequired));
            }
            let Remote::Seat {
                id: current,
                connection_reference,
            } = &mut session.remote
            else {
                return Err(Error::new(ProviderErrorCode::OutcomeUnknown));
            };
            if current != id {
                return Err(Error::new(ProviderErrorCode::OutcomeUnknown));
            }
            *connection_reference = Some(reference);
            store.save(next)?;
        }
        let observed =
            boosteroid_media::preflight(&connection, &session.request.preferences, cancel.clone())
                .await
                .map_err(|_| {
                    Error::new(if cancel.is_cancelled() {
                        ProviderErrorCode::Cancelled
                    } else {
                        ProviderErrorCode::UnsupportedFeature
                    })
                })?;
        let facts = MediaFacts {
            video: observed.video,
            audio: observed.audio,
            input: observed.input,
        };
        facts.video.validate().map_err(|_| Error::schema())?;
        if facts.video.dynamic_range() != opennow_plugin_api::media::DynamicRange::Sdr {
            return Err(Error::new(ProviderErrorCode::UnsupportedFeature));
        }
        {
            let mut store = self.store()?;
            let mut next = store.state.clone();
            let session = next
                .sessions
                .iter_mut()
                .find(|session| &session.key == key)
                .ok_or_else(Error::invalid)?;
            if session.revoked {
                return Err(Error::new(ProviderErrorCode::CleanupRequired));
            }
            session.media = Some(facts.clone());
            session.preparation_error = None;
            store.save(next)?;
        }
        Ok((connection, facts))
    }
}

fn created(session: &Session) -> Completion {
    Completion {
        reply: ProviderReply::SessionCreate(CreateReply {
            session: session.view(),
        }),
        allocation: Some(session.ticket()),
        effects: vec![],
    }
}

fn admit_media(
    offer: &opennow_plugin_api::media::NativeOffer,
    facts: MediaFacts,
) -> Result<opennow_plugin_api::media::AcceptedMedia> {
    use opennow_plugin_api::media::{AcceptedMedia, InputCapabilities, RequestedVideo};
    boosteroid_media::input::validate_requested(&RequestedVideo {
        width: facts.video.width,
        height: facts.video.height,
        encoding: Some(facts.video.encoding),
        fps: Some(facts.video.fps),
        bit_depth: facts.video.bit_depth,
        chroma: facts.video.chroma,
        hdr: facts.video.dynamic_range() != opennow_plugin_api::media::DynamicRange::Sdr,
    })
    .map_err(|_| Error::new(ProviderErrorCode::UnsupportedFeature))?;
    let offered = &offer.input;
    let slots = facts.input.gamepad_slots.min(offered.gamepad_slots);
    let input = InputCapabilities {
        keyboard: facts.input.keyboard && offered.keyboard,
        relative_mouse: facts.input.relative_mouse && offered.relative_mouse,
        absolute_mouse: facts.input.absolute_mouse && offered.absolute_mouse,
        text: facts.input.text && offered.text,
        gamepad_slots: slots,
        rumble: slots > 0 && facts.input.rumble && offered.rumble,
    };
    let audio = facts
        .audio
        .filter(|audio| offer.audio_formats.contains(audio));
    let accepted = AcceptedMedia {
        offer_id: offer.offer_id.clone(),
        runtime_epoch: offer.runtime_epoch,
        video: facts.video,
        audio,
        input,
    };
    accepted
        .validate_against(offer, now_ms())
        .map_err(|_| Error::new(ProviderErrorCode::UnsupportedFeature))?;
    Ok(accepted)
}

fn app_id(id: &GameId) -> Result<u64> {
    id.as_str()
        .parse::<u64>()
        .ok()
        .filter(|id| *id > 0)
        .ok_or_else(Error::invalid)
}

fn summary(app: Application) -> Result<GameSummary> {
    Ok(GameSummary {
        id: GameId::new(app.id.to_string()).map_err(|_| Error::schema())?,
        title: text(app.title)?,
        artwork: app
            .artwork
            .map(PublicUrl::new)
            .transpose()
            .map_err(|_| Error::schema())?,
        subtitle: None,
        badges: List::default(),
        availability: Availability::Unknown,
    })
}

fn catalog_revision(scope: &AccountScope) -> Result<Text<256>> {
    let bytes = serde_json::to_vec(scope).map_err(|_| Error::internal())?;
    text(format!(
        "account-view-{}",
        hex::encode(Sha256::digest(bytes))
    ))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    scope: AccountScope,
    query: String,
    limit: u16,
    page: u32,
}

#[cfg(test)]
mod tests;
