mod storage;

use opennow_media_protocol::wire::WorkerBootstrap;
use opennow_plugin_api::{
    PackageFile, PluginId,
    media::{AcceptedMedia, DynamicRange},
    provider::{
        AuthKind, Capability, List, ProviderManifest, RoleEntrypoints, SecretBytes, SecretString,
        SessionKey,
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fmt,
    fs::File,
    io,
    path::Path,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};
use storage::PrivateRoot;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const PLUGIN_ID: &str = "org.opennow.boosteroid";
pub const VERSION: &str = "0.1.2";
pub const MAX_CONTROL_STATE_BYTES: usize = 1024 * 1024;
pub const MAX_GRANT_BYTES: usize = 64 * 1024;
const MAX_AUTHORIZATION_BYTES: usize = 32 * 1024;
const MAX_GRANTS: usize = 64;
const SCHEMA: u32 = 1;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewayConnection {
    pub upstream_session_id: String,
    pub session_query: SecretString,
    pub gateways: Vec<String>,
    pub home_url: Option<SecretString>,
    pub peer_id: String,
    pub bitrate_kbps: u32,
}

impl fmt::Debug for GatewayConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GatewayConnection([private])")
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorizedMedia {
    pub session: SessionKey,
    pub accepted: AcceptedMedia,
    pub connection: GatewayConnection,
    pub revocation_generation: u64,
}

impl fmt::Debug for AuthorizedMedia {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthorizedMedia([private])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase", deny_unknown_fields)]
pub enum SessionAuthorization {
    Pending { generation: u64 },
    Active { generation: u64 },
    Revoked { generation: u64 },
}

impl SessionAuthorization {
    pub fn generation(&self) -> u64 {
        match self {
            Self::Pending { generation }
            | Self::Active { generation }
            | Self::Revoked { generation } => *generation,
        }
    }
}

pub struct AuthorizationWriter {
    root: PrivateRoot,
    _lock: File,
    mutation: Mutex<()>,
}

pub struct WorkerSessionLock {
    _lock: File,
    _root: PrivateRoot,
}

impl Drop for AuthorizationWriter {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self._lock);
    }
}

impl Drop for WorkerSessionLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self._lock);
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SessionRecord {
    version: u32,
    session: SessionKey,
    authorization: SessionAuthorization,
    grants: Vec<RegisteredGrant>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RegisteredGrant {
    digest: [u8; 32],
    expires_at_ms: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Grant {
    version: u32,
    nonce: [u8; 32],
    session: SessionKey,
    accepted: AcceptedMedia,
    connection: GatewayConnection,
    revocation_generation: u64,
    expires_at_ms: u64,
}

impl AuthorizationWriter {
    pub fn open(root: &Path) -> io::Result<Self> {
        let root = PrivateRoot::open(root, true)?;
        let lock = root.lock("control.lock")?;
        root.remove_abandoned_temps()?;
        Ok(Self {
            root,
            _lock: lock,
            mutation: Mutex::new(()),
        })
    }

    pub fn read_control_state(&self) -> io::Result<Option<Vec<u8>>> {
        let bytes = self
            .root
            .read("control-state.json", MAX_CONTROL_STATE_BYTES)?;
        if let Some(bytes) = &bytes {
            validate_control_state(bytes)?;
        }
        Ok(bytes)
    }

    pub fn write_control_state(&self, state: &[u8]) -> io::Result<()> {
        validate_control_state(state)?;
        let _guard = self
            .mutation
            .lock()
            .map_err(|_| invalid("Control writer is poisoned"))?;
        self.root
            .replace("control-state.json", state, MAX_CONTROL_STATE_BYTES)
    }

    pub fn register_session(&self, session: &SessionKey) -> io::Result<()> {
        let _guard = self
            .mutation
            .lock()
            .map_err(|_| invalid("Control writer is poisoned"))?;
        if read_session(&self.root, session)?.is_some() {
            return Ok(());
        }
        let record = SessionRecord {
            version: SCHEMA,
            session: session.clone(),
            authorization: SessionAuthorization::Pending { generation: 1 },
            grants: vec![],
        };
        self.write_session(&record)
    }

    pub fn activate_session(&self, session: &SessionKey) -> io::Result<()> {
        let _guard = self
            .mutation
            .lock()
            .map_err(|_| invalid("Control writer is poisoned"))?;
        let mut record = required_session(&self.root, session)?;
        match record.authorization {
            SessionAuthorization::Pending { generation } => {
                record.authorization = SessionAuthorization::Active { generation }
            }
            SessionAuthorization::Active { .. } => return Ok(()),
            SessionAuthorization::Revoked { .. } => return Err(denied()),
        }
        self.write_session(&record)
    }

    pub fn revoke_session(&self, session: &SessionKey) -> io::Result<()> {
        let _guard = self
            .mutation
            .lock()
            .map_err(|_| invalid("Control writer is poisoned"))?;
        let mut record = read_session(&self.root, session)?.unwrap_or_else(|| SessionRecord {
            version: SCHEMA,
            session: session.clone(),
            authorization: SessionAuthorization::Pending { generation: 1 },
            grants: vec![],
        });
        if matches!(record.authorization, SessionAuthorization::Revoked { .. }) {
            return Ok(());
        }
        let generation = record
            .authorization
            .generation()
            .checked_add(1)
            .ok_or_else(|| invalid("Authorization generation exhausted"))?;
        record.authorization = SessionAuthorization::Revoked { generation };
        record.grants.clear();
        self.write_session(&record)
    }

    pub fn issue_grant(
        &self,
        session: &SessionKey,
        accepted: &AcceptedMedia,
        connection: GatewayConnection,
        expires_at_ms: u64,
    ) -> io::Result<SecretBytes> {
        validate_media(accepted)?;
        validate_connection(&connection)?;
        let now = now_ms()?;
        if expires_at_ms <= now {
            return Err(invalid("Grant expiry must be in the future"));
        }
        let _guard = self
            .mutation
            .lock()
            .map_err(|_| invalid("Control writer is poisoned"))?;
        let mut record = required_session(&self.root, session)?;
        let SessionAuthorization::Active { generation } = record.authorization else {
            return Err(denied());
        };
        record.grants.retain(|grant| grant.expires_at_ms > now);
        if record.grants.len() >= MAX_GRANTS {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Too many unexpired session grants",
            ));
        }
        let grant = Grant {
            version: SCHEMA,
            nonce: random_bytes()?,
            session: session.clone(),
            accepted: accepted.clone(),
            connection,
            revocation_generation: generation,
            expires_at_ms,
        };
        let payload =
            Zeroizing::new(serde_json::to_vec(&grant).map_err(|_| invalid("Cannot encode grant"))?);
        if payload.len() > MAX_GRANT_BYTES {
            return Err(invalid("Grant exceeds its limit"));
        }
        record.grants.push(RegisteredGrant {
            digest: digest(&payload),
            expires_at_ms,
        });
        self.write_session(&record)?;
        SecretBytes::new(payload.to_vec()).map_err(|_| invalid("Grant exceeds SDK limit"))
    }

    fn write_session(&self, record: &SessionRecord) -> io::Result<()> {
        let bytes =
            serde_json::to_vec(record).map_err(|_| invalid("Cannot encode authorization"))?;
        self.root.replace(
            &session_file(&record.session)?,
            &bytes,
            MAX_AUTHORIZATION_BYTES,
        )
    }
}

pub fn authorization_status(
    root: &Path,
    session: &SessionKey,
) -> io::Result<Option<SessionAuthorization>> {
    Ok(read_session(&PrivateRoot::open(root, false)?, session)?.map(|record| record.authorization))
}

pub fn lock_worker_session(root: &Path, session: &SessionKey) -> io::Result<WorkerSessionLock> {
    let root = PrivateRoot::open(root, false)?;
    let record = required_session(&root, session)?;
    if !matches!(record.authorization, SessionAuthorization::Active { .. }) {
        return Err(denied());
    }
    let lock = root.lock(&format!("worker-{}.lock", session_hash(session)?))?;
    Ok(WorkerSessionLock {
        _lock: lock,
        _root: root,
    })
}

pub fn authorize_worker(
    root: &Path,
    bootstrap: &WorkerBootstrap,
    now_ms: u64,
) -> io::Result<AuthorizedMedia> {
    bootstrap.validate().map_err(|_| denied())?;
    if bootstrap.binding.source_id.as_str() != PLUGIN_ID || now_ms == 0 {
        return Err(denied());
    }
    validate_media(&bootstrap.accepted)?;
    let payload = bootstrap.provider_bootstrap.expose_secret();
    if payload.is_empty() || payload.len() > MAX_GRANT_BYTES {
        return Err(denied());
    }
    let root = PrivateRoot::open(root, false)?;
    let record = required_session(&root, &bootstrap.binding.session)?;
    let SessionAuthorization::Active { generation } = record.authorization else {
        return Err(denied());
    };
    let payload_digest = digest(payload);
    let mut registered = subtle::Choice::from(0);
    for grant in &record.grants {
        registered |= grant.digest.ct_eq(&payload_digest)
            & subtle::Choice::from(u8::from(grant.expires_at_ms > now_ms));
    }
    if !bool::from(registered) {
        return Err(denied());
    }
    let grant: Grant = serde_json::from_slice(payload).map_err(|_| denied())?;
    if grant.version != SCHEMA
        || grant.session != bootstrap.binding.session
        || grant.accepted != bootstrap.accepted
        || grant.revocation_generation != generation
        || grant.expires_at_ms <= now_ms
    {
        return Err(denied());
    }
    validate_connection(&grant.connection)?;
    Ok(AuthorizedMedia {
        session: grant.session,
        accepted: grant.accepted,
        connection: grant.connection,
        revocation_generation: generation,
    })
}

pub fn session_authorized(root: &Path, active: &AuthorizedMedia) -> io::Result<bool> {
    let record = read_session(&PrivateRoot::open(root, false)?, &active.session)?;
    Ok(record.is_some_and(|record| {
        record.authorization
            == SessionAuthorization::Active {
                generation: active.revocation_generation,
            }
    }))
}

pub fn manifest(target: &str, files: Vec<PackageFile>) -> ProviderManifest {
    let extension = if target.contains("windows") {
        ".exe"
    } else {
        ""
    };
    ProviderManifest {
        schema_version: 2,
        protocol_version: 2,
        id: PluginId::new(PLUGIN_ID).expect("constant plugin ID"),
        name: "Boosteroid".into(),
        version: VERSION.into(),
        publisher: "OpenCloudGaming".into(),
        description: "Native Boosteroid provider for OpenNOW".into(),
        capabilities: List::new(vec![
            Capability::AuthBrowser,
            Capability::Accounts,
            Capability::LibraryCatalog,
            Capability::CatalogDetails,
            Capability::Launch,
            Capability::Sessions,
            Capability::MediaWorker,
        ])
        .expect("bounded constant capabilities"),
        auth_kinds: List::new(vec![AuthKind::Browser]).expect("bounded constant auth kinds"),
        entrypoints: BTreeMap::from([(
            target.into(),
            RoleEntrypoints {
                control: format!("bin/control{extension}"),
                media: format!("bin/media{extension}"),
            },
        )]),
        files,
    }
}

fn validate_media(media: &AcceptedMedia) -> io::Result<()> {
    media
        .video
        .validate()
        .map_err(|_| invalid("Invalid accepted video"))?;
    if media.runtime_epoch == 0
        || media.video.dynamic_range() != DynamicRange::Sdr
        || media.input.gamepad_slots > 4
    {
        return Err(invalid("Invalid accepted media binding"));
    }
    if let Some(audio) = &media.audio {
        audio
            .validate()
            .map_err(|_| invalid("Invalid accepted audio"))?;
    }
    Ok(())
}

fn validate_connection(connection: &GatewayConnection) -> io::Result<()> {
    let text = |value: &str, max: usize| {
        !value.trim().is_empty() && value.len() <= max && !value.chars().any(char::is_control)
    };
    if !(1..=200_000).contains(&connection.bitrate_kbps)
        || !text(&connection.upstream_session_id, 256)
        || !text(&connection.peer_id, 256)
        || !text(connection.session_query.expose_secret(), 16 * 1024)
        || connection.gateways.len() > 16
        || connection.gateways.is_empty()
        || connection
            .gateways
            .iter()
            .any(|gateway| !text(gateway, 2048))
        || connection
            .home_url
            .as_ref()
            .is_some_and(|url| !text(url.expose_secret(), 4096))
    {
        return Err(invalid("Invalid gateway grant"));
    }
    Ok(())
}

fn validate_control_state(bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_CONTROL_STATE_BYTES {
        return Err(invalid("Control state exceeds its limit"));
    }
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| invalid("Control state must be bounded JSON"))?;
    if !value.is_object() {
        return Err(invalid("Control state must be a JSON object"));
    }
    fn has_credentials(value: &serde_json::Value) -> bool {
        match value {
            serde_json::Value::Object(fields) => fields.iter().any(|(key, value)| {
                let normalized: String = key
                    .chars()
                    .filter(|ch| ch.is_ascii_alphanumeric())
                    .flat_map(char::to_lowercase)
                    .collect();
                matches!(
                    normalized.as_str(),
                    "accesstoken"
                        | "refreshtoken"
                        | "authorizationdata"
                        | "boosteroidauth"
                        | "password"
                ) || has_credentials(value)
            }),
            serde_json::Value::Array(values) => values.iter().any(has_credentials),
            _ => false,
        }
    }
    if has_credentials(&value) {
        return Err(invalid("Credentials do not belong in the control journal"));
    }
    Ok(())
}

fn read_session(root: &PrivateRoot, session: &SessionKey) -> io::Result<Option<SessionRecord>> {
    let Some(bytes) = root.read(&session_file(session)?, MAX_AUTHORIZATION_BYTES)? else {
        return Ok(None);
    };
    let record: SessionRecord =
        serde_json::from_slice(&bytes).map_err(|_| invalid("Invalid authorization record"))?;
    if record.version != SCHEMA
        || record.session != *session
        || record.authorization.generation() == 0
        || record.grants.len() > MAX_GRANTS
        || record.grants.iter().any(|grant| grant.expires_at_ms == 0)
        || (!matches!(record.authorization, SessionAuthorization::Active { .. })
            && !record.grants.is_empty())
    {
        return Err(invalid("Invalid authorization record"));
    }
    Ok(Some(record))
}

fn required_session(root: &PrivateRoot, session: &SessionKey) -> io::Result<SessionRecord> {
    read_session(root, session)?.ok_or_else(denied)
}

fn session_file(session: &SessionKey) -> io::Result<String> {
    Ok(format!("session-{}.json", session_hash(session)?))
}

fn session_hash(session: &SessionKey) -> io::Result<String> {
    Ok(hex(&digest(
        &serde_json::to_vec(session).map_err(|_| invalid("Invalid session key"))?,
    )))
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn random_bytes() -> io::Result<[u8; 32]> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|_| io::Error::other("Secure randomness unavailable"))?;
    Ok(bytes)
}
fn now_ms() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid("System clock precedes epoch"))?
        .as_millis()
        .try_into()
        .map_err(|_| invalid("System clock is out of range"))
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "Session grant is not authorized",
    )
}
