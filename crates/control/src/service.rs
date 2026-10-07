use crate::{Error, Result};
use boosteroid_common::GatewayConnection;
use futures_util::StreamExt;
use opennow_plugin_api::provider::{ProviderErrorCode as Code, SecretString};
use reqwest::{Client, Method, StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::time::Duration;

const BODY_LIMIT: usize = 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub access: SecretString,
    pub refresh: SecretString,
    pub authorization_data: Option<SecretString>,
}

#[derive(Clone)]
pub struct BoosteroidClient {
    client: Client,
    base: Url,
}

impl BoosteroidClient {
    #[cfg(test)]
    pub(crate) fn fixture(base: Url) -> Result<Self> {
        Self::new(base)
    }
    pub fn production() -> Result<Self> {
        Self::new(Url::parse("https://cloud.boosteroid.com").map_err(|_| Error::internal())?)
    }

    fn new(base: Url) -> Result<Self> {
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|_| Error::internal())?;
        Ok(Self { client, base })
    }

    pub fn approval_url(&self, code: &str) -> Result<String> {
        let mut url = self
            .base
            .join("/api/v1/auth/login/qr-code/validate")
            .map_err(|_| Error::internal())?;
        url.query_pairs_mut().append_pair("auth-code", code);
        Ok(url.to_string())
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        auth: Option<&Credentials>,
        body: Option<Value>,
    ) -> Result<(StatusCode, Value)> {
        let url = self.base.join(path).map_err(|_| Error::invalid())?;
        if url.origin() != self.base.origin() {
            return Err(Error::invalid());
        }
        let mut request = self
            .client
            .request(method, url)
            .header("Accept", "application/json")
            .header(
                "User-Agent",
                "BoosteroidAndroidTVClient tv.1.2.9; OpenNOW community provider",
            )
            .header("Device-Name", "OpenNOW Boosteroid provider")
            .header("Device-Uniq-Id", "")
            .header("Nonce", "0")
            .header(
                "Cookie",
                "boosteroid_entrypoint_source=1;boosteroid_entrypoint_page=1",
            );
        if let Some(auth) = auth {
            let access = auth.access.expose_secret();
            let value = if access.starts_with("Bearer ") {
                access.to_owned()
            } else {
                format!("Bearer {access}")
            };
            request = request.header("Authorization", value);
            if let Some(value) = &auth.authorization_data {
                request = request.header("Authorization-Data", value.expose_secret());
            }
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request
            .send()
            .await
            .map_err(|_| Error::new(Code::ServiceUnavailable))?;
        let status = response.status();
        let retry = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u32>().ok())
            .map(|s| s.saturating_mul(1000).clamp(1000, 3_600_000));
        if status == StatusCode::TOO_MANY_REQUESTS {
            return Err(Error {
                code: Code::RateLimited,
                retry_after_ms: retry,
            });
        }
        if response
            .content_length()
            .is_some_and(|length| length > BODY_LIMIT as u64)
        {
            return Err(Error::schema());
        }
        let mut stream = response.bytes_stream();
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| Error::new(Code::ServiceUnavailable))?;
            if bytes.len().saturating_add(chunk.len()) > BODY_LIMIT {
                return Err(Error::schema());
            }
            bytes.extend_from_slice(&chunk);
        }
        if bytes.is_empty() && status == StatusCode::NO_CONTENT {
            return Ok((status, Value::Null));
        }
        let body = serde_json::from_slice(&bytes).map_err(|_| Error::schema())?;
        Ok((status, body))
    }

    async fn checked(
        &self,
        method: Method,
        path: &str,
        auth: Option<&Credentials>,
        body: Option<Value>,
    ) -> Result<Value> {
        let (status, body) = self.request(method, path, auth, body).await?;
        if status == StatusCode::UNAUTHORIZED {
            return Err(Error::new(Code::AuthRequired));
        }
        if !status.is_success() {
            return Err(Error::new(Code::ServiceUnavailable));
        }
        unwrap(body)
    }

    pub async fn poll_auth(&self, code: &str) -> Result<Option<Credentials>> {
        let (status, data) = self
            .request(
                Method::POST,
                "/api/v1/auth/login/qr-code/sync",
                None,
                Some(json!({"auth-code":code,"clientId":6})),
            )
            .await?;
        if status.is_client_error() {
            return Ok(None);
        }
        if status != StatusCode::OK {
            return Err(Error::new(Code::ServiceUnavailable));
        }
        parse_credentials(unwrap(data)?, None).map(Some)
    }

    pub async fn refresh(&self, auth: &Credentials) -> Result<Credentials> {
        let data = self
            .checked(
                Method::POST,
                "/api/v1/auth/refresh-token",
                None,
                Some(json!({"refresh_token":auth.refresh.expose_secret()})),
            )
            .await?;
        parse_credentials(data, Some(auth))
    }

    pub async fn user(&self, auth: &Credentials) -> Result<User> {
        parse_user(
            self.checked(Method::GET, "/api/v1/user", Some(auth), None)
                .await?,
        )
    }

    pub async fn library(
        &self,
        auth: &Credentials,
        page: u32,
        limit: u16,
    ) -> Result<Vec<Application>> {
        let data = self
            .checked(
                Method::GET,
                &format!("/api/v1/boostore/applications/installed?page={page}&paginate={limit}"),
                Some(auth),
                None,
            )
            .await?;
        let values = data.as_array().ok_or_else(Error::schema)?;
        if values.len() > usize::from(limit) {
            return Err(Error::schema());
        }
        values.iter().cloned().map(parse_application).collect()
    }

    pub async fn application(&self, auth: &Credentials, id: u64) -> Result<Application> {
        let value = self
            .checked(
                Method::GET,
                &format!("/api/v1/boostore/applications/{id}"),
                Some(auth),
                None,
            )
            .await?;
        let app = parse_application(value)?;
        if app.id != id {
            return Err(Error::schema());
        }
        Ok(app)
    }

    pub async fn enqueue(&self, auth: &Credentials, app: u64) -> Result<Value> {
        self.checked(
            Method::POST,
            "/api/v2/streaming/session/enqueue",
            Some(auth),
            Some(json!({"appId":app})),
        )
        .await
    }

    pub async fn start(&self, auth: &Credentials, app: u64, token: &SecretString) -> Result<Value> {
        self.checked(
            Method::POST,
            "/api/v2/streaming/session/start",
            Some(auth),
            Some(json!({"appId":app,"sessionToken":token.expose_secret()})),
        )
        .await
    }

    pub async fn details(&self, auth: &Credentials, seat: &str) -> Result<Value> {
        let mut url = self
            .base
            .join("/api/v1/streaming/session/details")
            .map_err(|_| Error::internal())?;
        url.query_pairs_mut().append_pair("sessionId", seat);
        let path = format!("{}?{}", url.path(), url.query().unwrap_or_default());
        self.checked(Method::POST, &path, Some(auth), Some(Value::Null))
            .await
    }

    pub async fn active(&self, auth: &Credentials) -> Result<Value> {
        self.checked(
            Method::GET,
            "/api/v1/streaming/user/active-sessions",
            Some(auth),
            None,
        )
        .await
    }

    pub async fn connection(
        &self,
        auth: &Credentials,
        seat: &str,
        bitrate_kbps: u32,
    ) -> Result<GatewayConnection> {
        let details = self.details(auth, seat).await?;
        let query = details
            .get("queryString")
            .or_else(|| details.get("query"))
            .or_else(|| details.get("sessionQuery"))
            .and_then(Value::as_str)
            .filter(|query| !query.is_empty() && query.len() <= 16_384)
            .ok_or_else(Error::schema)?;
        let pairs = reqwest::Url::parse(&format!(
            "https://cloud.boosteroid.com/?{}",
            query.trim_start_matches('?')
        ))
        .map_err(|_| Error::schema())?;
        let ids = pairs
            .query_pairs()
            .filter(|(key, _)| matches!(key.as_ref(), "sessionId" | "sessionid" | "session"))
            .map(|(_, value)| value.into_owned())
            .collect::<Vec<_>>();
        if ids.len() != 1 || ids[0] != seat || pairs.query_pairs().count() < 2 {
            return Err(Error::schema());
        }
        if seat_id(&details).is_ok_and(|id| id != seat) {
            return Err(Error::schema());
        }
        let gateways = match details
            .get("gateways")
            .or_else(|| details.get("gateway"))
            .or_else(|| details.get("gw"))
        {
            Some(value) => value.clone(),
            None => {
                self.checked(Method::GET, "/api/v1/streaming/gateways", Some(auth), None)
                    .await?
            }
        };
        let values = match gateways {
            Value::Array(values) => values,
            Value::String(_) | Value::Object(_) => vec![gateways],
            _ => return Err(Error::schema()),
        };
        if values.is_empty() || values.len() > 16 {
            return Err(Error::schema());
        }
        let gateways = values.iter().map(gateway).collect::<Result<Vec<_>>>()?;
        Ok(GatewayConnection {
            upstream_session_id: seat.to_owned(),
            session_query: SecretString::new(query).map_err(|_| Error::schema())?,
            gateways,
            home_url: None,
            peer_id: uuid::Uuid::new_v4().to_string(),
            bitrate_kbps,
        })
    }

    pub async fn logout(&self, auth: &Credentials) -> Result<()> {
        self.checked(
            Method::POST,
            "/api/v2/auth/logout",
            Some(auth),
            Some(json!({})),
        )
        .await?;
        Ok(())
    }
}

fn gateway(value: &Value) -> Result<String> {
    let text = value
        .as_str()
        .or_else(|| {
            ["address", "gw", "gateway", "url"]
                .iter()
                .find_map(|key| value.get(key).and_then(Value::as_str))
        })
        .ok_or_else(Error::schema)?;
    let url = Url::parse(
        if text.contains("://") {
            text.to_owned()
        } else {
            format!("https://{text}")
        }
        .as_str(),
    )
    .map_err(|_| Error::schema())?;
    let host = url.host_str().ok_or_else(Error::schema)?;
    if !matches!(url.scheme(), "https" | "wss")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.port().is_some_and(|port| port != 443)
        || !(host == "boosteroid.com" || host.ends_with(".boosteroid.com"))
    {
        return Err(Error::schema());
    }
    Ok(host.to_owned())
}

fn unwrap(value: Value) -> Result<Value> {
    match value {
        Value::Object(mut object) => Ok(object.remove("data").unwrap_or(Value::Object(object))),
        Value::Array(_) => Ok(value),
        _ => Err(Error::schema()),
    }
}

fn secret(value: &Value) -> Result<SecretString> {
    let text = value
        .as_str()
        .filter(|v| !v.is_empty() && v.len() <= 16_384)
        .ok_or_else(Error::schema)?;
    SecretString::new(text).map_err(|_| Error::schema())
}

fn parse_credentials(value: Value, old: Option<&Credentials>) -> Result<Credentials> {
    let access = secret(&value["access_token"])?;
    let refresh = match value.get("refresh_token") {
        Some(value) => secret(value)?,
        None => old.map(|v| v.refresh.clone()).ok_or_else(Error::schema)?,
    };
    let auth_data = match value.get("user_data") {
        Some(data @ Value::String(_)) => Some(data),
        Some(Value::Object(data)) => [
            "boosteroid_auth",
            "boosteroidAuth",
            "authorization_data",
            "authorizationData",
        ]
        .iter()
        .find_map(|key| data.get(*key)),
        _ => None,
    };
    let authorization_data = auth_data
        .map(secret)
        .transpose()?
        .or_else(|| old.and_then(|v| v.authorization_data.clone()));
    Ok(Credentials {
        access,
        refresh,
        authorization_data,
    })
}

pub struct User {
    pub id: String,
    pub name: String,
}

fn parse_user(value: Value) -> Result<User> {
    let id = match &value["id"] {
        Value::String(id) if !id.is_empty() && id.len() <= 256 => id.clone(),
        Value::Number(id) => id
            .as_u64()
            .map(|v| v.to_string())
            .ok_or_else(Error::schema)?,
        _ => return Err(Error::schema()),
    };
    let name = value
        .get("name")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty() && v.len() <= 256)
        .unwrap_or("Boosteroid account")
        .to_owned();
    Ok(User { id, name })
}

#[derive(Clone)]
pub struct Application {
    pub id: u64,
    pub title: String,
    pub artwork: Option<String>,
    pub description: Option<String>,
}

fn parse_application(value: Value) -> Result<Application> {
    let value = value.get("application").unwrap_or(&value);
    let id = value["id"]
        .as_u64()
        .filter(|v| *v > 0)
        .ok_or_else(Error::schema)?;
    let title = value["name"]
        .as_str()
        .filter(|v| !v.is_empty() && v.len() <= 256)
        .ok_or_else(Error::schema)?
        .to_owned();
    let artwork = value
        .get("cover")
        .or_else(|| value.get("icon"))
        .filter(|v| !v.is_null())
        .map(|v| v.as_str().ok_or_else(Error::schema).and_then(public_url))
        .transpose()?;
    let description = value
        .get("description")
        .filter(|v| !v.is_null())
        .map(|v| {
            v.as_str()
                .filter(|v| v.len() <= 8192)
                .map(str::to_owned)
                .ok_or_else(Error::schema)
        })
        .transpose()?;
    Ok(Application {
        id,
        title,
        artwork,
        description,
    })
}

fn public_url(value: &str) -> Result<String> {
    let url = Url::parse(value).map_err(|_| Error::schema())?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::schema());
    }
    Ok(url.to_string())
}

pub fn seat_id(value: &Value) -> Result<String> {
    let id = value
        .get("sessionId")
        .or_else(|| value.get("sessionID"))
        .or_else(|| value.get("sid"))
        .and_then(Value::as_str)
        .ok_or_else(Error::schema)?;
    uuid::Uuid::parse_str(id).map_err(|_| Error::schema())?;
    Ok(id.to_owned())
}

pub fn queue_token(value: &Value) -> Result<SecretString> {
    let value = value
        .get("sessionToken")
        .or_else(|| value.get("token"))
        .ok_or_else(Error::schema)?;
    secret(value)
}

pub fn terminal_reason(
    value: &Value,
    expected_seat: &str,
) -> Result<Option<opennow_plugin_api::provider::TerminalReason>> {
    use opennow_plugin_api::provider::TerminalReason;
    if seat_id(value)? != expected_seat {
        return Err(Error::schema());
    }
    let mut status: Option<String> = None;
    for field in ["status", "sessionStatus", "state", "stage"] {
        if let Some(value) = value.get(field) {
            let value = value
                .as_str()
                .filter(|text| text.len() <= 64)
                .ok_or_else(Error::schema)?
                .trim()
                .to_ascii_uppercase();
            if status.as_ref().is_some_and(|previous| previous != &value) {
                return Err(Error::schema());
            }
            status = Some(value);
        }
    }
    Ok(match status.as_deref() {
        Some("ENDED" | "FINISHED" | "TERMINATED") => Some(TerminalReason::RemoteEnded),
        Some("EXPIRED" | "TIMEOUT") => Some(TerminalReason::Expired),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn identity_never_uses_email_or_jwt_fallback() {
        assert!(parse_user(json!({"email":"person@example.com"})).is_err());
        assert_eq!(
            parse_user(json!({"id":18446744073709551615u64}))
                .unwrap()
                .id,
            "18446744073709551615"
        );
        assert!(parse_user(json!({"id":1.5})).is_err());
    }

    #[test]
    fn schemas_do_not_turn_unknown_data_into_empty_success() {
        assert!(unwrap(Value::Null).is_err());
        assert!(parse_application(json!({"id":1,"title":"invented alias"})).is_err());
        assert!(seat_id(&json!({"nested":{"sessionId":"123"}})).is_err());
        assert!(parse_credentials(json!({"access_token":"token"}), None).is_err());
    }

    #[test]
    fn credentials_preserve_direct_and_nested_authorization_data() {
        for user_data in [
            json!("fixture-authorization-data"),
            json!({"boosteroid_auth":"fixture-authorization-data"}),
            json!({"boosteroidAuth":"fixture-authorization-data"}),
            json!({"authorization_data":"fixture-authorization-data"}),
            json!({"authorizationData":"fixture-authorization-data"}),
        ] {
            let credentials = parse_credentials(
                json!({"access_token":"fixture-access","refresh_token":"fixture-refresh","user_data":user_data}),
                None,
            )
            .unwrap();
            assert_eq!(
                credentials
                    .authorization_data
                    .as_ref()
                    .map(SecretString::expose_secret),
                Some("fixture-authorization-data")
            );
        }
    }

    #[test]
    fn direct_authorization_data_is_bounded_and_rotates_with_refresh() {
        let old = Credentials {
            access: SecretString::new("fixture-access").unwrap(),
            refresh: SecretString::new("fixture-refresh").unwrap(),
            authorization_data: Some(SecretString::new("fixture-old-data").unwrap()),
        };
        let rotated = parse_credentials(
            json!({"access_token":"fixture-new-access","user_data":"fixture-new-data"}),
            Some(&old),
        )
        .unwrap();
        assert_eq!(rotated.refresh.expose_secret(), "fixture-refresh");
        assert_eq!(
            rotated.authorization_data.unwrap().expose_secret(),
            "fixture-new-data"
        );
        let retained =
            parse_credentials(json!({"access_token":"fixture-new-access"}), Some(&old)).unwrap();
        assert_eq!(
            retained.authorization_data.unwrap().expose_secret(),
            "fixture-old-data"
        );
        for data in [String::new(), "x".repeat(16_385)] {
            assert!(
                parse_credentials(
                    json!({"access_token":"fixture-access","user_data":data}),
                    Some(&old)
                )
                .is_err()
            );
        }
    }

    #[tokio::test]
    async fn qr_approval_forwards_direct_authorization_data_to_identity_request() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for step in 0..2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.windows(4).any(|part| part == b"\r\n\r\n") {
                    let mut chunk = [0; 1024];
                    let count = socket.read(&mut chunk).await.unwrap();
                    assert!(count > 0 && request.len() + count <= 8192);
                    request.extend_from_slice(&chunk[..count]);
                }
                let header_end = request
                    .windows(4)
                    .position(|part| part == b"\r\n\r\n")
                    .unwrap()
                    + 4;
                let body_length = String::from_utf8_lossy(&request[..header_end])
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|length| length.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                assert!(header_end + body_length <= 8192);
                while request.len() < header_end + body_length {
                    let mut chunk = [0; 1024];
                    let count = socket.read(&mut chunk).await.unwrap();
                    assert!(count > 0 && request.len() + count <= 8192);
                    request.extend_from_slice(&chunk[..count]);
                }
                let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
                let (status, body) = if step == 0 {
                    assert!(request.starts_with("post /api/v1/auth/login/qr-code/sync "));
                    (
                        "200 OK",
                        json!({"data":{"access_token":"fixture-access","refresh_token":"fixture-refresh","user_data":"fixture-authorization-data"}}),
                    )
                } else {
                    assert!(request.starts_with("get /api/v1/user "));
                    assert!(request.contains("authorization: bearer fixture-access\r\n"));
                    if request.contains("authorization-data: fixture-authorization-data\r\n") {
                        ("200 OK", json!({"data":{"id":123,"name":"Fixture user"}}))
                    } else {
                        ("401 Unauthorized", json!({}))
                    }
                };
                let body = body.to_string();
                socket.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
            }
        });
        let client =
            BoosteroidClient::fixture(Url::parse(&format!("http://{addr}")).unwrap()).unwrap();
        let credentials = client
            .poll_auth("fixture-approval-code")
            .await
            .unwrap()
            .unwrap();
        let user = client.user(&credentials).await;
        server.await.unwrap();
        assert_eq!(user.unwrap().id, "123");
    }

    #[tokio::test]
    async fn real_http_fixture_enforces_wire_request_and_body_limit() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = vec![0; 8192];
            let n = socket.read(&mut bytes).await.unwrap();
            let request = String::from_utf8_lossy(&bytes[..n]);
            assert!(request.starts_with("GET /api/v1/user "));
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("authorization: bearer test-access")
            );
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2000000\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
        });
        let client = BoosteroidClient::new(Url::parse(&format!("http://{addr}")).unwrap()).unwrap();
        let auth = Credentials {
            access: SecretString::new("test-access").unwrap(),
            refresh: SecretString::new("test-refresh").unwrap(),
            authorization_data: None,
        };
        assert!(client.user(&auth).await.is_err());
        server.await.unwrap();
    }
}
