use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use rand::RngCore;
use serde_json::Value;

use crate::db::{now, Db};
use crate::error::{ApiError, ApiResult};
use crate::models::UserRow;
use crate::util::{hex, s};
use crate::AppState;

/// Usuário autenticado por `Authorization: Bearer <token>`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuthUser {
    #[sqlx(flatten)]
    pub user: UserRow,
    pub token: String,
    pub session_expires_at: Option<i64>,
}

impl AuthUser {
    pub fn require_admin(&self) -> Result<(), ApiError> {
        if self.user.is_admin != 0 {
            Ok(())
        } else {
            Err(ApiError::forbidden())
        }
    }
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let token = bearer_from_headers(&parts.headers).ok_or_else(ApiError::unauthorized)?;
        let user = lookup_session(&state.db, &token).await?;
        sqlx::query("UPDATE sessions SET last_seen_at = ? WHERE token = ?")
            .bind(now())
            .bind(&token)
            .execute(&state.db)
            .await?;
        Ok(user)
    }
}

/// Sessão do token com usuário ativo e dentro das validades; uma sessão vencida é apagada.
/// Qualquer recusa é 401 (a mensagem diz o motivo).
pub async fn lookup_session(db: &Db, token: &str) -> ApiResult<AuthUser> {
    let user = sqlx::query_as::<_, AuthUser>(
        "SELECT u.*, s.token, s.expires_at AS session_expires_at \
         FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?",
    )
    .bind(token)
    .fetch_optional(db)
    .await?
    .ok_or_else(ApiError::unauthorized)?;
    if user.user.status != 1 {
        return Err(ApiError::unauthorized());
    }
    let t = now();
    if user.user.expires_at.is_some_and(|exp| exp <= t) {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "Account expired"));
    }
    if user.session_expires_at.is_some_and(|exp| exp <= t) {
        sqlx::query("DELETE FROM sessions WHERE token = ?")
            .bind(token)
            .execute(db)
            .await?;
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "Session expired"));
    }
    Ok(user)
}

pub fn bearer_from_headers(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?.trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_owned())
    }
}

pub fn new_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex(&bytes)
}

/// Cria a sessão de um login aprovado; `v` é o corpo do `/api/login` (id, uuid, deviceInfo).
/// A validade vem de `users.session_hours` (0 = sem validade).
pub async fn create_session(db: &Db, user: &UserRow, v: &Value) -> ApiResult<String> {
    let token = new_token();
    let dev = v.get("deviceInfo").cloned().unwrap_or(Value::Null);
    let t = now();
    let expires_at = (user.session_hours > 0).then(|| t + user.session_hours * 3600);
    sqlx::query(
        "INSERT INTO sessions (token, user_id, device_id, device_uuid, device_os, device_name, device_type, \
         created_at, last_seen_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&token)
    .bind(user.id)
    .bind(s(v, "id"))
    .bind(s(v, "uuid"))
    .bind(s(&dev, "os"))
    .bind(s(&dev, "name"))
    .bind(s(&dev, "type"))
    .bind(t)
    .bind(t)
    .bind(expires_at)
    .execute(db)
    .await?;
    Ok(token)
}

pub async fn hash_password(password: String) -> anyhow::Result<String> {
    tokio::task::spawn_blocking(move || -> anyhow::Result<String> {
        let mut salt = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);
        let salt = SaltString::encode_b64(&salt).map_err(|e| anyhow::anyhow!("{e}"))?;
        let hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(hash.to_string())
    })
    .await?
}

pub async fn verify_password(password: String, hash: String) -> bool {
    tokio::task::spawn_blocking(move || {
        let Ok(parsed) = PasswordHash::new(&hash) else {
            return false;
        };
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    })
    .await
    .unwrap_or(false)
}
