use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::http::HeaderMap;
use rand::RngCore;

use crate::db::now;
use crate::error::ApiError;
use crate::models::UserRow;
use crate::util::hex;
use crate::AppState;

/// Usuário autenticado por `Authorization: Bearer <token>`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuthUser {
    #[sqlx(flatten)]
    pub user: UserRow,
    pub token: String,
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
        let user = sqlx::query_as::<_, AuthUser>(
            "SELECT u.*, s.token FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?",
        )
        .bind(&token)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(ApiError::unauthorized)?;
        if user.user.status != 1 {
            return Err(ApiError::unauthorized());
        }
        sqlx::query("UPDATE sessions SET last_seen_at = ? WHERE token = ?")
            .bind(now())
            .bind(&token)
            .execute(&state.db)
            .await?;
        Ok(user)
    }
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
