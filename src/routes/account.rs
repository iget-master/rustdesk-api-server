use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};

use crate::auth::{self, AuthUser};
use crate::db::{now, Db};
use crate::error::{ApiError, ApiResult};
use crate::models::{UserRow, TFA_CONSOLE};
use crate::util::{parse_value, s};
use crate::AppState;

/// Tempo para digitar o código depois de a senha ter sido aceita.
const CHALLENGE_TTL_SECS: i64 = 600;

/// Sem provedores OIDC: lista vazia. Também atende o `HEAD` que o Rust usa como sonda TLS.
pub async fn login_options() -> Json<Value> {
    Json(json!([]))
}

/// `POST /api/login` — etapa 1: usuário e senha. Contas com código de acesso recebem
/// `email_check`/`tfa_check` e voltam na etapa 2 (`type: email_code`) com o `secret` e o código.
pub async fn login(State(st): State<AppState>, body: Bytes) -> ApiResult<Json<Value>> {
    let v = parse_value(&body)?;
    let typ = s(&v, "type");
    if typ == "email_code" || typ == "tfa_code" {
        return login_with_code(&st.db, &v).await;
    }
    if !typ.is_empty() && typ != "account" {
        return Err(ApiError::bad_request("Login type not supported"));
    }
    let username = s(&v, "username").trim().to_owned();
    let password = s(&v, "password");
    if username.is_empty() || password.is_empty() {
        return Err(ApiError::bad_request("Username and password are required"));
    }

    let user = sqlx::query_as::<_, UserRow>("SELECT * FROM users WHERE name = ?")
        .bind(&username)
        .fetch_optional(&st.db)
        .await?;
    let wrong = || ApiError::new(StatusCode::UNAUTHORIZED, "Wrong username or password");
    let Some(user) = user else {
        return Err(wrong());
    };
    if !auth::verify_password(password, user.password_hash.clone()).await {
        return Err(wrong());
    }
    if user.status != 1 {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "User is disabled"));
    }
    let t = now();
    if user.expires_at.is_some_and(|exp| exp <= t) {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "Account expired"));
    }

    if user.tfa == TFA_CONSOLE {
        let secret = auth::new_token();
        sqlx::query("DELETE FROM login_challenges WHERE user_id = ? OR expires_at < ?")
            .bind(user.id)
            .bind(t)
            .execute(&st.db)
            .await?;
        sqlx::query(
            "INSERT INTO login_challenges (secret, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
        )
        .bind(&secret)
        .bind(user.id)
        .bind(t)
        .bind(t + CHALLENGE_TTL_SECS)
        .execute(&st.db)
        .await?;
        tracing::info!(user = %user.name, "senha aceita; aguardando código de acesso");
        return Ok(Json(json!({
            "type": "email_check",
            "tfa_type": "tfa_check",
            "secret": secret,
            "user": user.payload(),
        })));
    }

    let token = auth::create_session(&st.db, &user, &v).await?;
    tracing::info!(user = %user.name, device = %s(&v, "id"), "login");
    Ok(Json(json!({
        "access_token": token,
        "type": "access_token",
        "user": user.payload(),
    })))
}

/// Etapa 2: o `secret` prova que a senha foi aceita há pouco; o código tem de estar
/// entre os emitidos pelo console para este usuário, dentro da validade e ainda sem uso.
async fn login_with_code(db: &Db, v: &Value) -> ApiResult<Json<Value>> {
    let secret = s(v, "secret");
    if secret.is_empty() {
        return Err(ApiError::bad_request("secret is required"));
    }
    let expired = || ApiError::new(StatusCode::UNAUTHORIZED, "Login expired, please sign in again");
    let challenge: Option<(i64, i64)> =
        sqlx::query_as("SELECT user_id, expires_at FROM login_challenges WHERE secret = ?")
            .bind(&secret)
            .fetch_optional(db)
            .await?;
    let Some((user_id, expires_at)) = challenge else {
        return Err(expired());
    };
    let t = now();
    if expires_at <= t {
        sqlx::query("DELETE FROM login_challenges WHERE secret = ?")
            .bind(&secret)
            .execute(db)
            .await?;
        return Err(expired());
    }
    let mut code = s(v, "tfaCode").trim().to_owned();
    if code.is_empty() {
        code = s(v, "verificationCode").trim().to_owned();
    }
    if code.is_empty() {
        return Err(ApiError::bad_request("Verification code is required"));
    }
    let user = sqlx::query_as::<_, UserRow>("SELECT * FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(db)
        .await?
        .ok_or_else(expired)?;
    let used = sqlx::query(
        "UPDATE access_codes SET used_at = ? \
         WHERE id = (SELECT id FROM access_codes WHERE user_id = ? AND code = ? AND used_at IS NULL \
                     AND expires_at > ? ORDER BY expires_at LIMIT 1)",
    )
    .bind(t)
    .bind(user_id)
    .bind(&code)
    .bind(t)
    .execute(db)
    .await?;
    if used.rows_affected() == 0 {
        tracing::warn!(user = %user.name, "código de acesso inválido ou vencido");
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "Wrong verification code"));
    }
    sqlx::query("DELETE FROM login_challenges WHERE secret = ?")
        .bind(&secret)
        .execute(db)
        .await?;
    let token = auth::create_session(db, &user, v).await?;
    tracing::info!(user = %user.name, session_hours = user.session_hours, "login com código de acesso");
    Ok(Json(json!({
        "access_token": token,
        "type": "access_token",
        "user": user.payload(),
    })))
}

/// O cliente ignora a resposta e apaga o token localmente de qualquer forma.
pub async fn logout(State(st): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    if let Some(token) = auth::bearer_from_headers(&headers) {
        sqlx::query("DELETE FROM sessions WHERE token = ?")
            .bind(token)
            .execute(&st.db)
            .await?;
    }
    Ok(Json(json!({})))
}

pub async fn current_user(
    State(st): State<AppState>,
    user: AuthUser,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    let v = parse_value(&body)?;
    let id = s(&v, "id");
    if !id.is_empty() {
        sqlx::query("UPDATE sessions SET device_id = ?, device_uuid = ? WHERE token = ?")
            .bind(id)
            .bind(s(&v, "uuid"))
            .bind(&user.token)
            .execute(&st.db)
            .await?;
    }
    Ok(Json(user.user.payload()))
}
