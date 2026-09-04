use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};

use crate::auth::{self, AuthUser};
use crate::db::now;
use crate::error::{ApiError, ApiResult};
use crate::models::UserRow;
use crate::util::{parse_value, s};
use crate::AppState;

/// Sem provedores OIDC: lista vazia. Também atende o `HEAD` que o Rust usa como sonda TLS.
pub async fn login_options() -> Json<Value> {
    Json(json!([]))
}

pub async fn login(State(st): State<AppState>, body: Bytes) -> ApiResult<Json<Value>> {
    let v = parse_value(&body)?;
    let typ = s(&v, "type");
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

    let token = auth::new_token();
    let dev = v.get("deviceInfo").cloned().unwrap_or(Value::Null);
    let t = now();
    sqlx::query(
        "INSERT INTO sessions (token, user_id, device_id, device_uuid, device_os, device_name, device_type, created_at, last_seen_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&token)
    .bind(user.id)
    .bind(s(&v, "id"))
    .bind(s(&v, "uuid"))
    .bind(s(&dev, "os"))
    .bind(s(&dev, "name"))
    .bind(s(&dev, "type"))
    .bind(t)
    .bind(t)
    .execute(&st.db)
    .await?;
    tracing::info!(user = %user.name, device = %s(&v, "id"), "login");

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
