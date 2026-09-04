use axum::extract::{Query, State};
use axum::Json;
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::auth::AuthUser;
use crate::error::ApiResult;
use crate::models::{DeviceRow, UserRow, DEVICE_SELECT};
use crate::util::{page_json, Page};
use crate::AppState;

/// `GET /api/users` — todos os usuários ativos são visíveis entre si (instalação de um só inquilino).
pub async fn users(
    State(st): State<AppState>,
    _user: AuthUser,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult<Json<Value>> {
    let page = Page::from_query(&q);
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE status = 1")
        .fetch_one(&st.db)
        .await?;
    let rows = sqlx::query_as::<_, UserRow>(
        "SELECT * FROM users WHERE status = 1 ORDER BY name LIMIT ? OFFSET ?",
    )
    .bind(page.size)
    .bind(page.offset)
    .fetch_all(&st.db)
    .await?;
    Ok(Json(page_json(
        total,
        rows.iter().map(UserRow::payload).collect(),
    )))
}

/// `GET /api/peers` — dispositivos conhecidos pelo heartbeat/sysinfo.
pub async fn peers(
    State(st): State<AppState>,
    _user: AuthUser,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult<Json<Value>> {
    let page = Page::from_query(&q);
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM devices")
        .fetch_one(&st.db)
        .await?;
    let rows = sqlx::query_as::<_, DeviceRow>(&format!(
        "{DEVICE_SELECT} ORDER BY d.hostname, d.id LIMIT ? OFFSET ?"
    ))
    .bind(page.size)
    .bind(page.offset)
    .fetch_all(&st.db)
    .await?;
    Ok(Json(page_json(
        total,
        rows.iter().map(DeviceRow::payload).collect(),
    )))
}

/// `GET /api/device-group/accessible` — grupos distintos vindos de `preset-device-group-name`/CLI.
pub async fn device_groups(
    State(st): State<AppState>,
    _user: AuthUser,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult<Json<Value>> {
    let page = Page::from_query(&q);
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT device_group) FROM devices WHERE device_group <> ''",
    )
    .fetch_one(&st.db)
    .await?;
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT device_group FROM devices WHERE device_group <> '' ORDER BY device_group LIMIT ? OFFSET ?",
    )
    .bind(page.size)
    .bind(page.offset)
    .fetch_all(&st.db)
    .await?;
    Ok(Json(page_json(
        total,
        names.into_iter().map(|n| json!({ "name": n })).collect(),
    )))
}
