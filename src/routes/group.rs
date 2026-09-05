use axum::extract::{Query, State};
use axum::Json;
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::auth::AuthUser;
use crate::db::now;
use crate::error::ApiResult;
use crate::models::{DeviceRow, UserRow, DEVICE_SELECT};
use crate::groups::SYSTEM_USER;
use crate::util::{page_json, Page};
use crate::AppState;

/// Grupos que um usuário externo pode ver: os que têm um acesso válido para ele.
const GRANTED_GROUPS: &str = "SELECT st.id FROM groups st \
    JOIN address_book_shares sh ON sh.ab_guid = st.ab_guid \
    WHERE sh.user_id = ? AND sh.rule >= 1 AND (sh.expires_at IS NULL OR sh.expires_at > ?)";

/// `GET /api/users` — a equipe vê todos os usuários ativos; um externo não vê ninguém.
pub async fn users(
    State(st): State<AppState>,
    user: AuthUser,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult<Json<Value>> {
    if user.user.is_external() {
        return Ok(Json(page_json(0, Vec::new())));
    }
    let page = Page::from_query(&q);
    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE status = 1 AND name <> ?")
            .bind(SYSTEM_USER)
            .fetch_one(&st.db)
            .await?;
    let rows = sqlx::query_as::<_, UserRow>(
        "SELECT * FROM users WHERE status = 1 AND name <> ? ORDER BY name LIMIT ? OFFSET ?",
    )
    .bind(SYSTEM_USER)
    .bind(page.size)
    .bind(page.offset)
    .fetch_all(&st.db)
    .await?;
    Ok(Json(page_json(
        total,
        rows.iter().map(UserRow::payload).collect(),
    )))
}

/// `GET /api/peers` — dispositivos conhecidos pelo heartbeat/sysinfo; externo só vê os do seu grupo.
pub async fn peers(
    State(st): State<AppState>,
    user: AuthUser,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult<Json<Value>> {
    let page = Page::from_query(&q);
    let (total, rows) = if user.user.is_external() {
        let t = now();
        let total: i64 = sqlx::query_scalar(&format!(
            "SELECT COUNT(*) FROM devices d WHERE d.group_id IN ({GRANTED_GROUPS})"
        ))
        .bind(user.user.id)
        .bind(t)
        .fetch_one(&st.db)
        .await?;
        let rows = sqlx::query_as::<_, DeviceRow>(&format!(
            "{DEVICE_SELECT} WHERE d.group_id IN ({GRANTED_GROUPS}) \
             ORDER BY d.hostname, d.id LIMIT ? OFFSET ?"
        ))
        .bind(user.user.id)
        .bind(t)
        .bind(page.size)
        .bind(page.offset)
        .fetch_all(&st.db)
        .await?;
        (total, rows)
    } else {
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
        (total, rows)
    };
    Ok(Json(page_json(
        total,
        rows.iter().map(DeviceRow::payload).collect(),
    )))
}

/// `GET /api/device-group/accessible` — os grupos (externo: só os seus).
pub async fn device_groups(
    State(st): State<AppState>,
    user: AuthUser,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult<Json<Value>> {
    let page = Page::from_query(&q);
    let names: Vec<String> = if user.user.is_external() {
        sqlx::query_scalar(&format!(
            "SELECT name FROM groups WHERE id IN ({GRANTED_GROUPS}) ORDER BY name LIMIT ? OFFSET ?"
        ))
        .bind(user.user.id)
        .bind(now())
        .bind(page.size)
        .bind(page.offset)
        .fetch_all(&st.db)
        .await?
    } else {
        sqlx::query_scalar("SELECT name FROM groups ORDER BY name LIMIT ? OFFSET ?")
            .bind(page.size)
            .bind(page.offset)
            .fetch_all(&st.db)
            .await?
    };
    let total = names.len() as i64 + page.offset;
    Ok(Json(page_json(
        total,
        names.into_iter().map(|n| json!({ "name": n })).collect(),
    )))
}
