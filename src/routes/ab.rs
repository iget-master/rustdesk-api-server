use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::auth::AuthUser;
use crate::db::{now, Db};
use crate::error::{ApiError, ApiResult};
use crate::models::{AbRow, PeerRow};
use crate::util::{opt_s, page_json, parse_value, s, tag_color, Page};
use crate::AppState;

pub const PERSONAL_AB_NAME: &str = "Personal";

const RULE_READ: i64 = 1;
const RULE_WRITE: i64 = 2;
const RULE_FULL: i64 = 3;

/// Address book + regra efetiva do usuário (dono = controle total).
async fn access(db: &Db, user: &AuthUser, guid: &str) -> ApiResult<(AbRow, i64)> {
    let ab = sqlx::query_as::<_, AbRow>(
        "SELECT guid, name, owner_id, is_personal, note FROM address_books WHERE guid = ?",
    )
    .bind(guid)
    .fetch_optional(db)
    .await?
    .ok_or_else(|| ApiError::not_found("Address book not found"))?;
    if ab.owner_id == user.user.id {
        return Ok((ab, RULE_FULL));
    }
    if ab.is_personal != 0 {
        return Err(ApiError::forbidden());
    }
    let rule: Option<i64> =
        sqlx::query_scalar("SELECT rule FROM address_book_shares WHERE ab_guid = ? AND user_id = ?")
            .bind(guid)
            .bind(user.user.id)
            .fetch_optional(db)
            .await?;
    match rule {
        Some(r) if r >= RULE_READ => Ok((ab, r)),
        _ => Err(ApiError::forbidden()),
    }
}

async fn writable(db: &Db, user: &AuthUser, guid: &str) -> ApiResult<AbRow> {
    let (ab, rule) = access(db, user, guid).await?;
    if rule >= RULE_WRITE {
        Ok(ab)
    } else {
        Err(ApiError::forbidden())
    }
}

pub async fn ensure_personal_ab(db: &Db, user_id: i64) -> ApiResult<String> {
    let existing: Option<String> =
        sqlx::query_scalar("SELECT guid FROM address_books WHERE owner_id = ? AND is_personal = 1")
            .bind(user_id)
            .fetch_optional(db)
            .await?;
    if let Some(guid) = existing {
        return Ok(guid);
    }
    let guid = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO address_books (guid, name, owner_id, is_personal, note, created_at) VALUES (?, ?, ?, 1, '', ?)",
    )
    .bind(&guid)
    .bind(PERSONAL_AB_NAME)
    .bind(user_id)
    .bind(now())
    .execute(db)
    .await?;
    Ok(guid)
}

/// `POST /api/ab/personal` — 200 aqui é o que tira o cliente do modo legado.
pub async fn personal(State(st): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    let guid = ensure_personal_ab(&st.db, user.user.id).await?;
    Ok(Json(json!({ "guid": guid })))
}

pub async fn settings(_user: AuthUser) -> Json<Value> {
    Json(json!({ "max_peer_one_ab": 0 }))
}

#[derive(sqlx::FromRow)]
struct ProfileRow {
    guid: String,
    name: String,
    owner: String,
    note: String,
    rule: i64,
}

pub async fn shared_profiles(
    State(st): State<AppState>,
    user: AuthUser,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult<Json<Value>> {
    let page = Page::from_query(&q);
    let filter = "FROM address_books ab JOIN users o ON o.id = ab.owner_id \
        LEFT JOIN address_book_shares sh ON sh.ab_guid = ab.guid AND sh.user_id = ? \
        WHERE ab.is_personal = 0 AND (ab.owner_id = ? OR sh.rule >= 1)";
    let total: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) {filter}"))
        .bind(user.user.id)
        .bind(user.user.id)
        .fetch_one(&st.db)
        .await?;
    let rows = sqlx::query_as::<_, ProfileRow>(&format!(
        "SELECT ab.guid, ab.name, o.name AS owner, ab.note, \
         CASE WHEN ab.owner_id = ? THEN 3 ELSE sh.rule END AS rule {filter} \
         ORDER BY ab.name LIMIT ? OFFSET ?"
    ))
    .bind(user.user.id)
    .bind(user.user.id)
    .bind(user.user.id)
    .bind(page.size)
    .bind(page.offset)
    .fetch_all(&st.db)
    .await?;
    let data = rows
        .iter()
        .map(|r| {
            json!({
                "guid": r.guid,
                "name": r.name,
                "owner": r.owner,
                "note": r.note,
                "info": null,
                "rule": r.rule,
            })
        })
        .collect();
    Ok(Json(page_json(total, data)))
}

pub async fn peers(
    State(st): State<AppState>,
    user: AuthUser,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult<Json<Value>> {
    let guid = q.get("ab").cloned().unwrap_or_default();
    if guid.is_empty() {
        return Err(ApiError::bad_request("ab is required"));
    }
    access(&st.db, &user, &guid).await?;
    let page = Page::from_query(&q);
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ab_peers WHERE ab_guid = ?")
        .bind(&guid)
        .fetch_one(&st.db)
        .await?;
    let rows = sqlx::query_as::<_, PeerRow>(
        "SELECT id, hash, password, username, hostname, platform, alias, tags, force_always_relay, \
         rdp_port, rdp_username, login_name, note FROM ab_peers WHERE ab_guid = ? \
         ORDER BY created_at, id LIMIT ? OFFSET ?",
    )
    .bind(&guid)
    .bind(page.size)
    .bind(page.offset)
    .fetch_all(&st.db)
    .await?;
    Ok(Json(page_json(
        total,
        rows.iter().map(PeerRow::payload).collect(),
    )))
}

#[derive(sqlx::FromRow)]
struct TagRow {
    name: String,
    color: i64,
}

pub async fn tags(
    State(st): State<AppState>,
    user: AuthUser,
    Path(guid): Path<String>,
) -> ApiResult<Json<Value>> {
    access(&st.db, &user, &guid).await?;
    let rows = sqlx::query_as::<_, TagRow>(
        "SELECT name, color FROM ab_tags WHERE ab_guid = ? ORDER BY rowid",
    )
    .bind(&guid)
    .fetch_all(&st.db)
    .await?;
    let data: Vec<Value> = rows
        .iter()
        .map(|t| json!({ "name": t.name, "color": t.color }))
        .collect();
    Ok(Json(Value::Array(data)))
}

fn tags_json(v: &Value) -> Option<String> {
    let arr = v.get("tags")?.as_array()?;
    let names: Vec<String> = arr
        .iter()
        .filter_map(|t| t.as_str().map(str::to_owned))
        .collect();
    serde_json::to_string(&names).ok()
}

fn relay_flag(v: &Value) -> Option<i64> {
    let x = v.get("forceAlwaysRelay")?;
    Some(i64::from(x.as_bool() == Some(true) || x.as_str() == Some("true")))
}

/// Insere ou atualiza um peer. `hash`/`password` vazios não sobrescrevem um valor guardado.
pub async fn upsert_peer(db: &Db, guid: &str, p: &Value) -> ApiResult<()> {
    let id = s(p, "id").trim().to_owned();
    if id.is_empty() {
        return Err(ApiError::bad_request("id is required"));
    }
    let t = now();
    sqlx::query(
        "INSERT INTO ab_peers (ab_guid, id, hash, password, username, hostname, platform, alias, tags, \
         force_always_relay, rdp_port, rdp_username, login_name, note, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
         ON CONFLICT(ab_guid, id) DO UPDATE SET \
           hash = CASE WHEN excluded.hash = '' THEN ab_peers.hash ELSE excluded.hash END, \
           password = CASE WHEN excluded.password = '' THEN ab_peers.password ELSE excluded.password END, \
           username = excluded.username, hostname = excluded.hostname, platform = excluded.platform, \
           alias = excluded.alias, tags = excluded.tags, force_always_relay = excluded.force_always_relay, \
           rdp_port = excluded.rdp_port, rdp_username = excluded.rdp_username, \
           login_name = excluded.login_name, note = excluded.note, updated_at = excluded.updated_at",
    )
    .bind(guid)
    .bind(&id)
    .bind(s(p, "hash"))
    .bind(s(p, "password"))
    .bind(s(p, "username"))
    .bind(s(p, "hostname"))
    .bind(s(p, "platform"))
    .bind(s(p, "alias"))
    .bind(tags_json(p).unwrap_or_else(|| "[]".to_owned()))
    .bind(relay_flag(p).unwrap_or(0))
    .bind(s(p, "rdpPort"))
    .bind(s(p, "rdpUsername"))
    .bind(s(p, "loginName"))
    .bind(s(p, "note"))
    .bind(t)
    .bind(t)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn peer_add(
    State(st): State<AppState>,
    user: AuthUser,
    Path(guid): Path<String>,
    body: Bytes,
) -> ApiResult<StatusCode> {
    let ab = writable(&st.db, &user, &guid).await?;
    let mut p = parse_value(&body)?;
    // AB pessoal guarda senha em hash; compartilhado guarda em claro (igual ao cliente).
    if let Some(obj) = p.as_object_mut() {
        if ab.is_personal != 0 {
            obj.remove("password");
        } else {
            obj.remove("hash");
        }
    }
    upsert_peer(&st.db, &guid, &p).await?;
    Ok(StatusCode::OK)
}

pub async fn peer_update(
    State(st): State<AppState>,
    user: AuthUser,
    Path(guid): Path<String>,
    body: Bytes,
) -> ApiResult<StatusCode> {
    writable(&st.db, &user, &guid).await?;
    let v = parse_value(&body)?;
    let id = s(&v, "id");
    if id.is_empty() {
        return Err(ApiError::bad_request("id is required"));
    }
    const FIELDS: &[(&str, &str)] = &[
        ("hash", "hash"),
        ("password", "password"),
        ("username", "username"),
        ("hostname", "hostname"),
        ("platform", "platform"),
        ("alias", "alias"),
        ("note", "note"),
        ("rdpPort", "rdp_port"),
        ("rdpUsername", "rdp_username"),
        ("loginName", "login_name"),
    ];
    let mut sets: Vec<String> = Vec::new();
    let mut binds: Vec<String> = Vec::new();
    for (key, col) in FIELDS {
        if let Some(val) = opt_s(&v, key) {
            sets.push(format!("{col} = ?"));
            binds.push(val);
        }
    }
    if let Some(tags) = tags_json(&v) {
        sets.push("tags = ?".to_owned());
        binds.push(tags);
    }
    if let Some(flag) = relay_flag(&v) {
        sets.push("force_always_relay = ?".to_owned());
        binds.push(flag.to_string());
    }
    if sets.is_empty() {
        return Ok(StatusCode::OK);
    }
    sets.push("updated_at = ?".to_owned());
    binds.push(now().to_string());
    let sql = format!(
        "UPDATE ab_peers SET {} WHERE ab_guid = ? AND id = ?",
        sets.join(", ")
    );
    let mut query = sqlx::query(&sql);
    for b in &binds {
        query = query.bind(b.as_str());
    }
    let res = query.bind(&guid).bind(&id).execute(&st.db).await?;
    if res.rows_affected() == 0 {
        return Err(ApiError::not_found("Peer not found"));
    }
    Ok(StatusCode::OK)
}

pub async fn peer_delete(
    State(st): State<AppState>,
    user: AuthUser,
    Path(guid): Path<String>,
    body: Bytes,
) -> ApiResult<StatusCode> {
    writable(&st.db, &user, &guid).await?;
    let ids: Vec<String> = serde_json::from_slice(&body)?;
    for id in ids {
        sqlx::query("DELETE FROM ab_peers WHERE ab_guid = ? AND id = ?")
            .bind(&guid)
            .bind(id)
            .execute(&st.db)
            .await?;
    }
    Ok(StatusCode::OK)
}

pub async fn ensure_tag(db: &Db, guid: &str, name: &str, color: Option<i64>) -> ApiResult<()> {
    sqlx::query("INSERT OR IGNORE INTO ab_tags (ab_guid, name, color) VALUES (?, ?, ?)")
        .bind(guid)
        .bind(name)
        .bind(color.unwrap_or_else(|| tag_color(name)))
        .execute(db)
        .await?;
    Ok(())
}

pub async fn tag_add(
    State(st): State<AppState>,
    user: AuthUser,
    Path(guid): Path<String>,
    body: Bytes,
) -> ApiResult<StatusCode> {
    writable(&st.db, &user, &guid).await?;
    let v = parse_value(&body)?;
    let name = s(&v, "name").trim().to_owned();
    if name.is_empty() {
        return Err(ApiError::bad_request("name is required"));
    }
    let exists: Option<i64> =
        sqlx::query_scalar("SELECT 1 FROM ab_tags WHERE ab_guid = ? AND name = ?")
            .bind(&guid)
            .bind(&name)
            .fetch_optional(&st.db)
            .await?;
    if exists.is_some() {
        return Err(ApiError::bad_request("Tag already exists"));
    }
    ensure_tag(&st.db, &guid, &name, v.get("color").and_then(Value::as_i64)).await?;
    Ok(StatusCode::OK)
}

/// Aplica uma transformação na lista de tags de cada peer do address book.
async fn rewrite_peer_tags(
    db: &Db,
    guid: &str,
    mut f: impl FnMut(&mut Vec<String>) -> bool,
) -> ApiResult<()> {
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT id, tags FROM ab_peers WHERE ab_guid = ?")
            .bind(guid)
            .fetch_all(db)
            .await?;
    for (id, tags) in rows {
        let mut list: Vec<String> = serde_json::from_str(&tags).unwrap_or_default();
        if f(&mut list) {
            sqlx::query("UPDATE ab_peers SET tags = ?, updated_at = ? WHERE ab_guid = ? AND id = ?")
                .bind(serde_json::to_string(&list)?)
                .bind(now())
                .bind(guid)
                .bind(id)
                .execute(db)
                .await?;
        }
    }
    Ok(())
}

pub async fn tag_rename(
    State(st): State<AppState>,
    user: AuthUser,
    Path(guid): Path<String>,
    body: Bytes,
) -> ApiResult<StatusCode> {
    writable(&st.db, &user, &guid).await?;
    let v = parse_value(&body)?;
    let old = s(&v, "old");
    let new = s(&v, "new").trim().to_owned();
    if old.is_empty() || new.is_empty() {
        return Err(ApiError::bad_request("old and new are required"));
    }
    if old == new {
        return Ok(StatusCode::OK);
    }
    let taken: Option<i64> =
        sqlx::query_scalar("SELECT 1 FROM ab_tags WHERE ab_guid = ? AND name = ?")
            .bind(&guid)
            .bind(&new)
            .fetch_optional(&st.db)
            .await?;
    if taken.is_some() {
        return Err(ApiError::bad_request("Tag already exists"));
    }
    let res = sqlx::query("UPDATE ab_tags SET name = ? WHERE ab_guid = ? AND name = ?")
        .bind(&new)
        .bind(&guid)
        .bind(&old)
        .execute(&st.db)
        .await?;
    if res.rows_affected() == 0 {
        return Err(ApiError::not_found("Tag not found"));
    }
    rewrite_peer_tags(&st.db, &guid, |list| {
        let mut changed = false;
        for t in list.iter_mut() {
            if *t == old {
                *t = new.clone();
                changed = true;
            }
        }
        changed
    })
    .await?;
    Ok(StatusCode::OK)
}

pub async fn tag_update(
    State(st): State<AppState>,
    user: AuthUser,
    Path(guid): Path<String>,
    body: Bytes,
) -> ApiResult<StatusCode> {
    writable(&st.db, &user, &guid).await?;
    let v = parse_value(&body)?;
    let name = s(&v, "name");
    let Some(color) = v.get("color").and_then(Value::as_i64) else {
        return Err(ApiError::bad_request("color is required"));
    };
    let res = sqlx::query("UPDATE ab_tags SET color = ? WHERE ab_guid = ? AND name = ?")
        .bind(color)
        .bind(&guid)
        .bind(&name)
        .execute(&st.db)
        .await?;
    if res.rows_affected() == 0 {
        return Err(ApiError::not_found("Tag not found"));
    }
    Ok(StatusCode::OK)
}

pub async fn tag_delete(
    State(st): State<AppState>,
    user: AuthUser,
    Path(guid): Path<String>,
    body: Bytes,
) -> ApiResult<StatusCode> {
    writable(&st.db, &user, &guid).await?;
    let names: Vec<String> = serde_json::from_slice(&body)?;
    for name in &names {
        sqlx::query("DELETE FROM ab_tags WHERE ab_guid = ? AND name = ?")
            .bind(&guid)
            .bind(name)
            .execute(&st.db)
            .await?;
    }
    rewrite_peer_tags(&st.db, &guid, |list| {
        let before = list.len();
        list.retain(|t| !names.contains(t));
        list.len() != before
    })
    .await?;
    Ok(StatusCode::OK)
}
