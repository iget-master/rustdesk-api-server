use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::auth::AuthUser;
use crate::db::{now, Db};
use crate::error::{ApiError, ApiResult};
use crate::util::{i, opt_s, parse_value, s};
use crate::AppState;

/// O cliente reenvia o mesmo registro (mesmo `nonce`) em erro de rede/5xx;
/// um nonce repetido significa "já gravado" e basta responder 200.
async fn nonce_is_new(db: &Db, nonce: &str) -> ApiResult<bool> {
    if nonce.is_empty() {
        return Ok(true);
    }
    let t = now();
    sqlx::query("DELETE FROM audit_nonces WHERE created_at < ?")
        .bind(t - 600)
        .execute(db)
        .await?;
    match sqlx::query("INSERT INTO audit_nonces (nonce, created_at) VALUES (?, ?)")
        .bind(nonce)
        .bind(t)
        .execute(db)
        .await
    {
        Ok(_) => Ok(true),
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => Ok(false),
        Err(e) => Err(e.into()),
    }
}

fn value_string(v: &Value) -> String {
    match v {
        Value::String(x) => x.clone(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    }
}

/// `POST /api/audit/conn` — três eventos do lado controlado (`new`, autenticou, `close`)
/// e a nota opcional enviada pelo lado controlador (`{id, session_id, note}`).
pub async fn conn(State(st): State<AppState>, body: Bytes) -> ApiResult<StatusCode> {
    let v = parse_value(&body)?;
    let id = s(&v, "id");
    if id.is_empty() {
        return Err(ApiError::bad_request("id is required"));
    }
    if !nonce_is_new(&st.db, &s(&v, "nonce")).await? {
        return Ok(StatusCode::OK);
    }
    let session_id = s(&v, "session_id");
    let uuid = s(&v, "uuid");
    let t = now();
    let action = s(&v, "action");

    match (action.as_str(), i(&v, "conn_id")) {
        ("new", Some(conn_id)) => {
            sqlx::query(
                "INSERT INTO audit_conn (guid, device_id, device_uuid, conn_id, session_id, ip, conn_audit_ref, started_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
                 ON CONFLICT(device_id, conn_id, session_id) DO UPDATE SET \
                   ip = excluded.ip, \
                   conn_audit_ref = COALESCE(excluded.conn_audit_ref, audit_conn.conn_audit_ref)",
            )
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(&id)
            .bind(&uuid)
            .bind(conn_id)
            .bind(&session_id)
            .bind(s(&v, "ip"))
            .bind(opt_s(&v, "conn_audit_ref"))
            .bind(t)
            .execute(&st.db)
            .await?;
        }
        ("close", Some(conn_id)) => {
            sqlx::query(
                "INSERT INTO audit_conn (guid, device_id, device_uuid, conn_id, session_id, started_at, closed_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?) \
                 ON CONFLICT(device_id, conn_id, session_id) DO UPDATE SET closed_at = excluded.closed_at",
            )
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(&id)
            .bind(&uuid)
            .bind(conn_id)
            .bind(&session_id)
            .bind(t)
            .bind(t)
            .execute(&st.db)
            .await?;
        }
        (_, Some(conn_id)) if v.get("peer").is_some() => {
            let (peer_id, peer_name) = match v.get("peer") {
                Some(Value::Array(a)) => (
                    a.first().map(value_string).unwrap_or_default(),
                    a.get(1).map(value_string).unwrap_or_default(),
                ),
                Some(other) => (value_string(other), String::new()),
                None => (String::new(), String::new()),
            };
            sqlx::query(
                "INSERT INTO audit_conn (guid, device_id, device_uuid, conn_id, session_id, peer_id, peer_name, \
                   conn_type, primary_auth, two_factor, started_at, authed_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
                 ON CONFLICT(device_id, conn_id, session_id) DO UPDATE SET \
                   peer_id = excluded.peer_id, peer_name = excluded.peer_name, conn_type = excluded.conn_type, \
                   primary_auth = excluded.primary_auth, two_factor = excluded.two_factor, authed_at = excluded.authed_at",
            )
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(&id)
            .bind(&uuid)
            .bind(conn_id)
            .bind(&session_id)
            .bind(peer_id)
            .bind(peer_name)
            .bind(i(&v, "type"))
            .bind(i(&v, "primary_auth"))
            .bind(i(&v, "two_factor"))
            .bind(t)
            .bind(t)
            .execute(&st.db)
            .await?;
        }
        (_, None) if v.get("note").is_some() => {
            sqlx::query(
                "UPDATE audit_conn SET note = ? WHERE guid = \
                 (SELECT guid FROM audit_conn WHERE device_id = ? AND session_id = ? ORDER BY started_at DESC LIMIT 1)",
            )
            .bind(s(&v, "note"))
            .bind(&id)
            .bind(&session_id)
            .execute(&st.db)
            .await?;
        }
        _ => return Err(ApiError::bad_request("unrecognized audit payload")),
    }
    Ok(StatusCode::OK)
}

/// `GET /api/audit/conn/active?id=&session_id=&conn_type=` — GUID do registro da sessão,
/// como string JSON. Vazio (e não 404) quando ainda não chegou: o cliente continua tentando.
pub async fn conn_active(
    State(st): State<AppState>,
    _user: AuthUser,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult<Json<Value>> {
    let id = q.get("id").cloned().unwrap_or_default();
    let session_id = q.get("session_id").cloned().unwrap_or_default();
    if id.is_empty() || session_id.is_empty() {
        return Err(ApiError::bad_request("id and session_id are required"));
    }
    let guid: Option<String> = sqlx::query_scalar(
        "SELECT guid FROM audit_conn WHERE device_id = ? AND session_id = ? ORDER BY started_at DESC LIMIT 1",
    )
    .bind(&id)
    .bind(&session_id)
    .fetch_optional(&st.db)
    .await?;
    Ok(Json(Value::String(guid.unwrap_or_default())))
}

/// `PUT /api/audit` — `{guid, note}` vindo do diálogo de fim de conexão.
pub async fn note(
    State(st): State<AppState>,
    _user: AuthUser,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    let v = parse_value(&body)?;
    let guid = s(&v, "guid");
    if guid.is_empty() {
        return Err(ApiError::bad_request("guid is required"));
    }
    let res = sqlx::query("UPDATE audit_conn SET note = ? WHERE guid = ?")
        .bind(s(&v, "note"))
        .bind(&guid)
        .execute(&st.db)
        .await?;
    if res.rows_affected() == 0 {
        return Err(ApiError::not_found("Audit record not found"));
    }
    Ok(Json(json!({})))
}

pub async fn file(State(st): State<AppState>, body: Bytes) -> ApiResult<StatusCode> {
    let v = parse_value(&body)?;
    let id = s(&v, "id");
    if id.is_empty() {
        return Err(ApiError::bad_request("id is required"));
    }
    if !nonce_is_new(&st.db, &s(&v, "nonce")).await? {
        return Ok(StatusCode::OK);
    }
    sqlx::query(
        "INSERT INTO audit_file (guid, device_id, device_uuid, peer_id, conn_id, type, path, is_file, info, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&id)
    .bind(s(&v, "uuid"))
    .bind(s(&v, "peer_id"))
    .bind(i(&v, "conn_id"))
    .bind(i(&v, "type"))
    .bind(s(&v, "path"))
    .bind(i64::from(v.get("is_file").and_then(Value::as_bool).unwrap_or(false)))
    .bind(s(&v, "info"))
    .bind(now())
    .execute(&st.db)
    .await?;
    Ok(StatusCode::OK)
}

pub async fn alarm(State(st): State<AppState>, body: Bytes) -> ApiResult<StatusCode> {
    let v = parse_value(&body)?;
    let id = s(&v, "id");
    if id.is_empty() {
        return Err(ApiError::bad_request("id is required"));
    }
    if !nonce_is_new(&st.db, &s(&v, "nonce")).await? {
        return Ok(StatusCode::OK);
    }
    sqlx::query(
        "INSERT INTO audit_alarm (guid, device_id, device_uuid, typ, info, conn_id, conn_audit_ref, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&id)
    .bind(s(&v, "uuid"))
    .bind(i(&v, "typ"))
    .bind(s(&v, "info"))
    .bind(i(&v, "conn_id"))
    .bind(opt_s(&v, "conn_audit_ref"))
    .bind(now())
    .execute(&st.db)
    .await?;
    tracing::warn!(device = %id, typ = ?i(&v, "typ"), "alarme de segurança recebido");
    Ok(StatusCode::OK)
}
