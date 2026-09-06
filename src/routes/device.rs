use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

use crate::auth::AuthUser;
use crate::db::{now, Db};
use crate::error::{ApiError, ApiResult};
use crate::routes::ab::{ensure_tag, upsert_peer};
use crate::groups;
use crate::util::{i, opt_s, parse_value, s};
use crate::AppState;

/// `POST /api/heartbeat` — chega a cada 15 s (3 s com sessões ativas), sem token.
/// Se ainda não temos o sysinfo deste ID (banco novo, por exemplo), pedimos com `sysinfo: true`.
/// Se o dispositivo pertence a um grupo cujas opções mudaram desde o `modified_at` que o
/// cliente conhece, devolve o `strategy` com as `config_options` do grupo.
pub async fn heartbeat(State(st): State<AppState>, body: Bytes) -> ApiResult<Json<Value>> {
    let v = parse_value(&body)?;
    let id = s(&v, "id");
    if id.is_empty() {
        return Err(ApiError::bad_request("id is required"));
    }
    let has_sysinfo: Option<i64> =
        sqlx::query_scalar("SELECT length(sysinfo_json) > 2 FROM devices WHERE id = ?")
            .bind(&id)
            .fetch_optional(&st.db)
            .await?;
    let conns = v
        .get("conns")
        .filter(|c| c.is_array())
        .map(Value::to_string)
        .unwrap_or_else(|| "[]".to_owned());
    let t = now();
    sqlx::query(
        "INSERT INTO devices (id, uuid, conns, first_seen_at, last_seen_at) VALUES (?, ?, ?, ?, ?) \
         ON CONFLICT(id) DO UPDATE SET \
           uuid = CASE WHEN excluded.uuid = '' THEN devices.uuid ELSE excluded.uuid END, \
           conns = excluded.conns, last_seen_at = excluded.last_seen_at",
    )
    .bind(&id)
    .bind(s(&v, "uuid"))
    .bind(conns)
    .bind(t)
    .bind(t)
    .execute(&st.db)
    .await?;

    let mut resp = json!({});
    if has_sysinfo != Some(1) {
        resp["sysinfo"] = json!(true);
    }
    // Cliente personalizado: o token de matrícula gravado na instalação prova que a máquina é
    // nossa; ela entra no grupo do token se ainda não tem grupo, e recebe a senha do grupo em que
    // está sempre que a tag da senha aplicada não bate (instalação nova, rotação, troca local).
    let enroll_token = s(&v, "enroll_token");
    if !enroll_token.is_empty() {
        match crate::groups::by_enroll_token(&st.db, &enroll_token).await? {
            Some(token_group) => {
                let assigned: Option<i64> =
                    sqlx::query_scalar("SELECT group_id FROM devices WHERE id = ?")
                        .bind(&id)
                        .fetch_one(&st.db)
                        .await?;
                let group = match assigned {
                    None => {
                        crate::groups::assign_device(&st.db, &id, Some(token_group.id)).await?;
                        tracing::info!(device = %id, group = %token_group.name, "máquina matriculada pelo heartbeat");
                        token_group
                    }
                    Some(gid) if gid == token_group.id => token_group,
                    Some(gid) => crate::groups::get(&st.db, gid).await?,
                };
                let tag = crate::groups::password_tag(&group.password);
                let synced = s(&v, "password_tag") == tag;
                if !synced {
                    resp["password"] = json!(group.password);
                    resp["password_tag"] = json!(tag);
                }
                sqlx::query(
                    "UPDATE devices SET sync_client = 1, password_synced = ?, \
                     password_synced_at = CASE WHEN ? THEN ? ELSE password_synced_at END WHERE id = ?",
                )
                .bind(i64::from(synced))
                .bind(synced)
                .bind(t)
                .bind(&id)
                .execute(&st.db)
                .await?;
            }
            None => tracing::warn!(device = %id, "heartbeat com token de matrícula inválido"),
        }
    }
    let strategy: Option<(String, i64)> = sqlx::query_as(
        "SELECT st.options, st.options_updated_at FROM devices d \
         JOIN groups st ON st.id = d.group_id WHERE d.id = ?",
    )
    .bind(&id)
    .fetch_optional(&st.db)
    .await?;
    if let Some((options, updated_at)) = strategy {
        if updated_at > 0 && i(&v, "modified_at") != Some(updated_at) {
            let options: Value = serde_json::from_str(&options).unwrap_or_else(|_| json!({}));
            resp["modified_at"] = json!(updated_at);
            resp["strategy"] = json!({ "config_options": options });
        }
    }
    Ok(Json(resp))
}

/// `POST /api/sysinfo` — resposta em texto puro, como o cliente compara.
pub async fn sysinfo(State(st): State<AppState>, body: Bytes) -> ApiResult<&'static str> {
    let v = parse_value(&body)?;
    let id = s(&v, "id");
    if id.is_empty() {
        return Err(ApiError::bad_request("id is required"));
    }
    let t = now();
    sqlx::query(
        "INSERT INTO devices (id, uuid, hostname, username, os, cpu, memory, version, sysinfo_json, first_seen_at, last_seen_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
         ON CONFLICT(id) DO UPDATE SET \
           uuid = CASE WHEN excluded.uuid = '' THEN devices.uuid ELSE excluded.uuid END, \
           hostname = excluded.hostname, username = excluded.username, os = excluded.os, \
           cpu = excluded.cpu, memory = excluded.memory, version = excluded.version, \
           sysinfo_json = excluded.sysinfo_json, last_seen_at = excluded.last_seen_at",
    )
    .bind(&id)
    .bind(s(&v, "uuid"))
    .bind(s(&v, "hostname"))
    .bind(s(&v, "username"))
    .bind(s(&v, "os"))
    .bind(s(&v, "cpu"))
    .bind(s(&v, "memory"))
    .bind(s(&v, "version"))
    .bind(serde_json::to_string(&v)?)
    .bind(t)
    .bind(t)
    .execute(&st.db)
    .await?;

    // Campos `preset-*` de uma instalação pré-configurada (auto-provisionamento).
    let assignment = Assignment {
        user_name: opt_s(&v, "preset-user-name"),
        group: opt_s(&v, "preset-device-group-name"),
        note: opt_s(&v, "preset-note"),
        ab_name: opt_s(&v, "preset-address-book-name"),
        ab_tag: opt_s(&v, "preset-address-book-tag"),
        ab_alias: opt_s(&v, "preset-address-book-alias"),
        ab_password: opt_s(&v, "preset-address-book-password"),
        ab_note: opt_s(&v, "preset-address-book-note"),
        device_username: None,
        device_name: None,
    };
    apply_assignment(&st.db, &id, &assignment, false).await?;
    // O hostname/usuário podem ter mudado: reflete no address book do grupo.
    let group: Option<Option<i64>> =
        sqlx::query_scalar("SELECT group_id FROM devices WHERE id = ?")
            .bind(&id)
            .fetch_optional(&st.db)
            .await?;
    if let Some(Some(group_id)) = group {
        groups::sync_ab(&st.db, group_id).await?;
    }
    tracing::info!(device = %id, hostname = %s(&v, "hostname"), "sysinfo atualizado");
    Ok("SYSINFO_UPDATED")
}

/// `POST /api/enroll` — usado pelo script de instalação do grupo: `{token, id, uuid?, hostname?}`.
pub async fn enroll(State(st): State<AppState>, body: Bytes) -> ApiResult<Json<Value>> {
    let v = parse_value(&body)?;
    let token = s(&v, "token");
    let id = s(&v, "id").trim().to_owned();
    if token.is_empty() || id.is_empty() {
        return Err(ApiError::bad_request("token and id are required"));
    }
    let Some(group) = groups::by_enroll_token(&st.db, &token).await? else {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "Invalid enrollment token"));
    };
    groups::ensure_device(&st.db, &id, &s(&v, "uuid"), &s(&v, "hostname")).await?;
    groups::assign_device(&st.db, &id, Some(group.id)).await?;
    tracing::info!(device = %id, group = %group.name, "dispositivo matriculado no grupo");
    Ok(Json(json!({ "result": "OK", "group": group.name })))
}

/// `POST /api/switch-grant` — sem a chave pública do dispositivo (fica no hbbs) não há como
/// verificar a assinatura; aceitar mantém o "trocar lados" funcionando e o log do cliente limpo.
pub async fn switch_grant() -> Json<Value> {
    Json(json!({ "accepted": true }))
}

/// `POST /api/devices/deploy` — só faz sentido com um hbbs que exija deploy; o OSS não exige.
pub async fn deploy() -> Json<Value> {
    Json(json!({ "result": "NOT_ENABLED" }))
}

/// `POST /api/devices/cli` — `rustdesk --assign --token <token de admin> ...`
pub async fn cli_assign(
    State(st): State<AppState>,
    user: AuthUser,
    body: Bytes,
) -> ApiResult<StatusCode> {
    user.require_admin()?;
    let v = parse_value(&body)?;
    let id = s(&v, "id");
    if id.is_empty() {
        return Err(ApiError::bad_request("id is required"));
    }
    groups::ensure_device(&st.db, &id, &s(&v, "uuid"), "").await?;
    let assignment = Assignment {
        user_name: opt_s(&v, "user_name"),
        group: opt_s(&v, "device_group_name"),
        note: opt_s(&v, "note"),
        ab_name: opt_s(&v, "address_book_name"),
        ab_tag: opt_s(&v, "address_book_tag"),
        ab_alias: opt_s(&v, "address_book_alias"),
        ab_password: opt_s(&v, "address_book_password"),
        ab_note: opt_s(&v, "address_book_note"),
        device_username: opt_s(&v, "device_username"),
        device_name: opt_s(&v, "device_name"),
    };
    apply_assignment(&st.db, &id, &assignment, true).await?;
    tracing::info!(device = %id, by = %user.user.name, "dispositivo atribuído via --assign");
    Ok(StatusCode::OK)
}

#[derive(Debug, Default, Clone)]
pub struct Assignment {
    pub user_name: Option<String>,
    pub group: Option<String>,
    pub note: Option<String>,
    pub ab_name: Option<String>,
    pub ab_tag: Option<String>,
    pub ab_alias: Option<String>,
    pub ab_password: Option<String>,
    pub ab_note: Option<String>,
    pub device_username: Option<String>,
    pub device_name: Option<String>,
}

fn non_empty(v: &Option<String>) -> Option<&str> {
    v.as_deref().map(str::trim).filter(|x| !x.is_empty())
}

/// `strict` (CLI/--assign): usuário inexistente é erro e a atribuição sobrescreve a atual.
/// Não-strict (presets do sysinfo): usuário desconhecido é ignorado, dono já definido é mantido
/// e o peer só entra no address book pessoal se ainda não estiver lá (não clobbera edições).
/// O grupo é sempre um grupo: cria o grupo se não existir e move o dispositivo para ele.
pub async fn apply_assignment(
    db: &Db,
    device_id: &str,
    a: &Assignment,
    strict: bool,
) -> ApiResult<()> {
    let mut user_id: Option<i64> = None;
    if let Some(name) = non_empty(&a.user_name) {
        let found: Option<i64> = sqlx::query_scalar("SELECT id FROM users WHERE name = ?")
            .bind(name)
            .fetch_optional(db)
            .await?;
        match found {
            Some(uid) => user_id = Some(uid),
            None if strict => {
                return Err(ApiError::bad_request(format!("User '{name}' not found")))
            }
            None => tracing::warn!(device = %device_id, user = name, "preset-user-name desconhecido; ignorado"),
        }
    }
    if let Some(uid) = user_id {
        let sql = if strict {
            "UPDATE devices SET user_id = ? WHERE id = ?"
        } else {
            "UPDATE devices SET user_id = ? WHERE id = ? AND user_id IS NULL"
        };
        sqlx::query(sql).bind(uid).bind(device_id).execute(db).await?;
    }
    if let Some(g) = non_empty(&a.group) {
        let group = groups::find_or_create_by_name(db, g).await?;
        groups::assign_device(db, device_id, Some(group.id)).await?;
    }
    if let Some(n) = non_empty(&a.note) {
        sqlx::query("UPDATE devices SET note = ? WHERE id = ?")
            .bind(n)
            .bind(device_id)
            .execute(db)
            .await?;
    }
    if let Some(u) = non_empty(&a.device_username) {
        sqlx::query("UPDATE devices SET username = ? WHERE id = ?")
            .bind(u)
            .bind(device_id)
            .execute(db)
            .await?;
    }
    if let Some(h) = non_empty(&a.device_name) {
        sqlx::query("UPDATE devices SET hostname = ? WHERE id = ?")
            .bind(h)
            .bind(device_id)
            .execute(db)
            .await?;
    }

    let Some(ab_name) = non_empty(&a.ab_name) else {
        return Ok(());
    };
    // Dono efetivo: o usuário desta chamada ou o já atribuído ao dispositivo.
    let owner: Option<i64> = match user_id {
        Some(uid) => Some(uid),
        None => sqlx::query_scalar("SELECT user_id FROM devices WHERE id = ?")
            .bind(device_id)
            .fetch_optional(db)
            .await?
            .flatten(),
    };
    let found: Option<(String, i64)> = sqlx::query_as(
        "SELECT guid, is_personal FROM address_books WHERE name = ? AND (owner_id = ? OR is_personal = 0) \
         ORDER BY (owner_id = ?) DESC LIMIT 1",
    )
    .bind(ab_name)
    .bind(owner.unwrap_or(-1))
    .bind(owner.unwrap_or(-1))
    .fetch_optional(db)
    .await?;
    let (guid, is_personal) = match (found, owner) {
        (Some(x), _) => x,
        (None, Some(uid)) => {
            let guid = uuid::Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO address_books (guid, name, owner_id, is_personal, note, created_at) VALUES (?, ?, ?, 0, '', ?)",
            )
            .bind(&guid)
            .bind(ab_name)
            .bind(uid)
            .bind(now())
            .execute(db)
            .await?;
            tracing::info!(ab = ab_name, "address book compartilhado criado por atribuição");
            (guid, 0)
        }
        (None, None) if strict => {
            return Err(ApiError::bad_request(format!(
                "Address book '{ab_name}' not found; pass user_name to create it"
            )))
        }
        (None, None) => return Ok(()),
    };

    if !strict {
        let exists: Option<i64> =
            sqlx::query_scalar("SELECT 1 FROM ab_peers WHERE ab_guid = ? AND id = ?")
                .bind(&guid)
                .bind(device_id)
                .fetch_optional(db)
                .await?;
        if exists.is_some() {
            return Ok(());
        }
    }
    let dev: Option<(String, String, String)> =
        sqlx::query_as("SELECT username, hostname, os FROM devices WHERE id = ?")
            .bind(device_id)
            .fetch_optional(db)
            .await?;
    let (username, hostname, os) = dev.unwrap_or_default();
    let mut tags: Vec<String> = Vec::new();
    if let Some(tag) = non_empty(&a.ab_tag) {
        ensure_tag(db, &guid, tag, None).await?;
        tags.push(tag.to_owned());
    }
    let mut peer = json!({
        "id": device_id,
        "username": username,
        "hostname": hostname,
        "platform": crate::models::platform_from_os(&os),
        "alias": non_empty(&a.ab_alias).unwrap_or(""),
        "tags": tags,
        "note": non_empty(&a.ab_note).unwrap_or(""),
    });
    // O AB pessoal guarda a senha em hash calculado pelo cliente; só o compartilhado aceita texto.
    if is_personal == 0 {
        if let Some(pw) = non_empty(&a.ab_password) {
            peer["password"] = json!(pw);
        }
    }
    upsert_peer(db, &guid, &peer).await?;
    Ok(())
}
