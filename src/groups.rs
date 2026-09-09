//! Grupos: grupo de dispositivos com uma senha permanente única, um address book
//! compartilhado mantido pelo servidor (as máquinas do grupo com essa senha) e um
//! conjunto de opções empurradas aos clientes pelo heartbeat.

use rand::distributions::Alphanumeric;
use rand::Rng;
use serde_json::{json, Value};

use crate::auth;
use crate::db::{now, Db};
use crate::error::{ApiError, ApiResult};
use crate::models::{platform_from_os, GroupRow};

/// Dono técnico dos address books dos grupos: nunca faz login (status 0, hash inválido),
/// e por isso não some quando um administrador é apagado.
pub const SYSTEM_USER: &str = "_console";

pub fn default_options() -> Value {
    json!({
        "approve-mode": "password",
        "verification-method": "use-permanent-password",
    })
}

/// Identificador curto e não reversível da senha; a máquina informa no heartbeat a tag da
/// senha que aplicou por último e a API reenvia a senha quando a tag não bate.
pub fn password_tag(password: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(password.as_bytes());
    crate::util::hex(&digest[..8])
}

pub fn new_password() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(12)
        .map(char::from)
        .collect()
}

pub async fn ensure_system_user(db: &Db) -> ApiResult<i64> {
    let existing: Option<i64> = sqlx::query_scalar("SELECT id FROM users WHERE name = ?")
        .bind(SYSTEM_USER)
        .fetch_optional(db)
        .await?;
    if let Some(id) = existing {
        return Ok(id);
    }
    let res = sqlx::query(
        "INSERT INTO users (name, display_name, email, note, password_hash, status, is_admin, created_at, kind) \
         VALUES (?, 'Console', '', 'dono técnico dos address books dos grupos', '!', 0, 0, ?, 'staff')",
    )
    .bind(SYSTEM_USER)
    .bind(now())
    .execute(db)
    .await?;
    Ok(res.last_insert_rowid())
}

pub async fn get(db: &Db, id: i64) -> ApiResult<GroupRow> {
    sqlx::query_as::<_, GroupRow>("SELECT * FROM groups WHERE id = ?")
        .bind(id)
        .fetch_optional(db)
        .await?
        .ok_or_else(|| ApiError::not_found("Group not found"))
}

pub async fn by_name(db: &Db, name: &str) -> ApiResult<Option<GroupRow>> {
    Ok(sqlx::query_as::<_, GroupRow>("SELECT * FROM groups WHERE name = ?")
        .bind(name.trim())
        .fetch_optional(db)
        .await?)
}

pub async fn by_enroll_token(db: &Db, token: &str) -> ApiResult<Option<GroupRow>> {
    if token.trim().is_empty() {
        return Ok(None);
    }
    Ok(
        sqlx::query_as::<_, GroupRow>("SELECT * FROM groups WHERE enroll_token = ?")
            .bind(token.trim())
            .fetch_optional(db)
            .await?,
    )
}

pub async fn find_or_create_by_name(db: &Db, name: &str) -> ApiResult<GroupRow> {
    if let Some(st) = by_name(db, name).await? {
        return Ok(st);
    }
    create(db, name, None, "", None).await
}

/// Só strings são aceitas: é o que `Config::set_options` do cliente grava.
pub fn options_to_storage(v: Value) -> ApiResult<String> {
    let Some(obj) = v.as_object() else {
        return Err(ApiError::bad_request("options must be an object"));
    };
    let mut clean = serde_json::Map::new();
    for (k, val) in obj {
        let key = k.trim();
        if key.is_empty() {
            continue;
        }
        let sval = match val {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Null => String::new(),
            _ => return Err(ApiError::bad_request(format!("option {key} must be a string"))),
        };
        clean.insert(key.to_owned(), Value::String(sval));
    }
    Ok(Value::Object(clean).to_string())
}

pub async fn create(
    db: &Db,
    name: &str,
    password: Option<String>,
    note: &str,
    options: Option<Value>,
) -> ApiResult<GroupRow> {
    let name = name.trim();
    if name.is_empty() {
        return Err(ApiError::bad_request("name is required"));
    }
    if by_name(db, name).await?.is_some() {
        return Err(ApiError::bad_request("Group already exists"));
    }
    let password = password
        .filter(|p| !p.trim().is_empty())
        .unwrap_or_else(new_password);
    let options = options_to_storage(options.unwrap_or_else(default_options))?;
    let t = now();
    let res = sqlx::query(
        "INSERT INTO groups (name, password, ab_guid, options, options_updated_at, note, enroll_token, created_at) \
         VALUES (?, ?, NULL, ?, ?, ?, ?, ?)",
    )
    .bind(name)
    .bind(&password)
    .bind(options)
    .bind(t)
    .bind(note)
    .bind(auth::new_token())
    .bind(t)
    .execute(db)
    .await?;
    let id = res.last_insert_rowid();
    sync_ab(db, id).await?;
    get(db, id).await
}

pub async fn rename(db: &Db, id: i64, name: &str) -> ApiResult<()> {
    let name = name.trim();
    if name.is_empty() {
        return Err(ApiError::bad_request("name is required"));
    }
    if let Some(other) = by_name(db, name).await? {
        if other.id != id {
            return Err(ApiError::bad_request("Group already exists"));
        }
    }
    sqlx::query("UPDATE groups SET name = ? WHERE id = ?")
        .bind(name)
        .bind(id)
        .execute(db)
        .await?;
    sqlx::query("UPDATE devices SET device_group = ? WHERE group_id = ?")
        .bind(name)
        .bind(id)
        .execute(db)
        .await?;
    sync_ab(db, id).await?;
    Ok(())
}

pub async fn set_note(db: &Db, id: i64, note: &str) -> ApiResult<()> {
    sqlx::query("UPDATE groups SET note = ? WHERE id = ?")
        .bind(note)
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn set_require_login(db: &Db, id: i64, require: bool) -> ApiResult<()> {
    sqlx::query("UPDATE groups SET require_login = ? WHERE id = ?")
        .bind(i64::from(require))
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

/// Troca a senha do grupo e a espelha nos peers do address book compartilhado.
/// A senha permanente de cada máquina continua sendo gravada nela (`rustdesk --password`).
pub async fn set_password(db: &Db, id: i64, password: &str) -> ApiResult<()> {
    let password = password.trim();
    if password.is_empty() {
        return Err(ApiError::bad_request("password is required"));
    }
    sqlx::query("UPDATE groups SET password = ? WHERE id = ?")
        .bind(password)
        .bind(id)
        .execute(db)
        .await?;
    sqlx::query(
        "UPDATE ab_peers SET password = ?, updated_at = ? \
         WHERE ab_guid = (SELECT ab_guid FROM groups WHERE id = ?)",
    )
    .bind(password)
    .bind(now())
    .bind(id)
    .execute(db)
    .await?;
    // Rotação: marca todas as máquinas do grupo como não sincronizadas para o próximo heartbeat
    // reentregar a senha nova.
    sqlx::query("UPDATE devices SET password_synced = 0 WHERE group_id = ?")
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

/// Grava as opções e avança `options_updated_at`, que é o `modified_at` do heartbeat:
/// os clientes do grupo recebem o novo `strategy` no próximo batimento.
pub async fn set_options(db: &Db, id: i64, options: Value) -> ApiResult<i64> {
    let storage = options_to_storage(options)?;
    // Estritamente crescente: duas alterações no mesmo segundo ainda mudam o `modified_at`
    // que o cliente compara, senão a segunda nunca seria entregue.
    let previous = get(db, id).await?.options_updated_at;
    let t = now().max(previous + 1);
    sqlx::query("UPDATE groups SET options = ?, options_updated_at = ? WHERE id = ?")
        .bind(storage)
        .bind(t)
        .bind(id)
        .execute(db)
        .await?;
    Ok(t)
}

/// Garante o address book do grupo e o deixa igual à lista de máquinas do grupo,
/// cada uma com a senha do grupo. Apelido e nota editados pelos usuários são preservados.
pub async fn sync_ab(db: &Db, id: i64) -> ApiResult<String> {
    let st = get(db, id).await?;
    let owner = ensure_system_user(db).await?;
    let existing: Option<String> = match st.ab_guid.as_deref() {
        Some(g) => sqlx::query_scalar("SELECT guid FROM address_books WHERE guid = ?")
            .bind(g)
            .fetch_optional(db)
            .await?,
        None => None,
    };
    let guid = match existing {
        Some(g) => {
            sqlx::query("UPDATE address_books SET name = ? WHERE guid = ?")
                .bind(&st.name)
                .bind(&g)
                .execute(db)
                .await?;
            g
        }
        None => {
            let g = uuid::Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO address_books (guid, name, owner_id, is_personal, note, created_at) \
                 VALUES (?, ?, ?, 0, 'Grupo (mantido pelo console)', ?)",
            )
            .bind(&g)
            .bind(&st.name)
            .bind(owner)
            .bind(now())
            .execute(db)
            .await?;
            sqlx::query("UPDATE groups SET ab_guid = ? WHERE id = ?")
                .bind(&g)
                .bind(id)
                .execute(db)
                .await?;
            g
        }
    };

    let devices: Vec<(String, String, String, String, String)> = sqlx::query_as(
        "SELECT id, username, hostname, os, note FROM devices WHERE group_id = ?",
    )
    .bind(id)
    .fetch_all(db)
    .await?;
    let t = now();
    for (device_id, username, hostname, os, note) in &devices {
        sqlx::query(
            "INSERT INTO ab_peers (ab_guid, id, hash, password, username, hostname, platform, alias, tags, \
             force_always_relay, rdp_port, rdp_username, login_name, note, created_at, updated_at) \
             VALUES (?, ?, '', ?, ?, ?, ?, ?, '[]', 0, '', '', '', ?, ?, ?) \
             ON CONFLICT(ab_guid, id) DO UPDATE SET \
               password = excluded.password, username = excluded.username, hostname = excluded.hostname, \
               platform = excluded.platform, \
               alias = CASE WHEN ab_peers.alias = '' THEN excluded.alias ELSE ab_peers.alias END, \
               note = CASE WHEN ab_peers.note = '' THEN excluded.note ELSE ab_peers.note END, \
               updated_at = excluded.updated_at",
        )
        .bind(&guid)
        .bind(device_id)
        .bind(&st.password)
        .bind(username)
        .bind(hostname)
        .bind(platform_from_os(os))
        .bind(hostname)
        .bind(note)
        .bind(t)
        .bind(t)
        .execute(db)
        .await?;
    }
    sqlx::query(
        "DELETE FROM ab_peers WHERE ab_guid = ? AND id NOT IN (SELECT id FROM devices WHERE group_id = ?)",
    )
    .bind(&guid)
    .bind(id)
    .execute(db)
    .await?;
    Ok(guid)
}

/// Move o dispositivo para um grupo (ou para nenhum) e atualiza os address books envolvidos.
pub async fn assign_device(db: &Db, device_id: &str, group: Option<i64>) -> ApiResult<()> {
    let old: Option<Option<i64>> =
        sqlx::query_scalar("SELECT group_id FROM devices WHERE id = ?")
            .bind(device_id)
            .fetch_optional(db)
            .await?;
    let Some(old) = old else {
        return Err(ApiError::not_found("Device not found"));
    };
    let name = match group {
        Some(id) => get(db, id).await?.name,
        None => String::new(),
    };
    // Zera `password_synced` na troca de grupo: assim o próximo heartbeat entrega a senha do novo
    // grupo (é o que torna a matrícula pelo console suficiente, sem tocar na máquina).
    let changed = old != group;
    sqlx::query(
        "UPDATE devices SET group_id = ?, device_group = ?, \
         password_synced = CASE WHEN ? THEN 0 ELSE password_synced END WHERE id = ?",
    )
    .bind(group)
    .bind(name)
    .bind(changed)
    .bind(device_id)
    .execute(db)
    .await?;
    if let Some(o) = old {
        if Some(o) != group {
            sync_ab(db, o).await?;
        }
    }
    if let Some(n) = group {
        sync_ab(db, n).await?;
    }
    Ok(())
}

/// Cria a linha do dispositivo se ainda não existir (matrícula antes do primeiro heartbeat).
pub async fn ensure_device(db: &Db, id: &str, uuid: &str, hostname: &str) -> ApiResult<()> {
    sqlx::query(
        "INSERT INTO devices (id, uuid, hostname, first_seen_at, last_seen_at) VALUES (?, ?, ?, ?, 0) \
         ON CONFLICT(id) DO UPDATE SET \
           uuid = CASE WHEN excluded.uuid = '' THEN devices.uuid ELSE excluded.uuid END, \
           hostname = CASE WHEN excluded.hostname = '' THEN devices.hostname ELSE excluded.hostname END",
    )
    .bind(id)
    .bind(uuid)
    .bind(hostname)
    .bind(now())
    .execute(db)
    .await?;
    Ok(())
}

pub async fn delete(db: &Db, id: i64) -> ApiResult<()> {
    let st = get(db, id).await?;
    sqlx::query("UPDATE devices SET group_id = NULL, device_group = '' WHERE group_id = ?")
        .bind(id)
        .execute(db)
        .await?;
    if let Some(guid) = st.ab_guid {
        sqlx::query("DELETE FROM address_books WHERE guid = ?")
            .bind(guid)
            .execute(db)
            .await?;
    }
    sqlx::query("DELETE FROM groups WHERE id = ?")
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}
