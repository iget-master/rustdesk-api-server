//! `POST /api/internal/authorize` — o hbbs do fork deste projeto pergunta, antes de intermediar
//! uma conexão (punch hole ou relay), se o cliente pode acessar a máquina. O pedido traz o
//! `access_token` que o cliente recebeu no `/api/login` e o ID de destino; o hbbs se identifica
//! pelo segredo de *Configurações* no cabeçalho `X-Hbbs-Secret`.
//!
//! Regras: sem token válido só entram máquinas de grupos sem "exigir login"; equipe e
//! administradores logados entram em tudo; externos só nas máquinas dos grupos concedidos (acesso
//! não vencido). As recusas ficam em `authz_denied` e aparecem em *Auditoria → Recusadas*.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};

use crate::auth;
use crate::db::{now, Db};
use crate::error::{ApiError, ApiResult};
use crate::util::{parse_value, s};
use crate::AppState;

pub const HBBS_SECRET_KEY: &str = "hbbs_secret";
const SECRET_HEADER: &str = "x-hbbs-secret";

/// Segredo compartilhado com o hbbs, gerado na primeira vez que alguém precisa dele.
pub async fn ensure_hbbs_secret(db: &Db) -> ApiResult<String> {
    let current: Option<String> = sqlx::query_scalar("SELECT value FROM settings WHERE key = ?")
        .bind(HBBS_SECRET_KEY)
        .fetch_optional(db)
        .await?;
    if let Some(v) = current.filter(|v| !v.is_empty()) {
        return Ok(v);
    }
    sqlx::query(
        "INSERT INTO settings (key, value) VALUES (?, ?) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value WHERE settings.value = ''",
    )
    .bind(HBBS_SECRET_KEY)
    .bind(auth::new_token())
    .execute(db)
    .await?;
    // relê: outra requisição pode ter gerado primeiro
    Ok(sqlx::query_scalar("SELECT value FROM settings WHERE key = ?")
        .bind(HBBS_SECRET_KEY)
        .fetch_one(db)
        .await?)
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub async fn authorize(
    State(st): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    let secret = ensure_hbbs_secret(&st.db).await?;
    let given = headers
        .get(SECRET_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !constant_time_eq(given, &secret) {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "Invalid hbbs secret"));
    }
    let v = parse_value(&body)?;
    let token = s(&v, "token");
    let peer_id = s(&v, "peer_id");
    let from = s(&v, "from");
    if peer_id.is_empty() {
        return Err(ApiError::bad_request("peer_id is required"));
    }

    // política da máquina de destino (desconhecida = sem política)
    let target: Option<(Option<i64>, Option<String>, Option<i64>)> = sqlx::query_as(
        "SELECT d.group_id, g.name, g.require_login FROM devices d \
         LEFT JOIN groups g ON g.id = d.group_id WHERE d.id = ?",
    )
    .bind(&peer_id)
    .fetch_optional(&st.db)
    .await?;
    let (group_id, group_name, require_login) = match target {
        Some((gid, name, rl)) => (gid, name.unwrap_or_default(), rl.unwrap_or(0) != 0),
        None => (None, String::new(), false),
    };

    // quem está conectando: sessão válida ou anônimo
    let user = if token.is_empty() {
        None
    } else {
        match auth::lookup_session(&st.db, &token).await {
            Ok(u) => Some(u),
            Err(e) if e.status == StatusCode::UNAUTHORIZED => None,
            Err(e) => return Err(e),
        }
    };

    let decision: Result<&str, String> = match &user {
        None if !require_login => Ok("anonymous"),
        None if token.is_empty() => Err(
            "Este computador só aceita conexões de usuários logados. Entre com sua conta no RustDesk."
                .to_owned(),
        ),
        None => Err("Sua sessão expirou. Entre de novo com sua conta no RustDesk.".to_owned()),
        Some(u) if !u.user.is_external() => Ok("staff"),
        Some(u) => {
            let granted = match group_id {
                Some(gid) => {
                    sqlx::query_scalar::<_, i64>(
                        "SELECT COUNT(*) FROM groups st \
                         JOIN address_book_shares sh ON sh.ab_guid = st.ab_guid \
                         WHERE st.id = ? AND sh.user_id = ? AND sh.rule >= 1 \
                         AND (sh.expires_at IS NULL OR sh.expires_at > ?)",
                    )
                    .bind(gid)
                    .bind(u.user.id)
                    .bind(now())
                    .fetch_one(&st.db)
                    .await?
                        > 0
                }
                None => false,
            };
            if granted {
                Ok("granted")
            } else {
                Err("Sua conta não tem acesso a este computador.".to_owned())
            }
        }
    };

    let user_name = user.as_ref().map(|u| u.user.name.clone());
    match decision {
        Ok(why) => {
            tracing::info!(peer = %peer_id, user = user_name.as_deref().unwrap_or("-"), from = %from, why, "conexão autorizada");
            Ok(Json(json!({ "allow": true, "user": user_name, "reason": why })))
        }
        Err(reason) => {
            tracing::warn!(peer = %peer_id, user = user_name.as_deref().unwrap_or("-"), from = %from, group = %group_name, reason = %reason, "conexão recusada");
            sqlx::query(
                "INSERT INTO authz_denied (at, peer_id, group_id, from_ip, user_name, reason) \
                 VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(now())
            .bind(&peer_id)
            .bind(group_id)
            .bind(&from)
            .bind(user_name.as_deref().unwrap_or(""))
            .bind(&reason)
            .execute(&st.db)
            .await?;
            Ok(Json(json!({ "allow": false, "user": user_name, "reason": reason })))
        }
    }
}
