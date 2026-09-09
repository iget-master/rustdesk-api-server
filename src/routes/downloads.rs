//! Instaladores hospedados na própria API (`<dados>/downloads`), para distribuir o cliente
//! personalizado sem expor o link publicamente: o download exige o token de matrícula de um
//! grupo (`X-Enroll-Token` ou `?token=`), que o script de instalação já carrega; upload,
//! listagem e remoção são do console (administrador) ou do workflow de build com um token.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::auth::{self, AuthUser};
use crate::error::{ApiError, ApiResult};
use crate::AppState;

/// Só nomes simples de arquivo: nada de barras, `..` ou nome começando com ponto.
/// Extrai um `x.y.z` de um nome de arquivo (o trecho entre hífens que são só números e pontos).
fn version_from_name(name: &str) -> Option<String> {
    name.split('-')
        .find(|part| {
            let comps: Vec<&str> = part.split('.').collect();
            comps.len() == 3
                && comps
                    .iter()
                    .all(|c| !c.is_empty() && c.chars().all(|ch| ch.is_ascii_digit()))
        })
        .map(str::to_owned)
}

fn checked_name(name: &str) -> ApiResult<&str> {
    let ok = !name.is_empty()
        && name.len() <= 120
        && !name.starts_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if ok {
        Ok(name)
    } else {
        Err(ApiError::not_found("file not found"))
    }
}

/// `GET /downloads/{name}` — token de matrícula de qualquer grupo, ou sessão de administrador.
pub async fn get_file(
    State(st): State<AppState>,
    Path(name): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> ApiResult<impl IntoResponse> {
    let name = checked_name(&name)?.to_owned();
    let token = headers
        .get("x-enroll-token")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .or_else(|| q.get("token").cloned())
        .unwrap_or_default();
    let mut allowed = false;
    if !token.trim().is_empty() {
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM groups WHERE enroll_token = ?")
            .bind(token.trim())
            .fetch_one(&st.db)
            .await?;
        allowed = n > 0;
    }
    if !allowed {
        if let Some(bearer) = auth::bearer_from_headers(&headers) {
            allowed = auth::lookup_session(&st.db, &bearer)
                .await
                .map(|u| u.user.is_admin != 0)
                .unwrap_or(false);
        }
    }
    if !allowed {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "enroll token required"));
    }
    let path = st.downloads_dir.join(&name);
    let data = tokio::fs::read(&path)
        .await
        .map_err(|_| ApiError::not_found("file not found"))?;
    Ok((
        StatusCode::OK,
        [
            (CONTENT_TYPE, "application/octet-stream".to_owned()),
            (CONTENT_DISPOSITION, format!("attachment; filename=\"{name}\"")),
        ],
        data,
    ))
}

fn entry_json(name: &str, meta: &std::fs::Metadata) -> Value {
    let modified = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64);
    json!({ "name": name, "size": meta.len(), "modified_at": modified })
}

/// `GET /admin/api/downloads`
pub async fn list(State(st): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    user.require_admin()?;
    let mut out = Vec::new();
    if let Ok(mut dir) = tokio::fs::read_dir(&st.downloads_dir).await {
        while let Ok(Some(entry)) = dir.next_entry().await {
            let name = entry.file_name().to_string_lossy().into_owned();
            if checked_name(&name).is_err() {
                continue;
            }
            if let Ok(meta) = entry.metadata().await {
                if meta.is_file() {
                    out.push(entry_json(&name, &meta));
                }
            }
        }
    }
    out.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    Ok(Json(Value::Array(out)))
}

/// `PUT /admin/api/downloads/{name}` — corpo = o arquivo (`application/octet-stream`).
pub async fn upload(
    State(st): State<AppState>,
    user: AuthUser,
    Path(name): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    user.require_admin()?;
    let name = checked_name(&name)
        .map_err(|_| ApiError::bad_request("invalid file name"))?
        .to_owned();
    if body.is_empty() {
        return Err(ApiError::bad_request("empty body"));
    }
    tokio::fs::create_dir_all(&st.downloads_dir)
        .await
        .map_err(|e| ApiError::internal(format!("downloads dir: {e}")))?;
    let path = st.downloads_dir.join(&name);
    let tmp = st.downloads_dir.join(format!(".{name}.part"));
    tokio::fs::write(&tmp, &body)
        .await
        .map_err(|e| ApiError::internal(format!("write: {e}")))?;
    tokio::fs::rename(&tmp, &path)
        .await
        .map_err(|e| ApiError::internal(format!("rename: {e}")))?;
    let meta = tokio::fs::metadata(&path)
        .await
        .map_err(|e| ApiError::internal(format!("stat: {e}")))?;
    tracing::info!(file = %name, size = body.len(), by = %user.user.name, "instalador enviado");
    // `?use=1`: o script de instalação passa a baixar este arquivo (precisa da URL da API)
    let mut used = false;
    if q.get("use").is_some_and(|v| v == "1" || v == "true") {
        let api_url: Option<String> =
            sqlx::query_scalar("SELECT value FROM settings WHERE key = 'api_url'")
                .fetch_optional(&st.db)
                .await?;
        if let Some(api_url) = api_url.filter(|u| !u.trim().is_empty()) {
            let url = format!("{}/downloads/{name}", api_url.trim().trim_end_matches('/'));
            sqlx::query(
                "INSERT INTO settings (key, value) VALUES ('download_url', ?) \
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            )
            .bind(&url)
            .execute(&st.db)
            .await?;
            // A versão sai do nome do arquivo (ex.: RustdeskOlirio-1.4.10-x86_64.exe -> 1.4.10) e
            // vira `client_version`, que dispara o auto-update nas máquinas em versão mais antiga.
            if let Some(ver) = version_from_name(&name) {
                sqlx::query(
                    "INSERT INTO settings (key, value) VALUES ('client_version', ?) \
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                )
                .bind(&ver)
                .execute(&st.db)
                .await?;
            }
            used = true;
        }
    }
    let mut out = entry_json(&name, &meta);
    out["used"] = json!(used);
    Ok(Json(out))
}

/// `DELETE /admin/api/downloads/{name}`
pub async fn delete(
    State(st): State<AppState>,
    user: AuthUser,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    user.require_admin()?;
    let name = checked_name(&name)?.to_owned();
    tokio::fs::remove_file(st.downloads_dir.join(&name))
        .await
        .map_err(|_| ApiError::not_found("file not found"))?;
    Ok(Json(json!({})))
}
