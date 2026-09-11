//! API do console (`/admin/api/*`): tudo exige um usuário administrador.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use rand::Rng;
use serde_json::{json, Map, Value};
use std::collections::HashMap;

use crate::auth::{self, AuthUser};
use crate::cli::create_user;
use crate::db::{now, Db};
use crate::error::{ApiError, ApiResult};
use crate::models::{
    DeviceRow, GroupRow, UserRow, DEVICE_SELECT, ONLINE_WINDOW_SECS, TFA_CONSOLE,
    USER_KIND_EXTERNAL,
};
use crate::groups::{self, SYSTEM_USER};
use crate::util::{i, opt_s, parse_value, s};
use crate::AppState;

use super::authorize::{ensure_hbbs_secret, HBBS_SECRET_KEY};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/overview", get(overview))
        .route("/settings", get(settings_get).put(settings_put))
        .route("/groups", get(groups_list).post(groups_create))
        .route("/groups/{id}", put(groups_update).delete(groups_delete))
        .route("/groups/{id}/rotate-password", post(groups_rotate))
        .route("/groups/{id}/install-script", get(groups_install_script))
        .route("/devices", get(devices_list))
        .route("/devices/{id}", put(devices_update).delete(devices_delete))
        .route("/users", get(users_list).post(users_create))
        .route("/users/{id}", put(users_update).delete(users_delete))
        .route("/users/{id}/password", post(users_password))
        .route("/users/{id}/access-code", post(users_access_code))
        .route("/users/{id}/access-code/{code_id}", delete(users_access_code_delete))
        .route("/users/{id}/logout", post(users_logout))
        .route("/grants", get(grants_list).post(grants_create).delete(grants_delete))
        .route("/audit/conn", get(audit_conn))
        .route("/audit/file", get(audit_file))
        .route("/audit/alarm", get(audit_alarm))
        .route("/audit/denied", get(audit_denied))
        .route("/downloads", get(super::downloads::list))
        .route(
            "/installer-token/rotate",
            post(super::downloads::rotate_installer_token),
        )
        .route(
            "/downloads/{name}",
            put(super::downloads::upload).delete(super::downloads::delete),
        )
        // upload de instaladores (o padrão do axum é 2 MB)
        .layer(axum::extract::DefaultBodyLimit::max(300 * 1024 * 1024))
}

const SETTING_KEYS: &[&str] = &["server_host", "server_key", "api_url", "download_url", "client_app_name", "require_group", "client_version"];

async fn settings_map(db: &Db) -> ApiResult<Map<String, Value>> {
    let rows: Vec<(String, String)> = sqlx::query_as("SELECT key, value FROM settings")
        .fetch_all(db)
        .await?;
    let mut map = Map::new();
    for k in SETTING_KEYS {
        map.insert((*k).to_owned(), Value::String(String::new()));
    }
    for (k, v) in rows {
        map.insert(k, Value::String(v));
    }
    map.insert(
        HBBS_SECRET_KEY.to_owned(),
        Value::String(ensure_hbbs_secret(db).await?),
    );
    map.insert(
        crate::routes::downloads::INSTALLER_TOKEN_KEY.to_owned(),
        Value::String(crate::routes::downloads::ensure_installer_token(db).await?),
    );
    Ok(map)
}

pub async fn settings_get(State(st): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    user.require_admin()?;
    Ok(Json(Value::Object(settings_map(&st.db).await?)))
}

pub async fn settings_put(
    State(st): State<AppState>,
    user: AuthUser,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    user.require_admin()?;
    let v = parse_value(&body)?;
    for k in SETTING_KEYS {
        if let Some(val) = opt_s(&v, k) {
            sqlx::query(
                "INSERT INTO settings (key, value) VALUES (?, ?) \
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            )
            .bind(k)
            .bind(val.trim())
            .execute(&st.db)
            .await?;
        }
    }
    Ok(Json(Value::Object(settings_map(&st.db).await?)))
}

// ---------------------------------------------------------------- grupos

#[derive(sqlx::FromRow)]
struct GrantRow {
    user_id: i64,
    user_name: String,
    display_name: String,
    kind: String,
    group_id: i64,
    group_name: String,
    rule: i64,
    expires_at: Option<i64>,
}

const GRANT_SELECT: &str = "SELECT u.id AS user_id, u.name AS user_name, u.display_name, u.kind, \
    st.id AS group_id, st.name AS group_name, sh.rule, sh.expires_at \
    FROM address_book_shares sh JOIN users u ON u.id = sh.user_id JOIN groups st ON st.ab_guid = sh.ab_guid";

fn grant_json(g: &GrantRow, t: i64) -> Value {
    json!({
        "user_id": g.user_id,
        "user_name": g.user_name,
        "display_name": g.display_name,
        "kind": g.kind,
        "group_id": g.group_id,
        "group_name": g.group_name,
        "rule": g.rule,
        "expires_at": g.expires_at,
        "expired": g.expires_at.is_some_and(|e| e <= t),
    })
}

async fn group_json(db: &Db, st: &GroupRow, t: i64) -> ApiResult<Value> {
    let (devices, online): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COALESCE(SUM(last_seen_at >= ?), 0) FROM devices WHERE group_id = ?",
    )
    .bind(t - ONLINE_WINDOW_SECS)
    .bind(st.id)
    .fetch_one(db)
    .await?;
    let grants = sqlx::query_as::<_, GrantRow>(&format!(
        "{GRANT_SELECT} WHERE st.id = ? ORDER BY u.name"
    ))
    .bind(st.id)
    .fetch_all(db)
    .await?;
    Ok(json!({
        "id": st.id,
        "name": st.name,
        "password": st.password,
        "note": st.note,
        "ab_guid": st.ab_guid,
        "options": st.options_json(),
        "options_updated_at": st.options_updated_at,
        "enroll_token": st.enroll_token,
        "require_login": st.require_login != 0,
        "created_at": st.created_at,
        "devices": devices,
        "online": online,
        "grants": grants.iter().map(|g| grant_json(g, t)).collect::<Vec<_>>(),
    }))
}

pub async fn groups_list(State(st): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    user.require_admin()?;
    let rows = sqlx::query_as::<_, GroupRow>("SELECT * FROM groups ORDER BY name")
        .fetch_all(&st.db)
        .await?;
    let t = now();
    let mut out = Vec::with_capacity(rows.len());
    for row in &rows {
        out.push(group_json(&st.db, row, t).await?);
    }
    Ok(Json(Value::Array(out)))
}

pub async fn groups_create(
    State(st): State<AppState>,
    user: AuthUser,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    user.require_admin()?;
    let v = parse_value(&body)?;
    let group = groups::create(
        &st.db,
        &s(&v, "name"),
        opt_s(&v, "password"),
        s(&v, "note").trim(),
        v.get("options").cloned(),
    )
    .await?;
    tracing::info!(group = %group.name, by = %user.user.name, "grupo criado");
    Ok(Json(group_json(&st.db, &group, now()).await?))
}

pub async fn groups_update(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<i64>,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    user.require_admin()?;
    let v = parse_value(&body)?;
    groups::get(&st.db, id).await?;
    if let Some(name) = opt_s(&v, "name") {
        groups::rename(&st.db, id, &name).await?;
    }
    if let Some(password) = opt_s(&v, "password") {
        groups::set_password(&st.db, id, &password).await?;
    }
    if let Some(note) = opt_s(&v, "note") {
        groups::set_note(&st.db, id, note.trim()).await?;
    }
    if let Some(options) = v.get("options") {
        groups::set_options(&st.db, id, options.clone()).await?;
    }
    if let Some(require) = v.get("require_login").and_then(Value::as_bool) {
        groups::set_require_login(&st.db, id, require).await?;
        tracing::info!(group = id, require_login = require, by = %user.user.name, "política de conexão alterada");
    }
    let group = groups::get(&st.db, id).await?;
    Ok(Json(group_json(&st.db, &group, now()).await?))
}

pub async fn groups_delete(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    user.require_admin()?;
    groups::delete(&st.db, id).await?;
    Ok(Json(json!({})))
}

pub async fn groups_rotate(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    user.require_admin()?;
    let password = groups::new_password();
    groups::set_password(&st.db, id, &password).await?;
    tracing::info!(group = id, by = %user.user.name, "senha do grupo rotacionada");
    Ok(Json(json!({ "password": password })))
}

fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Script de instalação do Windows. Os marcadores `@NOME@` são trocados por literais PowerShell já
/// entre aspas (`ps_quote`) ou por blocos inteiros. Ele é feito para falhar alto: cada etapa é
/// conferida, porque as opções do cliente (`--option`, `--password`) vão por IPC para o serviço e
/// são **descartadas em silêncio** quando o serviço não está no ar — foi assim que uma máquina
/// ficou "instalada" sem token nem senha.
const WIN_INSTALL_PS1: &str = r##"# @APPNAME@ — Grupo: @GROUPNAME@
# Instala o cliente, liga no seu servidor, aplica a senha do grupo e matricula esta máquina.
# Rode como Administrador. Se salvar em arquivo, chame assim (o .ps1 não roda por duplo clique):
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\instalar.ps1
# Pelo console, o botão "baixar .cmd" gera um arquivo que já faz isso sozinho.
#
# Antivírus: o instalador não é assinado, então escudos comportamentais (Avast, por exemplo)
# podem matá-lo no meio e mandá-lo para a quarentena. Se acontecer, libere estes dois caminhos:
#   C:\Program Files\@APPNAME@\
#   %TEMP%\@APPNAME@-setup\

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072
$app   = @APP@
$exe   = @EXE@
$token = @TOKEN@
$api   = @API@
$senha = @SENHA@
$grupo = @GRUPO@
$erro  = $null
function Etapa($t) { Write-Host ''; Write-Host ('== ' + $t) -ForegroundColor Cyan }

try {
  $eu = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
  if (-not $eu.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Rode como Administrador (botão direito no PowerShell > Executar como administrador).'
  }

  Etapa 'Instalação'
@INSTALL@

  Etapa 'Serviço do Windows'
  # Sem o serviço no ar, tudo abaixo é descartado em silêncio: as opções vão por IPC para ele.
  if (-not (Get-Service -Name $app -ErrorAction SilentlyContinue)) {
    Write-Host 'Serviço ausente — criando.'
    Start-Process -FilePath $exe -ArgumentList '--install-service' -Wait
    for ($i = 0; $i -lt 30 -and -not (Get-Service -Name $app -ErrorAction SilentlyContinue); $i++) { Start-Sleep -Seconds 1 }
  }
  if (-not (Get-Service -Name $app -ErrorAction SilentlyContinue)) {
    throw ("O serviço $app não foi criado. Rode à mão: & '" + $exe + "' --install-service")
  }
  if ((Get-Service -Name $app).Status -ne 'Running') { Start-Service -Name $app }
  for ($i = 0; $i -lt 30 -and (Get-Service -Name $app).Status -ne 'Running'; $i++) { Start-Sleep -Seconds 1 }
  if ((Get-Service -Name $app).Status -ne 'Running') { throw "O serviço $app não iniciou." }
  Write-Host "Serviço $app rodando."

  Etapa 'Configuração'
@SERVEROPTS@
  & $exe --option approve-mode 'password' | Out-Null
  & $exe --option verification-method 'use-permanent-password' | Out-Null
  & $exe --option enroll-token $token | Out-Null
  Start-Sleep -Milliseconds 500
  $lido = "$(& $exe --option enroll-token | Select-Object -Last 1)".Trim()
  if ($lido -ne $token) { throw 'O cliente não gravou o token de matrícula (o serviço recusou a configuração).' }
  $res = "$(& $exe --password $senha | Select-Object -Last 1)".Trim()
  if ($res -ne 'Done!') { throw ('Não consegui gravar a senha do grupo: ' + $res) }
  Write-Host 'Token de matrícula e senha do grupo aplicados.'

  Etapa 'Matrícula'
  $id = ''
  for ($i = 0; $i -lt 15; $i++) {
    $id = "$(& $exe --get-id | Select-Object -Last 1)".Trim()
    if ($id -match '^[0-9]{6,}$') { break }
    Start-Sleep -Seconds 2
  }
  if ($id -notmatch '^[0-9]{6,}$') { throw ("Não consegui ler o ID desta máquina (li '" + $id + "').") }
  $body = @{ token = $token; id = $id; hostname = $env:COMPUTERNAME } | ConvertTo-Json
  Invoke-RestMethod -Method Post -Uri ($api + '/api/enroll') -ContentType 'application/json' -Body $body | Out-Null
  Write-Host ''
  Write-Host "Pronto: máquina $id matriculada no grupo $grupo." -ForegroundColor Green
}
catch {
  $erro = $_
  Write-Host ''
  Write-Host ('FALHOU: ' + $erro) -ForegroundColor Red
}
if ($PSCommandPath) { Write-Host ''; Read-Host 'Enter para fechar' | Out-Null }
if ($erro) { exit 1 }
"##;

/// Mesmo script embrulhado num `.cmd`: pede elevação, roda o PowerShell com `-ExecutionPolicy
/// Bypass` (o padrão do Windows recusa `.ps1`) e dá `pause` no fim, para a janela não fechar
/// levando o erro junto. O `LastIndexOf` acha o marcador da segunda vez — a primeira é esta linha.
const WIN_INSTALL_CMD: &str = r##"@echo off
chcp 65001 >nul
setlocal
set "SELF=%~f0"
if /i "%~1"=="-elevado" goto :rodar
net session >nul 2>&1
if not errorlevel 1 goto :rodar
echo Pedindo privilegios de administrador...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath $env:SELF -Verb RunAs -ArgumentList '-elevado'"
exit /b
:rodar
powershell -NoProfile -ExecutionPolicy Bypass -Command "$t=[IO.File]::ReadAllText($env:SELF,[Text.Encoding]::UTF8); Invoke-Expression $t.Substring($t.LastIndexOf('#--POWERSHELL--#'))"
echo.
pause
exit /b
#--POWERSHELL--#
"##;

pub async fn groups_install_script(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<i64>,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult<impl IntoResponse> {
    user.require_admin()?;
    let group = groups::get(&st.db, id).await?;
    let settings = settings_map(&st.db).await?;
    let get = |k: &str| {
        settings
            .get(k)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned()
    };
    let (host, key, api, download, custom_app) = (
        get("server_host"),
        get("server_key"),
        get("api_url"),
        get("download_url"),
        get("client_app_name"),
    );
    if host.is_empty() || api.is_empty() {
        return Err(ApiError::bad_request(
            "Preencha o servidor de ID e a URL da API em Configurações",
        ));
    }
    let os = q.get("os").map(String::as_str).unwrap_or("windows");
    let script = if os == "linux" {
        let mut lines = vec![
            "#!/usr/bin/env bash".to_owned(),
            format!("# RustDesk — Grupo: {}. Execute como root com o RustDesk já instalado.", group.name),
            "set -e".to_owned(),
            "command -v rustdesk >/dev/null || { echo 'Instale o RustDesk primeiro'; exit 1; }".to_owned(),
            format!("rustdesk --option custom-rendezvous-server {}", sh_quote(&host)),
        ];
        if !key.is_empty() {
            lines.push(format!("rustdesk --option key {}", sh_quote(&key)));
        }
        lines.extend([
            format!("rustdesk --option api-server {}", sh_quote(&api)),
            "rustdesk --option approve-mode password".to_owned(),
            "rustdesk --option verification-method use-permanent-password".to_owned(),
            format!("rustdesk --option enroll-token {}", sh_quote(&group.enroll_token)),
            format!("rustdesk --password {}", sh_quote(&group.password)),
            "ID=$(rustdesk --get-id | tail -n 1 | tr -d '[:space:]')".to_owned(),
            format!(
                "curl -sS -X POST {} -H 'Content-Type: application/json' \\",
                sh_quote(&format!("{api}/api/enroll"))
            ),
            format!(
                "  -d \"{{\\\"token\\\":\\\"{}\\\",\\\"id\\\":\\\"$ID\\\",\\\"hostname\\\":\\\"$(hostname)\\\"}}\"",
                group.enroll_token
            ),
            format!("echo; echo \"Máquina $ID matriculada no grupo {}.\"", group.name),
        ]);
        lines.join("\n") + "\n"
    } else {
        // Cliente personalizado (client_app_name): instala em C:\Program Files\<App>\<App>.exe e já
        // vem com servidor, relay, API e chave fixos; só precisa do token de matrícula.
        let app = if custom_app.is_empty() { "RustDesk" } else { custom_app.as_str() };
        let exe_name = if custom_app.is_empty() { "rustdesk.exe".to_owned() } else { format!("{custom_app}.exe") };
        let install = if download.is_empty() {
            "  if (-not (Test-Path $exe)) { throw ('Instale o ' + $app + ' primeiro: o link do instalador não está preenchido em Configurações.') }\n  Write-Host \"$app já instalado.\"".to_owned()
        } else {
            format!(
                "  if (Test-Path $exe) {{\n    Write-Host \"$app já instalado em $exe.\"\n  }} else {{\n\
                 \x20   # Pasta dedicada: antivírus com escudo comportamental (o Avast marca este\n\
                 \x20   # instalador como IDP.HELU.*) matam o processo do instalador, e a exceção\n\
                 \x20   # precisa apontar para onde ele roda. Uma pasta própria deixa a exceção\n\
                 \x20   # estreita, em vez de liberar o %TEMP% inteiro.\n\
                 \x20   $setup = Join-Path $env:TEMP ($app + '-setup')\n\
                 \x20   New-Item -ItemType Directory -Path $setup -Force | Out-Null\n\
                 \x20   Get-ChildItem $setup -Filter *.exe -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue\n\
                 \x20   $pacote = Join-Path $setup ($app + '-install-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.exe')\n\
                 \x20   Write-Host \"Baixando o instalador para $setup ...\"\n\
                 \x20   Invoke-WebRequest -Uri {url} -OutFile $pacote -Headers @{{ 'X-Enroll-Token' = $token }} -UseBasicParsing\n\
                 \x20   Write-Host 'Instalando (silencioso)...'\n\
                 \x20   Start-Process -FilePath $pacote -ArgumentList '--silent-install' -Wait\n\
                 \x20   for ($i = 0; $i -lt 60 -and -not (Test-Path $exe); $i++) {{ Start-Sleep -Seconds 1 }}\n\
                 \x20   Remove-Item $pacote -Force -ErrorAction SilentlyContinue\n\
                 \x20   if (-not (Test-Path $exe)) {{ throw ('A instalação não concluiu: não encontrei ' + $exe) }}\n\
                 \x20   Write-Host \"$app instalado.\"\n  }}",
                url = ps_quote(&download)
            )
        };
        let server_opts = if custom_app.is_empty() {
            let mut o = vec![format!(
                "  & $exe --option custom-rendezvous-server {} | Out-Null",
                ps_quote(&host)
            )];
            if !key.is_empty() {
                o.push(format!("  & $exe --option key {} | Out-Null", ps_quote(&key)));
            }
            o.push(format!("  & $exe --option api-server {} | Out-Null", ps_quote(&api)));
            o.join("\n")
        } else {
            "  # Servidor, relay, API e chave já vêm fixos no cliente personalizado.".to_owned()
        };
        let ps = WIN_INSTALL_PS1
            .replace("@APPNAME@", app)
            .replace("@GROUPNAME@", &group.name)
            .replace("@APP@", &ps_quote(app))
            .replace("@EXE@", &ps_quote(&format!("C:\\Program Files\\{app}\\{exe_name}")))
            .replace("@TOKEN@", &ps_quote(&group.enroll_token))
            .replace("@API@", &ps_quote(api.trim_end_matches('/')))
            .replace("@SENHA@", &ps_quote(&group.password))
            .replace("@GRUPO@", &ps_quote(&group.name))
            .replace("@INSTALL@", &install)
            .replace("@SERVEROPTS@", &server_opts);
        let ps = if q.get("format").is_some_and(|f| f == "cmd") {
            format!("{WIN_INSTALL_CMD}{ps}")
        } else {
            ps
        };
        ps.replace('\n', "\r\n")
    };
    Ok((
        StatusCode::OK,
        [(CONTENT_TYPE, "text/plain; charset=utf-8")],
        script,
    ))
}

// ---------------------------------------------------------------- dispositivos

pub async fn devices_list(
    State(st): State<AppState>,
    user: AuthUser,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult<Json<Value>> {
    user.require_admin()?;
    let mut filters: Vec<&str> = Vec::new();
    let mut binds: Vec<String> = Vec::new();
    match q.get("group").map(String::as_str) {
        None | Some("") => {}
        Some("none") => filters.push("d.group_id IS NULL"),
        Some(id) => {
            filters.push("d.group_id = ?");
            binds.push(id.to_owned());
        }
    }
    if let Some(term) = q.get("q").map(|x| x.trim()).filter(|x| !x.is_empty()) {
        filters.push(
            "(d.id LIKE ? OR d.hostname LIKE ? OR d.username LIKE ? OR d.note LIKE ? OR d.lan_ip LIKE ?)",
        );
        let pattern = format!("%{term}%");
        binds.extend(std::iter::repeat(pattern).take(5));
    }
    let where_clause = if filters.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", filters.join(" AND "))
    };
    let sql = format!("{DEVICE_SELECT}{where_clause} ORDER BY d.last_seen_at DESC, d.id");
    let mut query = sqlx::query_as::<_, DeviceRow>(&sql);
    for b in &binds {
        query = query.bind(b.as_str());
    }
    let rows = query.fetch_all(&st.db).await?;
    let t = now();
    Ok(Json(Value::Array(
        rows.iter().map(|d| d.admin_json(t)).collect(),
    )))
}

async fn device_json(db: &Db, id: &str) -> ApiResult<Value> {
    let row = sqlx::query_as::<_, DeviceRow>(&format!("{DEVICE_SELECT} WHERE d.id = ?"))
        .bind(id)
        .fetch_optional(db)
        .await?
        .ok_or_else(|| ApiError::not_found("Device not found"))?;
    Ok(row.admin_json(now()))
}

pub async fn devices_update(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    user.require_admin()?;
    let v = parse_value(&body)?;
    if let Some(group) = v.get("group_id") {
        groups::assign_device(&st.db, &id, group.as_i64()).await?;
    }
    if let Some(note) = opt_s(&v, "note") {
        sqlx::query("UPDATE devices SET note = ? WHERE id = ?")
            .bind(note.trim())
            .bind(&id)
            .execute(&st.db)
            .await?;
    }
    if let Some(name) = opt_s(&v, "user_name") {
        let owner: Option<i64> = if name.trim().is_empty() {
            None
        } else {
            Some(
                sqlx::query_scalar("SELECT id FROM users WHERE name = ?")
                    .bind(name.trim())
                    .fetch_optional(&st.db)
                    .await?
                    .ok_or_else(|| ApiError::bad_request("User not found"))?,
            )
        };
        sqlx::query("UPDATE devices SET user_id = ? WHERE id = ?")
            .bind(owner)
            .bind(&id)
            .execute(&st.db)
            .await?;
    }
    Ok(Json(device_json(&st.db, &id).await?))
}

pub async fn devices_delete(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    user.require_admin()?;
    let group: Option<Option<i64>> =
        sqlx::query_scalar("SELECT group_id FROM devices WHERE id = ?")
            .bind(&id)
            .fetch_optional(&st.db)
            .await?;
    sqlx::query("DELETE FROM devices WHERE id = ?")
        .bind(&id)
        .execute(&st.db)
        .await?;
    if let Some(Some(group_id)) = group {
        groups::sync_ab(&st.db, group_id).await?;
    }
    Ok(Json(json!({})))
}

// ---------------------------------------------------------------- usuários

async fn user_json(db: &Db, u: &UserRow, t: i64) -> ApiResult<Value> {
    let sessions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE user_id = ?")
        .bind(u.id)
        .fetch_one(db)
        .await?;
    let grants = sqlx::query_as::<_, GrantRow>(&format!(
        "{GRANT_SELECT} WHERE u.id = ? ORDER BY st.name"
    ))
    .bind(u.id)
    .fetch_all(db)
    .await?;
    let codes: Vec<(i64, String, i64, i64)> = sqlx::query_as(
        "SELECT id, code, expires_at, created_at FROM access_codes \
         WHERE user_id = ? AND used_at IS NULL AND expires_at > ? ORDER BY expires_at",
    )
    .bind(u.id)
    .bind(t)
    .fetch_all(db)
    .await?;
    let mut v = u.admin_json();
    v["sessions"] = json!(sessions);
    v["expired"] = json!(u.expires_at.is_some_and(|e| e <= t));
    v["grants"] = json!(grants.iter().map(|g| grant_json(g, t)).collect::<Vec<_>>());
    v["access_codes"] = json!(codes
        .iter()
        .map(|(id, code, expires_at, created_at)| json!({
            "id": id, "code": code, "expires_at": expires_at, "created_at": created_at
        }))
        .collect::<Vec<_>>());
    Ok(v)
}

fn parse_tfa(v: &Value) -> ApiResult<Option<String>> {
    match opt_s(v, "tfa") {
        None => Ok(None),
        Some(x) if x == "none" || x == TFA_CONSOLE => Ok(Some(x)),
        Some(_) => Err(ApiError::bad_request("tfa must be none or console")),
    }
}

async fn set_user_policy(db: &Db, id: i64, v: &Value) -> ApiResult<()> {
    if let Some(tfa) = parse_tfa(v)? {
        sqlx::query("UPDATE users SET tfa = ? WHERE id = ?")
            .bind(tfa)
            .bind(id)
            .execute(db)
            .await?;
    }
    if let Some(hours) = i(v, "session_hours") {
        sqlx::query("UPDATE users SET session_hours = ? WHERE id = ?")
            .bind(hours.clamp(0, 24 * 365))
            .bind(id)
            .execute(db)
            .await?;
    }
    Ok(())
}

async fn user_by_id(db: &Db, id: i64) -> ApiResult<UserRow> {
    sqlx::query_as::<_, UserRow>("SELECT * FROM users WHERE id = ?")
        .bind(id)
        .fetch_optional(db)
        .await?
        .ok_or_else(|| ApiError::not_found("User not found"))
}

pub async fn users_list(State(st): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    user.require_admin()?;
    let rows = sqlx::query_as::<_, UserRow>("SELECT * FROM users WHERE name <> ? ORDER BY name")
        .bind(SYSTEM_USER)
        .fetch_all(&st.db)
        .await?;
    let t = now();
    let mut out = Vec::with_capacity(rows.len());
    for u in &rows {
        out.push(user_json(&st.db, u, t).await?);
    }
    Ok(Json(Value::Array(out)))
}

fn parse_kind(v: &Value) -> ApiResult<Option<String>> {
    match opt_s(v, "kind") {
        None => Ok(None),
        Some(k) if k == "staff" || k == USER_KIND_EXTERNAL => Ok(Some(k)),
        Some(_) => Err(ApiError::bad_request("kind must be staff or external")),
    }
}

/// `expires_at`: ausente = não mexe; null/0/"" = sem validade; número = timestamp.
fn parse_expires(v: &Value) -> Option<Option<i64>> {
    let x = v.get("expires_at")?;
    if x.is_null() {
        return Some(None);
    }
    match i(v, "expires_at") {
        Some(ts) if ts > 0 => Some(Some(ts)),
        _ => Some(None),
    }
}

pub async fn users_create(
    State(st): State<AppState>,
    user: AuthUser,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    user.require_admin()?;
    let v = parse_value(&body)?;
    let name = s(&v, "name").trim().to_owned();
    if name.is_empty() || name == SYSTEM_USER {
        return Err(ApiError::bad_request("name is required"));
    }
    let exists: Option<i64> = sqlx::query_scalar("SELECT id FROM users WHERE name = ?")
        .bind(&name)
        .fetch_optional(&st.db)
        .await?;
    if exists.is_some() {
        return Err(ApiError::bad_request("User already exists"));
    }
    let password = opt_s(&v, "password")
        .filter(|p| !p.trim().is_empty())
        .unwrap_or_else(groups::new_password);
    let kind = parse_kind(&v)?.unwrap_or_else(|| "staff".to_owned());
    let is_admin = v.get("is_admin").and_then(Value::as_bool).unwrap_or(false);
    let id = create_user(
        &st.db,
        &name,
        &password,
        is_admin,
        s(&v, "display_name").trim(),
        s(&v, "email").trim(),
        &kind,
    )
    .await?;
    if let Some(expires) = parse_expires(&v) {
        sqlx::query("UPDATE users SET expires_at = ? WHERE id = ?")
            .bind(expires)
            .bind(id)
            .execute(&st.db)
            .await?;
    }
    if let Some(note) = opt_s(&v, "note") {
        sqlx::query("UPDATE users SET note = ? WHERE id = ?")
            .bind(note.trim())
            .bind(id)
            .execute(&st.db)
            .await?;
    }
    set_user_policy(&st.db, id, &v).await?;
    tracing::info!(user = %name, kind = %kind, by = %user.user.name, "usuário criado pelo console");
    let created = user_by_id(&st.db, id).await?;
    Ok(Json(json!({
        "user": user_json(&st.db, &created, now()).await?,
        "password": password,
    })))
}

pub async fn users_update(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<i64>,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    user.require_admin()?;
    let target = user_by_id(&st.db, id).await?;
    if target.name == SYSTEM_USER {
        return Err(ApiError::forbidden());
    }
    let v = parse_value(&body)?;
    let is_self = target.id == user.user.id;
    if let Some(x) = opt_s(&v, "display_name") {
        sqlx::query("UPDATE users SET display_name = ? WHERE id = ?")
            .bind(x.trim())
            .bind(id)
            .execute(&st.db)
            .await?;
    }
    if let Some(x) = opt_s(&v, "email") {
        sqlx::query("UPDATE users SET email = ? WHERE id = ?")
            .bind(x.trim())
            .bind(id)
            .execute(&st.db)
            .await?;
    }
    if let Some(x) = opt_s(&v, "note") {
        sqlx::query("UPDATE users SET note = ? WHERE id = ?")
            .bind(x.trim())
            .bind(id)
            .execute(&st.db)
            .await?;
    }
    if let Some(kind) = parse_kind(&v)? {
        sqlx::query("UPDATE users SET kind = ? WHERE id = ?")
            .bind(kind)
            .bind(id)
            .execute(&st.db)
            .await?;
    }
    if let Some(admin) = v.get("is_admin").and_then(Value::as_bool) {
        if is_self && !admin {
            return Err(ApiError::bad_request("You cannot remove your own admin role"));
        }
        sqlx::query("UPDATE users SET is_admin = ? WHERE id = ?")
            .bind(i64::from(admin))
            .bind(id)
            .execute(&st.db)
            .await?;
    }
    if let Some(status) = i(&v, "status") {
        if is_self && status != 1 {
            return Err(ApiError::bad_request("You cannot disable yourself"));
        }
        sqlx::query("UPDATE users SET status = ? WHERE id = ?")
            .bind(i64::from(status == 1))
            .bind(id)
            .execute(&st.db)
            .await?;
        if status != 1 {
            sqlx::query("DELETE FROM sessions WHERE user_id = ?")
                .bind(id)
                .execute(&st.db)
                .await?;
        }
    }
    if let Some(expires) = parse_expires(&v) {
        sqlx::query("UPDATE users SET expires_at = ? WHERE id = ?")
            .bind(expires)
            .bind(id)
            .execute(&st.db)
            .await?;
    }
    set_user_policy(&st.db, id, &v).await?;
    let updated = user_by_id(&st.db, id).await?;
    Ok(Json(user_json(&st.db, &updated, now()).await?))
}

/// Emite um código de acesso de uso único (6 dígitos) para o segundo fator do login.
pub async fn users_access_code(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<i64>,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    user.require_admin()?;
    let target = user_by_id(&st.db, id).await?;
    if target.name == SYSTEM_USER {
        return Err(ApiError::forbidden());
    }
    let v = parse_value(&body)?;
    let ttl_minutes = i(&v, "ttl_minutes").unwrap_or(10).clamp(1, 24 * 60);
    let t = now();
    sqlx::query("DELETE FROM access_codes WHERE expires_at < ?")
        .bind(t - 86_400)
        .execute(&st.db)
        .await?;
    let code = format!("{:06}", rand::thread_rng().gen_range(0..1_000_000u32));
    let expires_at = t + ttl_minutes * 60;
    let res = sqlx::query(
        "INSERT INTO access_codes (user_id, code, expires_at, used_at, created_by, created_at) \
         VALUES (?, ?, ?, NULL, ?, ?)",
    )
    .bind(id)
    .bind(&code)
    .bind(expires_at)
    .bind(user.user.id)
    .bind(t)
    .execute(&st.db)
    .await?;
    tracing::info!(user = %target.name, by = %user.user.name, ttl_minutes, "código de acesso emitido");
    Ok(Json(json!({
        "id": res.last_insert_rowid(),
        "code": code,
        "expires_at": expires_at,
        "tfa_enabled": target.tfa == TFA_CONSOLE,
    })))
}

pub async fn users_access_code_delete(
    State(st): State<AppState>,
    user: AuthUser,
    Path((id, code_id)): Path<(i64, i64)>,
) -> ApiResult<Json<Value>> {
    user.require_admin()?;
    sqlx::query("DELETE FROM access_codes WHERE id = ? AND user_id = ?")
        .bind(code_id)
        .bind(id)
        .execute(&st.db)
        .await?;
    Ok(Json(json!({})))
}

/// Encerra todas as sessões do usuário: o cliente dele recebe 401 e apaga o address book.
pub async fn users_logout(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    user.require_admin()?;
    let target = user_by_id(&st.db, id).await?;
    sqlx::query("DELETE FROM sessions WHERE user_id = ?")
        .bind(id)
        .execute(&st.db)
        .await?;
    sqlx::query("DELETE FROM login_challenges WHERE user_id = ?")
        .bind(id)
        .execute(&st.db)
        .await?;
    tracing::info!(user = %target.name, by = %user.user.name, "sessões encerradas pelo console");
    Ok(Json(json!({})))
}

pub async fn users_password(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<i64>,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    user.require_admin()?;
    let target = user_by_id(&st.db, id).await?;
    if target.name == SYSTEM_USER {
        return Err(ApiError::forbidden());
    }
    let v = parse_value(&body)?;
    let password = opt_s(&v, "password")
        .filter(|p| !p.trim().is_empty())
        .unwrap_or_else(groups::new_password);
    let hash = auth::hash_password(password.clone()).await?;
    sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
        .bind(hash)
        .bind(id)
        .execute(&st.db)
        .await?;
    sqlx::query("DELETE FROM sessions WHERE user_id = ?")
        .bind(id)
        .execute(&st.db)
        .await?;
    Ok(Json(json!({ "password": password })))
}

pub async fn users_delete(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    user.require_admin()?;
    let target = user_by_id(&st.db, id).await?;
    if target.name == SYSTEM_USER || target.id == user.user.id {
        return Err(ApiError::bad_request("This user cannot be deleted"));
    }
    sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(id)
        .execute(&st.db)
        .await?;
    Ok(Json(json!({})))
}

// ---------------------------------------------------------------- acessos (grants)

pub async fn grants_list(State(st): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    user.require_admin()?;
    let rows = sqlx::query_as::<_, GrantRow>(&format!("{GRANT_SELECT} ORDER BY st.name, u.name"))
        .fetch_all(&st.db)
        .await?;
    let t = now();
    Ok(Json(Value::Array(
        rows.iter().map(|g| grant_json(g, t)).collect(),
    )))
}

pub async fn grants_create(
    State(st): State<AppState>,
    user: AuthUser,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    user.require_admin()?;
    let v = parse_value(&body)?;
    let (Some(user_id), Some(group_id)) = (i(&v, "user_id"), i(&v, "group_id")) else {
        return Err(ApiError::bad_request("user_id and group_id are required"));
    };
    let rule = i(&v, "rule").unwrap_or(1);
    if !(1..=3).contains(&rule) {
        return Err(ApiError::bad_request("rule must be 1, 2 or 3"));
    }
    let target = user_by_id(&st.db, user_id).await?;
    if target.name == SYSTEM_USER {
        return Err(ApiError::forbidden());
    }
    let guid = groups::sync_ab(&st.db, group_id).await?;
    let expires = parse_expires(&v).flatten();
    sqlx::query(
        "INSERT INTO address_book_shares (ab_guid, user_id, rule, expires_at) VALUES (?, ?, ?, ?) \
         ON CONFLICT(ab_guid, user_id) DO UPDATE SET rule = excluded.rule, expires_at = excluded.expires_at",
    )
    .bind(&guid)
    .bind(user_id)
    .bind(rule)
    .bind(expires)
    .execute(&st.db)
    .await?;
    let row = sqlx::query_as::<_, GrantRow>(&format!(
        "{GRANT_SELECT} WHERE u.id = ? AND st.id = ?"
    ))
    .bind(user_id)
    .bind(group_id)
    .fetch_one(&st.db)
    .await?;
    tracing::info!(user = %target.name, group = group_id, rule, by = %user.user.name, "acesso concedido");
    Ok(Json(grant_json(&row, now())))
}

pub async fn grants_delete(
    State(st): State<AppState>,
    user: AuthUser,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    user.require_admin()?;
    let v = parse_value(&body)?;
    let (Some(user_id), Some(group_id)) = (i(&v, "user_id"), i(&v, "group_id")) else {
        return Err(ApiError::bad_request("user_id and group_id are required"));
    };
    sqlx::query(
        "DELETE FROM address_book_shares WHERE user_id = ? \
         AND ab_guid = (SELECT ab_guid FROM groups WHERE id = ?)",
    )
    .bind(user_id)
    .bind(group_id)
    .execute(&st.db)
    .await?;
    Ok(Json(json!({})))
}

// ---------------------------------------------------------------- auditoria

fn limit_offset(q: &HashMap<String, String>) -> (i64, i64) {
    let limit = q
        .get("limit")
        .and_then(|x| x.parse::<i64>().ok())
        .unwrap_or(100)
        .clamp(1, 500);
    let offset = q
        .get("offset")
        .and_then(|x| x.parse::<i64>().ok())
        .unwrap_or(0)
        .max(0);
    (limit, offset)
}

/// Filtros comuns: `group` (id), `device` (id), `since`/`until` (unix).
fn audit_filters(q: &HashMap<String, String>, ts_column: &str) -> (String, Vec<String>) {
    let mut filters: Vec<String> = Vec::new();
    let mut binds: Vec<String> = Vec::new();
    if let Some(x) = q.get("group").filter(|x| !x.is_empty()) {
        filters.push("d.group_id = ?".to_owned());
        binds.push(x.clone());
    }
    if let Some(x) = q.get("device").filter(|x| !x.is_empty()) {
        filters.push("a.device_id = ?".to_owned());
        binds.push(x.clone());
    }
    if let Some(x) = q.get("since").filter(|x| !x.is_empty()) {
        filters.push(format!("a.{ts_column} >= ?"));
        binds.push(x.clone());
    }
    if let Some(x) = q.get("until").filter(|x| !x.is_empty()) {
        filters.push(format!("a.{ts_column} <= ?"));
        binds.push(x.clone());
    }
    let clause = if filters.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", filters.join(" AND "))
    };
    (clause, binds)
}

#[derive(sqlx::FromRow)]
struct AuditConnRow {
    guid: String,
    device_id: String,
    hostname: Option<String>,
    group_id: Option<i64>,
    group_name: Option<String>,
    peer_id: String,
    peer_name: String,
    ip: String,
    conn_type: Option<i64>,
    primary_auth: Option<i64>,
    two_factor: Option<i64>,
    note: String,
    started_at: i64,
    authed_at: Option<i64>,
    closed_at: Option<i64>,
}

const AUDIT_CONN_FROM: &str = "FROM audit_conn a LEFT JOIN devices d ON d.id = a.device_id \
    LEFT JOIN groups st ON st.id = d.group_id";

fn audit_conn_json(r: &AuditConnRow) -> Value {
    json!({
        "guid": r.guid,
        "device_id": r.device_id,
        "hostname": r.hostname,
        "group_id": r.group_id,
        "group": r.group_name,
        "peer_id": r.peer_id,
        "peer_name": r.peer_name,
        "ip": r.ip,
        "conn_type": r.conn_type,
        "primary_auth": r.primary_auth,
        "two_factor": r.two_factor,
        "note": r.note,
        "started_at": r.started_at,
        "authed_at": r.authed_at,
        "closed_at": r.closed_at,
    })
}

pub async fn audit_conn(
    State(st): State<AppState>,
    user: AuthUser,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult<Json<Value>> {
    user.require_admin()?;
    let (clause, binds) = audit_filters(&q, "started_at");
    let (limit, offset) = limit_offset(&q);
    let count_sql = format!("SELECT COUNT(*) {AUDIT_CONN_FROM}{clause}");
    let mut count = sqlx::query_scalar::<_, i64>(&count_sql);
    for b in &binds {
        count = count.bind(b.as_str());
    }
    let total = count.fetch_one(&st.db).await?;
    let sql = format!(
        "SELECT a.guid, a.device_id, d.hostname, d.group_id, st.name AS group_name, a.peer_id, a.peer_name, \
         a.ip, a.conn_type, a.primary_auth, a.two_factor, a.note, a.started_at, a.authed_at, a.closed_at \
         {AUDIT_CONN_FROM}{clause} ORDER BY a.started_at DESC LIMIT ? OFFSET ?"
    );
    let mut query = sqlx::query_as::<_, AuditConnRow>(&sql);
    for b in &binds {
        query = query.bind(b.as_str());
    }
    let rows = query.bind(limit).bind(offset).fetch_all(&st.db).await?;
    Ok(Json(json!({
        "total": total,
        "data": rows.iter().map(audit_conn_json).collect::<Vec<_>>(),
    })))
}

#[derive(sqlx::FromRow)]
struct AuditDeniedRow {
    at: i64,
    peer_id: String,
    hostname: Option<String>,
    group_id: Option<i64>,
    group_name: Option<String>,
    from_ip: String,
    user_name: String,
    reason: String,
}

/// `GET /admin/api/audit/denied` — conexões que o hbbs recusou depois de consultar a API.
/// Filtros: `group` (id), `device` (ID da máquina), `since`/`until` (unix).
pub async fn audit_denied(
    State(st): State<AppState>,
    user: AuthUser,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult<Json<Value>> {
    user.require_admin()?;
    let mut filters: Vec<&str> = Vec::new();
    let mut binds: Vec<String> = Vec::new();
    for (param, column) in [
        ("group", "a.group_id = ?"),
        ("device", "a.peer_id = ?"),
        ("since", "a.at >= ?"),
        ("until", "a.at <= ?"),
    ] {
        if let Some(x) = q.get(param).filter(|x| !x.is_empty()) {
            filters.push(column);
            binds.push(x.clone());
        }
    }
    let clause = if filters.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", filters.join(" AND "))
    };
    let (limit, offset) = limit_offset(&q);
    const FROM: &str = "FROM authz_denied a LEFT JOIN devices d ON d.id = a.peer_id \
        LEFT JOIN groups st ON st.id = a.group_id";
    let count_sql = format!("SELECT COUNT(*) {FROM}{clause}");
    let mut count = sqlx::query_scalar::<_, i64>(&count_sql);
    for b in &binds {
        count = count.bind(b.as_str());
    }
    let total = count.fetch_one(&st.db).await?;
    let sql = format!(
        "SELECT a.at, a.peer_id, d.hostname, a.group_id, st.name AS group_name, a.from_ip, a.user_name, a.reason \
         {FROM}{clause} ORDER BY a.at DESC LIMIT ? OFFSET ?"
    );
    let mut query = sqlx::query_as::<_, AuditDeniedRow>(&sql);
    for b in &binds {
        query = query.bind(b.as_str());
    }
    let rows = query.bind(limit).bind(offset).fetch_all(&st.db).await?;
    Ok(Json(json!({
        "total": total,
        "data": rows.iter().map(|r| json!({
            "at": r.at,
            "peer_id": r.peer_id,
            "hostname": r.hostname,
            "group_id": r.group_id,
            "group": r.group_name,
            "from_ip": r.from_ip,
            "user_name": r.user_name,
            "reason": r.reason,
        })).collect::<Vec<_>>(),
    })))
}

#[derive(sqlx::FromRow)]
struct AuditFileRow {
    guid: String,
    device_id: String,
    hostname: Option<String>,
    group_name: Option<String>,
    peer_id: String,
    conn_id: Option<i64>,
    typ: Option<i64>,
    path: String,
    is_file: i64,
    info: String,
    created_at: i64,
}

pub async fn audit_file(
    State(st): State<AppState>,
    user: AuthUser,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult<Json<Value>> {
    user.require_admin()?;
    let (clause, binds) = audit_filters(&q, "created_at");
    let (limit, offset) = limit_offset(&q);
    let from = "FROM audit_file a LEFT JOIN devices d ON d.id = a.device_id \
        LEFT JOIN groups st ON st.id = d.group_id";
    let count_sql = format!("SELECT COUNT(*) {from}{clause}");
    let mut count = sqlx::query_scalar::<_, i64>(&count_sql);
    for b in &binds {
        count = count.bind(b.as_str());
    }
    let total = count.fetch_one(&st.db).await?;
    let sql = format!(
        "SELECT a.guid, a.device_id, d.hostname, st.name AS group_name, a.peer_id, a.conn_id, a.type AS typ, \
         a.path, a.is_file, a.info, a.created_at {from}{clause} ORDER BY a.created_at DESC LIMIT ? OFFSET ?"
    );
    let mut query = sqlx::query_as::<_, AuditFileRow>(&sql);
    for b in &binds {
        query = query.bind(b.as_str());
    }
    let rows = query.bind(limit).bind(offset).fetch_all(&st.db).await?;
    let data: Vec<Value> = rows
        .iter()
        .map(|r| {
            let info: Value = serde_json::from_str(&r.info).unwrap_or(Value::String(r.info.clone()));
            json!({
                "guid": r.guid,
                "device_id": r.device_id,
                "hostname": r.hostname,
                "group": r.group_name,
                "peer_id": r.peer_id,
                "conn_id": r.conn_id,
                "type": r.typ,
                "path": r.path,
                "is_file": r.is_file != 0,
                "info": info,
                "created_at": r.created_at,
            })
        })
        .collect();
    Ok(Json(json!({ "total": total, "data": data })))
}

#[derive(sqlx::FromRow)]
struct AuditAlarmRow {
    guid: String,
    device_id: String,
    hostname: Option<String>,
    group_name: Option<String>,
    typ: Option<i64>,
    info: String,
    conn_id: Option<i64>,
    created_at: i64,
}

pub async fn audit_alarm(
    State(st): State<AppState>,
    user: AuthUser,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult<Json<Value>> {
    user.require_admin()?;
    let (clause, binds) = audit_filters(&q, "created_at");
    let (limit, offset) = limit_offset(&q);
    let from = "FROM audit_alarm a LEFT JOIN devices d ON d.id = a.device_id \
        LEFT JOIN groups st ON st.id = d.group_id";
    let count_sql = format!("SELECT COUNT(*) {from}{clause}");
    let mut count = sqlx::query_scalar::<_, i64>(&count_sql);
    for b in &binds {
        count = count.bind(b.as_str());
    }
    let total = count.fetch_one(&st.db).await?;
    let sql = format!(
        "SELECT a.guid, a.device_id, d.hostname, st.name AS group_name, a.typ, a.info, a.conn_id, a.created_at \
         {from}{clause} ORDER BY a.created_at DESC LIMIT ? OFFSET ?"
    );
    let mut query = sqlx::query_as::<_, AuditAlarmRow>(&sql);
    for b in &binds {
        query = query.bind(b.as_str());
    }
    let rows = query.bind(limit).bind(offset).fetch_all(&st.db).await?;
    let data: Vec<Value> = rows
        .iter()
        .map(|r| {
            let info: Value = serde_json::from_str(&r.info).unwrap_or(Value::String(r.info.clone()));
            json!({
                "guid": r.guid,
                "device_id": r.device_id,
                "hostname": r.hostname,
                "group": r.group_name,
                "typ": r.typ,
                "info": info,
                "conn_id": r.conn_id,
                "created_at": r.created_at,
            })
        })
        .collect();
    Ok(Json(json!({ "total": total, "data": data })))
}

// ---------------------------------------------------------------- visão geral

pub async fn overview(State(st): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    user.require_admin()?;
    let t = now();
    let (devices, online): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COALESCE(SUM(last_seen_at >= ?), 0) FROM devices",
    )
    .bind(t - ONLINE_WINDOW_SECS)
    .fetch_one(&st.db)
    .await?;
    let unassigned: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM devices WHERE group_id IS NULL")
        .fetch_one(&st.db)
        .await?;
    let (users, externals): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COALESCE(SUM(kind = 'external'), 0) FROM users WHERE status = 1 AND name <> ?",
    )
    .bind(SYSTEM_USER)
    .fetch_one(&st.db)
    .await?;
    let conns_24h: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_conn WHERE started_at >= ? AND authed_at IS NOT NULL",
    )
    .bind(t - 86_400)
    .fetch_one(&st.db)
    .await?;
    let active: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_conn WHERE authed_at IS NOT NULL AND closed_at IS NULL AND started_at >= ?",
    )
    .bind(t - 86_400)
    .fetch_one(&st.db)
    .await?;
    let groups_rows = sqlx::query_as::<_, GroupRow>("SELECT * FROM groups ORDER BY name")
        .fetch_all(&st.db)
        .await?;
    let mut groups_out = Vec::with_capacity(groups_rows.len());
    for row in &groups_rows {
        let (total, on): (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*), COALESCE(SUM(last_seen_at >= ?), 0) FROM devices WHERE group_id = ?",
        )
        .bind(t - ONLINE_WINDOW_SECS)
        .bind(row.id)
        .fetch_one(&st.db)
        .await?;
        groups_out.push(json!({ "id": row.id, "name": row.name, "devices": total, "online": on }));
    }
    let recent = sqlx::query_as::<_, AuditConnRow>(&format!(
        "SELECT a.guid, a.device_id, d.hostname, d.group_id, st.name AS group_name, a.peer_id, a.peer_name, \
         a.ip, a.conn_type, a.primary_auth, a.two_factor, a.note, a.started_at, a.authed_at, a.closed_at \
         {AUDIT_CONN_FROM} ORDER BY a.started_at DESC LIMIT 10"
    ))
    .fetch_all(&st.db)
    .await?;
    Ok(Json(json!({
        "now": t,
        "devices": devices,
        "online": online,
        "unassigned": unassigned,
        "groups": groups_out.len(),
        "users": users,
        "externals": externals,
        "connections_24h": conns_24h,
        "active_sessions": active,
        "per_group": groups_out,
        "recent": recent.iter().map(audit_conn_json).collect::<Vec<_>>(),
    })))
}
