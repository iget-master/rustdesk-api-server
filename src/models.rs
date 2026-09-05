use serde_json::{json, Value};

// As structs *Row espelham as colunas das tabelas; nem todo campo é lido pelo servidor.
#[allow(dead_code)]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserRow {
    pub id: i64,
    pub name: String,
    pub display_name: String,
    pub email: String,
    pub note: String,
    pub password_hash: String,
    pub status: i64,
    pub is_admin: i64,
    pub created_at: i64,
    pub kind: String,
    pub expires_at: Option<i64>,
    pub tfa: String,
    pub session_hours: i64,
}

pub const USER_KIND_EXTERNAL: &str = "external";
/// Segundo fator: código de acesso de uso único emitido pelo console.
pub const TFA_CONSOLE: &str = "console";

impl UserRow {
    /// `UserPayload` como o cliente lê em `/api/login`, `/api/currentUser` e `/api/users`.
    pub fn payload(&self) -> Value {
        json!({
            "name": self.name,
            "display_name": self.display_name,
            "avatar": "",
            "email": self.email,
            "note": self.note,
            "status": self.status,
            "is_admin": self.is_admin != 0,
            "info": {
                "email_verification": false,
                "email_alarm_notification": false,
                "login_device_whitelist": [],
                "other": {}
            },
            "third_auth_type": null
        })
    }

    pub fn is_external(&self) -> bool {
        self.kind == USER_KIND_EXTERNAL
    }

    /// Campos que o console mostra (sem hash de senha).
    pub fn admin_json(&self) -> Value {
        json!({
            "id": self.id,
            "name": self.name,
            "display_name": self.display_name,
            "email": self.email,
            "note": self.note,
            "status": self.status,
            "is_admin": self.is_admin != 0,
            "kind": self.kind,
            "expires_at": self.expires_at,
            "tfa": self.tfa,
            "session_hours": self.session_hours,
            "created_at": self.created_at,
        })
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AbRow {
    pub guid: String,
    pub name: String,
    pub owner_id: i64,
    pub is_personal: i64,
    pub note: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PeerRow {
    pub id: String,
    pub hash: String,
    pub password: String,
    pub username: String,
    pub hostname: String,
    pub platform: String,
    pub alias: String,
    pub tags: String,
    pub force_always_relay: i64,
    pub rdp_port: String,
    pub rdp_username: String,
    pub login_name: String,
    pub note: String,
}

impl PeerRow {
    /// Formato `Peer` de `flutter/lib/models/peer_model.dart`.
    pub fn payload(&self) -> Value {
        let tags: Value = serde_json::from_str(&self.tags).unwrap_or_else(|_| json!([]));
        json!({
            "id": self.id,
            "hash": self.hash,
            "password": self.password,
            "username": self.username,
            "hostname": self.hostname,
            "platform": self.platform,
            "alias": self.alias,
            "tags": tags,
            "forceAlwaysRelay": if self.force_always_relay != 0 { "true" } else { "false" },
            "rdpPort": self.rdp_port,
            "rdpUsername": self.rdp_username,
            "loginName": self.login_name,
            "note": self.note,
        })
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DeviceRow {
    pub id: String,
    pub uuid: String,
    pub hostname: String,
    pub username: String,
    pub os: String,
    pub cpu: String,
    pub memory: String,
    pub version: String,
    pub user_id: Option<i64>,
    pub user_name: Option<String>,
    pub device_group: String,
    pub note: String,
    pub conns: String,
    pub first_seen_at: i64,
    pub last_seen_at: i64,
    pub group_id: Option<i64>,
    pub group_name: Option<String>,
}

pub const DEVICE_SELECT: &str = "SELECT d.id, d.uuid, d.hostname, d.username, d.os, d.cpu, d.memory, d.version, \
    d.user_id, u.name AS user_name, d.device_group, d.note, d.conns, d.first_seen_at, d.last_seen_at, \
    d.group_id, st.name AS group_name \
    FROM devices d LEFT JOIN users u ON u.id = d.user_id LEFT JOIN groups st ON st.id = d.group_id";

/// Sem heartbeat por mais que isso, o dispositivo é considerado offline
/// (o cliente envia a cada 15 s quando ocioso).
pub const ONLINE_WINDOW_SECS: i64 = 45;

impl DeviceRow {
    pub fn group_name(&self) -> &str {
        self.group_name.as_deref().unwrap_or(&self.device_group)
    }

    /// Formato `PeerPayload` de `/api/peers` (aba Grupo).
    pub fn payload(&self) -> Value {
        let user = self.user_name.clone().unwrap_or_default();
        json!({
            "id": self.id,
            "info": {
                "username": self.username,
                "os": self.os,
                "device_name": self.hostname,
            },
            "status": 1,
            "user": user,
            "user_name": user,
            "device_group_name": self.group_name(),
            "note": self.note,
        })
    }

    pub fn is_online(&self, now: i64) -> bool {
        now - self.last_seen_at <= ONLINE_WINDOW_SECS
    }

    /// Linha do console.
    pub fn admin_json(&self, now: i64) -> Value {
        let conns: Value = serde_json::from_str(&self.conns).unwrap_or_else(|_| json!([]));
        json!({
            "id": self.id,
            "hostname": self.hostname,
            "username": self.username,
            "os": self.os,
            "platform": platform_from_os(&self.os),
            "cpu": self.cpu,
            "memory": self.memory,
            "version": self.version,
            "user_id": self.user_id,
            "user_name": self.user_name,
            "group_id": self.group_id,
            "group_name": self.group_name,
            "note": self.note,
            "conns": conns,
            "online": self.is_online(now),
            "first_seen_at": self.first_seen_at,
            "last_seen_at": self.last_seen_at,
        })
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct GroupRow {
    pub id: i64,
    pub name: String,
    pub password: String,
    pub ab_guid: Option<String>,
    pub options: String,
    pub options_updated_at: i64,
    pub note: String,
    pub enroll_token: String,
    pub created_at: i64,
    /// 1 = o hbbs só intermedeia conexões de usuários logados com acesso ao grupo.
    pub require_login: i64,
}

impl GroupRow {
    pub fn options_json(&self) -> Value {
        serde_json::from_str(&self.options).unwrap_or_else(|_| json!({}))
    }
}

/// O cliente mapeia o primeiro trecho de `os` (antes de " / ") para a plataforma
/// do peer; os nomes esperados vêm de `flutter/lib/consts.dart`.
pub fn platform_from_os(os: &str) -> String {
    let head = os.split(" / ").next().unwrap_or("").trim().to_ascii_lowercase();
    match head.as_str() {
        "windows" => "Windows",
        "macos" => "Mac OS",
        "android" => "Android",
        "ios" => "iOS",
        _ if head.contains("linux") || !head.is_empty() => "Linux",
        _ => "",
    }
    .to_owned()
}
