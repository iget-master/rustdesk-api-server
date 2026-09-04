use clap::Subcommand;
use rand::distributions::Alphanumeric;
use rand::Rng;

use crate::auth;
use crate::db::{now, Db};
use crate::models::{DeviceRow, DEVICE_SELECT};

#[derive(Subcommand)]
pub enum UserCmd {
    /// Cria um usuário (senha por --password, RUSTDESK_API_PASSWORD, ou gerada e impressa)
    Add {
        name: String,
        #[arg(long, env = "RUSTDESK_API_PASSWORD", hide_env_values = true)]
        password: Option<String>,
        /// Torna o usuário administrador (pode usar `rustdesk --assign`)
        #[arg(long)]
        admin: bool,
        #[arg(long, default_value = "")]
        display_name: String,
        #[arg(long, default_value = "")]
        email: String,
    },
    /// Troca a senha e invalida as sessões abertas
    Passwd {
        name: String,
        #[arg(long, env = "RUSTDESK_API_PASSWORD", hide_env_values = true)]
        password: Option<String>,
    },
    /// Lista usuários
    List,
    /// Reabilita um usuário desabilitado
    Enable { name: String },
    /// Desabilita o usuário e invalida as sessões
    Disable { name: String },
    /// Remove o usuário com seus address books e sessões
    Delete { name: String },
}

#[derive(Subcommand)]
pub enum AbCmd {
    /// Cria um address book compartilhado
    Create {
        name: String,
        /// Usuário dono (controle total)
        #[arg(long)]
        owner: String,
    },
    /// Dá acesso a outro usuário: read, rw ou full
    Share {
        name: String,
        #[arg(long)]
        owner: String,
        #[arg(long)]
        user: String,
        #[arg(long, default_value = "read", value_parser = ["read", "rw", "full"])]
        rule: String,
    },
    /// Remove o acesso de um usuário
    Unshare {
        name: String,
        #[arg(long)]
        owner: String,
        #[arg(long)]
        user: String,
    },
    /// Lista address books (pessoais e compartilhados)
    List,
}

#[derive(Subcommand)]
pub enum DeviceCmd {
    /// Lista dispositivos vistos pelo heartbeat
    List,
    /// Atribui o dispositivo a um usuário/grupo (aparece na aba Grupo com esse dono)
    Assign {
        /// ID RustDesk do dispositivo
        id: String,
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        group: Option<String>,
        #[arg(long)]
        note: Option<String>,
    },
    /// Remove o dispositivo do inventário (volta no próximo heartbeat)
    Delete { id: String },
}

pub async fn create_user(
    db: &Db,
    name: &str,
    password: &str,
    admin: bool,
    display_name: &str,
    email: &str,
) -> anyhow::Result<i64> {
    let hash = auth::hash_password(password.to_owned()).await?;
    let res = sqlx::query(
        "INSERT INTO users (name, display_name, email, note, password_hash, status, is_admin, created_at) \
         VALUES (?, ?, ?, '', ?, 1, ?, ?)",
    )
    .bind(name)
    .bind(display_name)
    .bind(email)
    .bind(hash)
    .bind(i64::from(admin))
    .bind(now())
    .execute(db)
    .await?;
    Ok(res.last_insert_rowid())
}

/// Na primeira subida (banco sem usuários) cria o admin a partir das variáveis de ambiente.
pub async fn bootstrap_admin(db: &Db) -> anyhow::Result<()> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(db)
        .await?;
    if count > 0 {
        return Ok(());
    }
    let password = std::env::var("RUSTDESK_API_ADMIN_PASSWORD").unwrap_or_default();
    if password.is_empty() {
        tracing::warn!(
            "nenhum usuário cadastrado; defina RUSTDESK_API_ADMIN_PASSWORD ou rode `rustdesk-api user add <nome> --admin`"
        );
        return Ok(());
    }
    let name = std::env::var("RUSTDESK_API_ADMIN_USER").unwrap_or_else(|_| "admin".to_owned());
    create_user(db, &name, &password, true, "", "").await?;
    tracing::info!(user = %name, "usuário administrador inicial criado");
    Ok(())
}

async fn user_id(db: &Db, name: &str) -> anyhow::Result<i64> {
    sqlx::query_scalar("SELECT id FROM users WHERE name = ?")
        .bind(name)
        .fetch_optional(db)
        .await?
        .ok_or_else(|| anyhow::anyhow!("usuário '{name}' não encontrado"))
}

fn password_or_generate(given: Option<String>) -> (String, bool) {
    match given.filter(|p| !p.is_empty()) {
        Some(p) => (p, false),
        None => {
            let p: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(16)
                .map(char::from)
                .collect();
            (p, true)
        }
    }
}

pub async fn user(db: &Db, cmd: UserCmd) -> anyhow::Result<()> {
    match cmd {
        UserCmd::Add {
            name,
            password,
            admin,
            display_name,
            email,
        } => {
            let (password, generated) = password_or_generate(password);
            create_user(db, &name, &password, admin, &display_name, &email).await?;
            if generated {
                println!("usuário '{name}' criado com a senha: {password}");
            } else {
                println!("usuário '{name}' criado");
            }
        }
        UserCmd::Passwd { name, password } => {
            let uid = user_id(db, &name).await?;
            let (password, generated) = password_or_generate(password);
            let hash = auth::hash_password(password.clone()).await?;
            sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
                .bind(hash)
                .bind(uid)
                .execute(db)
                .await?;
            sqlx::query("DELETE FROM sessions WHERE user_id = ?")
                .bind(uid)
                .execute(db)
                .await?;
            if generated {
                println!("nova senha de '{name}': {password}");
            } else {
                println!("senha de '{name}' alterada; sessões encerradas");
            }
        }
        UserCmd::List => {
            let rows: Vec<(String, String, i64, i64, i64)> = sqlx::query_as(
                "SELECT u.name, u.display_name, u.status, u.is_admin, \
                 (SELECT COUNT(*) FROM sessions s WHERE s.user_id = u.id) FROM users u ORDER BY u.name",
            )
            .fetch_all(db)
            .await?;
            println!("{:<20} {:<24} {:<8} {:<6} {}", "NOME", "EXIBIÇÃO", "STATUS", "ADMIN", "SESSÕES");
            for (name, display, status, admin, sessions) in rows {
                println!(
                    "{:<20} {:<24} {:<8} {:<6} {}",
                    name,
                    display,
                    if status == 1 { "ativo" } else { "inativo" },
                    if admin != 0 { "sim" } else { "não" },
                    sessions
                );
            }
        }
        UserCmd::Enable { name } => {
            let uid = user_id(db, &name).await?;
            sqlx::query("UPDATE users SET status = 1 WHERE id = ?")
                .bind(uid)
                .execute(db)
                .await?;
            println!("usuário '{name}' habilitado");
        }
        UserCmd::Disable { name } => {
            let uid = user_id(db, &name).await?;
            sqlx::query("UPDATE users SET status = 0 WHERE id = ?")
                .bind(uid)
                .execute(db)
                .await?;
            sqlx::query("DELETE FROM sessions WHERE user_id = ?")
                .bind(uid)
                .execute(db)
                .await?;
            println!("usuário '{name}' desabilitado; sessões encerradas");
        }
        UserCmd::Delete { name } => {
            let uid = user_id(db, &name).await?;
            sqlx::query("DELETE FROM users WHERE id = ?")
                .bind(uid)
                .execute(db)
                .await?;
            println!("usuário '{name}' removido");
        }
    }
    Ok(())
}

async fn shared_ab_guid(db: &Db, owner: i64, name: &str) -> anyhow::Result<String> {
    sqlx::query_scalar(
        "SELECT guid FROM address_books WHERE owner_id = ? AND name = ? AND is_personal = 0",
    )
    .bind(owner)
    .bind(name)
    .fetch_optional(db)
    .await?
    .ok_or_else(|| anyhow::anyhow!("address book '{name}' não encontrado para esse dono"))
}

pub async fn ab(db: &Db, cmd: AbCmd) -> anyhow::Result<()> {
    match cmd {
        AbCmd::Create { name, owner } => {
            let oid = user_id(db, &owner).await?;
            let guid = uuid::Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO address_books (guid, name, owner_id, is_personal, note, created_at) VALUES (?, ?, ?, 0, '', ?)",
            )
            .bind(&guid)
            .bind(&name)
            .bind(oid)
            .bind(now())
            .execute(db)
            .await?;
            println!("address book '{name}' criado (guid {guid}), dono '{owner}'");
        }
        AbCmd::Share {
            name,
            owner,
            user,
            rule,
        } => {
            let oid = user_id(db, &owner).await?;
            let guid = shared_ab_guid(db, oid, &name).await?;
            let uid = user_id(db, &user).await?;
            let rule_n: i64 = match rule.as_str() {
                "full" => 3,
                "rw" => 2,
                _ => 1,
            };
            sqlx::query(
                "INSERT INTO address_book_shares (ab_guid, user_id, rule) VALUES (?, ?, ?) \
                 ON CONFLICT(ab_guid, user_id) DO UPDATE SET rule = excluded.rule",
            )
            .bind(&guid)
            .bind(uid)
            .bind(rule_n)
            .execute(db)
            .await?;
            println!("'{user}' agora tem acesso {rule} a '{name}'");
        }
        AbCmd::Unshare { name, owner, user } => {
            let oid = user_id(db, &owner).await?;
            let guid = shared_ab_guid(db, oid, &name).await?;
            let uid = user_id(db, &user).await?;
            sqlx::query("DELETE FROM address_book_shares WHERE ab_guid = ? AND user_id = ?")
                .bind(&guid)
                .bind(uid)
                .execute(db)
                .await?;
            println!("acesso de '{user}' a '{name}' removido");
        }
        AbCmd::List => {
            let rows: Vec<(String, String, String, i64, i64, i64)> = sqlx::query_as(
                "SELECT ab.guid, ab.name, o.name, ab.is_personal, \
                 (SELECT COUNT(*) FROM ab_peers p WHERE p.ab_guid = ab.guid), \
                 (SELECT COUNT(*) FROM address_book_shares s WHERE s.ab_guid = ab.guid) \
                 FROM address_books ab JOIN users o ON o.id = ab.owner_id ORDER BY o.name, ab.is_personal DESC, ab.name",
            )
            .fetch_all(db)
            .await?;
            println!("{:<38} {:<24} {:<16} {:<8} {:<6} {}", "GUID", "NOME", "DONO", "TIPO", "PEERS", "COMPARTILHADO COM");
            for (guid, name, owner, personal, peers, shares) in rows {
                println!(
                    "{:<38} {:<24} {:<16} {:<8} {:<6} {}",
                    guid,
                    name,
                    owner,
                    if personal != 0 { "pessoal" } else { "comp." },
                    peers,
                    shares
                );
            }
        }
    }
    Ok(())
}

pub async fn device(db: &Db, cmd: DeviceCmd) -> anyhow::Result<()> {
    match cmd {
        DeviceCmd::List => {
            let rows = sqlx::query_as::<_, DeviceRow>(&format!(
                "{DEVICE_SELECT} ORDER BY d.last_seen_at DESC"
            ))
            .fetch_all(db)
            .await?;
            let t = now();
            println!(
                "{:<11} {:<20} {:<14} {:<8} {:<7} {:<14} {:<12} {}",
                "ID", "HOST", "USUÁRIO SO", "VERSÃO", "ONLINE", "DONO", "GRUPO", "SO"
            );
            for d in rows {
                println!(
                    "{:<11} {:<20} {:<14} {:<8} {:<7} {:<14} {:<12} {}",
                    d.id,
                    d.hostname,
                    d.username,
                    d.version,
                    if d.is_online(t) { "sim" } else { "não" },
                    d.user_name.clone().unwrap_or_default(),
                    d.device_group,
                    d.os
                );
            }
        }
        DeviceCmd::Assign {
            id,
            user,
            group,
            note,
        } => {
            let exists: Option<i64> = sqlx::query_scalar("SELECT 1 FROM devices WHERE id = ?")
                .bind(&id)
                .fetch_optional(db)
                .await?;
            if exists.is_none() {
                let t = now();
                sqlx::query(
                    "INSERT INTO devices (id, first_seen_at, last_seen_at) VALUES (?, ?, 0)",
                )
                .bind(&id)
                .bind(t)
                .execute(db)
                .await?;
            }
            if let Some(u) = user {
                let uid = user_id(db, &u).await?;
                sqlx::query("UPDATE devices SET user_id = ? WHERE id = ?")
                    .bind(uid)
                    .bind(&id)
                    .execute(db)
                    .await?;
            }
            if let Some(g) = group {
                sqlx::query("UPDATE devices SET device_group = ? WHERE id = ?")
                    .bind(g)
                    .bind(&id)
                    .execute(db)
                    .await?;
            }
            if let Some(n) = note {
                sqlx::query("UPDATE devices SET note = ? WHERE id = ?")
                    .bind(n)
                    .bind(&id)
                    .execute(db)
                    .await?;
            }
            println!("dispositivo {id} atualizado");
        }
        DeviceCmd::Delete { id } => {
            sqlx::query("DELETE FROM devices WHERE id = ?")
                .bind(&id)
                .execute(db)
                .await?;
            println!("dispositivo {id} removido");
        }
    }
    Ok(())
}

pub async fn token(db: &Db, user: &str) -> anyhow::Result<()> {
    let uid = user_id(db, user).await?;
    let token = auth::new_token();
    let t = now();
    sqlx::query(
        "INSERT INTO sessions (token, user_id, device_name, device_type, created_at, last_seen_at) \
         VALUES (?, ?, 'cli', 'token', ?, ?)",
    )
    .bind(&token)
    .bind(uid)
    .bind(t)
    .bind(t)
    .execute(db)
    .await?;
    println!("{token}");
    Ok(())
}

/// GET /healthz sem dependências externas, para o HEALTHCHECK do container.
pub fn health(bind: &str) -> anyhow::Result<()> {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpStream};
    use std::time::Duration;

    let addr = bind.replace("0.0.0.0", "127.0.0.1").replace("[::]", "[::1]");
    let timeout = Duration::from_secs(3);
    let mut stream = match addr.parse::<SocketAddr>() {
        Ok(sa) => TcpStream::connect_timeout(&sa, timeout)?,
        Err(_) => TcpStream::connect(&addr)?,
    };
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    stream.write_all(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n")?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf)?;
    let first = buf.lines().next().unwrap_or("");
    if first.contains(" 200 ") {
        println!("ok");
        Ok(())
    } else {
        anyhow::bail!("resposta inesperada: {first}")
    }
}
