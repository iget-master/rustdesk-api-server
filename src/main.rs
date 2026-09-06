mod auth;
mod cli;
mod db;
mod error;
mod models;
mod routes;
mod groups;
mod util;

use clap::{Parser, Subcommand};
use db::Db;
use tracing_subscriber::EnvFilter;

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    /// Pasta dos instaladores servidos em `/downloads/{name}` (ao lado do banco, ou
    /// `RUSTDESK_API_DOWNLOADS_DIR`).
    pub downloads_dir: std::path::PathBuf,
}

#[derive(Parser)]
#[command(
    name = "rustdesk-api",
    version,
    about = "Servidor de API compatível com o cliente RustDesk (login, address book, grupo, heartbeat, auditoria)"
)]
struct Cli {
    /// Caminho do arquivo SQLite
    #[arg(long, global = true, env = "RUSTDESK_API_DB_PATH", default_value = "rustdesk-api.db")]
    db: String,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Sobe o servidor HTTP (padrão quando nenhum subcomando é informado)
    Serve {
        /// Endereço de escuta
        #[arg(long, env = "RUSTDESK_API_BIND", default_value = "0.0.0.0:21114")]
        bind: String,
    },
    /// Gerencia usuários
    User {
        #[command(subcommand)]
        cmd: cli::UserCmd,
    },
    /// Gerencia address books compartilhados
    Ab {
        #[command(subcommand)]
        cmd: cli::AbCmd,
    },
    /// Consulta e atribui dispositivos vistos pelo heartbeat
    Device {
        #[command(subcommand)]
        cmd: cli::DeviceCmd,
    },
    /// Emite um token de API para um usuário (para `rustdesk --assign --token` ou scripts)
    Token {
        /// Nome do usuário
        user: String,
    },
    /// Verifica se o servidor responde (usado no HEALTHCHECK do container)
    Health {
        #[arg(long, env = "RUSTDESK_API_BIND", default_value = "0.0.0.0:21114")]
        bind: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,sqlx=warn")),
        )
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
        .init();

    let cli = Cli::parse();
    if let Some(Command::Health { bind }) = &cli.command {
        return cli::health(bind);
    }

    let db = db::connect(&cli.db).await?;
    let downloads_dir = std::env::var("RUSTDESK_API_DOWNLOADS_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            std::path::Path::new(&cli.db)
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| std::path::Path::new("."))
                .join("downloads")
        });
    let command = cli.command.unwrap_or(Command::Serve {
        bind: std::env::var("RUSTDESK_API_BIND").unwrap_or_else(|_| "0.0.0.0:21114".to_owned()),
    });
    match command {
        Command::Serve { bind } => serve(db, downloads_dir, &bind).await,
        Command::User { cmd } => cli::user(&db, cmd).await,
        Command::Ab { cmd } => cli::ab(&db, cmd).await,
        Command::Device { cmd } => cli::device(&db, cmd).await,
        Command::Token { user } => cli::token(&db, &user).await,
        Command::Health { .. } => unreachable!(),
    }
}

async fn serve(db: Db, downloads_dir: std::path::PathBuf, bind: &str) -> anyhow::Result<()> {
    cli::bootstrap_admin(&db).await?;
    std::fs::create_dir_all(&downloads_dir)?;
    tracing::info!(dir = %downloads_dir.display(), "instaladores em /downloads");
    let app = routes::router(AppState { db, downloads_dir });
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!("rustdesk-api escutando em http://{bind}");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.ok();
    };
    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("encerrando");
}
