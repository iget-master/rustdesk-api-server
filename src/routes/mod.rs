pub mod ab;
pub mod account;
pub mod admin;
pub mod audit;
pub mod authorize;
pub mod device;
pub mod group;

use axum::response::Html;
use axum::routing::{delete, get, post, put};
use axum::Router;
use tower_http::cors::CorsLayer;
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::Level;

use crate::error::ApiError;
use crate::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        // console web (embutido no binário)
        .route("/", get(console))
        .route("/console", get(console))
        .route("/console/", get(console))
        .route("/healthz", get(|| async { "ok" }))
        // conta
        .route("/api/login-options", get(account::login_options))
        .route("/api/login", post(account::login))
        .route("/api/logout", post(account::logout))
        .route("/api/currentUser", post(account::current_user))
        // address book (formato atual)
        .route("/api/ab/personal", post(ab::personal))
        .route("/api/ab/settings", post(ab::settings))
        .route("/api/ab/shared/profiles", post(ab::shared_profiles))
        .route("/api/ab/peers", post(ab::peers))
        .route("/api/ab/tags/{guid}", post(ab::tags))
        .route("/api/ab/peer/add/{guid}", post(ab::peer_add))
        .route("/api/ab/peer/update/{guid}", put(ab::peer_update))
        .route("/api/ab/peer/{guid}", delete(ab::peer_delete))
        .route("/api/ab/tag/add/{guid}", post(ab::tag_add))
        .route("/api/ab/tag/rename/{guid}", put(ab::tag_rename))
        .route("/api/ab/tag/update/{guid}", put(ab::tag_update))
        .route("/api/ab/tag/{guid}", delete(ab::tag_delete))
        // aba grupo
        .route("/api/users", get(group::users))
        .route("/api/peers", get(group::peers))
        .route("/api/device-group/accessible", get(group::device_groups))
        // serviço em background dos dispositivos
        .route("/api/heartbeat", post(device::heartbeat))
        .route("/api/sysinfo", post(device::sysinfo))
        .route("/api/switch-grant", post(device::switch_grant))
        .route("/api/devices/deploy", post(device::deploy))
        .route("/api/devices/cli", post(device::cli_assign))
        .route("/api/enroll", post(device::enroll))
        // auditoria
        .route("/api/audit/conn", post(audit::conn))
        .route("/api/audit/conn/active", get(audit::conn_active))
        .route("/api/audit/file", post(audit::file))
        .route("/api/audit/alarm", post(audit::alarm))
        .route("/api/audit", put(audit::note))
        // hbbs (fork) pergunta se pode intermediar uma conexão
        .route("/api/internal/authorize", post(authorize::authorize))
        // console
        .nest("/admin/api", admin::router())
        .fallback(not_found)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        .layer(CorsLayer::permissive())
        .with_state(state)
}

async fn console() -> Html<&'static str> {
    Html(include_str!("../console/index.html"))
}

/// 404 rápido: o cliente RustDesk usa 404 como "recurso não suportado" e segue em frente.
async fn not_found() -> ApiError {
    ApiError::not_found("not found")
}
