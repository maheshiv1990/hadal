use actix_web::{HttpResponse, get, web};
use serde_json::json;
use sqlx::PgPool;

/// Liveness + DB readiness check. Used by the Docker healthcheck.
#[get("/health")]
pub async fn health(pool: web::Data<PgPool>) -> HttpResponse {
    match sqlx::query("SELECT 1").execute(pool.get_ref()).await {
        Ok(_) => HttpResponse::Ok().json(json!({ "status": "ok", "database": "ok" })),
        Err(err) => {
            tracing::warn!(error = %err, "health check: database unreachable");
            HttpResponse::ServiceUnavailable()
                .json(json!({ "status": "degraded", "database": "unreachable" }))
        }
    }
}
