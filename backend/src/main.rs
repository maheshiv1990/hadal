mod config;
mod error;
mod routes;
mod security;

use std::time::Duration;

use actix_web::{App, HttpServer, middleware, web};
use anyhow::Context;
use sqlx::postgres::PgPoolOptions;
use tracing_actix_web::TracingLogger;
use tracing_subscriber::EnvFilter;

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
    // .env is optional; in Docker the variables come from compose.
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = config::Config::from_env()?;

    let pool = PgPoolOptions::new()
        .max_connections(config.db_max_connections)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&config.database_url)
        .await
        .context("failed to connect to Postgres")?;

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .context("failed to run database migrations")?;

    let limiter = security::Limiter::new(
        config.rate_limit_per_second,
        config.rate_limit_burst,
        config.trust_proxy_headers,
    );
    {
        let limiter = limiter.clone();
        actix_web::rt::spawn(async move {
            let mut tick = actix_web::rt::time::interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                limiter.housekeep();
            }
        });
    }

    tracing::info!(host = %config.host, port = config.port, "starting server");

    let pool = web::Data::new(pool);
    let limiter = web::Data::new(limiter);
    HttpServer::new(move || {
        App::new()
            .app_data(pool.clone())
            .app_data(limiter.clone())
            // Order: last `wrap` runs first. Headers wrap everything, including 429s.
            .wrap(middleware::from_fn(security::rate_limit))
            .wrap(TracingLogger::default())
            .wrap(middleware::NormalizePath::trim())
            .wrap(security::security_headers())
            .configure(routes::configure)
    })
    .client_request_timeout(Duration::from_secs(10))
    .client_disconnect_timeout(Duration::from_secs(5))
    .bind((config.host.as_str(), config.port))?
    .run()
    .await?;

    Ok(())
}
