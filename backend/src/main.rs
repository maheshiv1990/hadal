mod auth;
mod config;
mod crypto;
mod error;
mod mail;
mod routes;
mod security;
#[cfg(test)]
mod test_support;

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
        .connect(config.database_url.expose())
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

    let auth_limiter = security::AuthLimiter(security::Limiter::per_minute(
        config.auth_rate_limit_per_minute,
        config.auth_rate_limit_burst,
        config.trust_proxy_headers,
    ));
    {
        let auth_limiter = auth_limiter.clone();
        actix_web::rt::spawn(async move {
            let mut tick = actix_web::rt::time::interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                auth_limiter.0.housekeep();
            }
        });
    }

    let account_limiter = auth::password::AccountLimiter::new();
    {
        let account_limiter = account_limiter.clone();
        actix_web::rt::spawn(async move {
            let mut tick = actix_web::rt::time::interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                account_limiter.housekeep();
            }
        });
    }

    // Expired sessions are already refused on use; this just deletes them.
    {
        let pool = pool.clone();
        let idle_secs = config.session.idle_secs;
        actix_web::rt::spawn(async move {
            let mut tick = actix_web::rt::time::interval(Duration::from_secs(300));
            loop {
                tick.tick().await;
                if let Err(err) = auth::session::purge_expired(&pool, idle_secs).await {
                    tracing::warn!(error = %err, "expired session cleanup failed");
                }
            }
        });
    }

    let google = auth::google::GoogleClient::new(&config.oauth)
        .context("failed to build the Google sign-in client")?;
    let cipher = crypto::DataCipher::from_base64(config.data_encryption_key.expose())?;

    tracing::info!(host = %config.host, port = config.port, "starting server");

    let pool = web::Data::new(pool);
    let limiter = web::Data::new(limiter);
    let auth_limiter = web::Data::new(auth_limiter);
    let account_limiter = web::Data::new(account_limiter);
    let google = web::Data::new(google);
    let cipher = web::Data::new(cipher);
    let session_config = web::Data::new(config.session.clone());
    let password_auth = web::Data::new(auth::PasswordAuth(config.password_auth_enabled));
    tracing::info!(
        enabled = config.password_auth_enabled,
        "local email sign-in accounts"
    );
    HttpServer::new(move || {
        App::new()
            .app_data(pool.clone())
            .app_data(limiter.clone())
            .app_data(auth_limiter.clone())
            .app_data(account_limiter.clone())
            .app_data(google.clone())
            .app_data(cipher.clone())
            .app_data(session_config.clone())
            .app_data(password_auth.clone())
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
