//! Shared helpers for tests that need Postgres or a full app.
//!
//! DB-backed tests use `TEST_DATABASE_URL`, a throwaway database started by
//! `scripts/test-db.sh` (scripts/verify.sh does this) or by CI. They fail
//! rather than skip when it is missing, so the auth and IDOR tests can't be
//! silently left out of the gate.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::num::NonZeroU32;
use std::time::Duration;

use actix_web::web;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

use crate::auth::cookies::SESSION_COOKIE;
use crate::auth::session;

pub fn nz(n: u32) -> NonZeroU32 {
    NonZeroU32::new(n).unwrap()
}

/// A pool that can never connect. For tests that must be rejected before any
/// query runs, or that check behaviour when the database is down.
pub fn unreachable_pool() -> web::Data<PgPool> {
    web::Data::new(
        PgPoolOptions::new()
            .acquire_timeout(Duration::from_secs(1))
            .connect_lazy("postgres://127.0.0.1:1/invalid")
            .unwrap(),
    )
}

pub async fn test_db() -> web::Data<PgPool> {
    let url = std::env::var("TEST_DATABASE_URL").expect(
        "TEST_DATABASE_URL is not set. Run `eval \"$(scripts/test-db.sh start)\"` \
         (scripts/verify.sh does this for you)",
    );
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&url)
        .await
        .expect("cannot reach TEST_DATABASE_URL");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("migrations failed");
    web::Data::new(pool)
}

/// Creates a fresh user with a live session. Returns the user id and a
/// `Cookie` header value carrying the session.
pub async fn signed_in_user(pool: &PgPool) -> (Uuid, String) {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO users (id, google_sub, email) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(format!("test-{id}"))
        .bind(format!("{id}@example.com"))
        .execute(pool)
        .await
        .unwrap();
    let token = session::create(pool, id, 3600).await.unwrap();
    (id, format!("{SESSION_COOKIE}={token}"))
}

/// Full API app with generous rate limits, wired like `main.rs`.
macro_rules! test_app {
    ($pool:expr) => {
        test_app!(
            $pool,
            $crate::auth::google::GoogleClient::new(&$crate::config::tests::test_config().oauth)
                .unwrap()
        )
    };
    ($pool:expr, $google:expr) => {{
        use $crate::security::{AuthLimiter, Limiter};
        use $crate::test_support::nz;
        actix_web::test::init_service(
            actix_web::App::new()
                // The same response headers as production (main.rs).
                .wrap($crate::security::security_headers())
                .app_data($pool.clone())
                .app_data(actix_web::web::Data::new(
                    $crate::config::tests::test_config().session,
                ))
                .app_data(actix_web::web::Data::new(Limiter::new(
                    nz(1000),
                    nz(1000),
                    false,
                )))
                .app_data(actix_web::web::Data::new(AuthLimiter(Limiter::per_minute(
                    nz(1000),
                    nz(1000),
                    false,
                ))))
                .app_data(actix_web::web::Data::new(
                    $crate::auth::password::AccountLimiter::new(),
                ))
                .app_data(actix_web::web::Data::new($google))
                .app_data(actix_web::web::Data::new(
                    $crate::crypto::tests::test_cipher(),
                ))
                .configure($crate::routes::configure),
        )
        .await
    }};
}
pub(crate) use test_app;
