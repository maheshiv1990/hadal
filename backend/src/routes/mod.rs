use actix_web::{HttpResponse, web};

use crate::error::AppError;

mod health;
mod notes;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.app_data(
        // Extractor failures return a generic message; serde/parse details
        // (field names, offsets, types) must not reach the client (ASVS V7.4.1).
        web::JsonConfig::default()
            .limit(64 * 1024)
            .error_handler(|err, _req| {
                tracing::debug!(error = %err, "rejected JSON body");
                AppError::BadRequest("invalid request body".into()).into()
            }),
    )
    .app_data(web::PathConfig::default().error_handler(|err, _req| {
        tracing::debug!(error = %err, "rejected path parameter");
        AppError::NotFound.into()
    }))
    .app_data(web::QueryConfig::default().error_handler(|err, _req| {
        tracing::debug!(error = %err, "rejected query string");
        AppError::BadRequest("invalid query string".into()).into()
    }))
    .service(
        web::scope("/api")
            .service(health::health)
            .service(notes::list)
            .service(notes::create)
            .service(notes::get)
            .service(notes::delete),
    )
    .default_service(web::to(|| async {
        HttpResponse::NotFound().json(serde_json::json!({ "error": "not found" }))
    }));
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use actix_web::{App, test};
    use sqlx::postgres::PgPoolOptions;

    /// Pool that never connects: these tests exercise paths that are rejected
    /// before any query runs.
    fn lazy_pool() -> web::Data<sqlx::PgPool> {
        web::Data::new(
            PgPoolOptions::new()
                .connect_lazy("postgres://invalid:invalid@127.0.0.1:1/invalid")
                .unwrap(),
        )
    }

    async fn post_notes(body: impl Into<String>) -> (u16, serde_json::Value) {
        let app = test::init_service(App::new().app_data(lazy_pool()).configure(configure)).await;
        let req = test::TestRequest::post()
            .uri("/api/notes")
            .insert_header(("content-type", "application/json"))
            .set_payload(body.into())
            .to_request();
        let resp = test::call_service(&app, req).await;
        let status = resp.status().as_u16();
        (status, test::read_body_json(resp).await)
    }

    #[actix_web::test]
    async fn malformed_json_does_not_leak_parser_details() {
        let (status, body) = post_notes(r#"{"title": "#).await;
        assert_eq!(status, 400);
        assert_eq!(body, serde_json::json!({ "error": "invalid request body" }));
    }

    #[actix_web::test]
    async fn unknown_fields_are_rejected() {
        let (status, _) = post_notes(r#"{"title":"a","created_at":"2000-01-01T00:00:00Z"}"#).await;
        assert_eq!(status, 400);
    }

    #[actix_web::test]
    async fn oversized_title_is_rejected() {
        let (status, _) = post_notes(format!(r#"{{"title":"{}"}}"#, "x".repeat(201))).await;
        assert_eq!(status, 400);
    }

    #[actix_web::test]
    async fn duplicate_json_keys_are_rejected() {
        // CASA 5.1.1: parameter pollution must not let a second value win silently.
        let (status, _) = post_notes(r#"{"title":"safe","title":"evil"}"#).await;
        assert_eq!(status, 400);
    }

    #[actix_web::test]
    async fn cross_site_form_post_is_rejected() {
        // CASA 3.1.5: a plain HTML form (no CORS preflight) cannot send
        // application/json, so state-changing endpoints refuse other types.
        let app = test::init_service(App::new().app_data(lazy_pool()).configure(configure)).await;
        for ct in [
            "application/x-www-form-urlencoded",
            "multipart/form-data; boundary=x",
            "text/plain",
        ] {
            let req = test::TestRequest::post()
                .uri("/api/notes")
                .insert_header(("content-type", ct))
                .set_payload(r#"{"title":"csrf"}"#)
                .to_request();
            assert_eq!(
                test::call_service(&app, req).await.status(),
                400,
                "accepted {ct}"
            );
        }
    }

    #[actix_web::test]
    async fn invalid_uuid_path_is_404() {
        let app = test::init_service(App::new().app_data(lazy_pool()).configure(configure)).await;
        let req = test::TestRequest::get()
            .uri("/api/notes/not-a-uuid")
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status(), 404);
    }

    #[actix_web::test]
    async fn unknown_route_is_json_404() {
        let app = test::init_service(App::new().app_data(lazy_pool()).configure(configure)).await;
        let req = test::TestRequest::get().uri("/nope").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }
}
