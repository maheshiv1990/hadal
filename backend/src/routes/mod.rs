use actix_web::{HttpResponse, middleware::from_fn, web};

use crate::auth;
use crate::error::AppError;

mod health;
mod mail;

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
            // Public: health check and the sign-in endpoints.
            .service(health::health)
            .configure(auth::configure)
            // Everything else needs a session (deny by default, CASA 3.1.1).
            .service(
                web::scope("/mail")
                    .wrap(from_fn(auth::require_session))
                    .service(mail::accounts)
                    .service(mail::disconnect)
                    // Each import makes up to ~100 Google calls per mailbox,
                    // so it gets the tight per-IP limit too.
                    .service(
                        web::scope("/import")
                            .wrap(from_fn(crate::security::auth_rate_limit))
                            .service(mail::import),
                    )
                    .service(mail::messages)
                    .service(mail::message),
            ),
    )
    .default_service(web::to(|| async {
        HttpResponse::NotFound().json(serde_json::json!({ "error": "not found" }))
    }));
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use actix_web::{App, HttpServer, dev::ServiceResponse, test};
    use reqwest::Url;
    use serde_json::{Value, json};

    use crate::auth::cookies::{LOGIN_COOKIE, SESSION_COOKIE};
    use crate::auth::google::{
        GoogleClient,
        tests::{CLIENT_ID, fake_id_token, good_claims},
    };
    use crate::auth::token::pkce_challenge;
    use crate::config::tests::test_config;
    use crate::test_support::{signed_in_user, test_app, test_db, unreachable_pool};

    async fn json_body(resp: ServiceResponse) -> (u16, Value) {
        let status = resp.status().as_u16();
        (status, test::read_body_json(resp).await)
    }

    fn set_cookies(resp: &ServiceResponse) -> Vec<String> {
        resp.headers()
            .get_all("set-cookie")
            .map(|v| v.to_str().unwrap().to_owned())
            .collect()
    }

    /// `name=value` for the cookie `name` set by this response, if any.
    fn cookie_pair(resp: &ServiceResponse, name: &str) -> Option<String> {
        set_cookies(resp)
            .into_iter()
            .find(|c| c.starts_with(&format!("{name}=")))
            .map(|c| c.split(';').next().unwrap().to_owned())
    }

    fn location(resp: &ServiceResponse) -> String {
        resp.headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned()
    }

    // ---- deny by default (no database needed) ---------------------------

    #[actix_web::test]
    async fn api_routes_require_a_session() {
        // CASA 3.1.1 / 2.4.1: every signed-in route, every method.
        let app = test_app!(unreachable_pool());
        let id = "00000000-0000-0000-0000-000000000000";
        for (method, uri) in [
            ("GET", "/api/auth/me".to_owned()),
            ("GET", "/api/auth/gmail/connect".to_owned()),
            ("GET", "/api/mail/accounts".to_owned()),
            ("DELETE", format!("/api/mail/accounts/{id}")),
            ("POST", "/api/mail/import".to_owned()),
            ("GET", "/api/mail/messages".to_owned()),
            ("GET", format!("/api/mail/messages/{id}")),
        ] {
            for cookie in [None, Some(format!("{SESSION_COOKIE}=not-a-real-token"))] {
                let mut req = test::TestRequest::default()
                    .method(method.parse().unwrap())
                    .uri(&uri)
                    .insert_header(("content-type", "application/json"))
                    .set_payload("{}");
                if let Some(c) = &cookie {
                    req = req.insert_header(("cookie", c.as_str()));
                }
                let (status, body) =
                    json_body(test::call_service(&app, req.to_request()).await).await;
                assert_eq!(status, 401, "{method} {uri} with {cookie:?}");
                assert_eq!(body, json!({ "error": "authentication required" }));
            }
        }
    }

    #[actix_web::test]
    async fn session_check_fails_closed_when_database_is_down() {
        // CASA 3.1.3: an error while checking the session must deny, not allow.
        let app = test_app!(unreachable_pool());
        let req = test::TestRequest::get()
            .uri("/api/mail/accounts")
            .insert_header(("cookie", format!("{SESSION_COOKIE}={}", "a".repeat(43))))
            .to_request();
        let (status, body) = json_body(test::call_service(&app, req).await).await;
        assert_eq!(status, 500);
        assert_eq!(body, json!({ "error": "internal server error" }));
    }

    #[actix_web::test]
    async fn session_check_fails_closed_when_not_configured() {
        // CASA 3.1.3: missing wiring is a 500, never a pass-through.
        let app = test::init_service(
            App::new().app_data(unreachable_pool()).service(
                web::scope("/x")
                    .wrap(from_fn(auth::require_session))
                    .route("", web::get().to(HttpResponse::Ok)),
            ),
        )
        .await;
        let req = test::TestRequest::get()
            .uri("/x")
            .insert_header(("cookie", format!("{SESSION_COOKIE}={}", "a".repeat(43))))
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status(), 500);
    }

    #[actix_web::test]
    async fn auth_user_extractor_rejects_unguarded_routes() {
        // A handler that takes AuthUser but was mounted without
        // require_session must refuse rather than run anonymously.
        async fn handler(_: auth::AuthUser) -> HttpResponse {
            HttpResponse::Ok().finish()
        }
        let app = test::init_service(App::new().route("/x", web::get().to(handler))).await;
        let req = test::TestRequest::get().uri("/x").to_request();
        assert_eq!(test::call_service(&app, req).await.status(), 401);
    }

    #[actix_web::test]
    async fn logout_rejects_cross_site_forms() {
        // CASA 3.1.5: logout needs a JSON body, which a cross-site form can't send.
        let app = test_app!(unreachable_pool());
        for ct in ["application/x-www-form-urlencoded", "text/plain"] {
            let req = test::TestRequest::post()
                .uri("/api/auth/logout")
                .insert_header(("content-type", ct))
                .set_payload("{}")
                .to_request();
            assert_eq!(test::call_service(&app, req).await.status(), 400, "{ct}");
        }
    }

    #[actix_web::test]
    async fn callback_without_login_cookie_is_refused() {
        // CASA 3.2.2: a callback not started in this browser is refused.
        let app = test_app!(unreachable_pool());
        let req = test::TestRequest::get()
            .uri("/api/auth/callback?code=abc&state=def")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 303);
        assert_eq!(location(&resp), "/?login=failed");
        assert!(cookie_pair(&resp, SESSION_COOKIE).is_none());
    }

    #[actix_web::test]
    async fn unknown_route_is_json_404() {
        let app = test_app!(unreachable_pool());
        let req = test::TestRequest::get().uri("/nope").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }

    // ---- input handling (signed in) -------------------------------------

    /// POST a raw body to /api/mail/import, the signed-in JSON endpoint.
    async fn post_import(body: impl Into<String>) -> (u16, Value) {
        let pool = test_db().await;
        let (_, cookie) = signed_in_user(&pool).await;
        let app = test_app!(pool);
        let req = test::TestRequest::post()
            .uri("/api/mail/import")
            .insert_header(("content-type", "application/json"))
            .insert_header(("cookie", cookie))
            .set_payload(body.into())
            .to_request();
        json_body(test::call_service(&app, req).await).await
    }

    #[actix_web::test]
    async fn malformed_json_does_not_leak_parser_details() {
        let (status, body) = post_import(r#"{"x": "#).await;
        assert_eq!(status, 400);
        assert_eq!(body, json!({ "error": "invalid request body" }));
    }

    #[actix_web::test]
    async fn unknown_fields_are_rejected() {
        // CASA 3.1.2: a client can't set owner_id (or anything else) itself.
        // The empty body is accepted, so a 400 below is the extra field's doing.
        let (status, _) = post_import("{}").await;
        assert_eq!(status, 200);
        for extra in [
            r#""created_at":"2000-01-01T00:00:00Z""#,
            r#""owner_id":"00000000-0000-0000-0000-000000000000""#,
        ] {
            let (status, _) = post_import(format!("{{{extra}}}")).await;
            assert_eq!(status, 400, "accepted {extra}");
        }
    }

    #[actix_web::test]
    async fn duplicate_json_keys_are_rejected() {
        // CASA 5.1.1: parameter pollution must not let a second value win silently.
        let app = test_app!(test_db().await);
        let req = test::TestRequest::post()
            .uri("/api/auth/password-login")
            .insert_header(("content-type", "application/json"))
            .set_payload(
                r#"{"email":"safe@example.com","email":"evil@example.com","password":"x"}"#,
            )
            .to_request();
        let (status, body) = json_body(test::call_service(&app, req).await).await;
        assert_eq!(
            (status, body),
            (400, json!({ "error": "invalid request body" }))
        );
    }

    #[actix_web::test]
    async fn cross_site_form_post_is_rejected() {
        // CASA 3.1.5: even with a valid session, a plain HTML form (no CORS
        // preflight) cannot send application/json, so it is refused.
        let pool = test_db().await;
        let (_, cookie) = signed_in_user(&pool).await;
        let app = test_app!(pool);
        for ct in [
            "application/x-www-form-urlencoded",
            "multipart/form-data; boundary=x",
            "text/plain",
        ] {
            let req = test::TestRequest::post()
                .uri("/api/mail/import")
                .insert_header(("content-type", ct))
                .insert_header(("cookie", cookie.as_str()))
                .set_payload("{}")
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
        let pool = test_db().await;
        let (_, cookie) = signed_in_user(&pool).await;
        let app = test_app!(pool);
        let req = test::TestRequest::get()
            .uri("/api/mail/messages/not-a-uuid")
            .insert_header(("cookie", cookie))
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status(), 404);
    }

    // ---- sessions and ownership -----------------------------------------

    #[actix_web::test]
    async fn unknown_session_token_is_rejected() {
        let pool = test_db().await;
        let app = test_app!(pool);
        let req = test::TestRequest::get()
            .uri("/api/mail/accounts")
            .insert_header(("cookie", format!("{SESSION_COOKIE}={}", "a".repeat(43))))
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status(), 401);
    }

    #[actix_web::test]
    async fn expired_and_idle_sessions_are_rejected() {
        // CASA 2.2.1 / 2.2.3: absolute and idle expiry, both enforced server-side.
        let pool = test_db().await;
        let (absolute_user, absolute_cookie) = signed_in_user(&pool).await;
        let (idle_user, idle_cookie) = signed_in_user(&pool).await;
        sqlx::query(
            "UPDATE sessions SET expires_at = now() - interval '1 second' WHERE user_id = $1",
        )
        .bind(absolute_user)
        .execute(pool.get_ref())
        .await
        .unwrap();
        // Idle window in test_config() is 30 minutes.
        sqlx::query(
            "UPDATE sessions SET last_seen_at = now() - interval '31 minutes' WHERE user_id = $1",
        )
        .bind(idle_user)
        .execute(pool.get_ref())
        .await
        .unwrap();
        let app = test_app!(pool);
        for cookie in [absolute_cookie, idle_cookie] {
            let req = test::TestRequest::get()
                .uri("/api/auth/me")
                .insert_header(("cookie", cookie))
                .to_request();
            assert_eq!(test::call_service(&app, req).await.status(), 401);
        }
    }

    #[actix_web::test]
    async fn logout_revokes_the_session_server_side() {
        // CASA 2.2.1: after logout the old token is dead even if replayed.
        let pool = test_db().await;
        let (_, cookie) = signed_in_user(&pool).await;
        let app = test_app!(pool);
        let me = || {
            test::TestRequest::get()
                .uri("/api/auth/me")
                .insert_header(("cookie", cookie.as_str()))
                .to_request()
        };
        assert_eq!(test::call_service(&app, me()).await.status(), 200);

        let req = test::TestRequest::post()
            .uri("/api/auth/logout")
            .insert_header(("content-type", "application/json"))
            .insert_header(("cookie", cookie.as_str()))
            .set_payload("{}")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 204);
        let cleared = set_cookies(&resp);
        assert!(
            cleared
                .iter()
                .any(|c| c.starts_with(&format!("{SESSION_COOKIE}=;")) && c.contains("Max-Age=0")),
            "{cleared:?}"
        );

        assert_eq!(test::call_service(&app, me()).await.status(), 401);
    }

    // ---- Google sign-in -------------------------------------------------

    /// Stands in for Google: the token endpoint (checks the request like
    /// Google would: code, PKCE verifier, redirect_uri, client; returns an ID
    /// token for `sub` with the nonce from the authorization request), token
    /// refresh, revocation and the Gmail API.
    #[derive(Default)]
    struct FakeGoogle {
        challenge: Mutex<Option<String>>,
        nonce: Mutex<Option<String>>,
        sub: Mutex<String>,
        calls: Mutex<u32>,
        /// Scope granted by the code exchange; `None` = sign-in scopes.
        scope: Mutex<Option<String>>,
        /// Refresh token issued by the code exchange, if any.
        refresh_token: Mutex<Option<String>>,
        revoked: Mutex<Vec<String>>,
        /// The mailbox, newest first.
        messages: Mutex<Vec<Value>>,
        message_fetches: Mutex<u32>,
    }

    const FAKE_ACCESS: &str = "fake-gmail-access";

    async fn fake_token_endpoint(
        st: web::Data<FakeGoogle>,
        form: web::Form<HashMap<String, String>>,
    ) -> HttpResponse {
        *st.calls.lock().unwrap() += 1;
        let cfg = test_config().oauth;
        let client_ok = form.get("client_id").map(String::as_str) == Some(CLIENT_ID)
            && form.get("client_secret").map(String::as_str) == Some(cfg.client_secret.expose());
        if form.get("grant_type").map(String::as_str) == Some("refresh_token") {
            let presented = form.get("refresh_token").cloned();
            let live = presented.is_some()
                && presented == *st.refresh_token.lock().unwrap()
                && !st
                    .revoked
                    .lock()
                    .unwrap()
                    .contains(presented.as_ref().unwrap());
            if !(client_ok && live) {
                return HttpResponse::BadRequest().json(json!({ "error": "invalid_grant" }));
            }
            return HttpResponse::Ok().json(json!({
                "access_token": FAKE_ACCESS, "expires_in": 3599, "token_type": "Bearer",
            }));
        }
        let challenge = st.challenge.lock().unwrap().clone();
        let ok = client_ok
            && form.get("grant_type").map(String::as_str) == Some("authorization_code")
            && form.get("code").map(String::as_str) == Some("good-code")
            && form.get("redirect_uri").map(String::as_str) == Some(cfg.redirect_uri.as_str())
            && form.get("code_verifier").map(|v| pkce_challenge(v)) == challenge;
        if !ok {
            return HttpResponse::BadRequest().json(json!({ "error": "invalid_grant" }));
        }
        let nonce = st.nonce.lock().unwrap().clone().unwrap();
        let sub = st.sub.lock().unwrap().clone();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let scope = st
            .scope
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| "openid email profile".into());
        let mut body = json!({
            "access_token": "not-a-real-access-token",
            "expires_in": 3599,
            "scope": scope,
            "token_type": "Bearer",
            "id_token": fake_id_token(&good_claims(&nonce, &sub, now)),
        });
        if let Some(refresh) = st.refresh_token.lock().unwrap().clone() {
            body["refresh_token"] = json!(refresh);
        }
        HttpResponse::Ok().json(body)
    }

    async fn fake_revoke(
        st: web::Data<FakeGoogle>,
        form: web::Form<HashMap<String, String>>,
    ) -> HttpResponse {
        st.revoked.lock().unwrap().push(form["token"].clone());
        HttpResponse::Ok().finish()
    }

    fn bearer_ok(req: &actix_web::HttpRequest) -> bool {
        req.headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            == Some(&format!("Bearer {FAKE_ACCESS}"))
    }

    async fn fake_gmail_list(
        st: web::Data<FakeGoogle>,
        req: actix_web::HttpRequest,
        q: web::Query<HashMap<String, String>>,
    ) -> HttpResponse {
        if !bearer_ok(&req) {
            return HttpResponse::Unauthorized().finish();
        }
        let max: usize = q["maxResults"].parse().unwrap();
        let list: Vec<Value> = st
            .messages
            .lock()
            .unwrap()
            .iter()
            .take(max)
            .map(|m| json!({ "id": m["id"], "threadId": m["id"] }))
            .collect();
        if list.is_empty() {
            return HttpResponse::Ok().json(json!({ "resultSizeEstimate": 0 }));
        }
        HttpResponse::Ok().json(json!({ "messages": list }))
    }

    async fn fake_gmail_get(
        st: web::Data<FakeGoogle>,
        req: actix_web::HttpRequest,
        id: web::Path<String>,
        q: web::Query<HashMap<String, String>>,
    ) -> HttpResponse {
        if !bearer_ok(&req) {
            return HttpResponse::Unauthorized().finish();
        }
        assert_eq!(q["format"], "full");
        *st.message_fetches.lock().unwrap() += 1;
        let found = st
            .messages
            .lock()
            .unwrap()
            .iter()
            .find(|m| m["id"] == id.as_str())
            .cloned();
        match found {
            Some(m) => HttpResponse::Ok().json(m),
            None => HttpResponse::NotFound().finish(),
        }
    }

    async fn start_fake_google(st: Arc<FakeGoogle>) -> GoogleClient {
        let data = web::Data::from(st);
        let server = HttpServer::new(move || {
            App::new()
                .app_data(data.clone())
                .route("/token", web::post().to(fake_token_endpoint))
                .route("/revoke", web::post().to(fake_revoke))
                .route(
                    "/gmail/v1/users/me/messages",
                    web::get().to(fake_gmail_list),
                )
                .route(
                    "/gmail/v1/users/me/messages/{id}",
                    web::get().to(fake_gmail_get),
                )
        })
        .workers(1)
        .bind(("127.0.0.1", 0))
        .unwrap();
        let addr = server.addrs()[0];
        actix_web::rt::spawn(server.run());
        let base = Url::parse(&format!("http://{addr}/")).unwrap();
        GoogleClient::for_test(&test_config().oauth, base).unwrap()
    }

    fn login_request() -> test::TestRequest {
        test::TestRequest::get().uri("/api/auth/login")
    }

    /// Checks a /login response and primes the fake with its PKCE challenge and
    /// nonce. Returns the login cookie and the authorize URL params.
    fn read_login(resp: ServiceResponse, fake: &FakeGoogle) -> (String, HashMap<String, String>) {
        assert_eq!(resp.status(), 303);
        let login_set_cookie = set_cookies(&resp)
            .into_iter()
            .find(|c| c.starts_with(LOGIN_COOKIE))
            .unwrap();
        for attr in ["Secure", "HttpOnly", "SameSite=Lax", "Max-Age=600"] {
            assert!(
                login_set_cookie.split("; ").any(|a| a == attr),
                "{login_set_cookie}"
            );
        }
        let url = Url::parse(&location(&resp)).unwrap();
        assert_eq!(url.host_str(), Some("accounts.google.com"));
        let q: HashMap<String, String> = url.query_pairs().into_owned().collect();
        *fake.challenge.lock().unwrap() = Some(q["code_challenge"].clone());
        *fake.nonce.lock().unwrap() = Some(q["nonce"].clone());
        (cookie_pair(&resp, LOGIN_COOKIE).unwrap(), q)
    }

    fn callback(state: &str, cookie: &str) -> test::TestRequest {
        test::TestRequest::get()
            .uri(&format!(
                "/api/auth/callback?code=good-code&state={state}&scope=openid+email&authuser=0"
            ))
            .insert_header(("cookie", cookie))
    }

    #[actix_web::test]
    async fn google_sign_in_creates_a_fresh_session() {
        // CASA 3.2.1 / 3.2.2 end to end: PKCE verified by the token endpoint,
        // state bound to the browser, nonce checked, new session issued.
        let pool = test_db().await;
        let fake = Arc::new(FakeGoogle::default());
        let sub = format!("google-{}", uuid::Uuid::new_v4());
        *fake.sub.lock().unwrap() = sub.clone();
        let google = start_fake_google(fake.clone()).await;
        let (_, old_session) = signed_in_user(&pool).await;
        let app = test_app!(pool, google);

        let (login_cookie, q) = read_login(
            test::call_service(&app, login_request().to_request()).await,
            &fake,
        );
        let resp = test::call_service(
            &app,
            callback(&q["state"], &format!("{login_cookie}; {old_session}")).to_request(),
        )
        .await;
        assert_eq!(resp.status(), 303);
        assert_eq!(location(&resp), "/");
        let session_set_cookie = set_cookies(&resp)
            .into_iter()
            .find(|c| c.starts_with(&format!("{SESSION_COOKIE}=")))
            .unwrap();
        for attr in ["Secure", "HttpOnly", "SameSite=Strict", "Path=/"] {
            assert!(
                session_set_cookie.split("; ").any(|a| a == attr),
                "{session_set_cookie}"
            );
        }
        let session = cookie_pair(&resp, SESSION_COOKIE).unwrap();
        assert_ne!(
            session, old_session,
            "session must be regenerated at sign-in"
        );

        let me = |cookie: &str| {
            test::TestRequest::get()
                .uri("/api/auth/me")
                .insert_header(("cookie", cookie))
                .to_request()
        };
        let (status, body) = json_body(test::call_service(&app, me(&session)).await).await;
        assert_eq!(
            (status, body),
            (
                200,
                json!({
                    "email": format!("{sub}@example.com"),
                    "first_name": "Ada",
                    "last_name": "Lovelace",
                    "has_password": false,
                })
            )
        );
        // The session the browser had before signing in is gone (fixation).
        assert_eq!(
            test::call_service(&app, me(&old_session)).await.status(),
            401
        );

        // The login can't be replayed.
        let resp =
            test::call_service(&app, callback(&q["state"], &login_cookie).to_request()).await;
        assert_eq!(location(&resp), "/?login=failed");
        assert_eq!(
            *fake.calls.lock().unwrap(),
            1,
            "replay must not reach Google"
        );
    }

    #[actix_web::test]
    async fn callback_rejects_forged_state() {
        // CASA 3.2.2: wrong state means no code exchange and no session.
        let pool = test_db().await;
        let fake = Arc::new(FakeGoogle::default());
        let google = start_fake_google(fake.clone()).await;
        let app = test_app!(pool, google);

        let (login_cookie, _) = read_login(
            test::call_service(&app, login_request().to_request()).await,
            &fake,
        );
        let resp =
            test::call_service(&app, callback(&"x".repeat(43), &login_cookie).to_request()).await;
        assert_eq!(resp.status(), 303);
        assert_eq!(location(&resp), "/?login=failed");
        assert!(cookie_pair(&resp, SESSION_COOKIE).is_none());
        assert_eq!(*fake.calls.lock().unwrap(), 0);
    }

    #[actix_web::test]
    async fn callback_rejects_wrong_pkce_verifier_and_issuer() {
        let pool = test_db().await;
        let fake = Arc::new(FakeGoogle::default());
        let google = start_fake_google(fake.clone()).await;
        let app = test_app!(pool, google);

        // Token endpoint refuses the verifier (as Google would if the code
        // was stolen and replayed with another verifier).
        let (login_cookie, q) = read_login(
            test::call_service(&app, login_request().to_request()).await,
            &fake,
        );
        *fake.challenge.lock().unwrap() = Some("some-other-challenge".into());
        let resp =
            test::call_service(&app, callback(&q["state"], &login_cookie).to_request()).await;
        assert_eq!(location(&resp), "/?login=failed");
        assert!(cookie_pair(&resp, SESSION_COOKIE).is_none());

        // RFC 9207: an authorization response from another issuer is refused.
        let (login_cookie, q) = read_login(
            test::call_service(&app, login_request().to_request()).await,
            &fake,
        );
        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/auth/callback?code=good-code&state={}&iss=https%3A%2F%2Fevil.example.com",
                q["state"]
            ))
            .insert_header(("cookie", login_cookie))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(location(&resp), "/?login=failed");
        assert!(cookie_pair(&resp, SESSION_COOKIE).is_none());
    }

    // ---- linked Gmail mailboxes -------------------------------------------

    /// Links the fake Google account `sub` to the user with `session`: starts
    /// at /api/auth/gmail/connect, then returns from Google with only the
    /// login cookie (the Strict session cookie isn't sent on that redirect).
    /// Evaluates to the callback response.
    macro_rules! link_mailbox {
        ($app:expr, $fake:expr, $session:expr, $sub:expr) => {{
            *$fake.sub.lock().unwrap() = $sub.to_owned();
            *$fake.scope.lock().unwrap() = Some(format!("openid email {}", GMAIL_SCOPE));
            *$fake.refresh_token.lock().unwrap() = Some(format!("refresh-for-{}", $sub));
            let req = test::TestRequest::get()
                .uri("/api/auth/gmail/connect")
                .insert_header(("cookie", $session))
                .to_request();
            let (login_cookie, q) = read_login(test::call_service(&$app, req).await, &$fake);
            assert_eq!(q["scope"], format!("openid email {}", GMAIL_SCOPE));
            assert_eq!(q["access_type"], "offline");
            test::call_service(&$app, callback(&q["state"], &login_cookie).to_request()).await
        }};
    }

    const GMAIL_SCOPE: &str = "https://www.googleapis.com/auth/gmail.readonly";

    /// A signed-in JSON request with an empty `{}` body.
    macro_rules! req {
        ($method:expr, $uri:expr, $cookie:expr) => {
            test::TestRequest::default()
                .method($method.parse().unwrap())
                .uri($uri)
                .insert_header(("cookie", AsRef::<str>::as_ref($cookie)))
                .insert_header(("content-type", "application/json"))
                .set_payload("{}")
                .to_request()
        };
    }

    #[actix_web::test]
    async fn linking_gmail_stores_an_encrypted_grant_and_keeps_the_session() {
        let pool = test_db().await;
        let fake = Arc::new(FakeGoogle::default());
        let google = start_fake_google(fake.clone()).await;
        let (user_id, session) = signed_in_user(&pool).await;
        let app = test_app!(pool, google);
        let sub = format!("mailbox-{}", uuid::Uuid::new_v4());

        let resp = link_mailbox!(app, fake, session.as_str(), sub.as_str());
        assert_eq!(resp.status(), 303);
        assert_eq!(location(&resp), "/?mail=linked");
        assert!(
            cookie_pair(&resp, SESSION_COOKIE).is_none(),
            "linking must not issue or replace a session"
        );

        let (owner, email, sealed): (uuid::Uuid, String, Vec<u8>) = sqlx::query_as(
            "SELECT owner_id, email, refresh_token_enc FROM mail_accounts WHERE google_sub = $1",
        )
        .bind(&sub)
        .fetch_one(pool.get_ref())
        .await
        .unwrap();
        assert_eq!((owner, email), (user_id, format!("{sub}@example.com")));
        // CASA 6.7.1: the refresh token is not stored in the clear.
        let plain = format!("refresh-for-{sub}");
        assert!(!sealed.windows(plain.len()).any(|w| w == plain.as_bytes()));
        // Linking a mailbox never creates a Google sign-in account for it.
        let users: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE google_sub = $1")
            .bind(&sub)
            .fetch_one(pool.get_ref())
            .await
            .unwrap();
        assert_eq!(users, 0);

        let (status, body) =
            json_body(test::call_service(&app, req!("GET", "/api/mail/accounts", &session)).await)
                .await;
        assert_eq!(status, 200);
        assert_eq!(body.as_array().unwrap().len(), 1);
        assert_eq!(body[0]["email"], format!("{sub}@example.com"));
        assert_eq!(body[0]["message_count"], 0);
        assert!(body[0].get("refresh_token_enc").is_none());

        // Relinking the same Google account updates it instead of adding one.
        let resp = link_mailbox!(app, fake, session.as_str(), sub.as_str());
        assert_eq!(location(&resp), "/?mail=linked");
        let (_, body) =
            json_body(test::call_service(&app, req!("GET", "/api/mail/accounts", &session)).await)
                .await;
        assert_eq!(body.as_array().unwrap().len(), 1);
    }

    #[actix_web::test]
    async fn linking_is_refused_without_gmail_access_or_an_offline_grant() {
        let pool = test_db().await;
        let fake = Arc::new(FakeGoogle::default());
        let google = start_fake_google(fake.clone()).await;
        let (user_id, session) = signed_in_user(&pool).await;
        let app = test_app!(pool, google);

        for (scope, refresh) in [
            // The user unticked Gmail on Google's consent screen.
            (Some("openid email"), Some("r1")),
            // No refresh token: nothing could ever be imported.
            (
                Some("openid email https://www.googleapis.com/auth/gmail.readonly"),
                None,
            ),
        ] {
            let req = test::TestRequest::get()
                .uri("/api/auth/gmail/connect")
                .insert_header(("cookie", session.as_str()))
                .to_request();
            let (login_cookie, q) = read_login(test::call_service(&app, req).await, &fake);
            *fake.sub.lock().unwrap() = format!("mailbox-{}", uuid::Uuid::new_v4());
            *fake.scope.lock().unwrap() = scope.map(str::to_owned);
            *fake.refresh_token.lock().unwrap() = refresh.map(str::to_owned);
            let resp =
                test::call_service(&app, callback(&q["state"], &login_cookie).to_request()).await;
            assert_eq!(location(&resp), "/?mail=failed", "{scope:?} {refresh:?}");
        }
        let linked: i64 =
            sqlx::query_scalar("SELECT count(*) FROM mail_accounts WHERE owner_id = $1")
                .bind(user_id)
                .fetch_one(pool.get_ref())
                .await
                .unwrap();
        assert_eq!(linked, 0);
    }

    #[actix_web::test]
    async fn import_stores_new_mail_encrypted_and_skips_what_it_already_has() {
        use crate::mail::tests::gmail_message;
        let pool = test_db().await;
        let fake = Arc::new(FakeGoogle::default());
        let google = start_fake_google(fake.clone()).await;
        let (_, session) = signed_in_user(&pool).await;
        let app = test_app!(pool, google);
        let sub = format!("mailbox-{}", uuid::Uuid::new_v4());
        link_mailbox!(app, fake, session.as_str(), sub.as_str());
        *fake.messages.lock().unwrap() = (0..3)
            .map(|i| {
                gmail_message(
                    &format!("a{i}"),
                    &format!("Quarterly plan {i}"),
                    "Body text",
                )
            })
            .collect();

        let (status, body) =
            json_body(test::call_service(&app, req!("POST", "/api/mail/import", &session)).await)
                .await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["imported"], 3);
        assert_eq!(body["accounts"][0]["email"], format!("{sub}@example.com"));
        assert_eq!(body["accounts"][0]["error"], Value::Null);

        let (status, list) =
            json_body(test::call_service(&app, req!("GET", "/api/mail/messages", &session)).await)
                .await;
        assert_eq!(status, 200);
        let list = list.as_array().unwrap().clone();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0]["from"], "Grace <grace@example.com>");
        assert!(
            list[0]["subject"]
                .as_str()
                .unwrap()
                .starts_with("Quarterly plan")
        );
        assert!(list[0].get("body").is_none(), "the list carries no bodies");

        let uri = format!("/api/mail/messages/{}", list[0]["id"].as_str().unwrap());
        let (status, detail) =
            json_body(test::call_service(&app, req!("GET", &uri, &session)).await).await;
        assert_eq!(status, 200);
        assert_eq!(detail["body"], "Body text");

        // CASA 6.7.1: neither the subject nor the body is in the clear.
        let rows: Vec<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT m.summary_enc, m.body_enc FROM mail_messages m
               JOIN mail_accounts a ON a.id = m.account_id
              WHERE a.google_sub = $1 AND m.owner_id = a.owner_id",
        )
        .bind(&sub)
        .fetch_all(pool.get_ref())
        .await
        .unwrap();
        assert_eq!(rows.len(), 3);
        for (summary, body) in rows {
            assert!(!summary.windows(9).any(|w| w == b"Quarterly"));
            assert!(!body.windows(9).any(|w| w == b"Body text"));
        }

        // A second import fetches only mail it hasn't seen.
        let fetched = *fake.message_fetches.lock().unwrap();
        fake.messages
            .lock()
            .unwrap()
            .insert(0, gmail_message("b0", "Newest", "New body"));
        let (_, body) =
            json_body(test::call_service(&app, req!("POST", "/api/mail/import", &session)).await)
                .await;
        assert_eq!(body["imported"], 1);
        assert_eq!(*fake.message_fetches.lock().unwrap(), fetched + 1);
    }

    #[actix_web::test]
    async fn import_reports_revoked_google_access() {
        let pool = test_db().await;
        let fake = Arc::new(FakeGoogle::default());
        let google = start_fake_google(fake.clone()).await;
        let (_, session) = signed_in_user(&pool).await;
        let app = test_app!(pool, google);
        let sub = format!("mailbox-{}", uuid::Uuid::new_v4());
        link_mailbox!(app, fake, session.as_str(), sub.as_str());
        fake.revoked
            .lock()
            .unwrap()
            .push(format!("refresh-for-{sub}"));

        let (status, body) =
            json_body(test::call_service(&app, req!("POST", "/api/mail/import", &session)).await)
                .await;
        assert_eq!(status, 200);
        assert_eq!(body["imported"], 0);
        assert_eq!(
            body["accounts"][0]["error"],
            "Google access was revoked or expired. Reconnect this mailbox."
        );
    }

    #[actix_web::test]
    async fn users_cannot_reach_each_others_mail() {
        // CASA 3.1.4: mailboxes and messages are scoped to their owner; another
        // user's rows are a 404, like missing ones.
        use crate::mail::tests::gmail_message;
        let pool = test_db().await;
        let fake = Arc::new(FakeGoogle::default());
        let google = start_fake_google(fake.clone()).await;
        let (_, alice) = signed_in_user(&pool).await;
        let (_, bob) = signed_in_user(&pool).await;
        let app = test_app!(pool, google);
        let sub = format!("mailbox-{}", uuid::Uuid::new_v4());
        link_mailbox!(app, fake, alice.as_str(), sub.as_str());
        *fake.messages.lock().unwrap() = vec![gmail_message("c1", "alice's mail", "private")];
        test::call_service(&app, req!("POST", "/api/mail/import", &alice)).await;

        let (_, accounts) =
            json_body(test::call_service(&app, req!("GET", "/api/mail/accounts", &alice)).await)
                .await;
        let account_id = accounts[0]["id"].as_str().unwrap().to_owned();
        let (_, messages) =
            json_body(test::call_service(&app, req!("GET", "/api/mail/messages", &alice)).await)
                .await;
        let message_id = messages[0]["id"].as_str().unwrap().to_owned();

        for uri in ["/api/mail/accounts", "/api/mail/messages"] {
            let (status, body) =
                json_body(test::call_service(&app, req!("GET", uri, &bob)).await).await;
            assert_eq!((status, body), (200, json!([])), "{uri}");
        }
        let (status, body) = json_body(
            test::call_service(
                &app,
                req!("GET", &format!("/api/mail/messages/{message_id}"), &bob),
            )
            .await,
        )
        .await;
        assert_eq!((status, body), (404, json!({ "error": "not found" })));
        let resp = test::call_service(
            &app,
            req!("DELETE", &format!("/api/mail/accounts/{account_id}"), &bob),
        )
        .await;
        assert_eq!(resp.status(), 404);
        // Bob's import touches only his own (zero) mailboxes.
        let (_, body) =
            json_body(test::call_service(&app, req!("POST", "/api/mail/import", &bob)).await).await;
        assert_eq!(body, json!({ "imported": 0, "accounts": [] }));

        let (_, still) =
            json_body(test::call_service(&app, req!("GET", "/api/mail/messages", &alice)).await)
                .await;
        assert_eq!(still.as_array().unwrap().len(), 1);
    }

    #[actix_web::test]
    async fn disconnecting_deletes_the_mail_and_revokes_google_access() {
        use crate::mail::tests::gmail_message;
        let pool = test_db().await;
        let fake = Arc::new(FakeGoogle::default());
        let google = start_fake_google(fake.clone()).await;
        let (user_id, session) = signed_in_user(&pool).await;
        let app = test_app!(pool, google);
        let sub = format!("mailbox-{}", uuid::Uuid::new_v4());
        link_mailbox!(app, fake, session.as_str(), sub.as_str());
        *fake.messages.lock().unwrap() = vec![gmail_message("d1", "bye", "gone soon")];
        test::call_service(&app, req!("POST", "/api/mail/import", &session)).await;
        let (_, accounts) =
            json_body(test::call_service(&app, req!("GET", "/api/mail/accounts", &session)).await)
                .await;
        assert_eq!(accounts[0]["message_count"], 1);
        let uri = format!("/api/mail/accounts/{}", accounts[0]["id"].as_str().unwrap());

        let resp = test::call_service(&app, req!("DELETE", &uri, &session)).await;
        assert_eq!(resp.status(), 204);
        assert_eq!(
            *fake.revoked.lock().unwrap(),
            vec![format!("refresh-for-{sub}")]
        );
        let left: i64 =
            sqlx::query_scalar("SELECT count(*) FROM mail_messages WHERE owner_id = $1")
                .bind(user_id)
                .fetch_one(pool.get_ref())
                .await
                .unwrap();
        assert_eq!(left, 0);
        assert_eq!(
            test::call_service(&app, req!("DELETE", &uri, &session))
                .await
                .status(),
            404
        );
    }

    // ---- email + password accounts --------------------------------------

    const PASSPHRASE: &str = "correct horse battery staple";

    fn post_json(uri: &str, body: Value) -> test::TestRequest {
        test::TestRequest::post()
            .uri(uri)
            .insert_header(("content-type", "application/json"))
            .set_payload(body.to_string())
    }

    fn registration(email: &str) -> Value {
        json!({
            "first_name": "Ada",
            "last_name": "Lovelace",
            "email": email,
            "password": PASSPHRASE,
        })
    }

    fn fresh_email() -> String {
        format!("Ada.{}@Example.com", uuid::Uuid::new_v4())
    }

    fn me_with(cookie: &str) -> test::TestRequest {
        test::TestRequest::get()
            .uri("/api/auth/me")
            .insert_header(("cookie", cookie))
    }

    #[actix_web::test]
    async fn registration_signs_in_and_stores_only_an_argon2id_hash() {
        // CASA 1.1.3: the password itself is never stored.
        let pool = test_db().await;
        let app = test_app!(pool);
        let email = fresh_email();

        let resp = test::call_service(
            &app,
            post_json("/api/auth/register", registration(&email)).to_request(),
        )
        .await;
        assert_eq!(resp.status(), 201);
        let set = set_cookies(&resp);
        assert!(
            set.iter()
                .any(|c| c.starts_with(&format!("{SESSION_COOKIE}="))
                    && c.contains("HttpOnly")
                    && c.contains("Secure")
                    && c.contains("SameSite=Strict")),
            "{set:?}"
        );
        let cookie = cookie_pair(&resp, SESSION_COOKIE).unwrap();
        let (status, body) = json_body(resp).await;
        assert_eq!(
            (status, body["email"].as_str()),
            (201, Some(email.to_lowercase().as_str()))
        );
        assert!(!body.to_string().contains(PASSPHRASE));
        assert_eq!(
            (body["first_name"].as_str(), body["last_name"].as_str()),
            (Some("Ada"), Some("Lovelace"))
        );

        let (_, me) =
            json_body(test::call_service(&app, me_with(&cookie).to_request()).await).await;
        assert_eq!(me["email"], email.to_lowercase());

        let (first, last, stored): (String, String, String) = sqlx::query_as(
            "SELECT first_name, last_name, password_hash FROM users WHERE email = $1",
        )
        .bind(email.to_lowercase())
        .fetch_one(pool.get_ref())
        .await
        .unwrap();
        assert_eq!((first.as_str(), last.as_str()), ("Ada", "Lovelace"));
        assert!(stored.starts_with("$argon2id$"), "{stored}");
        assert!(!stored.contains(PASSPHRASE));
    }

    #[actix_web::test]
    async fn duplicate_registration_is_refused_and_keeps_the_original_password() {
        let pool = test_db().await;
        let app = test_app!(pool);
        let email = fresh_email();
        let first = test::call_service(
            &app,
            post_json("/api/auth/register", registration(&email)).to_request(),
        )
        .await;
        assert_eq!(first.status(), 201);

        let mut again = registration(&email.to_uppercase());
        again["password"] = json!("a different passphrase here");
        let (status, body) = json_body(
            test::call_service(&app, post_json("/api/auth/register", again).to_request()).await,
        )
        .await;
        assert_eq!(status, 409);
        assert_eq!(
            body,
            json!({ "error": "an account with this email already exists" })
        );

        let login = json!({ "email": email, "password": PASSPHRASE });
        let resp = test::call_service(
            &app,
            post_json("/api/auth/password-login", login).to_request(),
        )
        .await;
        assert_eq!(resp.status(), 200);
    }

    #[actix_web::test]
    async fn registration_validates_input() {
        let pool = test_db().await;
        let app = test_app!(pool);
        let email = fresh_email();
        let cases = [
            ("password", json!("too short")),
            ("password", json!(" ".repeat(20))),
            ("email", json!("not-an-email")),
            ("first_name", json!("   ")),
            ("last_name", json!("x".repeat(101))),
        ];
        for (field, value) in cases {
            let mut body = registration(&email);
            body[field] = value;
            let resp =
                test::call_service(&app, post_json("/api/auth/register", body).to_request()).await;
            assert_eq!(resp.status(), 400, "{field}");
        }
        // Mass assignment: no extra fields, such as a chosen id or hash (CASA 3.1.2).
        for extra in ["id", "password_hash", "google_sub", "confirm_password"] {
            let mut body = registration(&email);
            body[extra] = json!("x");
            let resp =
                test::call_service(&app, post_json("/api/auth/register", body).to_request()).await;
            assert_eq!(resp.status(), 400, "{extra}");
        }
        // A cross-site HTML form can't register or sign someone in (CASA 3.1.5).
        let form = test::TestRequest::post()
            .uri("/api/auth/register")
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .set_payload("first_name=a&last_name=b&email=c%40d.com&password=eeeeeeeeeeee")
            .to_request();
        assert!(
            test::call_service(&app, form)
                .await
                .status()
                .is_client_error()
        );
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE email = $1)")
                .bind(email.to_lowercase())
                .fetch_one(pool.get_ref())
                .await
                .unwrap();
        assert!(!exists);
    }

    #[actix_web::test]
    async fn password_login_does_not_reveal_which_emails_exist() {
        let pool = test_db().await;
        let app = test_app!(pool);
        let email = fresh_email();
        let resp = test::call_service(
            &app,
            post_json("/api/auth/register", registration(&email)).to_request(),
        )
        .await;
        let first_session = cookie_pair(&resp, SESSION_COOKIE).unwrap();

        let wrong = json!({ "email": email, "password": "correct horse battery stapler" });
        let unknown = json!({ "email": fresh_email(), "password": PASSPHRASE });
        let (s1, b1) = json_body(
            test::call_service(
                &app,
                post_json("/api/auth/password-login", wrong).to_request(),
            )
            .await,
        )
        .await;
        let (s2, b2) = json_body(
            test::call_service(
                &app,
                post_json("/api/auth/password-login", unknown).to_request(),
            )
            .await,
        )
        .await;
        assert_eq!(
            (s1, &b1),
            (401, &json!({ "error": "invalid email or password" }))
        );
        assert_eq!((s2, &b2), (s1, &b1));

        // The right password, with the email typed differently, starts a new
        // session and revokes the one the browser had (session fixation).
        let right =
            json!({ "email": format!("  {}  ", email.to_uppercase()), "password": PASSPHRASE });
        let resp = test::call_service(
            &app,
            post_json("/api/auth/password-login", right)
                .insert_header(("cookie", first_session.as_str()))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), 200);
        let second_session = cookie_pair(&resp, SESSION_COOKIE).unwrap();
        assert_ne!(first_session, second_session);
        assert_eq!(
            test::call_service(&app, me_with(&second_session).to_request())
                .await
                .status(),
            200
        );
        assert_eq!(
            test::call_service(&app, me_with(&first_session).to_request())
                .await
                .status(),
            401
        );
    }

    #[actix_web::test]
    async fn password_and_google_accounts_stay_separate() {
        let pool = test_db().await;
        let app = test_app!(pool);
        let (google_user, google_cookie) = signed_in_user(&pool).await;
        let google_email: String = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
            .bind(google_user)
            .fetch_one(pool.get_ref())
            .await
            .unwrap();

        // A Google account has no password, so it can't be signed into with one.
        let login = json!({ "email": google_email, "password": PASSPHRASE });
        let resp = test::call_service(
            &app,
            post_json("/api/auth/password-login", login).to_request(),
        )
        .await;
        assert_eq!(resp.status(), 401);

        // Registering the same address makes a different user; the Google
        // user's session stays on the Google account.
        let resp = test::call_service(
            &app,
            post_json("/api/auth/register", registration(&google_email)).to_request(),
        )
        .await;
        assert_eq!(resp.status(), 201);
        let cookie = cookie_pair(&resp, SESSION_COOKIE).unwrap();
        let users: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE email = $1")
            .bind(&google_email)
            .fetch_one(pool.get_ref())
            .await
            .unwrap();
        assert_eq!(users, 2);
        let me = |cookie: &str| {
            test::TestRequest::get()
                .uri("/api/auth/me")
                .insert_header(("cookie", cookie.to_owned()))
                .to_request()
        };
        let (_, google_me) = json_body(test::call_service(&app, me(&google_cookie)).await).await;
        let (_, password_me) = json_body(test::call_service(&app, me(&cookie)).await).await;
        assert_eq!(google_me["has_password"], false);
        assert_eq!(password_me["has_password"], true);
    }

    #[actix_web::test]
    async fn password_login_is_throttled_per_account() {
        // CASA 1.1.1: guessing one account from many IPs is still slowed.
        use crate::auth::password::AccountLimiter;
        use crate::security::{AuthLimiter, Limiter};
        use crate::test_support::nz;
        let pool = test_db().await;
        let app = test::init_service(
            App::new()
                .app_data(pool.clone())
                .app_data(web::Data::new(test_config().session))
                .app_data(web::Data::new(Limiter::new(nz(1000), nz(1000), false)))
                .app_data(web::Data::new(AuthLimiter(Limiter::per_minute(
                    nz(1000),
                    nz(1000),
                    false,
                ))))
                .app_data(web::Data::new(AccountLimiter::with(
                    std::time::Duration::from_secs(3600),
                    2,
                )))
                .configure(configure),
        )
        .await;
        let target = fresh_email();
        let attempt = |email: &str| {
            post_json(
                "/api/auth/password-login",
                json!({ "email": email, "password": PASSPHRASE }),
            )
            .to_request()
        };
        assert_eq!(
            test::call_service(&app, attempt(&target)).await.status(),
            401
        );
        assert_eq!(
            test::call_service(&app, attempt(&target.to_uppercase()))
                .await
                .status(),
            401
        );
        assert_eq!(
            test::call_service(&app, attempt(&target)).await.status(),
            429
        );
        assert_eq!(
            test::call_service(&app, attempt(&fresh_email()))
                .await
                .status(),
            401
        );
    }

    #[actix_web::test]
    async fn password_login_fails_closed_without_account_limiter() {
        let app = test::init_service(
            App::new()
                .app_data(unreachable_pool())
                .app_data(web::Data::new(test_config().session))
                .service(web::resource("/login").route(web::post().to(auth::password::login))),
        )
        .await;
        let req = post_json(
            "/login",
            json!({ "email": "a@example.com", "password": PASSPHRASE }),
        )
        .to_request();
        assert_eq!(test::call_service(&app, req).await.status(), 500);
    }

    fn change_password(cookie: &str, current: &str, new: &str) -> actix_web::test::TestRequest {
        post_json(
            "/api/auth/password",
            json!({ "current_password": current, "new_password": new }),
        )
        .insert_header(("cookie", cookie))
    }

    const NEW_PASSPHRASE: &str = "a brand new passphrase";

    #[actix_web::test]
    async fn password_change_signs_out_every_other_session() {
        // CASA 2.2.2: after a password change, sessions elsewhere are dead.
        let pool = test_db().await;
        let app = test_app!(pool);
        let email = fresh_email();
        let resp = test::call_service(
            &app,
            post_json("/api/auth/register", registration(&email)).to_request(),
        )
        .await;
        let here = cookie_pair(&resp, SESSION_COOKIE).unwrap();
        let login = json!({ "email": email, "password": PASSPHRASE });
        let resp = test::call_service(
            &app,
            post_json("/api/auth/password-login", login).to_request(),
        )
        .await;
        let elsewhere = cookie_pair(&resp, SESSION_COOKIE).unwrap();
        assert_eq!(
            test::call_service(&app, me_with(&elsewhere).to_request())
                .await
                .status(),
            200
        );

        let resp = test::call_service(
            &app,
            change_password(&here, PASSPHRASE, NEW_PASSPHRASE).to_request(),
        )
        .await;
        assert_eq!(resp.status(), 200);
        let fresh = cookie_pair(&resp, SESSION_COOKIE).unwrap();
        let (_, body) = json_body(resp).await;
        assert_eq!(body["has_password"], json!(true));

        // The other browser and the old token here are both signed out; only
        // the session issued by the change is live.
        assert_eq!(
            test::call_service(&app, me_with(&elsewhere).to_request())
                .await
                .status(),
            401
        );
        assert_eq!(
            test::call_service(&app, me_with(&here).to_request())
                .await
                .status(),
            401
        );
        assert_eq!(
            test::call_service(&app, me_with(&fresh).to_request())
                .await
                .status(),
            200
        );
        let live: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM sessions s JOIN users u ON u.id = s.user_id WHERE u.email = $1",
        )
        .bind(email.to_lowercase())
        .fetch_one(pool.get_ref())
        .await
        .unwrap();
        assert_eq!(live, 1);

        // Old password is gone, new one works.
        let old = json!({ "email": email, "password": PASSPHRASE });
        assert_eq!(
            test::call_service(
                &app,
                post_json("/api/auth/password-login", old).to_request()
            )
            .await
            .status(),
            401
        );
        let new = json!({ "email": email, "password": NEW_PASSPHRASE });
        assert_eq!(
            test::call_service(
                &app,
                post_json("/api/auth/password-login", new).to_request()
            )
            .await
            .status(),
            200
        );
    }

    #[actix_web::test]
    async fn password_change_needs_a_session_and_the_current_password() {
        let pool = test_db().await;
        let app = test_app!(pool);
        let email = fresh_email();
        let resp = test::call_service(
            &app,
            post_json("/api/auth/register", registration(&email)).to_request(),
        )
        .await;
        let cookie = cookie_pair(&resp, SESSION_COOKIE).unwrap();

        // No session: refused before anything else.
        let anon = post_json(
            "/api/auth/password",
            json!({ "current_password": PASSPHRASE, "new_password": NEW_PASSPHRASE }),
        );
        assert_eq!(
            test::call_service(&app, anon.to_request()).await.status(),
            401
        );

        // Wrong current password, a weak or unchanged new one: 400, and the
        // session survives (a 401 would make the app sign the user out).
        for (current, new) in [
            ("wrong passphrase entirely", NEW_PASSPHRASE),
            (PASSPHRASE, "short"),
            (PASSPHRASE, PASSPHRASE),
        ] {
            let resp =
                test::call_service(&app, change_password(&cookie, current, new).to_request()).await;
            assert_eq!(resp.status(), 400, "{current} -> {new}");
        }
        assert_eq!(
            test::call_service(&app, me_with(&cookie).to_request())
                .await
                .status(),
            200
        );
        let still = json!({ "email": email, "password": PASSPHRASE });
        assert_eq!(
            test::call_service(
                &app,
                post_json("/api/auth/password-login", still).to_request()
            )
            .await
            .status(),
            200
        );

        // Extra fields are refused (no setting someone else's password).
        let mut body = json!({ "current_password": PASSPHRASE, "new_password": NEW_PASSPHRASE });
        body["user_id"] = json!(uuid::Uuid::new_v4().to_string());
        let resp = test::call_service(
            &app,
            post_json("/api/auth/password", body)
                .insert_header(("cookie", cookie.as_str()))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), 400);

        // Google accounts have no password to change.
        let (_, google_cookie) = signed_in_user(&pool).await;
        let resp = test::call_service(
            &app,
            change_password(&google_cookie, PASSPHRASE, NEW_PASSPHRASE).to_request(),
        )
        .await;
        assert_eq!(resp.status(), 400);
    }
}
