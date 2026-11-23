//! CASA / OWASP ASVS cross-cutting controls: response hardening headers and
//! per-client rate limiting. See docs/casa/controls.md for the mapping.

use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroU32;
use std::sync::Arc;

use actix_web::{
    Error, HttpResponse,
    body::{EitherBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    middleware::{DefaultHeaders, Next},
    web,
};
use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use serde_json::json;

/// Headers applied to every response (ASVS V14.4). The API never serves HTML,
/// so the CSP denies everything; the frontend host sets its own CSP.
pub fn security_headers() -> DefaultHeaders {
    DefaultHeaders::new()
        .add((
            "Content-Security-Policy",
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        ))
        .add((
            "Strict-Transport-Security",
            "max-age=63072000; includeSubDomains",
        ))
        .add(("X-Content-Type-Options", "nosniff"))
        .add(("X-Frame-Options", "DENY"))
        .add(("Referrer-Policy", "no-referrer"))
        .add((
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=()",
        ))
        .add(("Cross-Origin-Opener-Policy", "same-origin"))
        .add(("Cross-Origin-Resource-Policy", "same-origin"))
        .add(("Cache-Control", "no-store"))
}

#[derive(Clone)]
pub struct Limiter {
    inner: Arc<DefaultKeyedRateLimiter<IpAddr>>,
    /// Only true when the backend is reachable solely through our nginx, which
    /// overwrites `X-Real-IP`. Otherwise clients could spoof the header to
    /// dodge the limit, so the TCP peer address is used.
    trust_proxy_headers: bool,
}

impl Limiter {
    pub fn new(per_second: NonZeroU32, burst: NonZeroU32, trust_proxy_headers: bool) -> Self {
        Self {
            inner: Arc::new(RateLimiter::keyed(
                Quota::per_second(per_second).allow_burst(burst),
            )),
            trust_proxy_headers,
        }
    }

    /// Drop idle per-IP buckets so memory stays bounded.
    pub fn housekeep(&self) {
        self.inner.retain_recent();
        self.inner.shrink_to_fit();
    }

    fn client_ip(&self, req: &ServiceRequest) -> IpAddr {
        if self.trust_proxy_headers
            && let Some(ip) = req
                .headers()
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.trim().parse().ok())
        {
            return ip;
        }
        req.peer_addr()
            .map(|a| a.ip())
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
    }
}

/// Per-client rate limit (CASA 1.1.1 / 3.1.5 anti-automation).
pub async fn rate_limit(
    req: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<EitherBody<impl MessageBody>>, Error> {
    let Some(limiter) = req.app_data::<web::Data<Limiter>>().cloned() else {
        // Fail closed: a missing limiter is a wiring bug, not a reason to skip the control.
        tracing::error!("rate limiter not configured");
        let resp =
            HttpResponse::InternalServerError().json(json!({ "error": "internal server error" }));
        return Ok(req.into_response(resp).map_into_right_body());
    };

    let ip = limiter.client_ip(&req);

    if limiter.inner.check_key(&ip).is_err() {
        tracing::warn!(client_ip = %ip, path = req.path(), "rate limit exceeded");
        let resp = HttpResponse::TooManyRequests()
            .insert_header(("Retry-After", "1"))
            .json(json!({ "error": "too many requests" }));
        return Ok(req.into_response(resp).map_into_right_body());
    }

    next.call(req)
        .await
        .map(ServiceResponse::map_into_left_body)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use actix_web::{App, middleware::from_fn, test};

    fn nz(n: u32) -> NonZeroU32 {
        NonZeroU32::new(n).unwrap()
    }

    #[actix_web::test]
    async fn every_response_carries_security_headers() {
        let app = test::init_service(
            App::new()
                .wrap(security_headers())
                .route("/", web::get().to(HttpResponse::Ok)),
        )
        .await;
        let resp = test::call_service(&app, test::TestRequest::get().uri("/").to_request()).await;
        let h = resp.headers();
        for name in [
            "content-security-policy",
            "strict-transport-security",
            "x-content-type-options",
            "x-frame-options",
            "referrer-policy",
            "permissions-policy",
            "cache-control",
        ] {
            assert!(h.contains_key(name), "missing header {name}");
        }
        assert_eq!(h.get("x-frame-options").unwrap(), "DENY");
        assert_eq!(h.get("x-content-type-options").unwrap(), "nosniff");
    }

    macro_rules! limited_app {
        ($trust_proxy:expr) => {
            test::init_service(
                App::new()
                    .app_data(web::Data::new(Limiter::new(nz(1), nz(2), $trust_proxy)))
                    .wrap(from_fn(rate_limit))
                    .route("/", web::get().to(HttpResponse::Ok)),
            )
        };
    }

    #[actix_web::test]
    async fn spoofed_real_ip_is_ignored_unless_proxy_trusted() {
        let app = limited_app!(false).await;
        let peer = "10.0.0.9:5000".parse().unwrap();
        let mut statuses = Vec::new();
        for i in 0..3 {
            let req = test::TestRequest::get()
                .uri("/")
                .peer_addr(peer)
                .insert_header(("x-real-ip", format!("203.0.113.{i}")))
                .to_request();
            statuses.push(test::call_service(&app, req).await.status().as_u16());
        }
        assert_eq!(
            statuses,
            [200, 200, 429],
            "header rotation must not bypass the limit"
        );
    }

    #[actix_web::test]
    async fn trusted_proxy_keys_on_real_ip() {
        let app = limited_app!(true).await;
        let proxy = "172.18.0.5:40000".parse().unwrap();
        let mut statuses = Vec::new();
        for i in 0..3 {
            let req = test::TestRequest::get()
                .uri("/")
                .peer_addr(proxy)
                .insert_header(("x-real-ip", format!("203.0.113.{i}")))
                .to_request();
            statuses.push(test::call_service(&app, req).await.status().as_u16());
        }
        assert_eq!(
            statuses,
            [200, 200, 200],
            "distinct clients behind nginx get own buckets"
        );
    }

    #[actix_web::test]
    async fn rate_limit_returns_429_after_burst() {
        let app = limited_app!(false).await;
        let peer = "10.0.0.1:5000".parse().unwrap();
        let mut statuses = Vec::new();
        for _ in 0..3 {
            let req = test::TestRequest::get()
                .uri("/")
                .peer_addr(peer)
                .to_request();
            statuses.push(test::call_service(&app, req).await.status().as_u16());
        }
        assert_eq!(statuses, [200, 200, 429]);

        // A different client is unaffected.
        let other = test::TestRequest::get()
            .uri("/")
            .peer_addr("10.0.0.2:5000".parse().unwrap())
            .to_request();
        assert_eq!(test::call_service(&app, other).await.status(), 200);
    }

    #[actix_web::test]
    async fn missing_limiter_fails_closed() {
        let app = test::init_service(
            App::new()
                .wrap(from_fn(rate_limit))
                .route("/", web::get().to(HttpResponse::Ok)),
        )
        .await;
        let resp = test::call_service(&app, test::TestRequest::get().uri("/").to_request()).await;
        assert_eq!(resp.status(), 500);
    }
}
