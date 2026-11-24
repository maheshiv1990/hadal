//! Google sign-in and session enforcement.
//!
//! Flow (CASA 3.2.1, 3.2.2):
//! 1. `GET /api/auth/login` stores a random `state`, `nonce` and PKCE verifier
//!    server-side under a random login id, sets that id in a short-lived
//!    `__Host-` cookie, and redirects to Google.
//! 2. `GET /api/auth/callback` consumes the login row (single use), compares
//!    `state` in constant time, redeems the code with the verifier, checks the
//!    ID token, then issues a fresh session (no fixation).
//! 3. `POST /api/auth/logout` deletes the session row and clears the cookie.
//!
//! Linking a Gmail mailbox (`GET /api/auth/gmail/connect`, signed in) runs the
//! same flow with the read-only Gmail scope and offline access. The pending
//! row records which user started it, so the shared callback stores the
//! mailbox for that user instead of signing anyone in. The session cookie is
//! SameSite=Strict and isn't sent on Google's redirect back, so the user can't
//! come from the cookie there; it comes only from the single-use row bound to
//! this browser's login cookie.
//!
//! Email + password accounts (`password.rs`) use `POST /api/auth/register` and
//! `POST /api/auth/password-login`, and get the same kind of session.
//!
//! `require_session` guards every authenticated route and fails closed.

pub mod cookies;
pub mod google;
pub mod password;
pub mod session;
pub mod token;

use std::future::{Ready, ready};

use actix_web::{
    Error, FromRequest, HttpMessage, HttpRequest, HttpResponse, HttpResponseBuilder, ResponseError,
    body::{EitherBody, MessageBody},
    dev::{Payload, ServiceRequest, ServiceResponse},
    http::{StatusCode, header},
    middleware::{Next, from_fn},
    web,
};
use serde::Deserialize;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use crate::config::SessionConfig;
use crate::crypto::DataCipher;
use crate::error::AppError;
use crate::{mail, security};
use cookies::{LOGIN_COOKIE, SESSION_COOKIE, SameSite, SetCookie};
use google::{AuthorizeUrl, GoogleClient, Grant, Purpose};
pub use session::AuthUser;
use token::{ct_eq, digest, pkce_challenge, random_token};

/// How long a user has to finish signing in at Google.
const LOGIN_TTL_SECS: u32 = 10 * 60;
/// Authorization codes are short; anything longer is junk.
const MAX_CODE_LEN: usize = 2048;

/// Why a sign-in attempt was refused. Logged server-side only; the browser
/// just sees "sign-in failed" (CASA 6.2.1).
#[derive(Debug)]
pub enum LoginRejected {
    MissingLoginCookie,
    UnknownOrExpiredLogin,
    ProviderDenied,
    StateMismatch,
    IssuerMismatch,
    MissingCode,
    ProviderUnreachable(String),
    ProviderStatus(u16),
    MalformedProviderResponse,
    InvalidClaim(&'static str),
    /// Linking: the user unticked Gmail access on Google's consent screen.
    MissingGmailScope,
    /// Linking: Google issued no refresh token, so mail can't be imported.
    MissingRefreshToken,
    /// Linking: the user already has the most mailboxes allowed.
    TooManyMailboxes,
}

impl std::fmt::Display for LoginRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoginRejected::MissingLoginCookie => f.write_str("no sign-in in progress"),
            LoginRejected::UnknownOrExpiredLogin => f.write_str("sign-in unknown, used or expired"),
            LoginRejected::ProviderDenied => f.write_str("user or Google cancelled sign-in"),
            LoginRejected::StateMismatch => f.write_str("state mismatch"),
            LoginRejected::IssuerMismatch => f.write_str("issuer mismatch"),
            LoginRejected::MissingCode => f.write_str("missing or oversized code"),
            LoginRejected::ProviderUnreachable(e) => write!(f, "Google unreachable: {e}"),
            LoginRejected::ProviderStatus(s) => write!(f, "Google returned HTTP {s}"),
            LoginRejected::MalformedProviderResponse => f.write_str("malformed Google response"),
            LoginRejected::InvalidClaim(c) => write!(f, "ID token claim `{c}` is invalid"),
            LoginRejected::MissingGmailScope => f.write_str("Gmail access was not granted"),
            LoginRejected::MissingRefreshToken => f.write_str("Google issued no offline grant"),
            LoginRejected::TooManyMailboxes => f.write_str("mailbox limit reached"),
        }
    }
}

enum LoginError {
    Rejected(LoginRejected),
    Internal(AppError),
}

impl From<AppError> for LoginError {
    fn from(e: AppError) -> Self {
        LoginError::Internal(e)
    }
}

impl From<sqlx::Error> for LoginError {
    fn from(e: sqlx::Error) -> Self {
        LoginError::Internal(e.into())
    }
}

impl From<LoginRejected> for LoginError {
    fn from(r: LoginRejected) -> Self {
        LoginError::Rejected(r)
    }
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            // Unauthenticated entry points get a much tighter per-IP limit
            // than the rest of the API (CASA 1.1.1).
            .service(
                web::resource("/login")
                    .wrap(from_fn(security::auth_rate_limit))
                    .route(web::get().to(login)),
            )
            .service(
                web::resource("/callback")
                    .wrap(from_fn(security::auth_rate_limit))
                    .route(web::get().to(callback)),
            )
            .service(
                web::resource("/register")
                    .wrap(from_fn(security::auth_rate_limit))
                    .route(web::post().to(password::register)),
            )
            .service(
                web::resource("/password-login")
                    .wrap(from_fn(security::auth_rate_limit))
                    .route(web::post().to(password::login)),
            )
            .service(
                web::resource("/password")
                    .wrap(from_fn(require_session))
                    .wrap(from_fn(security::auth_rate_limit))
                    .route(web::post().to(password::change)),
            )
            .service(
                web::resource("/gmail/connect")
                    .wrap(from_fn(require_session))
                    .wrap(from_fn(security::auth_rate_limit))
                    .route(web::get().to(connect_gmail)),
            )
            .service(
                web::resource("/me")
                    .wrap(from_fn(require_session))
                    .route(web::get().to(me)),
            )
            .service(web::resource("/logout").route(web::post().to(logout))),
    );
}

/// The only redirects the API issues. Each target is fixed: Google's
/// authorization endpoint (via `AuthorizeUrl`, which only `GoogleClient` can
/// build) or a constant same-origin path. Nothing comes from the request.
enum Redirect {
    Google(AuthorizeUrl),
    Home,
    LoginFailed,
    MailLinked,
    MailLinkFailed,
}

fn redirect(to: Redirect) -> HttpResponseBuilder {
    let target = match &to {
        Redirect::Google(url) => url.as_str(),
        Redirect::Home => "/",
        Redirect::LoginFailed => "/?login=failed",
        Redirect::MailLinked => "/?mail=linked",
        Redirect::MailLinkFailed => "/?mail=failed",
    };
    let mut resp = HttpResponse::build(StatusCode::SEE_OTHER);
    // casa-allow: open-redirect -- target is a closed enum: Google's fixed endpoint or a constant same-origin path
    resp.insert_header((header::LOCATION, target));
    resp
}

async fn login(
    pool: web::Data<PgPool>,
    google: web::Data<GoogleClient>,
) -> Result<HttpResponse, AppError> {
    start_authorization(&pool, &google, None).await
}

/// Starts linking a Gmail mailbox to the signed-in user.
async fn connect_gmail(
    user: AuthUser,
    pool: web::Data<PgPool>,
    google: web::Data<GoogleClient>,
) -> Result<HttpResponse, AppError> {
    start_authorization(&pool, &google, Some(user.user_id)).await
}

/// Stores a pending authorization and redirects to Google. `link_user` is the
/// signed-in user linking a mailbox, or `None` for sign-in.
async fn start_authorization(
    pool: &PgPool,
    google: &GoogleClient,
    link_user: Option<Uuid>,
) -> Result<HttpResponse, AppError> {
    let login_id = random_token()?;
    let state = random_token()?;
    let verifier = random_token()?;
    let nonce = random_token()?;
    sqlx::query(
        "INSERT INTO oauth_logins (id_hash, state, code_verifier, nonce, link_user_id, expires_at)
         VALUES ($1, $2, $3, $4, $5, now() + make_interval(secs => $6))",
    )
    .bind(digest(&login_id))
    .bind(&state)
    .bind(&verifier)
    .bind(&nonce)
    .bind(link_user)
    .bind(f64::from(LOGIN_TTL_SECS))
    .execute(pool)
    .await?;

    let purpose = match link_user {
        Some(_) => Purpose::LinkGmail,
        None => Purpose::SignIn,
    };
    let url = google.authorize_url(purpose, &state, &pkce_challenge(&verifier), &nonce);
    let mut resp = redirect(Redirect::Google(url));
    SetCookie::new(LOGIN_COOKIE, &login_id, LOGIN_TTL_SECS, SameSite::Lax).apply(&mut resp);
    Ok(resp.finish())
}

/// Query string Google sends back to the redirect URI.
#[derive(Deserialize)] // casa-allow: permissive-deserialize -- Google adds params (scope, authuser, prompt, hd); never persisted
pub struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    /// RFC 9207 issuer identifier (mix-up attack defence).
    iss: Option<String>,
}

async fn callback(
    req: HttpRequest,
    pool: web::Data<PgPool>,
    google: web::Data<GoogleClient>,
    sessions: web::Data<SessionConfig>,
    cipher: web::Data<DataCipher>,
    params: web::Query<CallbackParams>,
) -> Result<HttpResponse, AppError> {
    let pending = take_pending(&req, &pool).await;
    // Which flow this was is only known once the row is found; before that a
    // failure is reported as a failed sign-in.
    let linking = matches!(&pending, Ok(p) if p.link_user_id.is_some());
    let outcome = match pending {
        Ok(pending) => match pending.link_user_id {
            Some(user_id) => complete_link(
                &pool,
                &google,
                &cipher,
                user_id,
                &pending,
                params.into_inner(),
            )
            .await
            .map(|()| None),
            None => complete_login(
                &req,
                &pool,
                &google,
                &sessions,
                &pending,
                params.into_inner(),
            )
            .await
            .map(Some),
        },
        Err(e) => Err(e),
    };
    let mut resp = match outcome {
        // Signed in: fresh session.
        Ok(Some(session_token)) => {
            let mut resp = redirect(Redirect::Home);
            session_cookie(&session_token, &sessions).apply(&mut resp);
            resp
        }
        // Mailbox linked: the existing session is left as it is.
        Ok(None) => redirect(Redirect::MailLinked),
        Err(LoginError::Rejected(reason)) => {
            tracing::warn!(%reason, linking, "Google sign-in or mailbox link rejected");
            redirect(if linking {
                Redirect::MailLinkFailed
            } else {
                Redirect::LoginFailed
            })
        }
        Err(LoginError::Internal(e)) => return Err(e),
    };
    SetCookie::clear(LOGIN_COOKIE, SameSite::Lax).apply(&mut resp);
    Ok(resp.finish())
}

/// A started authorization, consumed by the callback.
struct Pending {
    state: String,
    code_verifier: String,
    nonce: String,
    link_user_id: Option<Uuid>,
}

/// Finds and deletes the authorization this browser started. `DELETE ...
/// RETURNING` makes it single-use, even under a race.
async fn take_pending(req: &HttpRequest, pool: &PgPool) -> Result<Pending, LoginError> {
    let login_id =
        cookies::read(req.headers(), LOGIN_COOKIE).ok_or(LoginRejected::MissingLoginCookie)?;
    let row: Option<(String, String, String, Option<Uuid>)> = sqlx::query_as(
        "DELETE FROM oauth_logins WHERE id_hash = $1 AND expires_at > now()
         RETURNING state, code_verifier, nonce, link_user_id",
    )
    .bind(digest(&login_id))
    .fetch_optional(pool)
    .await?;
    let (state, code_verifier, nonce, link_user_id) =
        row.ok_or(LoginRejected::UnknownOrExpiredLogin)?;
    Ok(Pending {
        state,
        code_verifier,
        nonce,
        link_user_id,
    })
}

/// Checks Google's response against the pending authorization and redeems
/// the code. Shared by sign-in and linking.
async fn redeem(
    google: &GoogleClient,
    pending: &Pending,
    params: CallbackParams,
) -> Result<Grant, LoginError> {
    if params.error.is_some() {
        return Err(LoginRejected::ProviderDenied.into());
    }
    let state = params.state.ok_or(LoginRejected::StateMismatch)?;
    if !ct_eq(&state, &pending.state) {
        return Err(LoginRejected::StateMismatch.into());
    }
    if params.iss.is_some_and(|iss| iss != google::ISSUER) {
        return Err(LoginRejected::IssuerMismatch.into());
    }
    let code = params
        .code
        .filter(|c| !c.is_empty() && c.len() <= MAX_CODE_LEN)
        .ok_or(LoginRejected::MissingCode)?;
    Ok(google
        .exchange_code(&code, &pending.code_verifier, &pending.nonce)
        .await?)
}

async fn complete_login(
    req: &HttpRequest,
    pool: &PgPool,
    google: &GoogleClient,
    sessions: &SessionConfig,
    pending: &Pending,
    params: CallbackParams,
) -> Result<String, LoginError> {
    // Sign-in never keeps Google's tokens.
    let identity = redeem(google, pending, params).await?.identity;

    let user_id: Uuid = sqlx::query_scalar(
        "INSERT INTO users (id, google_sub, email, first_name, last_name)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (google_sub) DO UPDATE SET
             email = EXCLUDED.email,
             -- Google is the source of truth, but a name it stops sending is kept.
             first_name = COALESCE(EXCLUDED.first_name, users.first_name),
             last_name = COALESCE(EXCLUDED.last_name, users.last_name),
             last_login_at = now()
         RETURNING id",
    )
    .bind(Uuid::new_v4())
    .bind(&identity.sub)
    .bind(&identity.email)
    .bind(&identity.first_name)
    .bind(&identity.last_name)
    .fetch_one(pool)
    .await?;

    Ok(start_session(req, pool, sessions, user_id).await?)
}

/// Stores the mailbox Google just authorized for `user_id`, with its refresh
/// token encrypted. Relinking the same Google account replaces the token.
async fn complete_link(
    pool: &PgPool,
    google: &GoogleClient,
    cipher: &DataCipher,
    user_id: Uuid,
    pending: &Pending,
    params: CallbackParams,
) -> Result<(), LoginError> {
    let grant = redeem(google, pending, params).await?;
    if !grant.has_scope(google::GMAIL_READONLY) {
        return Err(LoginRejected::MissingGmailScope.into());
    }
    let refresh = grant
        .refresh_token
        .as_ref()
        .ok_or(LoginRejected::MissingRefreshToken)?;
    match mail::store_account(pool, cipher, user_id, &grant.identity, refresh).await? {
        mail::Stored::Linked => Ok(()),
        mail::Stored::LimitReached => Err(LoginRejected::TooManyMailboxes.into()),
    }
}

/// Issues a new session after a successful sign-in of any kind. Any session
/// the browser already had is revoked first (session fixation).
async fn start_session(
    req: &HttpRequest,
    pool: &PgPool,
    sessions: &SessionConfig,
    user_id: Uuid,
) -> Result<String, AppError> {
    if let Some(old) = cookies::read(req.headers(), SESSION_COOKIE) {
        session::revoke(pool, &old).await?;
    }
    session::create(pool, user_id, sessions.absolute_secs).await
}

fn session_cookie(token: &str, sessions: &SessionConfig) -> SetCookie {
    SetCookie::new(
        SESSION_COOKIE,
        token,
        sessions.absolute_secs,
        SameSite::Strict,
    )
}

/// What the frontend shows for the signed-in user. Same shape for Google and
/// password accounts; names may be null for Google accounts without them.
async fn profile(pool: &PgPool, user_id: Uuid) -> Result<serde_json::Value, AppError> {
    let (email, first_name, last_name, has_password): (
        String,
        Option<String>,
        Option<String>,
        bool,
    ) = sqlx::query_as(
        "SELECT email, first_name, last_name, password_hash IS NOT NULL
             FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    Ok(json!({
        "email": email,
        "first_name": first_name,
        "last_name": last_name,
        "has_password": has_password,
    }))
}

async fn me(user: AuthUser, pool: web::Data<PgPool>) -> Result<HttpResponse, AppError> {
    Ok(HttpResponse::Ok().json(profile(&pool, user.user_id).await?))
}

/// Logout takes a JSON body so a cross-site form can't trigger it (CASA 3.1.5).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogoutRequest {}

async fn logout(
    req: HttpRequest,
    pool: web::Data<PgPool>,
    _body: web::Json<LogoutRequest>,
) -> Result<HttpResponse, AppError> {
    if let Some(token) = cookies::read(req.headers(), SESSION_COOKIE) {
        session::revoke(pool.get_ref(), &token).await?;
    }
    let mut resp = HttpResponse::NoContent();
    SetCookie::clear(SESSION_COOKIE, SameSite::Strict).apply(&mut resp);
    Ok(resp.finish())
}

fn deny<B>(req: ServiceRequest, err: AppError) -> ServiceResponse<EitherBody<B>> {
    req.into_response(err.error_response())
        .map_into_right_body()
}

/// Middleware for every authenticated route: no valid session, no access
/// (CASA 3.1.1). Fails closed when misconfigured or when the database errors
/// (CASA 3.1.3).
pub async fn require_session(
    req: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<EitherBody<impl MessageBody>>, Error> {
    let (Some(pool), Some(cfg)) = (
        req.app_data::<web::Data<PgPool>>().cloned(),
        req.app_data::<web::Data<SessionConfig>>().cloned(),
    ) else {
        let err = AppError::Internal(anyhow::anyhow!("session middleware not configured"));
        return Ok(deny(req, err));
    };
    let Some(token) = cookies::read(req.headers(), SESSION_COOKIE) else {
        return Ok(deny(req, AppError::Unauthorized));
    };
    match session::resolve(&pool, &token, cfg.idle_secs).await {
        Ok(Some(user)) => {
            req.extensions_mut().insert(user);
        }
        Ok(None) => return Ok(deny(req, AppError::Unauthorized)),
        Err(e) => return Ok(deny(req, e)),
    }
    next.call(req)
        .await
        .map(ServiceResponse::map_into_left_body)
}

/// Handlers take `AuthUser` to get the caller. If `require_session` did not
/// run, extraction fails with 401 instead of running unauthenticated.
impl FromRequest for AuthUser {
    type Error = AppError;
    type Future = Ready<Result<Self, AppError>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        ready(
            req.extensions()
                .get::<AuthUser>()
                .copied()
                .ok_or(AppError::Unauthorized),
        )
    }
}
