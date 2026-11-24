//! The only place `Set-Cookie` headers are built or `Cookie` headers parsed
//! (enforced by lint:cookie-flags). actix-web's cookie support is disabled
//! (it pulls a vulnerable `cookie` release; see docs/casa/exceptions.md), so
//! cookies are formatted here with fixed attributes.

use actix_web::{HttpResponseBuilder, http::header, http::header::HeaderMap};

use super::token::looks_like_token;

/// `__Host-` makes the browser insist on Secure, Path=/ and no Domain, so a
/// sibling subdomain can't plant or overwrite it.
pub const SESSION_COOKIE: &str = "__Host-hadal_session";
/// Binds the OAuth `state`, `nonce` and PKCE verifier to this browser.
pub const LOGIN_COOKIE: &str = "__Host-hadal_login";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SameSite {
    /// Session cookie: never sent on cross-site requests (CSRF, CASA 3.1.5).
    Strict,
    /// Login cookie: must survive the top-level redirect back from Google.
    Lax,
}

impl SameSite {
    fn as_str(self) -> &'static str {
        match self {
            SameSite::Strict => "Strict",
            SameSite::Lax => "Lax",
        }
    }
}

/// A `Set-Cookie` value. Always `Secure; HttpOnly; Path=/` with an explicit
/// SameSite (CASA 2.3.1, 2.3.2). Values are our own base64url tokens, so they
/// need no escaping.
pub struct SetCookie(String);

impl SetCookie {
    pub fn new(name: &'static str, value: &str, max_age_secs: u32, same_site: SameSite) -> Self {
        Self(format!(
            "{name}={value}; Path=/; Max-Age={max_age_secs}; Secure; HttpOnly; SameSite={}",
            same_site.as_str()
        ))
    }

    /// Tells the browser to delete the cookie now.
    pub fn clear(name: &'static str, same_site: SameSite) -> Self {
        Self(format!(
            "{name}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite={}",
            same_site.as_str()
        ))
    }

    pub fn apply(self, resp: &mut HttpResponseBuilder) {
        resp.append_header((header::SET_COOKIE, self.0));
    }

    #[cfg(test)]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Reads one of our token cookies. Returns `None` (treated as signed out) if it
/// is missing, malformed, or sent more than once: a duplicate means someone
/// may be trying to shadow the real cookie, so neither copy is trusted.
pub fn read(headers: &HeaderMap, name: &str) -> Option<String> {
    let mut found: Option<&str> = None;
    for value in headers.get_all(header::COOKIE) {
        let value = value.to_str().ok()?;
        for pair in value.split(';') {
            let Some((k, v)) = pair.trim().split_once('=') else {
                continue;
            };
            if k == name {
                if found.is_some() {
                    return None;
                }
                found = Some(v);
            }
        }
    }
    found.filter(|v| looks_like_token(v)).map(str::to_owned)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use actix_web::http::header::HeaderValue;

    fn headers(cookies: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for c in cookies {
            h.append(header::COOKIE, HeaderValue::from_str(c).unwrap());
        }
        h
    }

    #[test]
    fn session_cookie_has_secure_attributes() {
        // CASA 2.3.1 Secure, 2.3.2 HttpOnly, 3.1.5 SameSite.
        let c = SetCookie::new(SESSION_COOKIE, "tok", 60, SameSite::Strict);
        let s = c.as_str();
        assert!(s.starts_with("__Host-hadal_session=tok;"));
        for attr in [
            "Secure",
            "HttpOnly",
            "SameSite=Strict",
            "Path=/",
            "Max-Age=60",
        ] {
            assert!(s.split("; ").any(|a| a == attr), "missing {attr} in {s}");
        }
        assert!(!s.to_ascii_lowercase().contains("domain="));
    }

    #[test]
    fn cleared_cookie_expires_immediately_and_keeps_flags() {
        let s = SetCookie::clear(LOGIN_COOKIE, SameSite::Lax).0;
        assert!(s.starts_with("__Host-hadal_login=;"));
        for attr in ["Max-Age=0", "Secure", "HttpOnly", "SameSite=Lax"] {
            assert!(s.split("; ").any(|a| a == attr), "missing {attr} in {s}");
        }
    }

    #[test]
    fn reads_well_formed_token() {
        let tok = "a".repeat(43);
        let h = headers(&[&format!("other=1; {SESSION_COOKIE}={tok}")]);
        assert_eq!(read(&h, SESSION_COOKIE), Some(tok));
    }

    #[test]
    fn rejects_duplicate_malformed_and_missing_cookies() {
        let tok = "a".repeat(43);
        let dup = headers(&[&format!("{SESSION_COOKIE}={tok}; {SESSION_COOKIE}={tok}")]);
        assert_eq!(read(&dup, SESSION_COOKIE), None);
        let split_dup = headers(&[
            &format!("{SESSION_COOKIE}={tok}"),
            &format!("{SESSION_COOKIE}={tok}"),
        ]);
        assert_eq!(read(&split_dup, SESSION_COOKIE), None);
        let junk = headers(&[&format!("{SESSION_COOKIE}=' OR 1=1 --")]);
        assert_eq!(read(&junk, SESSION_COOKIE), None);
        assert_eq!(read(&headers(&[]), SESSION_COOKIE), None);
        // A cookie whose name merely contains ours is not ours.
        let prefixed = headers(&[&format!("x{SESSION_COOKIE}={tok}")]);
        assert_eq!(read(&prefixed, SESSION_COOKIE), None);
    }
}
