//! Random secrets for sessions, OAuth `state`, `nonce` and the PKCE verifier.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::AppError;

/// Length of every token we issue: 32 random bytes as unpadded base64url.
pub const TOKEN_LEN: usize = 43;

/// 256 bits from the OS CSPRNG (CASA 4.1.3). Fails closed: if the OS can't
/// supply randomness, the request fails instead of using weaker bytes.
pub fn random_token() -> Result<String, AppError> {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("OS random source failed: {e}")))?;
    Ok(URL_SAFE_NO_PAD.encode(buf))
}

/// True if `s` could be a token we issued (right length, base64url alphabet).
/// Used to reject junk before it reaches the database.
pub fn looks_like_token(s: &str) -> bool {
    s.len() == TOKEN_LEN
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// SHA-256 of a token. Only this digest is stored, so a database leak does not
/// hand out live sessions.
pub fn digest(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

/// PKCE S256 challenge for a verifier (RFC 7636 §4.2).
pub fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// Timing-safe equality for secrets such as `state` and `nonce`.
pub fn ct_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_256_bit_and_unique() {
        let a = random_token().unwrap();
        let b = random_token().unwrap();
        assert_eq!(a.len(), TOKEN_LEN);
        assert!(looks_like_token(&a));
        assert_ne!(a, b);
        assert_eq!(URL_SAFE_NO_PAD.decode(&a).unwrap().len(), 32);
    }

    #[test]
    fn token_shape_check_rejects_junk() {
        assert!(!looks_like_token(""));
        assert!(!looks_like_token(&"a".repeat(TOKEN_LEN + 1)));
        assert!(!looks_like_token(&format!(
            "{}=",
            "a".repeat(TOKEN_LEN - 1)
        )));
        assert!(!looks_like_token(&format!(
            "{};",
            "a".repeat(TOKEN_LEN - 1)
        )));
    }

    #[test]
    fn pkce_challenge_matches_rfc7636_example() {
        // RFC 7636 Appendix B.
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn ct_eq_compares_exactly() {
        assert!(ct_eq("abc", "abc"));
        assert!(!ct_eq("abc", "abd"));
        assert!(!ct_eq("abc", "abcd"));
    }
}
