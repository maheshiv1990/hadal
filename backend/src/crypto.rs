//! Encryption at rest for Google refresh tokens and imported mail (CASA 4.1.3,
//! 6.7.1).
//!
//! AES-256-GCM from `ring`, with a fresh random 96-bit nonce for every value.
//! Callers pass the row's identity as associated data, so a ciphertext copied
//! into another row, or another user's row, fails to decrypt instead of
//! leaking. Any failure is an error: nothing is ever returned unauthenticated
//! (CASA 4.1.4).

use base64::{Engine, engine::general_purpose::STANDARD};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};

use crate::error::AppError;

/// AES-256 key length in bytes.
pub const KEY_LEN: usize = 32;

pub struct DataCipher(LessSafeKey);

impl DataCipher {
    /// Builds the cipher from the base64 `DATA_ENCRYPTION_KEY`. The key is
    /// never echoed in the error.
    pub fn from_base64(encoded: &str) -> anyhow::Result<Self> {
        let key = STANDARD
            .decode(encoded.trim())
            .ok()
            .filter(|k| k.len() == KEY_LEN)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "DATA_ENCRYPTION_KEY must be {KEY_LEN} random bytes, base64 encoded \
                     (openssl rand -base64 32)"
                )
            })?;
        let key = UnboundKey::new(&AES_256_GCM, &key)
            .map_err(|_| anyhow::anyhow!("DATA_ENCRYPTION_KEY was rejected"))?;
        Ok(Self(LessSafeKey::new(key)))
    }

    /// Returns `nonce || ciphertext || tag`.
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, AppError> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce)
            .map_err(|e| AppError::Internal(anyhow::anyhow!("OS random source failed: {e}")))?;
        let mut sealed = plaintext.to_vec();
        self.0
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad),
                &mut sealed,
            )
            .map_err(|_| AppError::Internal(anyhow::anyhow!("encryption failed")))?;
        let mut out = Vec::with_capacity(NONCE_LEN + sealed.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// Reverses `encrypt`. Fails on a wrong key, wrong associated data, or
    /// any change to the stored bytes.
    pub fn decrypt(&self, stored: &[u8], aad: &[u8]) -> Result<Vec<u8>, AppError> {
        let failed = || AppError::Internal(anyhow::anyhow!("stored ciphertext failed to decrypt"));
        if stored.len() < NONCE_LEN + AES_256_GCM.tag_len() {
            return Err(failed());
        }
        let (nonce, sealed) = stored.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| failed())?;
        let mut buf = sealed.to_vec();
        let plain = self
            .0
            .open_in_place(nonce, Aad::from(aad), &mut buf)
            .map_err(|_| failed())?;
        Ok(plain.to_vec())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod tests {
    use super::*;

    /// A fixed, obviously fake key for tests.
    pub(crate) fn test_key() -> String {
        STANDARD.encode([7u8; KEY_LEN])
    }

    pub(crate) fn test_cipher() -> DataCipher {
        DataCipher::from_base64(&test_key()).unwrap()
    }

    #[test]
    fn round_trips_and_uses_a_fresh_nonce_each_time() {
        let c = test_cipher();
        let a = c.encrypt(b"refresh-me", b"row-1").unwrap();
        let b = c.encrypt(b"refresh-me", b"row-1").unwrap();
        assert_ne!(a, b, "same plaintext must not give the same ciphertext");
        assert!(!a.windows(10).any(|w| w == b"refresh-me"));
        assert_eq!(c.decrypt(&a, b"row-1").unwrap(), b"refresh-me");
    }

    #[test]
    fn tampering_wrong_row_or_wrong_key_fails_closed() {
        // CASA 4.1.4: authenticated encryption, no partial plaintext.
        let c = test_cipher();
        let sealed = c.encrypt(b"secret mail", b"row-1").unwrap();
        assert!(
            c.decrypt(&sealed, b"row-2").is_err(),
            "moved to another row"
        );
        let mut flipped = sealed.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 1;
        assert!(c.decrypt(&flipped, b"row-1").is_err(), "tampered");
        assert!(c.decrypt(&sealed[..10], b"row-1").is_err(), "truncated");
        let other = DataCipher::from_base64(&STANDARD.encode([8u8; KEY_LEN])).unwrap();
        assert!(other.decrypt(&sealed, b"row-1").is_err(), "wrong key");
    }

    #[test]
    fn key_must_be_32_bytes_of_base64() {
        for bad in ["", "not base64!", &STANDARD.encode([1u8; 16])] {
            assert!(DataCipher::from_base64(bad).is_err(), "accepted {bad:?}");
        }
    }
}
