//! HMAC challenge/response used to prove ownership of a token.
//!
//! The relay never needs the plaintext token: it stores only `SHA-256(token)`,
//! which is exactly the HMAC key, and builds an [`Authenticator`] from that with
//! [`Authenticator::from_key`]. The client builds the same authenticator from the
//! plaintext token with [`Authenticator::new`]. The relay sends a random
//! challenge and the client returns its HMAC, so the token never crosses the wire
//! after it is first issued.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Wrapper around a MAC used for authenticating clients that have a token.
pub struct Authenticator(Hmac<Sha256>);

impl Authenticator {
    /// Generate an authenticator from a plaintext secret (e.g. a token).
    pub fn new(secret: &str) -> Self {
        let hashed_secret = Sha256::new().chain_update(secret).finalize();
        Self::from_key(&hashed_secret)
    }

    /// Build an authenticator directly from an already-hashed key (the SHA-256
    /// of the secret). This lets the relay validate clients while only storing
    /// the hash of each token at rest — never the plaintext secret.
    pub fn from_key(hashed_secret: &[u8]) -> Self {
        Self(Hmac::new_from_slice(hashed_secret).expect("HMAC can take key of any size"))
    }

    /// Generate a reply message for a challenge.
    pub fn answer(&self, challenge: &Uuid) -> String {
        let mut hmac = self.0.clone();
        hmac.update(challenge.as_bytes());
        hex::encode(hmac.finalize().into_bytes())
    }

    /// Validate a reply to a challenge.
    ///
    /// ```
    /// use birdflop_tunnel::auth::Authenticator;
    /// use uuid::Uuid;
    ///
    /// let auth = Authenticator::new("secret");
    /// let challenge = Uuid::new_v4();
    ///
    /// assert!(auth.validate(&challenge, &auth.answer(&challenge)));
    /// assert!(!auth.validate(&challenge, "wrong answer"));
    /// ```
    pub fn validate(&self, challenge: &Uuid, tag: &str) -> bool {
        if let Ok(tag) = hex::decode(tag) {
            let mut hmac = self.0.clone();
            hmac.update(challenge.as_bytes());
            hmac.verify_slice(&tag).is_ok()
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Authenticator;
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    #[test]
    fn from_key_matches_new() {
        // The relay builds an authenticator from SHA-256(token); the client from
        // the plaintext token. They must produce matching HMACs.
        let token = "a-very-secret-token";
        let key = Sha256::digest(token.as_bytes());

        let client = Authenticator::new(token);
        let server = Authenticator::from_key(&key);
        let challenge = Uuid::new_v4();

        assert!(server.validate(&challenge, &client.answer(&challenge)));
        assert!(!server.validate(&challenge, &Authenticator::new("wrong").answer(&challenge)));
    }
}
