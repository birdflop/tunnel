//! Persistent per-user identity store.
//!
//! Each user has one stable subdomain (the public address) and one secret token
//! (proves ownership). We persist only the SHA-256 of the token, which is the
//! exact key the HMAC challenge uses — so the plaintext token is shown to the
//! user once at issuance and never stored on the relay.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::info;
use uuid::Uuid;

const SUBDOMAIN_LEN: usize = 6;
const SUBDOMAIN_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

/// One issued identity. The token itself is not stored, only its hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Identity {
    subdomain: String,
    /// Hex-encoded SHA-256 of the secret token.
    token_hash: String,
    /// Unix seconds when this identity was created.
    created_at: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct StoreData {
    /// Keyed by subdomain.
    identities: HashMap<String, Identity>,
}

/// Thread-safe, file-backed store of issued identities.
pub struct IdentityStore {
    path: PathBuf,
    data: Mutex<StoreData>,
}

impl IdentityStore {
    /// Load the store from `path`, creating an empty one if it does not exist.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let data = if path.exists() {
            let bytes = std::fs::read(&path)
                .with_context(|| format!("reading identity store at {}", path.display()))?;
            serde_json::from_slice(&bytes)
                .with_context(|| format!("parsing identity store at {}", path.display()))?
        } else {
            StoreData::default()
        };
        Ok(Self {
            path,
            data: Mutex::new(data),
        })
    }

    /// Issue a fresh identity, persisting it. Returns `(subdomain, plaintext token)`.
    pub fn issue(&self) -> Result<(String, String)> {
        let mut data = self.data.lock().unwrap();
        let subdomain = loop {
            let candidate = random_subdomain();
            if !data.identities.contains_key(&candidate) {
                break candidate;
            }
        };
        let token = random_token();
        let token_hash = hex::encode(Sha256::digest(token.as_bytes()));
        data.identities.insert(
            subdomain.clone(),
            Identity {
                subdomain: subdomain.clone(),
                token_hash,
                created_at: now(),
            },
        );
        persist(&self.path, &data)?;
        info!(%subdomain, "issued new identity");
        Ok((subdomain, token))
    }

    /// The HMAC key (raw SHA-256 of the token) for a known subdomain, if any.
    pub fn token_key(&self, subdomain: &str) -> Option<Vec<u8>> {
        let data = self.data.lock().unwrap();
        let identity = data.identities.get(subdomain)?;
        hex::decode(&identity.token_hash).ok()
    }
}

fn persist(path: &Path, data: &StoreData) -> Result<()> {
    let json = serde_json::to_vec_pretty(data)?;
    // Write to a temp file then rename, so a crash mid-write can't corrupt the store.
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A short, human-shareable subdomain. Not a secret.
fn random_subdomain() -> String {
    (0..SUBDOMAIN_LEN)
        .map(|_| {
            let i = fastrand::usize(..SUBDOMAIN_ALPHABET.len());
            SUBDOMAIN_ALPHABET[i] as char
        })
        .collect()
}

/// A 256-bit secret token (two v4 UUIDs of CSPRNG entropy, hex-encoded).
fn random_token() -> String {
    format!(
        "{}{}",
        Uuid::new_v4().as_simple(),
        Uuid::new_v4().as_simple()
    )
}

#[cfg(test)]
mod tests {
    use super::IdentityStore;
    use crate::auth::Authenticator;
    use uuid::Uuid;

    fn temp_path(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("bftunnel-test-{name}.json"));
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn issue_then_authenticate() {
        let path = temp_path("issue");
        let store = IdentityStore::load(&path).unwrap();

        let (subdomain, token) = store.issue().unwrap();
        assert_eq!(subdomain.len(), 6);

        // The relay reconstructs the authenticator from the stored key and can
        // validate an answer the client computes from the plaintext token.
        let key = store.token_key(&subdomain).expect("key present");
        let server = Authenticator::from_key(&key);
        let client = Authenticator::new(&token);
        let challenge = Uuid::new_v4();
        assert!(server.validate(&challenge, &client.answer(&challenge)));

        assert!(store.token_key("nope").is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn persists_across_reload() {
        let path = temp_path("reload");
        let subdomain = {
            let store = IdentityStore::load(&path).unwrap();
            store.issue().unwrap().0
        };
        // A fresh store loaded from the same file still knows the identity.
        let reloaded = IdentityStore::load(&path).unwrap();
        assert!(reloaded.token_key(&subdomain).is_some());
        let _ = std::fs::remove_file(&path);
    }
}
