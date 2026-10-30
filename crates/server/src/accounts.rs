//! A single admin login for the web page, so the API key is needed only once.
//!
//! - The account is created (or reset) by proving you hold the API key.
//! - Passwords are stored as Argon2id hashes in `<data>/admin-account.json`.
//! - Logins get a random session token in an HttpOnly, SameSite=Strict cookie.
//!   Only a SHA-256 of each token is kept, in `<data>/sessions.json`, so the
//!   file cannot be replayed if it leaks and a restart does not log you out.
//! - Resetting the account signs out every session.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Mutex,
    time::Duration,
};

use argon2::{
    Argon2, PasswordHasher, PasswordVerifier,
    password_hash::{PasswordHash, SaltString},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::auth::{random_hex, write_private};

pub const SESSION_COOKIE: &str = "mello_session";
pub const SESSION_LIFETIME: Duration = Duration::from_secs(30 * 86_400);
const MAX_SESSIONS: usize = 64;
pub const MIN_PASSWORD_LEN: usize = 10;

#[derive(Debug, thiserror::Error)]
pub enum AccountError {
    #[error("username must be 1-64 letters, digits, '.', '-' or '_'")]
    InvalidUsername,
    #[error("password must be at least {MIN_PASSWORD_LEN} characters")]
    WeakPassword,
    #[error("could not save the account: {0}")]
    Io(#[from] std::io::Error),
    #[error("password hashing failed")]
    Hash,
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredAccount {
    username: String,
    password_hash: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredSession {
    username: String,
    expires_at: DateTime<Utc>,
}

pub struct Accounts {
    account_path: PathBuf,
    sessions_path: PathBuf,
    account: Mutex<Option<StoredAccount>>,
    /// SHA-256 of the token (hex) -> session.
    sessions: Mutex<HashMap<String, StoredSession>>,
    /// One password check at a time: with Argon2 this caps guessing at a few
    /// attempts per second, and failures add a delay on top.
    login_gate: tokio::sync::Mutex<()>,
}

fn token_hash(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn valid_username(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

async fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> std::io::Result<Option<T>> {
    match tokio::fs::read(path).await {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| std::io::Error::other(format!("{}: {e}", path.display()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

impl Accounts {
    pub async fn open(data_dir: &Path) -> std::io::Result<Self> {
        let account_path = data_dir.join("admin-account.json");
        let sessions_path = data_dir.join("sessions.json");
        let account = read_json::<StoredAccount>(&account_path).await?;
        let mut sessions = read_json::<HashMap<String, StoredSession>>(&sessions_path)
            .await
            .unwrap_or_default()
            .unwrap_or_default();
        let now = Utc::now();
        sessions.retain(|_, s| s.expires_at > now);
        // Sessions belong to the current account only.
        if let Some(account) = &account {
            sessions.retain(|_, s| s.username == account.username);
        } else {
            sessions.clear();
        }
        Ok(Self {
            account_path,
            sessions_path,
            account: Mutex::new(account),
            sessions: Mutex::new(sessions),
            login_gate: tokio::sync::Mutex::new(()),
        })
    }

    pub fn account_exists(&self) -> bool {
        self.account.lock().is_ok_and(|a| a.is_some())
    }

    /// Creates or replaces the account. The caller must already have checked
    /// the API key. Every existing session is signed out.
    pub async fn set_account(&self, username: &str, password: &str) -> Result<(), AccountError> {
        if !valid_username(username) {
            return Err(AccountError::InvalidUsername);
        }
        if password.chars().count() < MIN_PASSWORD_LEN || password.len() > 1024 {
            return Err(AccountError::WeakPassword);
        }
        let password = password.to_owned();
        let password_hash = tokio::task::spawn_blocking(move || {
            let mut salt = [0u8; 16];
            getrandom::fill(&mut salt).map_err(|_| AccountError::Hash)?;
            let salt = SaltString::encode_b64(&salt).map_err(|_| AccountError::Hash)?;
            Argon2::default()
                .hash_password(password.as_bytes(), &salt)
                .map(|hash| hash.to_string())
                .map_err(|_| AccountError::Hash)
        })
        .await
        .map_err(|_| AccountError::Hash)??;
        let account = StoredAccount {
            username: username.to_owned(),
            password_hash,
        };
        let bytes = serde_json::to_vec_pretty(&account).map_err(std::io::Error::other)?;
        write_private(&self.account_path, &bytes).await?;
        if let Ok(mut current) = self.account.lock() {
            *current = Some(account);
        }
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.clear();
        }
        self.save_sessions().await?;
        tracing::info!(%username, "admin account saved; all sessions signed out");
        Ok(())
    }

    /// Checks a username and password; returns a new session token on success.
    pub async fn login(&self, username: &str, password: &str) -> Option<String> {
        let _gate = self.login_gate.lock().await;
        let account = self.account.lock().ok()?.clone();
        let verified = match account {
            Some(account) if account.username == username => {
                let password = password.to_owned();
                tokio::task::spawn_blocking(move || {
                    PasswordHash::new(&account.password_hash).is_ok_and(|hash| {
                        Argon2::default()
                            .verify_password(password.as_bytes(), &hash)
                            .is_ok()
                    })
                })
                .await
                .unwrap_or(false)
            }
            _ => false,
        };
        if !verified {
            tracing::warn!("failed admin login");
            tokio::time::sleep(Duration::from_secs(1)).await;
            return None;
        }
        self.new_session(username).await
    }

    /// Starts a session for `username` (after login or account creation).
    pub async fn new_session(&self, username: &str) -> Option<String> {
        let token = random_hex(32).ok()?;
        let expires_at = Utc::now() + chrono::Duration::from_std(SESSION_LIFETIME).ok()?;
        if let Ok(mut sessions) = self.sessions.lock() {
            let now = Utc::now();
            sessions.retain(|_, s| s.expires_at > now);
            if sessions.len() >= MAX_SESSIONS
                && let Some(oldest) = sessions
                    .iter()
                    .min_by_key(|(_, s)| s.expires_at)
                    .map(|(k, _)| k.clone())
            {
                sessions.remove(&oldest);
            }
            sessions.insert(
                token_hash(&token),
                StoredSession {
                    username: username.to_owned(),
                    expires_at,
                },
            );
        }
        if let Err(error) = self.save_sessions().await {
            tracing::warn!(%error, "could not save sessions; this login lasts until restart");
        }
        Some(token)
    }

    /// The signed-in username for a session token, if it is valid.
    pub fn session_user(&self, token: &str) -> Option<String> {
        let sessions = self.sessions.lock().ok()?;
        let session = sessions.get(&token_hash(token))?;
        (session.expires_at > Utc::now()).then(|| session.username.clone())
    }

    pub async fn logout(&self, token: &str) {
        let removed = self
            .sessions
            .lock()
            .is_ok_and(|mut sessions| sessions.remove(&token_hash(token)).is_some());
        if removed {
            let _ = self.save_sessions().await;
        }
    }

    async fn save_sessions(&self) -> std::io::Result<()> {
        let bytes = {
            let sessions = self
                .sessions
                .lock()
                .map_err(|_| std::io::Error::other("session lock poisoned"))?;
            serde_json::to_vec(&*sessions).map_err(std::io::Error::other)?
        };
        write_private(&self.sessions_path, &bytes).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn account_login_sessions_and_reset() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let accounts = Accounts::open(dir.path()).await?;
        assert!(!accounts.account_exists());
        assert!(accounts.login("me", "whatever-password").await.is_none());

        assert!(matches!(
            accounts.set_account("me", "short").await,
            Err(AccountError::WeakPassword)
        ));
        assert!(matches!(
            accounts.set_account("bad name", "long-enough-pw").await,
            Err(AccountError::InvalidUsername)
        ));
        accounts.set_account("me", "correct horse battery").await?;
        let stored = std::fs::read_to_string(dir.path().join("admin-account.json"))?;
        assert!(stored.contains("$argon2id$") && !stored.contains("correct horse"));

        assert!(accounts.login("me", "wrong password!").await.is_none());
        assert!(
            accounts
                .login("someone", "correct horse battery")
                .await
                .is_none()
        );
        let token = accounts
            .login("me", "correct horse battery")
            .await
            .ok_or("login failed")?;
        assert_eq!(accounts.session_user(&token).as_deref(), Some("me"));
        assert_eq!(accounts.session_user("not-a-token"), None);

        // Sessions survive a restart, and only their hashes are on disk.
        let sessions = std::fs::read_to_string(dir.path().join("sessions.json"))?;
        assert!(!sessions.contains(&token));
        let reopened = Accounts::open(dir.path()).await?;
        assert_eq!(reopened.session_user(&token).as_deref(), Some("me"));

        // Logout ends the session; a reset signs out everyone.
        let second = reopened
            .login("me", "correct horse battery")
            .await
            .ok_or("login failed")?;
        reopened.logout(&token).await;
        assert_eq!(reopened.session_user(&token), None);
        reopened.set_account("me", "a brand new password").await?;
        assert_eq!(reopened.session_user(&second), None);
        Ok(())
    }
}
