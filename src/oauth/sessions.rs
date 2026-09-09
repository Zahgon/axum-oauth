//! Server-side session storage.
//!
//! The source framework's session layer kept session state in a process-local
//! map and handed the client nothing but a key, so destroying a session removed
//! the record and a cookie replayed afterwards authenticated nobody. The
//! target's bundled cookie store puts the whole state inside the cookie
//! instead, which leaves a sign-out with nothing to revoke: the cookie stays
//! valid for as long as its holder keeps a copy. This store restores the
//! source's arrangement -- state on the server, key in the cookie -- so that
//! sign-out means the same thing on both sides.

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use actix_session::storage::{LoadError, SaveError, SessionKey, SessionStore, UpdateError};
use actix_web::{
    cookie::{
        time::{Duration, OffsetDateTime},
        CookieJar, Key,
    },
    HttpRequest,
};

type SessionState = HashMap<String, String>;

struct Record {
    state: SessionState,
    expires: OffsetDateTime,
}

/// An in-memory [`SessionStore`], shared by every worker of the server.
#[derive(Clone, Default)]
pub struct MemorySessionStore {
    inner: Arc<RwLock<HashMap<String, Record>>>,
}

impl MemorySessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn new_key() -> SessionKey {
        // 64 characters, as the bundled stores generate, from nanoid's URL-safe
        // alphabet.
        nanoid::nanoid!(64)
            .try_into()
            .expect("a 64 character key is a valid session key")
    }

    fn remove(&self, key: &str) {
        if let Ok(mut records) = self.inner.write() {
            records.remove(key);
        }
    }
}

impl SessionStore for MemorySessionStore {
    async fn load(&self, session_key: &SessionKey) -> Result<Option<SessionState>, LoadError> {
        let expired = {
            let records = self
                .inner
                .read()
                .map_err(|_| LoadError::Other(anyhow::anyhow!("session store is poisoned")))?;

            match records.get(session_key.as_ref()) {
                None => return Ok(None),
                Some(record) if record.expires > OffsetDateTime::now_utc() => {
                    return Ok(Some(record.state.clone()))
                }
                Some(_) => true,
            }
        };

        if expired {
            self.remove(session_key.as_ref());
        }

        Ok(None)
    }

    async fn save(
        &self,
        session_state: SessionState,
        ttl: &Duration,
    ) -> Result<SessionKey, SaveError> {
        let session_key = Self::new_key();
        let mut records = self
            .inner
            .write()
            .map_err(|_| SaveError::Other(anyhow::anyhow!("session store is poisoned")))?;
        records.insert(
            session_key.as_ref().to_owned(),
            Record {
                state: session_state,
                expires: OffsetDateTime::now_utc() + *ttl,
            },
        );

        Ok(session_key)
    }

    async fn update(
        &self,
        session_key: SessionKey,
        session_state: SessionState,
        ttl: &Duration,
    ) -> Result<SessionKey, UpdateError> {
        let mut records = self
            .inner
            .write()
            .map_err(|_| UpdateError::Other(anyhow::anyhow!("session store is poisoned")))?;
        records.insert(
            session_key.as_ref().to_owned(),
            Record {
                state: session_state,
                expires: OffsetDateTime::now_utc() + *ttl,
            },
        );

        Ok(session_key)
    }

    async fn update_ttl(&self, session_key: &SessionKey, ttl: &Duration) -> Result<(), anyhow::Error> {
        let mut records = self
            .inner
            .write()
            .map_err(|_| anyhow::anyhow!("session store is poisoned"))?;
        if let Some(record) = records.get_mut(session_key.as_ref()) {
            record.expires = OffsetDateTime::now_utc() + *ttl;
        }

        Ok(())
    }

    async fn delete(&self, session_key: &SessionKey) -> Result<(), anyhow::Error> {
        self.remove(session_key.as_ref());

        Ok(())
    }
}

/// The store together with the key its cookies are sealed with.
///
/// Sign-out has to drop the stored record itself: asking the session middleware
/// to purge would make it answer with a removal cookie of its own, stamped with
/// attributes the source's removal cookie does not carry, and only when a
/// session cookie arrived on the request. The handler keeps emitting the
/// removal unconditionally, exactly as before, and destroys the record through
/// this handle.
#[derive(Clone)]
pub struct Sessions {
    pub store: MemorySessionStore,
    pub key: Key,
    pub cookie_name: String,
}

impl Sessions {
    pub fn new(cookie_name: impl Into<String>, key: Key) -> Self {
        Self {
            store: MemorySessionStore::new(),
            key,
            cookie_name: cookie_name.into(),
        }
    }

    /// Remove the record the request's session cookie points at, if any.
    pub fn destroy(&self, req: &HttpRequest) {
        let Some(cookie) = req.cookie(&self.cookie_name) else {
            return;
        };

        let mut jar = CookieJar::new();
        jar.add_original(cookie);

        if let Some(cookie) = jar.private(&self.key).get(&self.cookie_name) {
            self.store.remove(cookie.value());
        }
    }
}
