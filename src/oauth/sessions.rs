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

use std::{collections::HashMap, sync::Arc};

use actix_session::storage::{LoadError, SaveError, SessionKey, SessionStore, UpdateError};
use actix_web::{
    cookie::{
        time::{Duration, OffsetDateTime},
        Cookie, CookieJar, Key,
    },
    http::header::{self, HeaderMap, HeaderValue},
    HttpRequest,
};
use tokio::sync::RwLock;

type SessionState = HashMap<String, String>;

struct Record {
    state: SessionState,
    expires: OffsetDateTime,
}

/// An in-memory [`SessionStore`], shared by every worker of the server.
///
/// The map sits behind the same async lock as the user and client maps, so a
/// contended request waits on the runtime instead of blocking a worker thread.
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

    async fn remove(&self, key: &str) {
        self.inner.write().await.remove(key);
    }
}

impl SessionStore for MemorySessionStore {
    async fn load(&self, session_key: &SessionKey) -> Result<Option<SessionState>, LoadError> {
        let expired = {
            let records = self.inner.read().await;

            match records.get(session_key.as_ref()) {
                None => return Ok(None),
                Some(record) if record.expires > OffsetDateTime::now_utc() => {
                    return Ok(Some(record.state.clone()))
                }
                Some(_) => true,
            }
        };

        if expired {
            self.remove(session_key.as_ref()).await;
        }

        Ok(None)
    }

    async fn save(
        &self,
        session_state: SessionState,
        ttl: &Duration,
    ) -> Result<SessionKey, SaveError> {
        let session_key = Self::new_key();
        self.inner.write().await.insert(
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
        self.inner.write().await.insert(
            session_key.as_ref().to_owned(),
            Record {
                state: session_state,
                expires: OffsetDateTime::now_utc() + *ttl,
            },
        );

        Ok(session_key)
    }

    async fn update_ttl(
        &self,
        session_key: &SessionKey,
        ttl: &Duration,
    ) -> Result<(), anyhow::Error> {
        if let Some(record) = self.inner.write().await.get_mut(session_key.as_ref()) {
            record.expires = OffsetDateTime::now_utc() + *ttl;
        }

        Ok(())
    }

    async fn delete(&self, session_key: &SessionKey) -> Result<(), anyhow::Error> {
        self.remove(session_key.as_ref()).await;

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
    pub async fn destroy(&self, req: &HttpRequest) {
        let Some(cookie) = req.cookie(&self.cookie_name) else {
            return;
        };

        let mut jar = CookieJar::new();
        jar.add_original(cookie);

        if let Some(cookie) = jar.signed(&self.key).get(&self.cookie_name) {
            self.store.remove(cookie.value()).await;
        }
    }

    /// The value the removal cookie carries.
    ///
    /// The source's removal cookie was never empty: it held the signed form of
    /// an empty session id, the same for every sign-out of a running server and
    /// different from any live session's cookie.
    pub fn removal_value(&self) -> String {
        let mut jar = CookieJar::new();
        jar.signed_mut(&self.key)
            .add(Cookie::new(self.cookie_name.clone(), ""));

        jar.get(&self.cookie_name)
            .map(|cookie| cookie.value().to_owned())
            .unwrap_or_default()
    }

    /// Leave only the session cookie the source would have honoured.
    ///
    /// The source read every `Cookie` header in order and took the first session
    /// cookie whose signature checked out, skipping forged or stale-keyed ones
    /// before it. The session middleware here only ever looks at the first
    /// session cookie, so when there is more than one, the others are dropped
    /// before it looks; other cookies pass through untouched. With no valid one
    /// among them the request is left as it is, which the middleware treats as
    /// carrying no session either way.
    pub fn keep_first_valid_session_cookie(&self, headers: &mut HeaderMap) {
        let pairs: Vec<String> = headers
            .get_all(header::COOKIE)
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(';'))
            .map(|pair| pair.trim().to_owned())
            .filter(|pair| !pair.is_empty())
            .collect();
        let prefix = format!("{}=", self.cookie_name);
        let is_session = |pair: &String| pair.starts_with(&prefix);
        if pairs.iter().filter(|pair| is_session(pair)).count() < 2 {
            return;
        }
        let Some(valid) = pairs
            .iter()
            .filter(|pair| is_session(pair))
            .position(|pair| self.verifies(pair))
        else {
            return;
        };

        let mut seen = 0;
        let kept: Vec<&str> = pairs
            .iter()
            .filter(|pair| {
                if !is_session(pair) {
                    return true;
                }
                seen += 1;
                seen == valid + 1
            })
            .map(String::as_str)
            .collect();
        if let Ok(value) = HeaderValue::from_str(&kept.join("; ")) {
            headers.remove(header::COOKIE);
            headers.insert(header::COOKIE, value);
        }
    }

    /// Whether a `name=value` session cookie pair carries a valid signature.
    fn verifies(&self, pair: &str) -> bool {
        let Ok(cookie) = Cookie::parse_encoded(pair.to_owned()) else {
            return false;
        };
        let mut jar = CookieJar::new();
        jar.add_original(cookie);

        jar.signed(&self.key).get(&self.cookie_name).is_some()
    }

    /// Bring the session cookie the middleware wrote into the source's shape.
    ///
    /// The source only ever sent a session cookie for a session the request
    /// did not already carry: once a client held a cookie, changes to its
    /// session were stored without a fresh `Set-Cookie`. A rewrite of the
    /// cookie the request arrived with is therefore dropped. A cookie that is
    /// sent gets the source's one-day `Expires` date instead of a `Max-Age`.
    /// Removal cookies, which already carry `Max-Age=0`, are left alone.
    pub fn shape_cookies(&self, incoming: Option<&str>, headers: &mut HeaderMap) {
        let cookies: Vec<HeaderValue> = headers.get_all(header::SET_COOKIE).cloned().collect();
        if cookies.is_empty() {
            return;
        }

        headers.remove(header::SET_COOKIE);
        for value in cookies {
            let session_cookie = value
                .to_str()
                .ok()
                .and_then(|text| Cookie::parse_encoded(text.to_owned()).ok())
                .filter(|cookie| {
                    cookie.name() == self.cookie_name
                        && cookie.max_age().is_none()
                        && cookie.expires().is_none()
                });
            let Some(mut cookie) = session_cookie else {
                headers.append(header::SET_COOKIE, value);
                continue;
            };
            if incoming == Some(cookie.value()) {
                continue;
            }

            // Keep the name/value pair exactly as the middleware encoded it and
            // take the attributes from the re-dated cookie.
            cookie.set_expires(OffsetDateTime::now_utc() + Duration::days(1));
            let pair = value
                .to_str()
                .unwrap_or_default()
                .split(';')
                .next()
                .unwrap_or_default();
            let rendered = cookie.to_string();
            let attributes = rendered
                .split_once(';')
                .map(|(_, rest)| rest)
                .unwrap_or_default();
            let stamped = HeaderValue::from_str(&format!("{pair};{attributes}")).ok();
            headers.append(header::SET_COOKIE, stamped.unwrap_or(value));
        }
    }
}
