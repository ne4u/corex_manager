//! Shared Valkey (Redis-compatible) async client for the Rust gateway.
//!
//! All keys are isolated under the `mcp:gw:` prefix so the Rust gateway does
//! not collide with the Python gateway's `mcp:` keys during parallel validation.

use redis::aio::MultiplexedConnection;
use redis::AsyncCommands;
use tracing::warn;

/// Key prefix for all Rust-gateway Valkey state.
pub const GW_PREFIX: &str = "mcp:gw:";

/// A Valkey client wrapper. Cloning is cheap (shares a multiplexed connection).
#[derive(Clone)]
pub struct ValkeyClient {
    conn: MultiplexedConnection,
}

/// Results of [`ValkeyClient::session_bundle`].
pub struct SessionBundle {
    pub session_json: Option<String>,
    pub identity_revoked: bool,
    pub jti_revoked: bool,
    /// Post-increment per-tool rate-limit count (when a limit was configured).
    pub rl_count: Option<i64>,
}

impl ValkeyClient {
    /// Connect using env vars: VALKEY_HOST (default "valkey"), VALKEY_PORT
    /// (default 6379), VALKEY_PASSWORD (optional).
    pub async fn connect() -> Result<Self, redis::RedisError> {
        let host = std::env::var("VALKEY_HOST").unwrap_or_else(|_| "valkey".into());
        let port: u16 = std::env::var("VALKEY_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(6379);
        let password = std::env::var("VALKEY_PASSWORD").ok().filter(|p| !p.is_empty());
        let url = match password {
            Some(pw) => format!("redis://:{pw}@{host}:{port}/0"),
            None => format!("redis://{host}:{port}/0"),
        };
        let client = redis::Client::open(url)?;
        let conn = client.get_multiplexed_async_connection().await?;
        Ok(Self { conn })
    }

    /// Build a gateway-scoped key: `mcp:gw:{rest}`.
    pub fn key(rest: &str) -> String {
        format!("{GW_PREFIX}{rest}")
    }

    pub async fn setex(&self, key: &str, ttl_seconds: u64, value: &str) -> Result<(), redis::RedisError> {
        let mut conn = self.conn.clone();
        conn.set_ex::<_, _, ()>(Self::key(key), value, ttl_seconds).await
    }

    pub async fn set(&self, key: &str, value: &str) -> Result<(), redis::RedisError> {
        let mut conn = self.conn.clone();
        conn.set::<_, _, ()>(Self::key(key), value).await
    }

    pub async fn get(&self, key: &str) -> Result<Option<String>, redis::RedisError> {
        let mut conn = self.conn.clone();
        conn.get::<_, Option<String>>(Self::key(key)).await
    }

    pub async fn exists(&self, key: &str) -> Result<bool, redis::RedisError> {
        let mut conn = self.conn.clone();
        let n: i64 = conn.exists(Self::key(key)).await?;
        Ok(n > 0)
    }

    pub async fn expire(&self, key: &str, ttl_seconds: u64) -> Result<(), redis::RedisError> {
        let mut conn = self.conn.clone();
        let _: () = conn.expire(Self::key(key), ttl_seconds as i64).await?;
        Ok(())
    }

    pub async fn del(&self, key: &str) -> Result<(), redis::RedisError> {
        let mut conn = self.conn.clone();
        let _: () = conn.del(Self::key(key)).await?;
        Ok(())
    }

    pub async fn incr(&self, key: &str) -> Result<i64, redis::RedisError> {
        let mut conn = self.conn.clone();
        conn.incr(Self::key(key), 1).await
    }

    pub async fn decr(&self, key: &str) -> Result<i64, redis::RedisError> {
        let mut conn = self.conn.clone();
        conn.decr(Self::key(key), 1).await
    }

    /// INCR a counter and set its TTL only if none exists (`EXPIRE … NX`),
    /// in a single round trip. Returns the post-increment count.
    pub async fn incr_expire_nx(&self, key: &str, ttl_seconds: u64) -> Result<i64, redis::RedisError> {
        let gkey = Self::key(key);
        let mut conn = self.conn.clone();
        let mut pipe = redis::pipe();
        pipe.cmd("INCR").arg(&gkey);
        pipe.cmd("EXPIRE").arg(&gkey).arg(ttl_seconds as i64).arg("NX").ignore();
        let (count,): (i64,) = pipe.query_async(&mut conn).await?;
        Ok(count)
    }

    /// Fixed-window rate-limit check: one `INCR` + `EXPIRE … NX` round trip.
    /// Returns (allowed, remaining).
    ///
    /// This replaces the former ZSET sliding window — a sorted-set member per
    /// request cannot sustain high quotas, and the three round trips were the
    /// dominant per-request cost. The trade-off is standard fixed-window
    /// semantics: up to ~2x `max_count` can pass across a window boundary.
    pub async fn fixed_window(
        &self,
        key: &str,
        max_count: i64,
        window_seconds: u64,
    ) -> Result<(bool, i64), redis::RedisError> {
        let count = self.incr_expire_nx(key, window_seconds).await?;
        if count > max_count {
            return Ok((false, 0));
        }
        Ok((true, max_count - count))
    }

    /// One round trip for the whole per-request Valkey batch:
    /// `GET` + `EXPIRE` the session (when a session id is present),
    /// `EXISTS` the identity revocation key (and the jti key for JWTs), and
    /// optionally `INCR` the per-tool rate-limit counter with a fresh window.
    ///
    /// Ignored commands contribute no entries to the result vector, so result
    /// indices are tracked in command order below.
    pub async fn session_bundle(
        &self,
        session_id: Option<&str>,
        session_ttl_seconds: u64,
        identity_id: i64,
        jti: Option<&str>,
        rl: Option<(&str, u64)>,
    ) -> Result<SessionBundle, redis::RedisError> {
        let mut pipe = redis::pipe();
        let mut next = 0usize;

        let sess_idx = session_id.map(|sid| {
            let k = Self::key(&format!("sess:{sid}"));
            pipe.cmd("GET").arg(&k);
            pipe.cmd("EXPIRE").arg(&k).arg(session_ttl_seconds as i64).ignore();
            let i = next;
            next += 1;
            i
        });

        pipe.cmd("EXISTS").arg(Self::key(&format!("rev:identity:{identity_id}")));
        let rev_idx = next;
        next += 1;

        let jti_idx = jti.map(|j| {
            pipe.cmd("EXISTS").arg(Self::key(&format!("rev:jti:{j}")));
            let i = next;
            next += 1;
            i
        });

        let rl_idx = rl.map(|(key, window)| {
            let k = Self::key(&format!("rl:{key}"));
            pipe.cmd("INCR").arg(&k);
            pipe.cmd("EXPIRE").arg(&k).arg(window as i64).arg("NX").ignore();
            let i = next;
            next += 1;
            i
        });

        let mut conn = self.conn.clone();
        let results: Vec<redis::Value> = pipe.query_async(&mut conn).await?;
        let get_i64 = |i: usize| -> i64 { redis::from_redis_value(&results[i]).unwrap_or(0) };

        Ok(SessionBundle {
            session_json: sess_idx.and_then(|i| redis::from_redis_value(&results[i]).unwrap_or(None)),
            identity_revoked: get_i64(rev_idx) > 0,
            jti_revoked: jti_idx.map(|i| get_i64(i) > 0).unwrap_or(false),
            rl_count: rl_idx.map(|i| get_i64(i)),
        })
    }

    /// Log a best-effort failure (used by callers that degrade gracefully).
    pub fn log_failure(context: &str, e: &redis::RedisError) {
        warn!("Valkey {context} failed: {e}");
    }

    /// Count keys matching a glob pattern (relative to the gateway prefix).
    /// Uses SCAN with a bounded number of iterations to avoid blocking.
    pub async fn scan_count(&self, pattern: &str, max_batches: usize) -> Result<usize, redis::RedisError> {
        let mut conn = self.conn.clone();
        let full_pattern = Self::key(pattern);
        let mut cursor: u64 = 0;
        let mut count = 0usize;
        for _ in 0..max_batches {
            let (next_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&full_pattern)
                .arg("COUNT")
                .arg(200)
                .query_async(&mut conn)
                .await?;
            count += keys.len();
            cursor = next_cursor;
            if cursor == 0 {
                break;
            }
        }
        Ok(count)
    }

    /// Return all keys matching a glob pattern (relative to the gateway prefix),
    /// bounded by `max_batches` SCAN iterations.
    pub async fn scan_keys(&self, pattern: &str, max_batches: usize) -> Result<Vec<String>, redis::RedisError> {
        let mut conn = self.conn.clone();
        let full_pattern = Self::key(pattern);
        let mut cursor: u64 = 0;
        let mut all: Vec<String> = Vec::new();
        for _ in 0..max_batches {
            let (next_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&full_pattern)
                .arg("COUNT")
                .arg(200)
                .query_async(&mut conn)
                .await?;
            all.extend(keys);
            cursor = next_cursor;
            if cursor == 0 {
                break;
            }
        }
        Ok(all)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sessions::SessionStore;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Minimal RESP server: parses command arrays, answers from an in-memory
    /// store, and records every command so tests can assert the pipeline
    /// contents and order.
    struct Fake {
        store: Arc<parking_lot::Mutex<HashMap<String, String>>>,
        log: Arc<parking_lot::Mutex<Vec<Vec<String>>>>,
    }

    async fn spawn_fake() -> (ValkeyClient, Fake) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let fake = Fake {
            store: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            log: Arc::new(parking_lot::Mutex::new(Vec::new())),
        };
        let store = fake.store.clone();
        let log = fake.log.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else { return };
                let store = store.clone();
                let log = log.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 16384];
                    loop {
                        let n = match socket.read(&mut tmp).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        buf.extend_from_slice(&tmp[..n]);
                        while let Some((cmd, used)) = parse_command(&buf) {
                            buf.drain(..used);
                            log.lock().push(cmd.clone());
                            let resp = respond(&cmd, &store);
                            if socket.write_all(&resp).await.is_err() {
                                return;
                            }
                        }
                    }
                });
            }
        });
        let conn = redis::Client::open(format!("redis://127.0.0.1:{port}"))
            .unwrap()
            .get_multiplexed_async_connection()
            .await
            .unwrap();
        (ValkeyClient { conn }, fake)
    }

    /// Parse one RESP array of bulk strings. Returns (args, bytes consumed).
    fn parse_command(buf: &[u8]) -> Option<(Vec<String>, usize)> {
        if buf.first() != Some(&b'*') {
            return None;
        }
        let (n, mut pos) = read_line_int(buf, 1)?;
        let mut args = Vec::with_capacity(n as usize);
        for _ in 0..n {
            if buf.get(pos) != Some(&b'$') {
                return None;
            }
            let (len, after) = read_line_int(buf, pos + 1)?;
            pos = after;
            let end = pos + len as usize + 2;
            if buf.len() < end {
                return None;
            }
            args.push(String::from_utf8_lossy(&buf[pos..pos + len as usize]).to_string());
            pos = end;
        }
        Some((args, pos))
    }

    /// Read `*\r\n`-style integer terminated by CRLF at `pos`. Returns (value, pos after CRLF).
    fn read_line_int(buf: &[u8], pos: usize) -> Option<(i64, usize)> {
        let end = buf[pos..].windows(2).position(|w| w == b"\r\n")? + pos;
        let v = std::str::from_utf8(&buf[pos..end]).ok()?.parse().ok()?;
        Some((v, end + 2))
    }

    fn respond(cmd: &[String], store: &parking_lot::Mutex<HashMap<String, String>>) -> Vec<u8> {
        let name = cmd.first().map(|s| s.to_uppercase()).unwrap_or_default();
        let arg = |i: usize| cmd.get(i).map(|s| s.as_str()).unwrap_or("");
        match name.as_str() {
            "GET" => match store.lock().get(arg(1)) {
                Some(v) => format!("${}\r\n{}\r\n", v.len(), v).into_bytes(),
                None => b"$-1\r\n".to_vec(),
            },
            "SET" | "SETEX" => {
                let (k, v) = if name == "SET" { (arg(1), arg(2)) } else { (arg(1), arg(3)) };
                store.lock().insert(k.to_string(), v.to_string());
                b"+OK\r\n".to_vec()
            }
            "EXISTS" => {
                let n = if store.lock().contains_key(arg(1)) { 1 } else { 0 };
                format!(":{n}\r\n").into_bytes()
            }
            "INCR" | "DECR" => {
                let mut m = store.lock();
                let cur: i64 = m.get(arg(1)).and_then(|s| s.parse().ok()).unwrap_or(0);
                let next = if name == "INCR" { cur + 1 } else { cur - 1 };
                m.insert(arg(1).to_string(), next.to_string());
                format!(":{next}\r\n").into_bytes()
            }
            "EXPIRE" => b":1\r\n".to_vec(),
            "DEL" => {
                let n = if store.lock().remove(arg(1)).is_some() { 1 } else { 0 };
                format!(":{n}\r\n").into_bytes()
            }
            _ => b"+OK\r\n".to_vec(),
        }
    }

    fn seed(fake: &Fake, key: &str, value: &str) {
        fake.store
            .lock()
            .insert(ValkeyClient::key(key), value.to_string());
    }

    #[tokio::test]
    async fn fixed_window_allows_then_denies() {
        let (client, _fake) = spawn_fake().await;
        assert_eq!(client.fixed_window("k", 3, 60).await.unwrap(), (true, 2));
        assert_eq!(client.fixed_window("k", 3, 60).await.unwrap(), (true, 1));
        assert_eq!(client.fixed_window("k", 3, 60).await.unwrap(), (true, 0));
        assert_eq!(client.fixed_window("k", 3, 60).await.unwrap(), (false, 0));
    }

    #[tokio::test]
    async fn fixed_window_sends_expire_nx() {
        let (client, fake) = spawn_fake().await;
        client.fixed_window("k2", 10, 60).await.unwrap();
        let log = fake.log.lock().clone();
        let expire = log
            .iter()
            .find(|c| c.first().map(|s| s.as_str()) == Some("EXPIRE"))
            .expect("EXPIRE must be pipelined");
        assert_eq!(expire.last().map(|s| s.as_str()), Some("NX"), "window TTL must only be set when absent");
    }

    #[tokio::test]
    async fn session_bundle_returns_all_parts() {
        let (client, fake) = spawn_fake().await;
        seed(&fake, "sess:s1", r#"{"identity_id":9,"team_id":2,"created_at":1.0}"#);
        seed(&fake, "rev:identity:9", "1");

        let b = client
            .session_bundle(Some("s1"), 3600, 9, Some("j1"), Some(("9:tool", 60)))
            .await
            .unwrap();
        assert!(b.session_json.unwrap().contains("\"identity_id\":9"));
        assert!(b.identity_revoked);
        assert!(!b.jti_revoked);
        assert_eq!(b.rl_count, Some(1));

        let b2 = client
            .session_bundle(Some("s1"), 3600, 9, Some("j1"), Some(("9:tool", 60)))
            .await
            .unwrap();
        assert_eq!(b2.rl_count, Some(2), "INCR must accumulate across calls");

        // Command order in one pipeline: GET, EXPIRE, EXISTS, EXISTS, INCR, EXPIRE.
        let cmds: Vec<String> = fake
            .log
            .lock()
            .iter()
            .map(|c| c[0].clone())
            .filter(|c| c != "CLIENT")
            .take(6)
            .collect();
        assert_eq!(cmds, vec!["GET", "EXPIRE", "EXISTS", "EXISTS", "INCR", "EXPIRE"]);
    }

    #[tokio::test]
    async fn session_bundle_without_session_only_checks_revocation() {
        let (client, fake) = spawn_fake().await;
        let b = client.session_bundle(None, 3600, 7, None, None).await.unwrap();
        assert!(b.session_json.is_none());
        assert!(!b.identity_revoked);
        let cmds: Vec<String> = fake
            .log
            .lock()
            .iter()
            .map(|c| c[0].clone())
            .filter(|c| c != "CLIENT")
            .collect();
        assert_eq!(cmds, vec!["EXISTS"]);
    }

    #[tokio::test]
    async fn fetch_bundle_parses_session_and_flags() {
        let (client, fake) = spawn_fake().await;
        seed(&fake, "sess:ok", r#"{"identity_id":1,"team_id":2,"created_at":1.0}"#);
        let store = SessionStore::new(Some(client));
        let check = store
            .fetch_bundle(Some("ok"), 1, None, Some(("1:t", 60)))
            .await;
        assert_eq!(check.data.unwrap().identity_id, 1);
        assert!(!check.revoked);
        assert_eq!(check.rl_count, Some(1));
    }

    #[tokio::test]
    async fn fetch_bundle_missing_session_returns_none() {
        let (client, _fake) = spawn_fake().await;
        let store = SessionStore::new(Some(client));
        let check = store.fetch_bundle(Some("nope"), 1, None, None).await;
        assert!(check.data.is_none());
        assert!(!check.revoked);
    }
}
