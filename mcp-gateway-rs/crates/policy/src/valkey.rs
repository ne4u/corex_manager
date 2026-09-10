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

    /// Sliding-window check using a ZSET. Returns (allowed, remaining).
    /// Removes entries older than `window_seconds`, counts remaining, and if
    /// under `max_count` adds the current timestamp.
    pub async fn sliding_window(
        &self,
        key: &str,
        max_count: i64,
        window_seconds: u64,
    ) -> Result<(bool, i64), redis::RedisError> {
        let now = chrono::Utc::now().timestamp_millis() as f64;
        let cutoff = now - (window_seconds as f64) * 1000.0;
        let gkey = Self::key(key);
        let mut conn = self.conn.clone();

        // Remove old entries (raw cmd — method name varies across redis-rs versions).
        let _: () = redis::cmd("ZREMRANGEBYSCORE")
            .arg(&gkey)
            .arg(0)
            .arg(cutoff)
            .query_async(&mut conn)
            .await?;
        let count: i64 = redis::cmd("ZCARD")
            .arg(&gkey)
            .query_async(&mut conn)
            .await?;

        if count >= max_count {
            return Ok((false, 0));
        }

        let member = format!("{now}:{count}");
        let mut pipe = redis::pipe();
        pipe.atomic();
        pipe.cmd("ZADD").arg(&gkey).arg(now).arg(&member).ignore();
        pipe.cmd("EXPIRE").arg(&gkey).arg((window_seconds + 5) as i64).ignore();
        pipe.query_async::<Vec<()>>(&mut conn).await?;

        Ok((true, max_count - count - 1))
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
