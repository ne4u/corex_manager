//! HAProxy filter for response body rewrite, injection, and bidirectional mask/unmask.
//!
//! Registers the `lua.resp_transform` filter, declared per-backend:
//!   `filter lua.resp_transform file:/app/data/resp-transform/{name}.json`
//!
//! The filter reads a JSON config file containing an ordered list of rules.
//! It processes both request and response payloads:
//!   - Response: applies replace/inject/mask rules in priority order.
//!   - Request: detokenizes/decrypts tokens from mask rules (bidirectional).
//!
//! Tokenize mode uses the `redis` crate (sync TCP) to talk to Valkey. If Valkey
//! is unreachable, it falls back to AES-256-GCM encrypt mode (fail-to-encrypt)
//! so sensitive data is still masked. A local LRU cache (DashMap with TTL)
//! fronts Valkey for detokenization reads to absorb brief network blips.
//! Encrypt mode uses AES-256-GCM with a key from an environment variable.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use dashmap::DashMap;
use haproxy_api::{Action, Core, FilterMethod, FilterResult, HttpMessage, Txn, UserFilter};
use mlua::prelude::*;
use once_cell::sync::OnceCell;
use parking_lot::{Mutex, RwLock};
use rand::RngCore;
use redis::Commands;
use regex::Regex;
use serde::Deserialize;

/// Whether verbose per-callback tracing is enabled (`RESP_TRANSFORM_DEBUG=1`).
///
/// Mirrors the img_2_webp module: the incremental emission path depends on
/// HAProxy re-invoking `http_payload` as the channel drains, which is
/// impossible to reason about from the outside. This makes that sequence
/// observable without a debug build.
fn trace_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var("RESP_TRANSFORM_DEBUG").is_ok())
}

macro_rules! trace {
    ($($arg:tt)*) => {
        if trace_enabled() {
            eprintln!("resp_transform: TRACE {}", format!($($arg)*));
        }
    };
}

// ---------------------------------------------------------------------------
// Config schema (parsed from the per-backend JSON file)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
struct TransformConfig {
    rules: Vec<TransformRule>,
}

#[derive(Debug, Clone, Deserialize)]
struct TransformRule {
    #[allow(dead_code)]
    id: u64,
    enabled: bool,
    priority: i32,
    transform_type: String, // replace | inject | mask
    #[serde(default)]
    content_types: Vec<String>,
    #[serde(default = "default_max_body_size")]
    max_body_size: usize,
    find_regex: Option<String>,
    replace_string: Option<String>,
    inject_string: Option<String>,
    inject_position: Option<String>, // before | after | replace
    mask_mode: Option<String>,       // regex | detector
    detector: Option<String>,        // email | phone | ssn | credit_card | ip
    token_mode: Option<String>,      // tokenize | encrypt
    token_prefix: Option<String>,
    token_ttl: Option<u64>,
    encrypt_key_env: Option<String>,
    #[serde(default)]
    path_patterns: Vec<String>, // URL path prefixes to match; empty = all paths
}

// ---------------------------------------------------------------------------
// Query detokenize config (global file read by the detokenize_query action)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
struct QueryDetokConfig {
    rules: Vec<QueryDetokRule>,
}

#[derive(Debug, Clone, Deserialize)]
struct QueryDetokRule {
    token_prefix: String,
    token_mode: String, // "tokenize" | "encrypt"
    encrypt_key_env: Option<String>,
}

fn default_max_body_size() -> usize {
    1_048_576
}

// ---------------------------------------------------------------------------
// Built-in PII detector regex patterns
// ---------------------------------------------------------------------------

fn detector_regex(name: &str) -> Option<Regex> {
    let pattern = match name {
        "email" => r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        "phone" => r"\+?\d[\d\s().-]{7,}\d",
        "ssn" => r"\b\d{3}-\d{2}-\d{4}\b",
        "credit_card" => r"\b(?:\d[ -]*?){13,19}\b",
        "ip" => r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        _ => return None,
    };
    Regex::new(pattern).ok()
}

// ---------------------------------------------------------------------------
// Compiled rule (regex pre-compiled for performance)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct CompiledRule {
    rule: TransformRule,
    find_re: Option<Regex>,
    token_re: Option<Regex>, // for detokenize/decrypt on request side
}

impl CompiledRule {
    fn compile(rule: TransformRule) -> Result<Self, String> {
        let find_re = if let Some(ref pat) = rule.find_regex {
            Some(Regex::new(pat).map_err(|e| format!("Invalid regex '{}': {}", pat, e))?)
        } else if rule.transform_type == "mask" && rule.mask_mode.as_deref() == Some("detector") {
            rule.detector
                .as_deref()
                .and_then(detector_regex)
        } else {
            None
        };

        // Token regex for request-side detokenize/decrypt
        let token_re = if rule.transform_type == "mask" {
            if let Some(ref prefix) = rule.token_prefix {
                let escaped = regex::escape(prefix);
                // Token format: prefix + base64-ish chars (A-Za-z0-9+/=) or base62
                let pat = format!(r"{}\S{{8,512}}", escaped);
                Regex::new(&pat).ok()
            } else {
                None
            }
        } else {
            None
        };

        Ok(CompiledRule { rule, find_re, token_re })
    }

    /// Check if this rule's content_types filter matches the given content-type.
    fn content_type_matches(&self, ct: &str) -> bool {
        if self.rule.content_types.is_empty() {
            return true;
        }
        let ct_lower = ct.to_ascii_lowercase();
        self.rule
            .content_types
            .iter()
            .any(|prefix| ct_lower.starts_with(&prefix.to_ascii_lowercase()))
    }

    /// Check if this rule's path_patterns filter matches the given request path.
    /// Empty path_patterns means "match all paths".
    fn path_matches(&self, path: &str) -> bool {
        if self.rule.path_patterns.is_empty() {
            return true;
        }
        self.rule
            .path_patterns
            .iter()
            .any(|prefix| path.starts_with(prefix.as_str()))
    }
}

// ---------------------------------------------------------------------------
// Config file with hot-reload (mtime-based, like the geoip module)
// ---------------------------------------------------------------------------

struct ConfigHolder {
    path: PathBuf,
    rules: Vec<CompiledRule>,
    mtime: Option<SystemTime>,
}

impl ConfigHolder {
    fn load(path: PathBuf) -> Self {
        let mut holder = ConfigHolder { path, rules: Vec::new(), mtime: None };
        holder.reload();
        holder
    }

    fn reload(&mut self) {
        let Ok(meta) = fs::metadata(&self.path) else {
            return;
        };
        let Ok(mtime) = meta.modified() else {
            return;
        };
        if Some(mtime) == self.mtime {
            return;
        }
        let Ok(text) = fs::read_to_string(&self.path) else {
            return;
        };
        match serde_json::from_str::<TransformConfig>(&text) {
            Ok(config) => {
                let mut compiled: Vec<CompiledRule> = Vec::new();
                for rule in config.rules {
                    if !rule.enabled {
                        continue;
                    }
                    match CompiledRule::compile(rule) {
                        Ok(cr) => compiled.push(cr),
                        Err(e) => {
                            eprintln!("resp_transform: skipping rule: {}", e);
                        }
                    }
                }
                compiled.sort_by_key(|r| r.rule.priority);
                self.rules = compiled;
                self.mtime = Some(mtime);
            }
            Err(e) => {
                eprintln!(
                    "resp_transform: failed to parse {}: {}",
                    self.path.display(),
                    e
                );
            }
        }
    }

    fn maybe_reload(&mut self) {
        let Ok(meta) = fs::metadata(&self.path) else {
            return;
        };
        if let Ok(mtime) = meta.modified() {
            if Some(mtime) != self.mtime {
                self.reload();
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Query detokenize config holder (hot-reload, like ConfigHolder)
// ---------------------------------------------------------------------------

struct QueryDetokHolder {
    path: PathBuf,
    rules: Vec<(QueryDetokRule, Regex)>, // (rule, compiled token_re)
    mtime: Option<SystemTime>,
}

impl QueryDetokHolder {
    fn load(path: PathBuf) -> Self {
        let mut holder = QueryDetokHolder { path, rules: Vec::new(), mtime: None };
        holder.reload();
        holder
    }

    fn reload(&mut self) {
        let Ok(meta) = fs::metadata(&self.path) else {
            return;
        };
        let Ok(mtime) = meta.modified() else {
            return;
        };
        if Some(mtime) == self.mtime {
            return;
        }
        let Ok(text) = fs::read_to_string(&self.path) else {
            return;
        };
        match serde_json::from_str::<QueryDetokConfig>(&text) {
            Ok(config) => {
                let mut compiled: Vec<(QueryDetokRule, Regex)> = Vec::new();
                for rule in config.rules {
                    // Token regex: prefix + non-whitespace chars (8-512)
                    let escaped = regex::escape(&rule.token_prefix);
                    let pat = format!(r"{}\S{{8,512}}", escaped);
                    match Regex::new(&pat) {
                        Ok(re) => compiled.push((rule, re)),
                        Err(e) => {
                            eprintln!(
                                "resp_transform: skipping query-detok rule (prefix '{}'): {}",
                                rule.token_prefix, e
                            );
                        }
                    }
                }
                self.rules = compiled;
                self.mtime = Some(mtime);
            }
            Err(e) => {
                eprintln!(
                    "resp_transform: failed to parse query-detok config {}: {}",
                    self.path.display(),
                    e
                );
            }
        }
    }

    fn maybe_reload(&mut self) {
        let Ok(meta) = fs::metadata(&self.path) else {
            return;
        };
        if let Ok(mtime) = meta.modified() {
            if Some(mtime) != self.mtime {
                self.reload();
            }
        }
    }
}

static QUERY_DETOK_CONFIG: OnceCell<RwLock<QueryDetokHolder>> = OnceCell::new();

// ---------------------------------------------------------------------------
// Global state: Valkey client, health, fallback key, token cache
// ---------------------------------------------------------------------------

/// Valkey connection parameters. All fields are Send + Sync.
struct ValkeyParams {
    client: redis::Client,
}

static VALKEY_CLIENT: OnceCell<ValkeyParams> = OnceCell::new();

/// Tracks Valkey health for state-transition logging.
static VALKEY_HEALTHY: AtomicBool = AtomicBool::new(true);

/// Name of the env var holding the fallback AES-256 key (for fail-to-encrypt).
static FALLBACK_KEY_ENV: OnceCell<String> = OnceCell::new();

/// Local LRU-ish cache for detokenization reads (fronts Valkey).
static TOKEN_CACHE: OnceCell<DashMap<String, (String, Instant)>> = OnceCell::new();

const CACHE_MAX_SIZE: usize = 10_000;
const CACHE_TTL: Duration = Duration::from_secs(300); // 5 min

// ---------------------------------------------------------------------------
// Health-check logging (logs only on state transitions)
// ---------------------------------------------------------------------------

fn mark_valkey_down() {
    if VALKEY_HEALTHY.swap(false, Ordering::Relaxed) {
        eprintln!(
            "resp_transform: WARNING - Valkey unreachable, falling back to encrypt mode \
             for tokenize rules. Set the fallback key env var to enable fail-to-encrypt."
        );
    }
}

fn mark_valkey_up() {
    if !VALKEY_HEALTHY.swap(true, Ordering::Relaxed) {
        eprintln!("resp_transform: INFO - Valkey connection restored");
    }
}

// ---------------------------------------------------------------------------
// Valkey connection management (thread-local, using redis crate)
// ---------------------------------------------------------------------------

thread_local! {
    static VALKEY_CONN: std::cell::RefCell<Option<redis::Connection>> = std::cell::RefCell::new(None);
}

/// Get a usable Valkey connection from the thread-local pool, or create one.
fn valkey_connection() -> Option<redis::Connection> {
    VALKEY_CONN.with(|cell| {
        // Try to reuse existing connection
        if let Some(mut conn) = cell.borrow_mut().take() {
            // Check liveness with PING
            match redis::cmd("PING").query::<String>(&mut conn) {
                Ok(ref resp) if resp == "PONG" => {
                    return Some(conn);
                }
                _ => {
                    // PING failed — connection is dead, drop it
                }
            }
        }
        // Create a new connection
        let params = VALKEY_CLIENT.get()?;
        match params.client.get_connection() {
            Ok(conn) => {
                mark_valkey_up();
                Some(conn)
            }
            Err(_) => {
                mark_valkey_down();
                None
            }
        }
    })
}

/// Return a connection to the thread-local pool for reuse.
fn return_connection(conn: redis::Connection) {
    VALKEY_CONN.with(|cell| {
        *cell.borrow_mut() = Some(conn);
    });
}

// ---------------------------------------------------------------------------
// Valkey SET/GET (using redis crate, with health tracking)
// ---------------------------------------------------------------------------

/// Store key→value with TTL. Returns true on success, false on failure.
fn valkey_set(key: &str, value: &str, ttl: u64) -> bool {
    let mut conn = match valkey_connection() {
        Some(c) => c,
        None => return false,
    };
    let result: redis::RedisResult<()> = conn.set_ex(key, value, ttl);
    match result {
        Ok(()) => {
            return_connection(conn);
            mark_valkey_up();
            true
        }
        Err(_) => {
            mark_valkey_down();
            false
        }
    }
}

/// Retrieve a value by key. Returns None if not found or on error.
fn valkey_get(key: &str) -> Option<String> {
    let mut conn = valkey_connection()?;
    let result: redis::RedisResult<Option<String>> = conn.get(key);
    match result {
        Ok(val) => {
            return_connection(conn);
            mark_valkey_up();
            val
        }
        Err(_) => {
            mark_valkey_down();
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Local token cache (DashMap with TTL, fronts Valkey for detokenization)
// ---------------------------------------------------------------------------

fn cache_get(token: &str) -> Option<String> {
    let cache = TOKEN_CACHE.get()?;
    let entry = cache.get(token)?;
    if entry.1 < Instant::now() {
        // Expired — remove and return None
        drop(entry);
        cache.remove(token);
        return None;
    }
    Some(entry.0.clone())
}

fn cache_put(token: String, original: String) {
    if let Some(cache) = TOKEN_CACHE.get() {
        // Simple eviction: if cache is full, clear it entirely.
        // This is a best-effort cache — clearing is fine since we fall back to Valkey.
        if cache.len() >= CACHE_MAX_SIZE {
            cache.clear();
        }
        let expiry = Instant::now() + CACHE_TTL;
        cache.insert(token, (original, expiry));
    }
}

// ---------------------------------------------------------------------------
// Fallback AES key (for fail-to-encrypt when Valkey is down)
// ---------------------------------------------------------------------------

fn get_fallback_key() -> Option<[u8; 32]> {
    let env_var = FALLBACK_KEY_ENV.get()?;
    get_aes_key(env_var)
}

// ---------------------------------------------------------------------------
// Token generation (base62 of 16 random bytes)
// ---------------------------------------------------------------------------

const B62_CHARS: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

fn random_token() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    let mut n: Vec<u8> = bytes.to_vec();
    let mut out = String::new();
    while !n.is_empty() && n.iter().any(|&b| b != 0) {
        let mut rem: u32 = 0;
        let mut new_n = Vec::new();
        for &byte in &n {
            let val = rem * 256 + byte as u32;
            let q = val / 62;
            rem = val % 62;
            if q > 0 || !new_n.is_empty() {
                new_n.push(q as u8);
            }
        }
        out.insert(0, B62_CHARS[rem as usize] as char);
        n = new_n;
    }
    if out.is_empty() {
        out.push('0');
    }
    out
}

// ---------------------------------------------------------------------------
// AES-256-GCM encrypt/decrypt
// ---------------------------------------------------------------------------

fn get_aes_key(env_var: &str) -> Option<[u8; 32]> {
    let key_str = env::var(env_var).ok()?;
    let key_bytes = key_str.as_bytes();
    if key_bytes.len() < 32 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes[..32]);
    Some(key)
}

fn aes_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Option<String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext).ok()?;
    let mut combined = Vec::with_capacity(12 + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);
    Some(B64.encode(&combined))
}

fn aes_decrypt(key: &[u8; 32], encoded: &str) -> Option<Vec<u8>> {
    let combined = B64.decode(encoded).ok()?;
    if combined.len() < 13 {
        return None;
    }
    let nonce = Nonce::from_slice(&combined[..12]);
    let ciphertext = &combined[12..];
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher.decrypt(nonce, ciphertext).ok()
}

// ---------------------------------------------------------------------------
// The filter
// ---------------------------------------------------------------------------

/// Smallest chunk we will attempt to hand to HAProxy. If even this is refused,
/// the channel is full and we wait for the next callback.
const MIN_SEND_CHUNK: usize = 1024;

/// Maximum send() attempts within a single http_payload callback.
const MAX_SEND_ATTEMPTS: u32 = 64;

/// Initial chunk size for send() — conservative for the default tune.bufsize
/// of 16384. Using a larger value causes send() to fail immediately when the
/// channel buffer is smaller than the chunk, wasting attempts.
const INITIAL_CHUNK: usize = 12288;

/// Maximum consecutive callbacks with zero flush progress before giving up.
/// Prevents holding the stream forever if the client stops reading.
const MAX_STALLED_CALLBACKS: u32 = 10_000;

#[derive(Default)]
pub struct RespTransformFilter {
    config_path: Option<PathBuf>,
    config: Option<Arc<RwLock<ConfigHolder>>>,
    // Per-request state
    active_response: bool,
    active_request: bool,
    response_rules: Vec<usize>,
    request_rules: Vec<usize>,
    body_buf: Vec<u8>,
    content_type: String,
    // Transformed output state (img_2_webp pattern)
    converted: bool,
    out: Vec<u8>,
    out_pos: usize,
    chunk: usize,
    /// Consecutive callbacks that made zero progress (liveness guard).
    stalled: u32,
}

impl RespTransformFilter {
    fn load_config(&mut self, config_path: &str) {
        let path = PathBuf::from(config_path);
        self.config_path = Some(path.clone());
        self.config = Some(get_or_load_config(path));
    }

    fn get_rules(&self) -> Vec<CompiledRule> {
        if let Some(ref arc) = self.config {
            let mut holder = arc.write();
            holder.maybe_reload();
            return holder.rules.clone();
        }
        Vec::new()
    }

    fn process_response_headers(&mut self, lua: &Lua, txn: &Txn, msg: &HttpMessage) -> LuaResult<()> {
        let status = txn.f.get::<u16>("status", ())?;
        if status < 200 || status >= 300 {
            self.active_response = false;
            return Ok(());
        }

        // Disk cache guard: when a cache-eligible client request is
        // routed to cache, the response coming back has already been
        // transformed on the origin→cache fetch path. Re-applying the
        // transform here would corrupt the body — double transformation,
        // Content-Length removal, and the send()/set_eom() flushing mechanism
        // can stall on cache's delivery pattern, trapping the body in the
        // filter buffer and producing a 200 OK with an empty body.
        //
        // HAProxy sets txn.is_disk_cache_eligible in the backend section for
        // cache-eligible client requests (!is_varnish_fetch). Varnish fetch
        // requests (is_varnish_fetch) don't set it, so the filter still runs
        // on the origin→Varnish path where transformation is needed.
        let is_disk_cache_eligible: String = txn.get_var("txn.is_disk_cache_eligible").unwrap_or_default();
        if !is_disk_cache_eligible.is_empty() {
            self.active_response = false;
            return Ok(());
        }

        let headers = msg.get_headers()?;
        let ct = headers
            .get_first::<String>("content-type")?
            .unwrap_or_default()
            .to_ascii_lowercase();
        self.content_type = ct.clone();

        // Get the request path for path_patterns matching
        let path = txn.f.get::<String>("path", ()).unwrap_or_default();

        let rules = self.get_rules();
        let matching: Vec<usize> = rules
            .iter()
            .enumerate()
            .filter(|(_, r)| r.content_type_matches(&ct) && r.path_matches(&path))
            .map(|(i, _)| i)
            .collect();

        if matching.is_empty() {
            self.active_response = false;
            return Ok(());
        }

        // Pre-check: if Content-Length is known and exceeds ALL matching rules'
        // max_body_size, skip the filter entirely. Every rule would skip the
        // body anyway, so there's no point buffering it and removing
        // Content-Length (which forces chunked re-emission and can truncate
        // large responses through the flush pipeline).
        let cl = headers.get_first::<String>("content-length")?;
        if let Some(ref cl_str) = cl {
            if let Ok(cl_val) = cl_str.trim().parse::<usize>() {
                let applicable_size = matching
                    .iter()
                    .filter_map(|&i| rules.get(i).map(|r| r.rule.max_body_size))
                    .max()
                    .unwrap_or(0);
                if cl_val > applicable_size {
                    self.active_response = false;
                    return Ok(());
                }
            }
        }

        self.response_rules = matching;
        self.active_response = true;
        self.body_buf.clear();
        self.converted = false;
        self.out.clear();
        self.out_pos = 0;
        self.stalled = 0;
        self.chunk = INITIAL_CHUNK;

        // Remove Content-Length and force body buffering — the transformed
        // body length may differ from the original. Without removing
        // Content-Length, the client may receive a truncated/invalid response.
        // (See https://github.com/haproxy/haproxy/issues/2517)
        msg.del_header("content-length")?;
        msg.set_body_len(None)?;

        // Register for data filtering so http_payload is called with body chunks.
        let _ = Self::register_data_filter(lua, txn.clone(), msg.channel()?);
        Ok(())
    }

    /// Push converted output into the channel using send() (immediately forwarded).
    /// Handles backpressure by trying smaller chunks if the channel is full.
    fn flush(&mut self, msg: &HttpMessage) -> LuaResult<usize> {
        let before = self.out_pos;
        let mut attempts = 0;

        while self.out_pos < self.out.len() && attempts < MAX_SEND_ATTEMPTS {
            attempts += 1;
            let n = self.chunk.min(self.out.len() - self.out_pos);
            let sent = msg.send(&self.out[self.out_pos..self.out_pos + n])?;
            if sent > 0 {
                self.out_pos += sent as usize;
                continue;
            }
            // Refused. Try a smaller chunk.
            if self.chunk > MIN_SEND_CHUNK {
                self.chunk = (self.chunk / 2).max(MIN_SEND_CHUNK);
                continue;
            }
            break;
        }

        if self.out_pos > before {
            self.stalled = 0;
        } else if self.pending() > 0 {
            self.stalled += 1;
            if self.stalled >= MAX_STALLED_CALLBACKS {
                eprintln!(
                    "resp_transform: ERROR - gave up after {} callbacks with no flush progress; \
                     {} of {} bytes were never sent and the response body is TRUNCATED.",
                    self.stalled,
                    self.pending(),
                    self.out.len()
                );
                self.out_pos = self.out.len();
            }
        }
        Ok(self.out_pos - before)
    }

    fn pending(&self) -> usize {
        self.out.len() - self.out_pos
    }

    fn process_request_headers(&mut self, lua: &Lua, txn: &Txn, msg: &HttpMessage) -> LuaResult<()> {
        let rules = self.get_rules();
        let mask_rules: Vec<usize> = rules
            .iter()
            .enumerate()
            .filter(|(_, r)| r.rule.transform_type == "mask")
            .map(|(i, _)| i)
            .collect();

        if mask_rules.is_empty() {
            self.active_request = false;
            return Ok(());
        }

        let headers = msg.get_headers()?;
        let ct = headers
            .get_first::<String>("content-type")?
            .unwrap_or_default()
            .to_ascii_lowercase();
        self.content_type = ct;

        self.request_rules = mask_rules;
        self.active_request = true;
        self.body_buf.clear();
        self.converted = false;
        self.out.clear();
        self.out_pos = 0;
        self.stalled = 0;
        self.chunk = INITIAL_CHUNK;

        let _ = Self::register_data_filter(lua, txn.clone(), msg.channel()?);
        Ok(())
    }

    fn transform_response_body(&mut self) -> Vec<u8> {
        let rules = self.get_rules();
        let mut body = std::mem::take(&mut self.body_buf);

        for &idx in &self.response_rules {
            if idx >= rules.len() {
                continue;
            }
            let rule = &rules[idx];
            if body.len() > rule.rule.max_body_size {
                continue;
            }
            match rule.rule.transform_type.as_str() {
                "replace" => {
                    if let (Some(ref re), Some(ref replacement)) = (&rule.find_re, &rule.rule.replace_string) {
                        let rust_replacement = convert_backrefs(replacement);
                        if let Ok(body_str) = std::str::from_utf8(&body) {
                            let new_str = re.replace_all(body_str, rust_replacement.as_str());
                            body = new_str.as_bytes().to_vec();
                        }
                    }
                }
                "inject" => {
                    if let (Some(ref re), Some(ref inject_str), Some(ref pos)) =
                        (&rule.find_re, &rule.rule.inject_string, &rule.rule.inject_position)
                    {
                        body = inject_at_anchor(re, inject_str, pos, &body);
                    }
                }
                "mask" => {
                    body = apply_mask(rule, &body);
                }
                _ => {}
            }
        }
        body
    }

    fn transform_request_body(&mut self) -> Vec<u8> {
        let rules = self.get_rules();
        let mut body = std::mem::take(&mut self.body_buf);

        for &idx in &self.request_rules {
            if idx >= rules.len() {
                continue;
            }
            let rule = &rules[idx];
            if body.len() > rule.rule.max_body_size {
                continue;
            }
            if let Some(ref token_re) = rule.token_re {
                let token_mode = rule.rule.token_mode.as_deref().unwrap_or("tokenize");
                match token_mode {
                    "tokenize" => {
                        body = detokenize(token_re, &body);
                    }
                    "encrypt" => {
                        if let Some(ref env_var) = rule.rule.encrypt_key_env {
                            if let Some(key) = get_aes_key(env_var) {
                                body = decrypt_tokens(token_re, &body, &key, &rule.rule);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        body
    }
}

// ---------------------------------------------------------------------------
// Transform helpers
// ---------------------------------------------------------------------------

/// Convert $1, $2 style backreferences to Rust regex ${1} syntax.
fn convert_backrefs(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '$' {
            if let Some(&next) = chars.peek() {
                if next.is_ascii_digit() {
                    chars.next();
                    let mut num = String::new();
                    num.push(next);
                    while let Some(&d) = chars.peek() {
                        if d.is_ascii_digit() {
                            num.push(d);
                            chars.next();
                        } else {
                            break;
                        }
                    }
                    result.push_str(&format!("${{{}}}", num));
                    continue;
                }
            }
            result.push('$');
        } else {
            result.push(c);
        }
    }
    result
}

/// Inject a string before/after/replace the first regex match anchor.
fn inject_at_anchor(re: &Regex, inject_str: &str, position: &str, body: &[u8]) -> Vec<u8> {
    let body_str = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => return body.to_vec(),
    };
    match re.find(body_str) {
        Some(m) => {
            let start = m.start();
            let end = m.end();
            let mut result = Vec::with_capacity(body.len() + inject_str.len());
            match position {
                "before" => {
                    result.extend_from_slice(&body[..start]);
                    result.extend_from_slice(inject_str.as_bytes());
                    result.extend_from_slice(&body[start..]);
                }
                "after" => {
                    result.extend_from_slice(&body[..end]);
                    result.extend_from_slice(inject_str.as_bytes());
                    result.extend_from_slice(&body[end..]);
                }
                "replace" => {
                    result.extend_from_slice(&body[..start]);
                    result.extend_from_slice(inject_str.as_bytes());
                    result.extend_from_slice(&body[end..]);
                }
                _ => return body.to_vec(),
            }
            result
        }
        None => body.to_vec(),
    }
}

/// Tokenize: replace each match with a token, store token→original in Valkey.
/// If Valkey is unreachable, fall back to AES-256-GCM encrypt (fail-to-encrypt)
/// so sensitive data is still masked. If no fallback key is available, leave
/// the original in place (degrade gracefully) and log a warning.
fn tokenize_mask(re: &Regex, body: &[u8], prefix: &str, ttl: u64) -> Vec<u8> {
    let body_str = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => return body.to_vec(),
    };

    // Try to get the fallback key once for the entire body.
    // If Valkey is down, we'll use this for every match.
    let fallback_key = get_fallback_key();

    let mut result = String::with_capacity(body.len());
    let mut last_end = 0;
    for m in re.find_iter(body_str) {
        let original = &body_str[m.start()..m.end()];
        let token = format!("{}{}", prefix, random_token());
        let key = format!("resp_transform:token:{}", token);
        if valkey_set(&key, original, ttl) {
            // Valkey SET succeeded — cache it for fast detokenization
            cache_put(token.clone(), original.to_string());
            result.push_str(&body_str[last_end..m.start()]);
            result.push_str(&token);
            last_end = m.end();
        } else if let Some(ref fkey) = fallback_key {
            // Valkey down — fail-to-encrypt: use AES-256-GCM with fallback key.
            // The token uses the same prefix, so the unmask side tries both
            // Valkey GET and AES decrypt. Valkey tokens are random base62 and
            // won't decrypt successfully, so there's no ambiguity.
            if let Some(enc) = aes_encrypt(fkey, original.as_bytes()) {
                let enc_token = format!("{}{}", prefix, enc);
                result.push_str(&body_str[last_end..m.start()]);
                result.push_str(&enc_token);
                last_end = m.end();
            }
            // If encrypt also fails (shouldn't happen if key is valid), leave original.
        } else {
            // No fallback key — log once and leave original unmasked.
            // This is a security concern; the operator should set the fallback key.
            static LOGGED_NO_KEY: AtomicBool = AtomicBool::new(false);
            if !LOGGED_NO_KEY.swap(true, Ordering::Relaxed) {
                eprintln!(
                    "resp_transform: WARNING - Valkey unreachable and no fallback key set. \
                     Sensitive data is passing through UNMASKED. Set the {} env var to enable \
                     fail-to-encrypt fallback.",
                    FALLBACK_KEY_ENV.get().unwrap_or(&"RESP_TRANSFORM_KEY".to_string())
                );
            }
        }
    }
    result.push_str(&body_str[last_end..]);
    result.into_bytes()
}

/// Encrypt: replace each match with prefix+base64(AES-GCM(original)).
fn encrypt_mask(re: &Regex, body: &[u8], prefix: &str, key: &[u8; 32]) -> Vec<u8> {
    let body_str = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => return body.to_vec(),
    };

    let mut result = String::with_capacity(body.len());
    let mut last_end = 0;
    for m in re.find_iter(body_str) {
        let original = &body_str[m.start()..m.end()];
        if let Some(enc) = aes_encrypt(key, original.as_bytes()) {
            let token = format!("{}{}", prefix, enc);
            result.push_str(&body_str[last_end..m.start()]);
            result.push_str(&token);
            last_end = m.end();
        }
    }
    result.push_str(&body_str[last_end..]);
    result.into_bytes()
}

/// Detokenize: find tokens, look up originals in cache → Valkey → decrypt fallback.
///
/// Resolution order for each token:
/// 1. Local LRU cache (fastest, absorbs brief Valkey blips)
/// 2. Valkey GET (authoritative for tokenize-mode tokens)
/// 3. AES-GCM decrypt with fallback key (for fail-to-encrypt tokens created
///    when Valkey was down)
/// 4. If all fail, leave the token as-is (functional failure, not a leak)
fn detokenize(token_re: &Regex, body: &[u8]) -> Vec<u8> {
    let body_str = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => return body.to_vec(),
    };

    let fallback_key = get_fallback_key();

    let mut result = String::with_capacity(body.len());
    let mut last_end = 0;
    for m in token_re.find_iter(body_str) {
        let token = &body_str[m.start()..m.end()];

        // 1. Try local cache
        if let Some(original) = cache_get(token) {
            result.push_str(&body_str[last_end..m.start()]);
            result.push_str(&original);
            last_end = m.end();
            continue;
        }

        // 2. Try Valkey
        let key = format!("resp_transform:token:{}", token);
        if let Some(original) = valkey_get(&key) {
            // Cache for future lookups
            cache_put(token.to_string(), original.clone());
            result.push_str(&body_str[last_end..m.start()]);
            result.push_str(&original);
            last_end = m.end();
            continue;
        }

        // 3. Try AES-GCM decrypt with fallback key (for fail-to-encrypt tokens).
        // Valkey tokens are random base62 — they won't be valid base64 AES-GCM
        // ciphertext, so this only succeeds for tokens created during a Valkey
        // outage. The token includes the prefix, so we need to strip it before
        // decrypting. We try stripping common prefixes.
        if let Some(ref fkey) = fallback_key {
            // The token is prefix + base64(nonce + ciphertext). We need to find
            // where the prefix ends. Since we don't know the exact prefix here,
            // try decrypting the token as-is (works if no prefix) and also try
            // common prefixes. In practice, the token_re already captures the
            // full token including prefix, and aes_decrypt will fail on non-
            // base64 input, so we just try the whole token.
            if let Some(plaintext) = aes_decrypt(fkey, token) {
                if let Ok(pt_str) = std::str::from_utf8(&plaintext) {
                    result.push_str(&body_str[last_end..m.start()]);
                    result.push_str(pt_str);
                    last_end = m.end();
                    continue;
                }
            }
        }

        // 4. All methods failed — leave token as-is
    }
    result.push_str(&body_str[last_end..]);
    result.into_bytes()
}

/// Decrypt tokens: find prefix+base64 tokens, AES-GCM decrypt, replace.
fn decrypt_tokens(token_re: &Regex, body: &[u8], key: &[u8; 32], rule: &TransformRule) -> Vec<u8> {
    let body_str = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => return body.to_vec(),
    };

    let prefix = rule.token_prefix.as_deref().unwrap_or("ENC_");
    let mut result = String::with_capacity(body.len());
    let mut last_end = 0;
    for m in token_re.find_iter(body_str) {
        let token_full = &body_str[m.start()..m.end()];
        if let Some(encoded) = token_full.strip_prefix(prefix) {
            if let Some(plaintext) = aes_decrypt(key, encoded) {
                if let Ok(pt_str) = std::str::from_utf8(&plaintext) {
                    result.push_str(&body_str[last_end..m.start()]);
                    result.push_str(pt_str);
                    last_end = m.end();
                }
            }
        }
    }
    result.push_str(&body_str[last_end..]);
    result.into_bytes()
}

/// Apply mask rules to the response body.
fn apply_mask(rule: &CompiledRule, body: &[u8]) -> Vec<u8> {
    let re = match &rule.find_re {
        Some(r) => r,
        None => return body.to_vec(),
    };
    let token_mode = rule.rule.token_mode.as_deref().unwrap_or("tokenize");
    let prefix = rule.rule.token_prefix.as_deref().unwrap_or("TOK_");

    match token_mode {
        "tokenize" => {
            let ttl = rule.rule.token_ttl.unwrap_or(3600);
            tokenize_mask(re, body, prefix, ttl)
        }
        "encrypt" => {
            let env_var = rule.rule.encrypt_key_env.as_deref().unwrap_or("");
            match get_aes_key(env_var) {
                Some(key) => encrypt_mask(re, body, prefix, &key),
                None => {
                    eprintln!(
                        "resp_transform: encrypt key '{}' not set or too short",
                        env_var
                    );
                    body.to_vec()
                }
            }
        }
        _ => body.to_vec(),
    }
}

// ---------------------------------------------------------------------------
// Query-string detokenization (request-side Lua action)
// ---------------------------------------------------------------------------

/// Resolve a single tokenize-mode token to its original value.
/// Tries: cache → Valkey → AES fallback (for fail-to-encrypt tokens).
/// Returns None if all methods fail.
fn resolve_token_tokenize(token: &str) -> Option<String> {
    // 1. Local cache
    if let Some(original) = cache_get(token) {
        return Some(original);
    }
    // 2. Valkey
    let key = format!("resp_transform:token:{}", token);
    if let Some(original) = valkey_get(&key) {
        cache_put(token.to_string(), original.clone());
        return Some(original);
    }
    // 3. AES fallback (for fail-to-encrypt tokens created when Valkey was down)
    if let Some(ref fkey) = get_fallback_key() {
        if let Some(plaintext) = aes_decrypt(fkey, token) {
            if let Ok(pt_str) = std::str::from_utf8(&plaintext) {
                return Some(pt_str.to_string());
            }
        }
    }
    None
}

/// Resolve a single encrypt-mode token to its original value.
/// Strips the prefix and AES-GCM decrypts with the provided key.
fn resolve_token_encrypt(token: &str, prefix: &str, key: &[u8; 32]) -> Option<String> {
    let encoded = token.strip_prefix(prefix)?;
    let plaintext = aes_decrypt(key, encoded)?;
    std::str::from_utf8(&plaintext).ok().map(|s| s.to_string())
}

/// Replace all tokenize-mode tokens in a string with their original values.
/// Returns (new_string, changed).
fn replace_tokens_tokenize(token_re: &Regex, input: &str) -> (String, bool) {
    let mut result = String::with_capacity(input.len());
    let mut last_end = 0;
    let mut changed = false;
    for m in token_re.find_iter(input) {
        let token = &input[m.start()..m.end()];
        if let Some(original) = resolve_token_tokenize(token) {
            result.push_str(&input[last_end..m.start()]);
            result.push_str(&original);
            last_end = m.end();
            changed = true;
        }
    }
    result.push_str(&input[last_end..]);
    (result, changed)
}

/// Replace all encrypt-mode tokens in a string with their original values.
/// Returns (new_string, changed).
fn replace_tokens_encrypt(token_re: &Regex, input: &str, prefix: &str, key: &[u8; 32]) -> (String, bool) {
    let mut result = String::with_capacity(input.len());
    let mut last_end = 0;
    let mut changed = false;
    for m in token_re.find_iter(input) {
        let token = &input[m.start()..m.end()];
        if let Some(original) = resolve_token_encrypt(token, prefix, key) {
            result.push_str(&input[last_end..m.start()]);
            result.push_str(&original);
            last_end = m.end();
            changed = true;
        }
    }
    result.push_str(&input[last_end..]);
    (result, changed)
}

/// HAProxy Lua action: detokenize/decrypt tokens in the URL query string.
///
/// Registered as `lua.detokenize_query` and called via:
///   http-request lua.detokenize_query if { query -m reg "PREFIX_" }
///   http-request set-query %[var(txn.detok_query)] if { var(txn.detok_query) -m found }
///
/// Parses the query string into (key, value) pairs (URL-decoding values),
/// resolves any tokens found in values, re-encodes, and stores the result in
/// `txn.detok_query`. If no tokens were resolved, the var is not set so the
/// `set-query` rule doesn't fire.
fn detokenize_query_action(_lua: &Lua, txn: Txn) -> LuaResult<()> {
    let query = txn.f.get_str("query", ()).unwrap_or_default();
    if query.is_empty() {
        return Ok(());
    }

    // Load/reload the query-detokenize config
    let holder = match QUERY_DETOK_CONFIG.get() {
        Some(h) => h,
        None => return Ok(()),
    };
    {
        let mut h = holder.write();
        h.maybe_reload();
    }
    let rules: Vec<(QueryDetokRule, Regex)> = {
        let h = holder.read();
        h.rules.clone()
    };
    if rules.is_empty() {
        return Ok(());
    }

    // Parse query string into (key, value) pairs with URL decoding
    let pairs: Vec<(String, String)> = form_urlencoded::parse(query.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    let mut changed = false;
    let mut new_pairs: Vec<(String, String)> = Vec::with_capacity(pairs.len());

    for (key, value) in pairs {
        let mut new_val = value.clone();

        for (rule, token_re) in &rules {
            match rule.token_mode.as_str() {
                "tokenize" => {
                    let (replaced, did) = replace_tokens_tokenize(token_re, &new_val);
                    if did {
                        new_val = replaced;
                        changed = true;
                    }
                }
                "encrypt" => {
                    if let Some(ref env_var) = rule.encrypt_key_env {
                        if let Some(key) = get_aes_key(env_var) {
                            let (replaced, did) = replace_tokens_encrypt(
                                token_re,
                                &new_val,
                                &rule.token_prefix,
                                &key,
                            );
                            if did {
                                new_val = replaced;
                                changed = true;
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        new_pairs.push((key, new_val));
    }

    if changed {
        let result = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(new_pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .finish();
        txn.set_var("txn.detok_query", result)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Config registry (shares ConfigHolder across filter instances per path)
// ---------------------------------------------------------------------------

static CONFIG_REGISTRY: OnceCell<Mutex<std::collections::HashMap<PathBuf, Arc<RwLock<ConfigHolder>>>>> =
    OnceCell::new();

fn get_or_load_config(path: PathBuf) -> Arc<RwLock<ConfigHolder>> {
    let map = CONFIG_REGISTRY.get_or_init(|| Mutex::new(std::collections::HashMap::new()));
    let mut guard = map.lock();
    if let Some(existing) = guard.get(&path) {
        return existing.clone();
    }
    let holder = Arc::new(RwLock::new(ConfigHolder::load(path.clone())));
    guard.insert(path, holder.clone());
    holder
}

// ---------------------------------------------------------------------------
// UserFilter implementation
// ---------------------------------------------------------------------------

impl UserFilter for RespTransformFilter {
    const METHODS: u8 = FilterMethod::HTTP_HEADERS | FilterMethod::HTTP_PAYLOAD | FilterMethod::HTTP_END;

    fn new(_: &Lua, args: LuaTable) -> LuaResult<Self> {
        // HAProxy passes filter arguments as a sequence array of "key:value"
        // strings (e.g. {"file:/app/data/resp-transform/foo.json"}), not as
        // named keys. Iterate the sequence and extract the "file:" argument.
        let mut config_path: Option<String> = None;
        for arg in args.clone().sequence_values::<String>() {
            let arg = arg?;
            if let Some(val) = arg.strip_prefix("file:") {
                config_path = Some(val.to_string());
            }
        }
        let config_path = config_path.ok_or_else(|| {
            mlua::Error::external("resp_transform filter requires a 'file:' argument")
        })?;
        let mut filter = RespTransformFilter::default();
        filter.load_config(&config_path);
        Ok(filter)
    }

    fn http_headers(&mut self, lua: &Lua, txn: Txn, msg: HttpMessage) -> LuaResult<FilterResult> {
        if msg.is_resp()? {
            self.process_response_headers(lua, &txn, &msg)?;
        } else {
            self.process_request_headers(lua, &txn, &msg)?;
        }
        Ok(FilterResult::Continue)
    }

    fn http_payload(&mut self, _lua: &Lua, _txn: Txn, msg: HttpMessage) -> LuaResult<Option<usize>> {
        if !self.active_response && !self.active_request {
            return Ok(None);
        }

        // Read EOM state BEFORE buffering (state may change after remove).
        let eom = msg.eom().unwrap_or(false);
        trace!(
            "http_payload ENTER is_resp={:?} body_buf={} out={} out_pos={} eom={} converted={} active_resp={} active_req={}",
            msg.is_resp(), self.body_buf.len(), self.out.len(), self.out_pos, eom, self.converted,
            self.active_response, self.active_request
        );

        // Buffer any available data and remove it from the incoming buffer
        // so it isn't forwarded untransformed.
        if let Some(chunk) = msg.body(None, Some(-1))? {
            let chunk_bytes = chunk.as_bytes();
            let chunk: &[u8] = &chunk_bytes;
            if !chunk.is_empty() {
                self.body_buf.extend_from_slice(chunk);
                msg.remove(None, None)?;
            }
        }

        // Convert exactly once at EOM. Unset EOM to keep the message in DATA
        // state so we can flush output across multiple http_payload calls.
        if eom && !self.converted {
            self.converted = true;
            if self.active_response {
                self.out = self.transform_response_body();
            } else if self.active_request {
                self.out = self.transform_request_body();
            }
            self.out_pos = 0;
            msg.set_eom(false)?;
            trace!("http_payload EOM -> transformed, out={} bytes, unset EOM", self.out.len());
        }

        // Drain converted output via send() (immediately forwarded).
        if self.converted {
            let sent = self.flush(&msg)?;
            trace!(
                "http_payload EXIT sent={} out_pos={}/{} pending={} stalled={}",
                sent, self.out_pos, self.out.len(), self.pending(), self.stalled
            );
            if self.pending() == 0 {
                // All output sent: re-set EOM so the analyzer can complete, and
                // return None to forward whatever residual input the filter
                // still holds. For chunked-input messages that residual is the
                // HTX EOT (end-of-trailers) block, which msg.remove() spares
                // (hlua's _hlua_http_msg_delete only deletes DATA blocks);
                // forwarding it lets the mux emit the chunked terminator.
                msg.set_eom(true)?;
                self.active_response = false;
                self.active_request = false;
                return Ok(None);
            }
            // Output still pending: report 0 forwarded so the residual input
            // stays held. The Lua http_payload return value is the number of
            // *input* bytes to forward (clamped to what remains). Returning
            // `sent` here would release the held EOT block of a chunked-input
            // message — the client-side mux would emit the chunked terminator
            // (0\r\n\r\n) and complete the response after the first flush
            // batch, silently TRUNCATING the remaining output. Content-Length
            // inputs have no EOT (0 bytes remain), which is why this bug only
            // affected chunked upstream responses (e.g. PHP/phpinfo pages).
            return Ok(Some(0));
        }

        // Not yet converted: report 0 forwarded (input was removed, nothing to send).
        Ok(Some(0))
    }

    fn http_end(&mut self, _lua: &Lua, _txn: Txn, _msg: HttpMessage) -> LuaResult<FilterResult> {
        // With the unset_eom strategy, http_end should only be reached when all
        // output has been sent (EOM is re-set, analyzer advances to ENDING).
        // If reached with pending data (defensive), return Wait to re-run the
        // analyzer, which re-calls http_payload where flush() can make progress.
        if self.converted && self.pending() > 0 {
            return Ok(FilterResult::Wait);
        }
        Ok(FilterResult::Continue)
    }
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

pub fn register(lua: &Lua, options: Option<LuaTable>) -> LuaResult<()> {
    let core = Core::new(lua)?;

    if let Some(opts) = options {
        let host: String = opts.get("valkey_host").unwrap_or_else(|_| "127.0.0.1".to_string());
        let port: u16 = opts.get("valkey_port").unwrap_or(6379);
        let db: u8 = opts.get("valkey_db").unwrap_or(0);
        let password: Option<String> = opts.get("valkey_password").ok().flatten();
        let fallback_key_env: String = opts
            .get("fallback_key_env")
            .unwrap_or_else(|_| "RESP_TRANSFORM_KEY".to_string());

        // Build the redis client URL.
        // Format: redis://[:password@]host:port/db
        let url = if let Some(ref pw) = password {
            if !pw.is_empty() {
                format!("redis://:{}@{}:{}/{}", pw, host, port, db)
            } else {
                format!("redis://{}:{}/{}", host, port, db)
            }
        } else {
            format!("redis://{}:{}/{}", host, port, db)
        };

        match redis::Client::open(url.as_str()) {
            Ok(client) => {
                let _ = VALKEY_CLIENT.set(ValkeyParams { client });
            }
            Err(e) => {
                eprintln!("resp_transform: failed to create Valkey client: {}", e);
            }
        }

        let _ = FALLBACK_KEY_ENV.set(fallback_key_env);
    }

    // Initialize the token cache
    let _ = TOKEN_CACHE.set(DashMap::new());

    // Initialize the query-detokenize config holder (global file, hot-reloaded)
    let detok_path = PathBuf::from("/app/data/resp-transform/query_detokenize.json");
    let _ = QUERY_DETOK_CONFIG.set(RwLock::new(QueryDetokHolder::load(detok_path)));

    // Register the query-string detokenize action (request-side)
    core.register_action("detokenize_query", &[Action::HttpReq], 0, detokenize_query_action)?;

    core.register_filter::<RespTransformFilter>("resp_transform")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replace_tokens_tokenize_no_match() {
        let re = Regex::new(r"SSN_\S{8,512}").unwrap();
        let (result, changed) = replace_tokens_tokenize(&re, "hello world");
        assert!(!changed);
        assert_eq!(result, "hello world");
    }

    #[test]
    fn test_replace_tokens_tokenize_match_not_in_cache_or_valkey() {
        // Without Valkey running, resolve_token_tokenize returns None,
        // so the token is left as-is.
        let re = Regex::new(r"SSN_\S{8,512}").unwrap();
        let input = "ssn=SSN_abc123456789";
        let (result, changed) = replace_tokens_tokenize(&re, input);
        // Token not found in cache/valkey → left as-is
        assert!(!changed);
        assert_eq!(result, input);
    }

    #[test]
    fn test_replace_tokens_encrypt_round_trip() {
        // Encrypt a value, then verify replace_tokens_encrypt decrypts it.
        let env_var = "TEST_RESP_TRANSFORM_KEY";
        // Set a 32-byte key
        std::env::set_var(env_var, "0123456789abcdef0123456789abcdef");
        let key = get_aes_key(env_var).unwrap();

        let prefix = "ENC_";
        let original = "123-45-6789";
        let encrypted = aes_encrypt(&key, original.as_bytes()).unwrap();
        let token = format!("{}{}", prefix, encrypted);

        let re = Regex::new(&format!(r"{}\S{{8,512}}", regex::escape(prefix))).unwrap();
        let input = format!("ssn={}", token);
        let (result, changed) = replace_tokens_encrypt(&re, &input, prefix, &key);

        assert!(changed);
        assert_eq!(result, format!("ssn={}", original));
    }

    #[test]
    fn test_replace_tokens_encrypt_no_match() {
        let env_var = "TEST_RESP_TRANSFORM_KEY2";
        std::env::set_var(env_var, "0123456789abcdef0123456789abcdef");
        let key = get_aes_key(env_var).unwrap();

        let re = Regex::new(r"ENC_\S{8,512}").unwrap();
        let (result, changed) = replace_tokens_encrypt(&re, "no tokens here", "ENC_", &key);
        assert!(!changed);
        assert_eq!(result, "no tokens here");
    }

    #[test]
    fn test_replace_tokens_encrypt_multiple_tokens() {
        // In the actual action, form_urlencoded::parse splits the query into
        // individual (key, value) pairs before the regex runs. So we test
        // replace_tokens_encrypt on individual decoded values, not the full
        // query string (where \S would match across & delimiters).
        let env_var = "TEST_RESP_TRANSFORM_KEY3";
        std::env::set_var(env_var, "0123456789abcdef0123456789abcdef");
        let key = get_aes_key(env_var).unwrap();

        let prefix = "ENC_";
        let ssn1 = "123-45-6789";
        let ssn2 = "987-65-4321";
        let enc1 = aes_encrypt(&key, ssn1.as_bytes()).unwrap();
        let enc2 = aes_encrypt(&key, ssn2.as_bytes()).unwrap();
        let token1 = format!("{}{}", prefix, enc1);
        let token2 = format!("{}{}", prefix, enc2);

        let re = Regex::new(&format!(r"{}\S{{8,512}}", regex::escape(prefix))).unwrap();

        // Resolve each value independently (as the action does)
        let (result1, changed1) = replace_tokens_encrypt(&re, &token1, prefix, &key);
        let (result2, changed2) = replace_tokens_encrypt(&re, &token2, prefix, &key);

        assert!(changed1);
        assert_eq!(result1, ssn1);
        assert!(changed2);
        assert_eq!(result2, ssn2);
    }

    #[test]
    fn test_form_urlencoded_round_trip() {
        // Verify that form_urlencoded parse + serialize preserves keys and
        // non-token values, and handles URL-encoded characters.
        let query = "name=John+Doe&ssn=SSN_abc123456789&special=a%2Bb%3Dc";
        let pairs: Vec<(String, String)> = form_urlencoded::parse(query.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();

        assert_eq!(pairs.len(), 3);
        assert_eq!(pairs[0].0, "name");
        assert_eq!(pairs[0].1, "John Doe"); // + decoded to space
        assert_eq!(pairs[1].0, "ssn");
        assert_eq!(pairs[1].1, "SSN_abc123456789");
        assert_eq!(pairs[2].0, "special");
        assert_eq!(pairs[2].1, "a+b=c"); // %2B → +, %3D → =

        // Re-encode
        let result = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .finish();
        // The re-encoded query should contain the same key=value structure
        assert!(result.contains("name=John+Doe"));
        assert!(result.contains("ssn=SSN_abc123456789"));
    }

    #[test]
    fn test_resolve_token_encrypt_wrong_prefix() {
        let env_var = "TEST_RESP_TRANSFORM_KEY4";
        std::env::set_var(env_var, "0123456789abcdef0123456789abcdef");
        let key = get_aes_key(env_var).unwrap();

        // Token with wrong prefix → None
        let result = resolve_token_encrypt("WRONG_abc123", "ENC_", &key);
        assert!(result.is_none());
    }

    #[test]
    fn test_resolve_token_encrypt_invalid_base64() {
        let env_var = "TEST_RESP_TRANSFORM_KEY5";
        std::env::set_var(env_var, "0123456789abcdef0123456789abcdef");
        let key = get_aes_key(env_var).unwrap();

        // Valid prefix but invalid ciphertext → None
        let result = resolve_token_encrypt("ENC_not_valid_base64!!!", "ENC_", &key);
        assert!(result.is_none());
    }
}
