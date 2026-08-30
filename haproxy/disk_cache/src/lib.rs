//! HAProxy in-process disk cache PoC using mmap shared across workers.
//!
//! Registers three primitives:
//! - `lua.disk_cache_hit` — a sample fetch that looks up the mmap cache and
//!   returns true on hit. Used as the ACL condition for `use-service`.
//! - `lua.serve_cached` — an HTTP service that serves cached responses from
//!   mmap. Only invoked on hits (guarded by the fetch ACL).
//! - `lua.disk_cache_store` — a filter declared last in the backend section
//!   that captures response bodies on misses and stores them in mmap.
//!
//! # Architecture
//!
//! ```text
//! http-request use-service lua.serve_cached if { lua.disk_cache_hit -m found }
//! ```
//!
//! On a cache hit, the service serves directly from mmap — no backend fetch,
//! no network hop. On a miss, the condition fails, the request proceeds to
//! the backend normally, and the `disk_cache_store` filter captures the
//! response (post-conversion, since it's declared after other filters) and
//! stores it in mmap for future hits.
//!
//! # Concurrency model
//!
//! The mmap file is opened once per thread (via `lua-load-per-thread`) and
//! shared across all HAProxy worker processes via `MAP_SHARED`. All mutable
//! state in the mmap (slot states, hash table entries, timestamps) is
//! accessed via atomic operations. A global spinlock in the header guards
//! slot allocation/eviction (the critical section is short: find a free slot
//! + update the hash table entry).

use std::fs::OpenOptions;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};

use haproxy_api::{Core, FilterMethod, FilterResult, HttpMessage, Txn, UserFilter, ServiceMode};
use memmap2::MmapMut;
use mlua::prelude::*;

// --------------------------------------------------------------------------
// Counters
// --------------------------------------------------------------------------

static CACHE_HITS: AtomicU64 = AtomicU64::new(0);
static CACHE_MISSES: AtomicU64 = AtomicU64::new(0);
static CACHE_STORES: AtomicU64 = AtomicU64::new(0);
static CACHE_EVICTIONS: AtomicU64 = AtomicU64::new(0);
static CACHE_ERRORS: AtomicU64 = AtomicU64::new(0);

fn trace_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var("DISK_CACHE_POC_DEBUG").is_ok())
}

macro_rules! trace {
    ($($arg:tt)*) => {
        if trace_enabled() {
            let msg = format!("disk_cache: TRACE {}\n", format!($($arg)*));
            unsafe {
                libc::write(2, msg.as_ptr() as *const _, msg.len());
            }
        }
    };
}

// --------------------------------------------------------------------------
// Constants
// --------------------------------------------------------------------------

const SLOT_COUNT: usize = 1000;
const SLOT_SIZE: usize = 1024 * 1024; // 1 MB per slot
const DEFAULT_TTL_SECS: u64 = 120;
const MAGIC: [u8; 8] = *b"DKCACHE1";

const SLOT_EMPTY: u8 = 0;
const SLOT_FILLING: u8 = 1;
const SLOT_READY: u8 = 2;
const SLOT_EVICTED: u8 = 3;

// Hash table sentinel values.
const HASH_EMPTY: u64 = u64::MAX;
const HASH_TOMBSTONE: u64 = u64::MAX - 1;

// --------------------------------------------------------------------------
// mmap layout (repr(C), aligned for atomic access)
// --------------------------------------------------------------------------

#[repr(C)]
struct CacheHeader {
    magic: [u8; 8],
    version: u32,
    slot_count: u32,
    slot_size: u32,
    _padding: u32,
    global_lock: AtomicU64,
    hash_table: [AtomicU64; SLOT_COUNT],
}

#[repr(C)]
struct SlotMeta {
    state: AtomicU8,
    _padding: [u8; 7],
    timestamp: AtomicU64,
    key_hash: AtomicU64,
    key_len: AtomicU64,
    body_len: AtomicU64,
    status: AtomicU64,
    headers_len: AtomicU64,
}

const SLOT_META_SIZE: usize = std::mem::size_of::<SlotMeta>();
const HEADER_SIZE: usize = std::mem::size_of::<CacheHeader>();
const SLOT_DATA_SIZE: usize = SLOT_SIZE - SLOT_META_SIZE;

// --------------------------------------------------------------------------
// MmapStore — raw pointer based, all access via atomics
// --------------------------------------------------------------------------

/// The mmap cache store. After initialization, all access is through raw
/// pointers + atomics, so `&self` methods can safely mutate the shared
/// memory region.
struct MmapStore {
    /// Base pointer of the mmap region. Valid for the lifetime of the store.
    /// The MmapMut is kept alive to hold the mapping.
    _mmap: MmapMut,
    ptr: *mut u8,
    len: usize,
}

// SAFETY: The mmap region is MAP_SHARED and accessed via atomics. Each HAProxy
// worker thread gets its own MmapStore (via lua-load-per-thread), but they all
// map the same file. The raw pointer is valid as long as _mmap is alive.
unsafe impl Send for MmapStore {}
unsafe impl Sync for MmapStore {}

static STORE: OnceLock<MmapStore> = OnceLock::new();
static STORE_INIT: Mutex<()> = Mutex::new(());

impl MmapStore {
    fn open(path: &str) -> Result<&'static MmapStore, String> {
        if let Some(store) = STORE.get() {
            return Ok(store);
        }
        let _guard = STORE_INIT.lock().map_err(|e| format!("lock: {e}"))?;
        // Double-check after acquiring the lock.
        if let Some(store) = STORE.get() {
            return Ok(store);
        }
        let path = PathBuf::from(path);
        let needs_init = !path.exists();
        if needs_init {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("create cache dir: {e}"))?;
            }
        }

        let total_size = HEADER_SIZE + SLOT_COUNT * SLOT_SIZE;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .map_err(|e| format!("open cache file: {e}"))?;

        let file_size = file
            .metadata()
            .map_err(|e| format!("file metadata: {e}"))?
            .len() as usize;

        if file_size < total_size {
            file.set_len(total_size as u64)
                .map_err(|e| format!("set file len: {e}"))?;
        }

        let mmap = unsafe { MmapMut::map_mut(&file).map_err(|e| format!("mmap: {e}"))? };
        let ptr = mmap.as_ptr() as *mut u8;
        let len = mmap.len();
        let mut store = MmapStore { _mmap: mmap, ptr, len };

        if needs_init || file_size < total_size {
            store.init_header();
        } else {
            let header = store.header();
            if header.magic != MAGIC {
                trace!("cache file magic mismatch, reinitializing");
                store.init_header();
            } else {
                // Verify the hash table is initialized (all entries should
                // be HASH_EMPTY for empty). If any of the first few entries
                // are not HASH_EMPTY, the file is corrupt — reinitialize.
                let needs_reinit = (0..10).any(|i| {
                    header.hash_table[i].load(Ordering::Relaxed) != HASH_EMPTY
                });
                if needs_reinit {
                    trace!("cache file hash table corrupt, reinitializing");
                    store.init_header();
                }
            }
        }

        trace!("cache opened: {} slots × {} bytes = {} MB",
               SLOT_COUNT, SLOT_SIZE, total_size / (1024 * 1024));

        // Insert into the OnceLock. This is safe because we hold the init lock
        // and STORE is currently None.
        match STORE.set(store) {
            Ok(()) => {}
            Err(_) => return Err("STORE.set failed".to_string()),
        }
        STORE.get().ok_or_else(|| "STORE.get failed after set".to_string())
    }

    fn init_header(&mut self) {
        // SAFETY: This is called only during initialization (before any
        // concurrent access), so direct writes are safe.
        trace!("init_header: HEADER_SIZE={} SLOT_META_SIZE={} SLOT_DATA_SIZE={} total={}",
               HEADER_SIZE, SLOT_META_SIZE, SLOT_DATA_SIZE,
               HEADER_SIZE + SLOT_COUNT * SLOT_SIZE);
        unsafe {
            let header = &mut *(self.ptr as *mut CacheHeader);
            header.magic = MAGIC;
            header.version = 1;
            header.slot_count = SLOT_COUNT as u32;
            header.slot_size = SLOT_SIZE as u32;
            header.global_lock = AtomicU64::new(0);
            // Initialize the hash table using store() on each atomic.
            // Using iter() gives immutable refs, but AtomicU64::store
            // only needs &self (interior mutability).
            for (i, entry) in header.hash_table.iter().enumerate() {
                entry.store(HASH_EMPTY, Ordering::Release);
            }
            trace!("init_header: hash_table initialized {} entries", header.hash_table.len());
            // Verify a few entries.
            for i in [0, 409, 769, 999] {
                let val = header.hash_table[i].load(Ordering::Acquire);
                trace!("init_header: hash_table[{}] = {:#x}", i, val);
            }
            for i in 0..SLOT_COUNT {
                let slot = self.slot_meta_ptr(i);
                (*slot).state.store(SLOT_EMPTY, Ordering::Release);
            }
        }
        self.flush();
    }

    fn flush(&self) {
        // msync to flush the mmap to disk.
        unsafe {
            libc::msync(self.ptr as *mut libc::c_void, self.len, libc::MS_SYNC);
        }
    }

    // -- raw pointer accessors (all &self, using atomics) --

    fn header(&self) -> &CacheHeader {
        unsafe { &*(self.ptr as *const CacheHeader) }
    }

    fn slot_meta_ptr(&self, index: usize) -> *mut SlotMeta {
        let offset = HEADER_SIZE + index * SLOT_SIZE;
        unsafe { self.ptr.add(offset) as *mut SlotMeta }
    }

    fn slot_meta(&self, index: usize) -> &SlotMeta {
        unsafe { &*self.slot_meta_ptr(index) }
    }

    fn slot_data(&self, index: usize) -> &[u8] {
        let offset = HEADER_SIZE + index * SLOT_SIZE + SLOT_META_SIZE;
        unsafe {
            std::slice::from_raw_parts(self.ptr.add(offset), SLOT_DATA_SIZE)
        }
    }

    fn slot_data_mut(&self, index: usize) -> &mut [u8] {
        let offset = HEADER_SIZE + index * SLOT_SIZE + SLOT_META_SIZE;
        unsafe {
            std::slice::from_raw_parts_mut(self.ptr.add(offset), SLOT_DATA_SIZE)
        }
    }

    // -- lock --

    fn lock(&self) {
        let lock = &self.header().global_lock;
        while lock.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_err() {
            std::hint::spin_loop();
        }
    }

    fn unlock(&self) {
        self.header().global_lock.store(0, Ordering::Release);
    }

    // -- hash --

    fn hash_index(&self, key_hash: u64) -> usize {
        (key_hash as usize) % SLOT_COUNT
    }

    // -- lookup --

    fn lookup(&self, key: &[u8]) -> Option<usize> {
        let key_hash = hash_key(key);
        let start_idx = self.hash_index(key_hash);
        trace!("lookup: key={} hash={:x} start_idx={}", String::from_utf8_lossy(key), key_hash, start_idx);

        for probe in 0..SLOT_COUNT {
            let idx = (start_idx + probe) % SLOT_COUNT;
            let entry = self.header().hash_table[idx].load(Ordering::Acquire);
            if entry == HASH_EMPTY {
                if probe == 0 {
                    trace!("lookup: hash_table[{}] is empty (no entries)", idx);
                } else {
                    trace!("lookup: hash_table[{}] is empty after {} probes", idx, probe);
                }
                return None;
            }
            if entry == HASH_TOMBSTONE {
                // Skip tombstones (evicted entries) — continue probing.
                continue;
            }
            let slot_idx = entry as usize;
            if slot_idx >= SLOT_COUNT {
                continue;
            }
            let slot = self.slot_meta(slot_idx);
            let slot_hash = slot.key_hash.load(Ordering::Acquire);
            if slot_hash != key_hash {
                continue;
            }
            let state = slot.state.load(Ordering::Acquire);
            if state != SLOT_READY {
                trace!("lookup: slot {} state={} (not READY)", slot_idx, state);
                continue;
            }
            let key_len = slot.key_len.load(Ordering::Acquire) as usize;
            if key_len != key.len() {
                continue;
            }
            let data = self.slot_data(slot_idx);
            if &data[..key_len] == key {
                let ts = slot.timestamp.load(Ordering::Acquire);
                let now = current_time_secs();
                if now.saturating_sub(ts) > DEFAULT_TTL_SECS {
                    trace!("lookup: slot {} expired", slot_idx);
                    return None;
                }
                trace!("lookup: HIT slot={}", slot_idx);
                return Some(slot_idx);
            }
        }
        None
    }

    // -- store --

    fn store(&self, key: &[u8], status: u16, headers: &[u8], body: &[u8]) -> Result<(), String> {
        let key_hash = hash_key(key);
        trace!("store: key={} hash={:x} hash_index={}",
               String::from_utf8_lossy(key), key_hash, (key_hash as usize) % SLOT_COUNT);
        let total_data = key.len() + headers.len() + body.len();
        if total_data > SLOT_DATA_SIZE {
            return Err(format!("data too large: {} > {}", total_data, SLOT_DATA_SIZE));
        }

        self.lock();
        let result = self.store_inner(key, key_hash, status, headers, body);
        self.unlock();
        result
    }

    fn store_inner(
        &self,
        key: &[u8],
        key_hash: u64,
        status: u16,
        headers: &[u8],
        body: &[u8],
    ) -> Result<(), String> {
        // Check if key already exists (update in place).
        let start_idx = self.hash_index(key_hash);
        for probe in 0..SLOT_COUNT {
            let idx = (start_idx + probe) % SLOT_COUNT;
            let entry = self.header().hash_table[idx].load(Ordering::Acquire);
            if entry == HASH_EMPTY {
                break;
            }
            if entry == HASH_TOMBSTONE {
                continue;
            }
            let slot_idx = entry as usize;
            if slot_idx >= SLOT_COUNT {
                continue;
            }
            let slot = self.slot_meta(slot_idx);
            if slot.key_hash.load(Ordering::Acquire) == key_hash {
                let key_len = slot.key_len.load(Ordering::Acquire) as usize;
                if key_len == key.len() {
                    let data = self.slot_data(slot_idx);
                    if &data[..key_len] == key {
                        self.write_slot(slot_idx, key, key_hash, status, headers, body);
                        trace!("store: updated slot={}", slot_idx);
                        return Ok(());
                    }
                }
            }
        }

        // Find a free slot or evict LRU.
        let slot_idx = self.find_free_slot();
        let hash_idx = self.find_hash_entry(key_hash);

        self.write_slot(slot_idx, key, key_hash, status, headers, body);
        self.header().hash_table[hash_idx].store(slot_idx as u64, Ordering::Release);

        trace!("store: stored slot={} hash_idx={}", slot_idx, hash_idx);
        Ok(())
    }

    fn find_free_slot(&self) -> usize {
        let mut oldest_ts = u64::MAX;
        let mut oldest_idx = 0;
        for i in 0..SLOT_COUNT {
            let state = self.slot_meta(i).state.load(Ordering::Acquire);
            if state == SLOT_EMPTY || state == SLOT_EVICTED {
                return i;
            }
            let ts = self.slot_meta(i).timestamp.load(Ordering::Acquire);
            if ts < oldest_ts {
                oldest_ts = ts;
                oldest_idx = i;
            }
        }
        // Evict LRU.
        let slot = self.slot_meta(oldest_idx);
        let old_key_hash = slot.key_hash.load(Ordering::Acquire);
        slot.state.store(SLOT_EVICTED, Ordering::Release);
        CACHE_EVICTIONS.fetch_add(1, Ordering::Relaxed);

        // Remove from hash table (use tombstone to preserve probe chains).
        let start_idx = self.hash_index(old_key_hash);
        for probe in 0..SLOT_COUNT {
            let idx = (start_idx + probe) % SLOT_COUNT;
            let entry = self.header().hash_table[idx].load(Ordering::Acquire);
            if entry == HASH_EMPTY {
                break;
            }
            if entry as usize == oldest_idx {
                self.header().hash_table[idx].store(HASH_TOMBSTONE, Ordering::Release);
                break;
            }
        }
        trace!("find_free_slot: evicted LRU slot={}", oldest_idx);
        oldest_idx
    }

    fn find_hash_entry(&self, key_hash: u64) -> usize {
        let start_idx = self.hash_index(key_hash);
        let mut first_tombstone = None;
        for probe in 0..SLOT_COUNT {
            let idx = (start_idx + probe) % SLOT_COUNT;
            let entry = self.header().hash_table[idx].load(Ordering::Acquire);
            if entry == HASH_EMPTY {
                // End of probe chain — return first tombstone if we saw one,
                // otherwise this empty slot.
                let result = first_tombstone.unwrap_or(idx);
                trace!("find_hash_entry: found {} at idx={} (probe={})",
                       if first_tombstone.is_some() { "tombstone" } else { "empty" }, result, probe);
                return result;
            }
            if entry == HASH_TOMBSTONE {
                // Remember first tombstone for reuse.
                if first_tombstone.is_none() {
                    first_tombstone = Some(idx);
                }
                continue;
            }
            // Check if this entry is for the same key (update in place).
            let slot_idx = entry as usize;
            if slot_idx < SLOT_COUNT {
                let slot = self.slot_meta(slot_idx);
                if slot.key_hash.load(Ordering::Acquire) == key_hash {
                    // Key already exists — return its hash table entry for update.
                    trace!("find_hash_entry: found existing at idx={} (probe={})", idx, probe);
                    return idx;
                }
            }
        }
        first_tombstone.unwrap_or(start_idx)
    }

    fn write_slot(
        &self,
        slot_idx: usize,
        key: &[u8],
        key_hash: u64,
        status: u16,
        headers: &[u8],
        body: &[u8],
    ) {
        let slot = self.slot_meta(slot_idx);
        slot.state.store(SLOT_FILLING, Ordering::Release);

        let data = self.slot_data_mut(slot_idx);
        let mut offset = 0;
        data[offset..offset + key.len()].copy_from_slice(key);
        offset += key.len();
        data[offset..offset + headers.len()].copy_from_slice(headers);
        offset += headers.len();
        data[offset..offset + body.len()].copy_from_slice(body);

        slot.key_hash.store(key_hash, Ordering::Release);
        slot.key_len.store(key.len() as u64, Ordering::Release);
        slot.headers_len.store(headers.len() as u64, Ordering::Release);
        slot.body_len.store(body.len() as u64, Ordering::Release);
        slot.status.store(status as u64, Ordering::Release);
        slot.timestamp.store(current_time_secs(), Ordering::Release);
        slot.state.store(SLOT_READY, Ordering::Release);
    }

    fn read_slot(&self, slot_idx: usize) -> Option<CachedResponse> {
        let slot = self.slot_meta(slot_idx);
        if slot.state.load(Ordering::Acquire) != SLOT_READY {
            return None;
        }
        let key_len = slot.key_len.load(Ordering::Acquire) as usize;
        let headers_len = slot.headers_len.load(Ordering::Acquire) as usize;
        let body_len = slot.body_len.load(Ordering::Acquire) as usize;
        let status = slot.status.load(Ordering::Acquire) as u16;

        let data = self.slot_data(slot_idx);
        if key_len + headers_len + body_len > data.len() {
            return None;
        }
        let headers = &data[key_len..key_len + headers_len];
        let body = &data[key_len + headers_len..key_len + headers_len + body_len];

        Some(CachedResponse {
            status,
            headers: headers.to_vec(),
            body: body.to_vec(),
        })
    }

    fn reset(&self) {
        self.lock();
        for i in 0..SLOT_COUNT {
            self.slot_meta(i).state.store(SLOT_EMPTY, Ordering::Release);
        }
        for i in 0..SLOT_COUNT {
            self.header().hash_table[i].store(HASH_EMPTY, Ordering::Release);
        }
        self.unlock();
        self.flush();
        CACHE_HITS.store(0, Ordering::Relaxed);
        CACHE_MISSES.store(0, Ordering::Relaxed);
        CACHE_STORES.store(0, Ordering::Relaxed);
        CACHE_EVICTIONS.store(0, Ordering::Relaxed);
        CACHE_ERRORS.store(0, Ordering::Relaxed);
    }
}

struct CachedResponse {
    status: u16,
    headers: Vec<u8>,
    body: Vec<u8>,
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

fn hash_key(key: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in key {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn current_time_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn compute_cache_key(txn: &Txn) -> LuaResult<Vec<u8>> {
    let method: String = txn.f.get_str("method", ())?;
    let path: String = txn.f.get_str("path", ())?;
    // Get the Host and Accept headers from the raw request headers block
    // (avoids the req.hdr(name) fetch syntax which uses parentheses and
    // is interpreted as a function call by the haproxy-api fetch parser).
    let raw_hdrs: String = txn.f.get_str("req_hdrs", ()).unwrap_or_default();
    let host = extract_header(&raw_hdrs, "host");
    let accept = extract_header(&raw_hdrs, "accept");
    let accept_variant = if accept.to_ascii_lowercase().contains("image/webp") {
        "webp"
    } else {
        ""
    };
    Ok(format!("{method}|{host}|{path}|{accept_variant}").into_bytes())
}

/// Extract the first value of a header from a raw HTTP header block
/// (as returned by the `req_hdrs` fetch). Each line is "Name: Value".
fn extract_header(raw_hdrs: &str, name: &str) -> String {
    let name_lower = name.to_ascii_lowercase();
    for line in raw_hdrs.lines() {
        if let Some(colon) = line.find(':') {
            let hdr_name = line[..colon].trim().to_ascii_lowercase();
            if hdr_name == name_lower {
                return line[colon + 1..].trim().to_string();
            }
        }
    }
    String::new()
}

fn serialize_headers(msg: &HttpMessage) -> LuaResult<Vec<u8>> {
    let headers = msg.get_headers()?;
    let mut buf = Vec::new();
    for pair in headers.pairs::<String>() {
        let (name, values) = pair?;
        let name_lower = name.to_ascii_lowercase();
        if matches!(
            name_lower.as_str(),
            "transfer-encoding" | "connection" | "keep-alive" |
            "x-cache" | "x-cache-backend" | "via" | "x-varnish" |
            "x-varnish-fetch" | "set-cookie" | "cache-control"
        ) {
            continue;
        }
        // Each header may have multiple values; serialize them as separate
        // name\0value\n entries.
        for value in &values {
            buf.extend_from_slice(name.as_bytes());
            buf.push(0);
            buf.extend_from_slice(value.as_bytes());
            buf.push(b'\n');
        }
    }
    Ok(buf)
}

fn parse_headers(data: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut headers = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        if let Some(ne) = data[pos..].iter().position(|&b| b == 0) {
            let name = String::from_utf8_lossy(&data[pos..pos + ne]).to_string();
            pos += ne + 1;
            if let Some(ve) = data[pos..].iter().position(|&b| b == b'\n') {
                let value = data[pos..pos + ve].to_vec();
                pos += ve + 1;
                headers.push((name, value));
            } else {
                break;
            }
        } else {
            break;
        }
    }
    headers
}

// --------------------------------------------------------------------------
// disk_cache_hit — sample fetch
// --------------------------------------------------------------------------

fn fetch_disk_cache_hit(_: &Lua, txn: Txn) -> LuaResult<bool> {
    let store = match STORE.get() {
        Some(s) => s,
        None => {
            trace!("fetch: store not initialized");
            return Ok(false);
        }
    };
    let key = match compute_cache_key(&txn) {
        Ok(k) => k,
        Err(e) => {
            trace!("fetch: compute_cache_key error: {:?}", e);
            return Ok(false);
        }
    };
    trace!("fetch: looking up key={}", String::from_utf8_lossy(&key));
    match store.lookup(&key) {
        Some(slot_idx) => {
            CACHE_HITS.fetch_add(1, Ordering::Relaxed);
            trace!("fetch: HIT slot={}", slot_idx);
            Ok(true)
        }
        None => {
            CACHE_MISSES.fetch_add(1, Ordering::Relaxed);
            trace!("fetch: MISS");
            Ok(false)
        }
    }
}

// --------------------------------------------------------------------------
// disk_cache_store — filter
// --------------------------------------------------------------------------

#[derive(Default)]
struct DiskCacheStoreFilter {
    active: bool,
    body_buf: Vec<u8>,
    status: u16,
    headers: Vec<u8>,
    key: Vec<u8>,
}

impl UserFilter for DiskCacheStoreFilter {
    const METHODS: u8 = FilterMethod::HTTP_HEADERS | FilterMethod::HTTP_PAYLOAD | FilterMethod::HTTP_END;

    fn new(_: &Lua, _args: LuaTable) -> LuaResult<Self> {
        Ok(DiskCacheStoreFilter::default())
    }

    fn http_headers(&mut self, lua: &Lua, txn: Txn, msg: HttpMessage) -> LuaResult<FilterResult> {
        if !msg.is_resp()? {
            // Request side: compute and save the cache key for later use
            // when the response arrives. The request headers (req_hdrs,
            // path, method) are only available on the request side.
            self.key = compute_cache_key(&txn).unwrap_or_default();
            trace!("http_headers(req): saved key={}", String::from_utf8_lossy(&self.key));
            return Ok(FilterResult::Continue);
        }

        // Response side: use the key computed from the request side.
        if self.key.is_empty() {
            self.active = false;
            return Ok(FilterResult::Continue);
        }

        self.status = txn.f.get::<u16>("status", ())?;
        if self.status != 200 {
            self.active = false;
            return Ok(FilterResult::Continue);
        }

        let ct: String = {
            let raw_hdrs: String = txn.f.get_str("res_hdrs", ()).unwrap_or_default();
            extract_header(&raw_hdrs, "content-type")
        };
        if !ct.to_ascii_lowercase().starts_with("image/") {
            self.active = false;
            return Ok(FilterResult::Continue);
        }

        let cl: u32 = msg.get_headers()?.get_first::<u32>("content-length")?.unwrap_or(0);
        if cl as usize > SLOT_DATA_SIZE {
            self.active = false;
            return Ok(FilterResult::Continue);
        }

        self.headers = serialize_headers(&msg)?;
        self.active = true;
        self.body_buf = Vec::new();
        Self::register_data_filter(lua, txn, msg.channel()?)?;
        trace!("http_headers: will cache status={} ct={}", self.status, ct);
        Ok(FilterResult::Continue)
    }

    fn http_payload(&mut self, _: &Lua, _: Txn, msg: HttpMessage) -> LuaResult<Option<usize>> {
        if !self.active {
            return Ok(None);
        }
        if let Some(chunk) = msg.body(None, Some(-1))? {
            let chunk_bytes = chunk.as_bytes();
            if !chunk_bytes.is_empty() {
                self.body_buf.extend_from_slice(&chunk_bytes);
            }
        }
        Ok(None)
    }

    fn http_end(&mut self, _: &Lua, _: Txn, _msg: HttpMessage) -> LuaResult<FilterResult> {
        if !self.active {
            return Ok(FilterResult::Continue);
        }
        let key = std::mem::take(&mut self.key);
        let headers = std::mem::take(&mut self.headers);
        let body = std::mem::take(&mut self.body_buf);

        trace!("http_end: storing {} bytes (status={})", body.len(), self.status);

        match STORE.get() {
            Some(store) => {
                match store.store(&key, self.status, &headers, &body) {
                    Ok(()) => {
                        CACHE_STORES.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => {
                        CACHE_ERRORS.fetch_add(1, Ordering::Relaxed);
                        trace!("http_end: store failed: {}", e);
                    }
                }
            }
            None => {
                CACHE_ERRORS.fetch_add(1, Ordering::Relaxed);
            }
        }
        Ok(FilterResult::Continue)
    }
}

// --------------------------------------------------------------------------
// Registration
// --------------------------------------------------------------------------

pub fn register(lua: &Lua, _: ()) -> LuaResult<()> {
    let core = Core::new(lua)?;

    let cache_path = std::env::var("DISK_CACHE_POC_PATH")
        .unwrap_or_else(|_| "/app/data/disk_cache/cache.bin".to_string());

    match MmapStore::open(&cache_path) {
        Ok(_) => trace!("register: cache opened at {}", cache_path),
        Err(e) => {
            let msg = format!("disk_cache: failed to open cache file {}: {}\n", cache_path, e);
            unsafe {
                libc::write(2, msg.as_ptr() as *const _, msg.len());
            }
        }
    }

    // Register the sample fetch.
    core.register_fetches("disk_cache_hit", fetch_disk_cache_hit)?;

    // Expose the serve function as a global for the Lua service code.
    lua.globals().set(
        "_disk_cache_serve",
        lua.create_function(|lua, key: String| {
            let store = match STORE.get() {
                Some(s) => s,
                None => return Ok(None),
            };
            let key_bytes = key.into_bytes();
            match store.lookup(&key_bytes) {
                Some(slot_idx) => {
                    if let Some(cached) = store.read_slot(slot_idx) {
                        let table = lua.create_table()?;
                        let hdr_table = lua.create_table()?;
                        for (name, value) in parse_headers(&cached.headers) {
                            let pair = lua.create_table()?;
                            pair.set("name", name)?;
                            // Convert Vec<u8> to a Lua string (not a table).
                            pair.set("value", lua.create_string(&value)?)?;
                            hdr_table.push(pair)?;
                        }
                        table.set("status", cached.status)?;
                        table.set("headers", hdr_table)?;
                        // Convert body to a Lua string for applet:send().
                        table.set("body", lua.create_string(&cached.body)?)?;
                        Ok(Some(table))
                    } else {
                        Ok(None)
                    }
                }
                None => Ok(None),
            }
        })?,
    )?;

    // The Lua service code for serving cache hits.
    core.register_lua_service(
        "serve_cached",
        ServiceMode::Http,
        r#"
local applet = ...

-- Wrap in pcall to catch any errors and log them.
local ok, err = pcall(function()
    local method = applet.method or "GET"
    local host = ""
    local path = applet.path or "/"
    local accept = ""
    local accept_variant = ""

    -- applet.headers is a table of header name -> array of values.
    if applet.headers then
        local host_hdr = applet.headers["host"]
        if host_hdr then
            if type(host_hdr) == "table" then
                host = host_hdr[1] or ""
                if host == "" then
                    for _, v in pairs(host_hdr) do
                        host = tostring(v)
                        break
                    end
                end
            elseif type(host_hdr) == "string" then
                host = host_hdr
            end
        end
        local accept_hdr = applet.headers["accept"]
        if accept_hdr and type(accept_hdr) == "table" and accept_hdr[1] then
            accept = accept_hdr[1]
        elseif accept_hdr and type(accept_hdr) == "string" then
            accept = accept_hdr
        end
    end

    if string.match(string.lower(accept), "image/webp") then
        accept_variant = "webp"
    end
    local key = method .. "|" .. host .. "|" .. path .. "|" .. accept_variant

    local cached = _disk_cache_serve(key)
    if cached == nil then
        -- Race: the fetch said hit but the slot is now gone (evicted/expired).
        applet:set_status(503)
        applet:add_header("content-length", "0")
        applet:start_response()
        return
    end

    applet:set_status(cached.status)
    for _, hdr in ipairs(cached.headers) do
        applet:add_header(hdr.name, hdr.value)
    end
    applet:add_header("x-cache", "HIT")
    applet:add_header("content-length", tostring(#cached.body))
    applet:start_response()

    local chunk_size = 65536
    local offset = 1
    while offset <= #cached.body do
        local chunk = string.sub(cached.body, offset, offset + chunk_size - 1)
        applet:send(chunk)
        offset = offset + chunk_size
    end
end)

if not ok then
    core.Alert("serve_cached: ERROR: " .. tostring(err))
    applet:set_status(500)
    applet:add_header("content-type", "text/plain")
    applet:add_header("content-length", tostring(#tostring(err)))
    applet:start_response()
    applet:send(tostring(err))
end
"#,
    )?;

    // Register the store filter.
    core.register_filter::<DiskCacheStoreFilter>("disk_cache_store")?;

    // Stats and reset CLI commands.
    lua.globals().set(
        "_disk_cache_stats",
        lua.create_function(|_, ()| {
            Ok(format!(
                "hits:{} misses:{} stores:{} evictions:{} errors:{}",
                CACHE_HITS.load(Ordering::Relaxed),
                CACHE_MISSES.load(Ordering::Relaxed),
                CACHE_STORES.load(Ordering::Relaxed),
                CACHE_EVICTIONS.load(Ordering::Relaxed),
                CACHE_ERRORS.load(Ordering::Relaxed),
            ))
        })?,
    )?;

    core.register_lua_cli(
        &["show", "disk-cache-stats"],
        "show disk-cache-stats: display disk cache PoC counters",
        r#"
        local applet = ...
        applet:send(_disk_cache_stats() .. "\n")
        "#,
    )?;

    lua.globals().set(
        "_disk_cache_reset",
        lua.create_function(|_, ()| {
            if let Some(store) = STORE.get() {
                store.reset();
            }
            Ok(())
        })?,
    )?;

    core.register_lua_cli(
        &["show", "disk-cache-reset"],
        "show disk-cache-reset: clear all cache slots and reset counters",
        r#"
        local applet = ...
        _disk_cache_reset()
        applet:send("cache reset\n")
        "#,
    )?;

    Ok(())
}
