//! Catalog store + worker — periodic upstream catalog refresh.
//!
//! Mirrors `mcp-gateway/catalog.py`:
//! - `mcp:gw:catalog:<id>` — cached catalog JSON (TTL 2h).
//! - `mcp:gw:catalog_hash:<id>` — content hash for list_changed detection.
//! - In-memory fallback cache.
//! - Background worker refreshes all enabled servers periodically.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use sha2::{Digest, Sha256};

use corex_core::config::ServerConfig;
use corex_policy::valkey::ValkeyClient;

use crate::upstream::{Catalog, UpstreamClient};
use crate::stdio::ProcessManager;

const CATALOG_TTL: u64 = 7200;

/// In-memory catalog cache (fallback when Valkey unavailable).
#[derive(Default)]
pub struct CatalogStore {
    cache: Mutex<HashMap<i64, Catalog>>,
    hashes: Mutex<HashMap<i64, String>>,
    changed: Mutex<std::collections::HashSet<i64>>,
    valkey: Option<ValkeyClient>,
}

impl CatalogStore {
    pub fn new(valkey: Option<ValkeyClient>) -> Self {
        Self {
            cache: Default::default(),
            hashes: Default::default(),
            changed: Default::default(),
            valkey,
        }
    }

    /// Compute a stable hash of catalog content for list_changed detection.
    ///
    /// Only `tools`, `resources`, and `prompts` are hashed — `fetched_at` is
    /// excluded so the hash is stable across refreshes when content is unchanged.
    fn compute_hash(catalog: &Catalog) -> String {
        let payload = serde_json::json!({
            "tools": catalog.tools,
            "resources": catalog.resources,
            "prompts": catalog.prompts,
        });
        let raw = serde_json::to_string(&payload).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(raw.as_bytes());
        hex::encode(&hasher.finalize()[..8])
    }

    /// Store a server's catalog in Valkey and the in-memory cache.
    pub async fn store(&self, server_id: i64, catalog: Catalog) {
        let new_hash = Self::compute_hash(&catalog);
        let old_hash = self.hashes.lock().get(&server_id).cloned();
        if let Some(c) = &self.valkey {
            let payload = serde_json::to_string(&catalog).unwrap_or_else(|_| "{}".into());
            let _ = c.setex(&format!("catalog:{server_id}"), CATALOG_TTL, &payload).await;
            let _ = c.setex(&format!("catalog_hash:{server_id}"), CATALOG_TTL, &new_hash).await;
        }
        self.cache.lock().insert(server_id, catalog);
        if let Some(old) = &old_hash {
            if old != &new_hash {
                self.changed.lock().insert(server_id);
                tracing::info!("Catalog changed for server {server_id} (hash {old} -> {new_hash})");
            }
        }
        self.hashes.lock().insert(server_id, new_hash);
    }

    /// Get a server's catalog from cache or Valkey.
    pub async fn get(&self, server_id: i64) -> Option<Catalog> {
        if let Some(c) = self.cache.lock().get(&server_id).cloned() {
            return Some(c);
        }
        let c = self.valkey.as_ref()?;
        let raw = c.get(&format!("catalog:{server_id}")).await.ok()??;
        let catalog: Catalog = serde_json::from_str(&raw).ok()?;
        self.cache.lock().insert(server_id, catalog.clone());
        Some(catalog)
    }

    /// Return and clear the set of server IDs whose catalog changed.
    pub fn pop_changed(&self) -> std::collections::HashSet<i64> {
        let mut changed = self.changed.lock();
        let out = changed.clone();
        changed.clear();
        out
    }

    /// Remove a server's catalog (e.g., when disabled).
    pub async fn clear(&self, server_id: i64) {
        self.cache.lock().remove(&server_id);
        self.hashes.lock().remove(&server_id);
        if let Some(c) = &self.valkey {
            let _ = c.del(&format!("catalog:{server_id}")).await;
            let _ = c.del(&format!("catalog_hash:{server_id}")).await;
        }
    }

    /// Clear all cached catalogs.
    pub fn clear_all(&self) {
        self.cache.lock().clear();
        self.hashes.lock().clear();
        self.changed.lock().clear();
    }

    /// Snapshot per-server catalog freshness as `(server_id, fetched_at, tool_count, resource_count, prompt_count)`.
    pub fn freshness(&self) -> Vec<(i64, f64, usize, usize, usize)> {
        self.cache
            .lock()
            .iter()
            .map(|(id, c)| {
                (*id, c.fetched_at, c.tools.len(), c.resources.len(), c.prompts.len())
            })
            .collect()
    }
}

/// Background worker that periodically refreshes upstream catalogs.
pub struct CatalogWorker {
    store: Arc<CatalogStore>,
    http: UpstreamClient,
    stdio: ProcessManager,
    refresh_interval: u64,
    shutdown: Arc<tokio::sync::Notify>,
}

impl CatalogWorker {
    pub fn new(
        store: Arc<CatalogStore>,
        http: UpstreamClient,
        stdio: ProcessManager,
        refresh_interval: u64,
    ) -> Self {
        Self {
            store,
            http,
            stdio,
            refresh_interval,
            shutdown: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// Run the worker until `stop()` is called.
    pub async fn run(&self, servers: Vec<ServerConfig>) {
        // Initial refresh + quick retries in case upstreams are still booting.
        for i in 0..5u32 {
            self.refresh_all(&servers).await;
            if i < 4 {
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {}
                    _ = self.shutdown.notified() => return,
                }
            }
        }
        loop {
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(self.refresh_interval)) => {
                    self.refresh_all(&servers).await;
                }
                _ = self.shutdown.notified() => break,
            }
        }
    }

    /// Stop the worker.
    pub fn stop(&self) {
        self.shutdown.notify_waiters();
    }

    async fn refresh_all(&self, servers: &[ServerConfig]) {
        let tasks: Vec<_> = servers
            .iter()
            .filter(|s| s.enabled)
            .map(|s| self.refresh_one(s.clone()))
            .collect();
        futures::future::join_all(tasks).await;
    }

    async fn refresh_one(&self, server: ServerConfig) {
        let sid = server.id;
        let catalog = if server.transport_type == "stdio" {
            // stdio: initialize then fetch.
            let _ = self.stdio.initialize_upstream(&server).await;
            self.stdio.fetch_catalog(&server).await
        } else {
            // HTTP: initialize then fetch.
            let upstream_sid = self.http.initialize(&server).await;
            self.http.fetch_catalog(&server, upstream_sid.as_deref()).await
        };
        match catalog {
            Some(c) => {
                self.store.store(sid, c).await;
            }
            None => {
                self.store.clear(sid).await;
                tracing::warn!("Failed to fetch catalog for server {}; cleared", server.name);
            }
        }
    }
}

// We need `hex` for hash encoding. Add a minimal inline encoder to avoid a dep.
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_stable() {
        let c = Catalog {
            tools: vec![serde_json::json!({"name": "a"})],
            resources: vec![],
            prompts: vec![],
            fetched_at: 1.0,
        };
        let h1 = CatalogStore::compute_hash(&c);
        let h2 = CatalogStore::compute_hash(&c);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 16);
    }

    #[test]
    fn hash_changes_on_content_change() {
        let c1 = Catalog { tools: vec![], resources: vec![], prompts: vec![], fetched_at: 1.0 };
        let c2 = Catalog { tools: vec![serde_json::json!({"name": "a"})], resources: vec![], prompts: vec![], fetched_at: 1.0 };
        assert_ne!(CatalogStore::compute_hash(&c1), CatalogStore::compute_hash(&c2));
    }

    #[tokio::test]
    async fn store_and_get_in_memory() {
        let store = CatalogStore::new(None);
        let c = Catalog { tools: vec![serde_json::json!({"name": "x"})], resources: vec![], prompts: vec![], fetched_at: 2.0 };
        store.store(1, c.clone()).await;
        let got = store.get(1).await.unwrap();
        assert_eq!(got.tools.len(), 1);
    }

    #[tokio::test]
    async fn pop_changed_tracks_changes() {
        let store = CatalogStore::new(None);
        let c1 = Catalog { tools: vec![], resources: vec![], prompts: vec![], fetched_at: 1.0 };
        store.store(1, c1).await;
        assert!(store.pop_changed().is_empty()); // first store, no old hash
        let c2 = Catalog { tools: vec![serde_json::json!({"name": "a"})], resources: vec![], prompts: vec![], fetched_at: 1.0 };
        store.store(1, c2).await;
        let changed = store.pop_changed();
        assert!(changed.contains(&1));
        assert!(store.pop_changed().is_empty()); // cleared
    }
}
