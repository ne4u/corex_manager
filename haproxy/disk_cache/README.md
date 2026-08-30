# haproxy-disk-cache (PoC)

> **Proof of concept** — an in-process disk cache for HAProxy using mmap shared
> across worker processes. This is a spike to validate whether the Varnish
> sidecar can be replaced with an in-process Rust Lua module.

## What it does

Registers three HAProxy Lua primitives:

- **`lua.disk_cache_hit`** — a sample fetch that looks up the mmap cache and
  returns `true` on hit. Used as the ACL condition for `use-service`.
- **`lua.serve_cached`** — an HTTP service that serves cached responses from
  mmap. Only invoked on hits (guarded by the fetch ACL).
- **`lua.disk_cache_store`** — a filter declared last in the backend section
  that captures response bodies on misses and stores them in mmap.

## Architecture

```
http-request use-service lua.serve_cached if { lua.disk_cache_hit -m found }
```

- **Hit**: `Client → HAProxy → service(mmap read) → Client` — no backend fetch.
- **Miss**: `Client → HAProxy → Origin → HAProxy(filter stores) → Client` —
  normal path, filter captures response inline.

No fetch-through-HAProxy loop (unlike Varnish). No `X-Varnish-Fetch` /
`is_varnish_fetch` headers.

## PoC scope

- GET requests only, `image/*` content type only.
- Fixed 1MB × 1000 slots (1 GB total).
- Fixed 120s TTL. No Vary (beyond WebP Accept), no grace, no PURGE/BAN.
- No durability (crash → rebuild on startup).

## Configuration

```
global
    lua-prepend-path /etc/haproxy/?.so cpath
    lua-load-per-thread disk_cache.lua

listen http-in
    bind *:8080
    http-request use-service lua.serve_cached if { lua.disk_cache_hit -m found }

backend origin
    server origin 127.0.0.1:8000
    filter lua.disk_cache_store
```

## CLI commands

- `show disk-cache-stats` — hit/miss/store/eviction/error counters.
- `show disk-cache-reset` — clear all slots and reset counters.

## Environment variables

- `DISK_CACHE_POC_PATH` — path to the cache file (default `/app/data/disk_cache/cache.bin`).
- `DISK_CACHE_POC_DEBUG=1` — enable stderr trace logging.

## License

MIT
