-- Loader for the haproxy-disk-cache Rust Lua module.
-- Loaded via lua-load-per-thread in the global section when the disk cache
-- PoC is enabled. Registers the `lua.disk_cache_hit` fetch, the
-- `lua.serve_cached` service, and the `lua.disk_cache_store` filter.
local disk_cache = require("haproxy_disk_cache_module")

disk_cache.register()
