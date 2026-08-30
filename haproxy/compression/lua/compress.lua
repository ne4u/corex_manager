-- Loader for the haproxy-compression Rust Lua module.
-- Loaded via lua-load-per-thread in the global section when brotli or zstd
-- compression is enabled. Registers the `lua.compress` filter.
local compress = require("haproxy_compression_module")

compress.register()
