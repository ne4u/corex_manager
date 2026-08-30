-- Response Transform Lua loader.
--
-- This file is dofile-ed by the generated modules.lua loader, which injects
-- the Valkey connection params from backend settings/env. It returns a table
-- with an init(opts) function that modules.lua calls.
--
-- The Rust module handles all Valkey TCP I/O directly (using std::net::TcpStream
-- with thread-local connection pooling), so the Lua layer only needs to pass
-- the connection params at registration time.

local M = {}

function M.init(opts)
    -- Register the Rust filter, passing the Valkey connection params.
    -- The Rust module stores these in a global static (all Send+Sync) and
    -- creates thread-local TCP connections on demand.
    local ok, mod = pcall(require, "haproxy_resp_transform_module")
    if not ok then
        core.Alert("resp_transform.lua: failed to load Rust module: " .. tostring(mod))
        return false
    end

    local rok, rerr = pcall(mod.register, {
        valkey_host = opts.valkey_host or "valkey",
        valkey_port = opts.valkey_port or 6379,
        valkey_db = opts.valkey_db or 0,
        valkey_password = opts.valkey_password,
        fallback_key_env = opts.fallback_key_env or "RESP_TRANSFORM_KEY",
    })
    if not rok then
        core.Alert("resp_transform.lua: filter register failed: " .. tostring(rerr))
        return false
    end

    return true
end

return M
