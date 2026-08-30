-- Loader for the haproxy-req-fp Rust Lua module.
-- Loaded via the combined modules.lua loader (single lua-load-per-thread)
-- when request fingerprinting is enabled. Registers the `lua.req_fp_capture`
-- (http-req) and `lua.req_fp` (http-res) actions.
local req_fp = require("haproxy_req_fp_module")

req_fp.register()
