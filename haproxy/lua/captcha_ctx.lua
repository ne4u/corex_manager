-- Captcha context store: stores challenge rule context in Valkey (server-side)
-- and returns an opaque random token. The token is passed in the challenge
-- redirect URL instead of the raw rule_id/rule_type/rule_name/request_id/redirect_url,
-- so internal security rule details and the redirect destination are never exposed
-- to the user. This prevents open redirect attacks (user cannot manipulate the
-- redirect parameter since it's stored server-side).
--
-- Registered actions:
--   lua.captcha_store_ctx     — stores txn vars in Valkey, sets txn.captcha_cid_token
--   lua.captcha_validate_cookie — validates the _cv cookie by looking it up in Valkey
--
-- Expects this txn var to be set before calling captcha_validate_cookie:
--   txn.cap_cv_val — the raw _cv cookie value (opaque token)
--
-- Sets on success:
--   txn.captcha_cookie_valid — 1 (the request is allowed to bypass challenge)
--
-- Static params (baked into the generated config at config-apply time):
--   rule_id, rule_type, rule_name — passed as action arguments to store_ctx
--
-- Valkey keys:
--   cap:cid:<token>  TTL: 120s  Value: JSON {"i","t","n","r","u"} — challenge context
--   cap:_cv:<token>  TTL: <ttl> Value: <binding_hash>              — solved cookie token
--     The binding_hash is a 32-char hex SHA-256 truncation of
--     ip\nuser_agent\nja4, binding the cookie to the client that solved
--     the challenge so it cannot be replayed from a different client.

-- Valkey connection params (injected from settings at config-apply time)
local VK_HOST = "valkey"
local VK_PORT = 6379
local VK_PASSWORD = nil

-- Simple RESP protocol encoder/decoder for SET with TTL and GET.
local function resp_encode(cmd, ...)
    local args = {cmd, ...}
    local parts = {"*" .. #args .. "\r\n"}
    for _, arg in ipairs(args) do
        parts[#parts + 1] = "$" .. #arg .. "\r\n"
        parts[#parts + 1] = arg .. "\r\n"
    end
    return table.concat(parts)
end

local function resp_read_value(socket)
    local line = socket:receive("*l")
    if not line then return nil end
    -- HAProxy's Lua receive("*l") may include trailing \r (it strips \n only)
    line = line:gsub("\r$", "")
    local prefix = line:sub(1, 1)
    if prefix == "+" then
        return line:sub(2)
    elseif prefix == "-" then
        return nil, line:sub(2)
    elseif prefix == "$" then
        local len = tonumber(line:sub(2))
        if len < 0 then return nil end
        local data = socket:receive(len)
        socket:receive("*l") -- consume trailing \r\n
        return data
    elseif prefix == ":" then
        return tonumber(line:sub(2))
    else
        return nil, "unexpected RESP prefix: " .. prefix
    end
end

local function valkey_command(cmd, ...)
    local sock = core.tcp()
    if not sock then return nil, "no socket" end
    sock:settimeout(1)
    if not sock:connect(VK_HOST, VK_PORT) then
        return nil, "connect failed"
    end
    -- Auth if password is set
    if VK_PASSWORD and VK_PASSWORD ~= "" then
        sock:send(resp_encode("AUTH", VK_PASSWORD))
        local ok = sock:receive("*l")
        if not ok or ok:gsub("\r$", ""):sub(1, 1) ~= "+" then
            sock:close()
            return nil, "auth failed"
        end
    end
    local encoded = resp_encode(cmd, ...)
    if not sock:send(encoded) then
        sock:close()
        return nil, "send failed"
    end
    local result, err = resp_read_value(sock)
    sock:close()
    return result, err
end

-- Generate a random hex token (16 bytes = 32 hex chars)
local function random_token()
    -- Use /dev/urandom for cryptographic randomness
    local f = io.open("/dev/urandom", "rb")
    if not f then
        -- Fallback: use math.random (not crypto-grade, but acceptable)
        math.randomseed(tostring(os.time()) .. tostring({}))
        local hex = ""
        for i = 1, 32 do
            hex = hex .. string.format("%x", math.random(0, 15))
        end
        return hex
    end
    local bytes = f:read(16)
    f:close()
    local hex = ""
    for i = 1, #bytes do
        hex = hex .. string.format("%02x", string.byte(bytes, i))
    end
    return hex
end

-- Escape a string for inclusion in a JSON string value.
-- Only handles the characters that can appear in rule names/types/IDs.
local function json_escape(s)
    s = s or ""
    s = s:gsub("\\", "\\\\")
    s = s:gsub('"', '\\"')
    s = s:gsub("\n", "\\n")
    s = s:gsub("\r", "\\r")
    s = s:gsub("\t", "\\t")
    return s
end

-- Action: store captcha context in Valkey and set txn.captcha_cid_token
-- Called as: http-request lua.captcha_store_ctx <rule_id> <rule_type> <rule_name>
-- rule_name uses "-" as placeholder when empty (HAProxy requires exactly 3 args)
local function captcha_store_ctx(txn, rule_id, rule_type, rule_name)
    local request_id = txn:get_var("txn.captcha_request_id") or ""
    local redirect_url = txn:get_var("txn.captcha_redirect") or "/"
    -- Convert "-" placeholder back to empty string
    if rule_name == "-" then rule_name = "" end
    -- Build JSON manually (no json module in HAProxy's Lua environment)
    -- Include redirect URL to prevent open redirect vulnerability (user can't
    -- manipulate the redirect destination since it's set server-side)
    local ctx = string.format(
        '{"i":%d,"t":"%s","n":"%s","r":"%s","u":"%s"}',
        tonumber(rule_id) or 0,
        json_escape(rule_type),
        json_escape(rule_name),
        json_escape(request_id),
        json_escape(redirect_url)
    )
    local token = random_token()
    local key = "cap:cid:" .. token
    -- SET with 120-second TTL (challenge page load + verify should complete well within this)
    local result, err = valkey_command("SET", key, ctx, "EX", "120", "NX")
    if not result then
        core.Warning("captcha_ctx.lua: failed to store context in Valkey: " .. tostring(err))
        -- Fallback: set token to empty so the backend knows to use defaults
        txn:set_var("txn.captcha_cid_token", "")
        return
    end
    core.Debug("captcha_ctx.lua: stored context with token " .. token)
    txn:set_var("txn.captcha_cid_token", token)
end

-- Init function called by the generated modules.lua loader with Valkey params
local M = {}

function M.init(opts)
    VK_HOST = opts.valkey_host or "valkey"
    VK_PORT = opts.valkey_port or 6379
    VK_PASSWORD = opts.valkey_password
    return true
end

-- Compute the client-binding hash from the txn vars set by the generated
-- HAProxy config before calling captcha_validate_cookie:
--   txn.cap_cv_ip  — client source IP (src)
--   txn.cap_cv_ua  — User-Agent header
--   txn.cap_cv_ja4 — JA4 TLS fingerprint (lua.ja4_fp, empty if JA4 disabled)
--
-- The algorithm MUST match the Python implementation in
-- backend/app/services/captcha_providers.py:compute_cv_binding_hash:
--   sha256(f"{ip}\n{ua}\n{ja4}")  → first 32 hex chars (lowercase)
local function compute_cv_binding_hash(txn)
    local ip = txn:get_var("txn.cap_cv_ip") or ""
    local ua = txn:get_var("txn.cap_cv_ua") or ""
    local ja4 = txn:get_var("txn.cap_cv_ja4") or ""
    local input = ip .. "\n" .. ua .. "\n" .. ja4
    local full_hash = string.lower(txn.c:hex(txn.c:digest(input, "sha256")))
    return string.sub(full_hash, 1, 32)
end

-- Action: validate the _cv cookie by looking up the opaque token in Valkey
-- and comparing the stored client-binding hash with the live request's hash.
-- Called as: http-request lua.captcha_validate_cookie
-- Expects these txn vars to be set before this call:
--   txn.cap_cv_val  — the raw _cv cookie value (opaque token)
--   txn.cap_cv_ip   — client source IP
--   txn.cap_cv_ua   — User-Agent header
--   txn.cap_cv_ja4  — JA4 TLS fingerprint (may be empty/unset if JA4 disabled)
-- Sets txn.captcha_cookie_valid = 1 if the token exists in Valkey AND the
-- stored binding hash matches the hash computed from the live request.
local function captcha_validate_cookie(txn)
    local token = txn:get_var("txn.cap_cv_val")
    if not token or token == "" then
        return
    end
    local key = "cap:_cv:" .. token
    local stored_hash, err = valkey_command("GET", key)
    if not stored_hash or stored_hash == "" then
        return
    end
    local live_hash = compute_cv_binding_hash(txn)
    if live_hash == stored_hash then
        txn:set_var("txn.captcha_cookie_valid", 1)
    end
end

-- Register the actions
core.register_action("captcha_store_ctx", {"http-req"}, captcha_store_ctx, 3)
core.register_action("captcha_validate_cookie", {"http-req"}, captcha_validate_cookie, 0)

return M
