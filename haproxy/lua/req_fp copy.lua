--[[
  SPDX-License-Identifier: Apache-2.0 WITH Commons-Clause
  Copyright (c) 2026 Austin Kauffman

  haproxy_req_fp - HAProxy request fingerprint module

  Registers two Lua actions:
    - "req_fp_capture" (http-req phase) — captures request data into txn vars
    - "req_fp"          (http-res phase) — builds the 17-field fingerprint
                                              using captured request data +
                                              response data, stores in txn.req_fp

  Two-phase design: HAProxy frees the request buffer before the http-res
  phase, so request headers/query/etc. are captured in http-req and stored
  in transaction variables for use in http-res.

  Uses txn.sf: (string sample-fetches) for maximum portability.

  Fingerprint format (17 underscore-separated fields):

    {path_b62}_{method2}_{http_ver}_{path_depth}_
    {param_keys}_{param_types}_{param_lens}_{req_ctype}_
    {hdr_count}_{hdr_list}_{accept_lang}_{auth_type}_
    {cookie}_{cookie_fields}_{referer}_
    {status}_{body_bytes}

  Field definitions:
    path_b62      - URI path bytes as a big-endian integer, base62-encoded
    method2       - first 2 chars of HTTP method, lowercased (ge, po, pu, de, ...)
    http_ver      - 2-digit protocol version: 09 10 11 20 30
    path_depth    - number of '/' chars in URI, zero-padded 2 digits, max 99
    param_keys    - first char of each param name sorted; "nil" if none (max 32)
    param_types   - type code per value, same order; "nil" if none
    param_lens    - decoded value lengths, dash-separated; "0" if none
    req_ctype     - first 4 alpha chars of request Content-Type subtype;
                    "0000" if absent (e.g. "json", "html", "xwww", "form")
    hdr_count     - count of request headers, zero-padded 2 digits, max 99
    hdr_list      - sorted first-char initials of all request header names; "nil" if none
    accept_lang   - first 4 lowercase alpha chars of primary Accept-Language tag;
                    "0000" if absent (hyphens and digits stripped)
    auth_type     - 'n' none, 'b' Basic, 't' Bearer/token, 'd' Digest, 'o' other
    cookie        - 'c' if Cookie header present, 'n' if absent
    cookie_fields - sorted first-char initials of cookie field names; "nil" if none
    referer       - 'n' no Referer, 's' same-domain, 'x' cross-domain
    status        - HTTP response status code
    body_bytes    - response Content-Length; falls back to res.body_len
                    (buffered body length) when Content-Length is absent/0

  Param source: URL query string only.
  Body params (application/x-www-form-urlencoded) require option http-buffer-request
  and a separate http-req action; see README for the two-phase pattern.

  Value type codes: int(i) float(f) string(s) char(c) bool(b) time(t)
                    date(d) datetime+tz(z) empty(e) object(o) list(l)

  Usage in haproxy.cfg:
    global
        lua-load /etc/haproxy/req_fp.lua

    frontend http-in
        http-request lua.req_fp_capture
        http-response lua.req_fp
        log-format "%ci [%t] %[var(txn.req_fp)]"
--]]

-- ---- Constants -------------------------------------------------------------

local MAX_PARAMS = 32
local PATH_MAX   = 2048
local B62_CHARS  = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

-- ---- Base62 encoder --------------------------------------------------------

-- Treats the bytes of s as a big-endian integer and encodes it in base62.
-- Caps input at PATH_MAX bytes. Returns "0" for empty input.
local function base62_encode(s)
    if #s > PATH_MAX then s = s:sub(1, PATH_MAX) end
    if #s == 0 then return "0" end

    -- n is an array of byte-width "digits" representing the big-endian integer.
    -- Long division by 62 is performed until the value reaches zero.
    local n   = { s:byte(1, #s) }
    local out = {}

    while #n > 0 do
        local rem   = 0
        local new_n = {}
        for i = 1, #n do
            local val = rem * 256 + n[i]
            local q   = math.floor(val / 62)
            rem       = val % 62
            if q > 0 or #new_n > 0 then
                new_n[#new_n + 1] = q
            end
        end
        table.insert(out, 1, B62_CHARS:sub(rem + 1, rem + 1))
        n = new_n
    end

    return table.concat(out)
end

-- ---- URL decoder -----------------------------------------------------------

local function url_decode(s)
    s = s:gsub('+', ' ')
    s = s:gsub('%%(%x%x)', function(h) return string.char(tonumber(h, 16)) end)
    return s
end

-- ---- Value type detector ---------------------------------------------------

local function detect_type(v)
    if #v == 0 then return 'e' end
    if v:sub(1, 1) == '{' then return 'o' end
    if v:sub(1, 1) == '[' then return 'l' end
    local lv = v:lower()
    if lv == 'true' or lv == 'false' then return 'b' end
    -- datetime with timezone (must check before plain date)
    if v:match('^%d%d%d%d%-%d%d%-%d%dT%d%d:%d%d:%d%d') then
        if v:match('[Zz]$') or v:match('[%+%-]%d%d:?%d%d$') then
            return 'z'
        end
    end
    if v:match('^%d%d%d%d%-%d%d%-%d%d$')   then return 'd' end
    if v:match('^%d%d:%d%d:%d%d')           then return 't' end
    if v:match('^%-?%d+$')                  then return 'i' end
    if v:match('^%-?%d*%.%d+$')             then return 'f' end
    if #v == 1                              then return 'c' end
    return 's'
end

-- ---- Query/body parameter parser -------------------------------------------

-- Parses a query-string or form-urlencoded byte string into a sorted array
-- of {name, value} tables, capped at MAX_PARAMS entries.
local function parse_params(qs)
    if not qs or #qs == 0 then return {} end
    local params = {}
    for kv in (qs .. '&'):gmatch('([^&]*)&') do
        if #kv > 0 and #params < MAX_PARAMS then
            local k, v = kv:match('^([^=]*)=?(.*)')
            k = k and url_decode(k) or ''
            v = v and url_decode(v) or ''
            if #k > 0 then
                params[#params + 1] = { name = k, value = v }
            end
        end
    end
    table.sort(params, function(a, b) return a.name < b.name end)
    return params
end

-- ---- HTTP version mapper ---------------------------------------------------

local VER_MAP = {
    ['0.9'] = '09', ['1.0'] = '10', ['1.1'] = '11',
    ['2']   = '20', ['2.0'] = '20',
    ['3']   = '30', ['3.0'] = '30',
}

local function http_ver_code(ver)
    return VER_MAP[ver] or '11'
end

-- ---- Path depth ------------------------------------------------------------

local function get_path_depth(path)
    local count = 0
    for _ in path:gmatch('/') do count = count + 1 end
    return math.min(count, 99)
end

-- ---- Header parsing from raw header block ----------------------------------

-- Parses a raw HTTP header block (from req.hdrs or res.hdrs) into:
--   (count, sorted_initials, header_table)
-- header_table is a lowercased-name → first-value mapping for individual lookups.
-- Both req.hdrs and res.hdrs return header lines only (no request/status
-- line), so every line is treated as a "Name: value" header.
local function parse_headers(raw)
    if not raw or raw == '' then return 0, 'nil', {} end

    local chars = {}
    local hdrs  = {}
    for line in raw:gmatch('[^\r\n]+') do
        -- Header line: "Name: value"
        local name, value = line:match('^([^:]+):%s*(.*)')
        if name then
            local lname = name:lower()
            if not hdrs[lname] then
                hdrs[lname] = value
                if #chars < MAX_PARAMS then
                    chars[#chars + 1] = lname:sub(1, 1)
                end
            end
        end
    end

    local count = math.min(#chars, 99)
    if count == 0 then return 0, 'nil', hdrs end
    table.sort(chars)
    return count, table.concat(chars), hdrs
end

-- ---- Request Content-Type subtype ------------------------------------------

-- Returns first 4 lowercase alpha chars of the Content-Type subtype (after '/').
-- Falls back to full value if no '/'. Returns "0000" if header absent.
local function get_req_ctype(hdrs)
    local val = hdrs['content-type']
    if not val or val == '' then return '0000' end
    local subtype  = val:match('/([^;]+)') or val
    local out      = {}
    for i = 1, #subtype do
        local c = subtype:sub(i, i)
        if c == ';' then break end
        if c:match('[a-zA-Z]') then
            out[#out + 1] = c:lower()
            if #out == 4 then break end
        end
    end
    while #out < 4 do out[#out + 1] = '0' end
    return table.concat(out)
end

-- ---- Accept-Language -------------------------------------------------------

-- Returns first 4 lowercase alpha chars of the primary language tag.
-- Stops at the first ',' or ';'. Returns "0000" if header absent.
local function get_accept_lang(hdrs)
    local val = hdrs['accept-language']
    if not val or val == '' then return '0000' end
    local out = {}
    for i = 1, #val do
        local c = val:sub(i, i)
        if c == ',' or c == ';' then break end
        if c:match('[a-zA-Z]') then
            out[#out + 1] = c:lower()
            if #out == 4 then break end
        end
    end
    while #out < 4 do out[#out + 1] = '0' end
    return table.concat(out)
end

-- ---- Authorization type ----------------------------------------------------

local function get_auth_type(hdrs)
    local val = hdrs['authorization']
    if not val or val == '' then return 'n' end
    local v = val:lower()
    if v:sub(1, 5) == 'basic'  then return 'b' end
    if v:sub(1, 6) == 'bearer' then return 't' end
    if v:sub(1, 6) == 'digest' then return 'd' end
    return 'o'
end

-- ---- Referer classifier ----------------------------------------------------

-- Strips port from a host string and lowercases it.
local function normalize_host(h)
    return h:lower():gsub(':%d+$', '')
end

local function get_referer_flag(hdrs)
    local ref_val = hdrs['referer']
    if not ref_val or ref_val == '' then return 'n' end
    local host_val = hdrs['host']
    if not host_val or host_val == '' then return 'x' end
    local srv_host = normalize_host(host_val)
    local ref_host = ref_val:lower():match('^https?://([^/?#]+)')
    if not ref_host then return 'x' end
    ref_host = normalize_host(ref_host)
    return (ref_host == srv_host) and 's' or 'x'
end

-- ---- Cookie fields builder -------------------------------------------------

-- Returns a sorted string of first-char initials of cookie field names.
local function get_cookie_fields(hdrs)
    local cookie_val = hdrs['cookie']
    if not cookie_val or cookie_val == '' then return 'nil' end
    local chars = {}
    for pair in (cookie_val .. ';'):gmatch('([^;]*);') do
        local name = pair:match('^%s*([^=%s]+)')
        if name and #name > 0 and #chars < MAX_PARAMS then
            chars[#chars + 1] = name:sub(1, 1):lower()
        end
    end
    if #chars == 0 then return 'nil' end
    table.sort(chars)
    return table.concat(chars)
end

-- ---- Phase 1: Capture request data (http-req) ------------------------------

local function capture_request(txn)
    -- Fetch all request-phase data now; the request buffer will be freed
    -- before the http-res phase runs.
    local raw_hdrs = txn.sf:req_hdrs() or ''
    txn:set_var('txn.req_fp.hdrs', raw_hdrs)
    txn:set_var('txn.req_fp.path',   txn.f:path()    or '/')
    txn:set_var('txn.req_fp.method', txn.f:method()  or 'ge')
    txn:set_var('txn.req_fp.query',  txn.f:query()   or '')
    txn:set_var('txn.req_fp.ver',    txn.f:req_ver() or '1.1')
end

-- ---- Phase 2: Build fingerprint (http-res) ----------------------------------

local function build_fingerprint(txn)
    -- Retrieve request data captured in phase 1.
    local path   = txn:get_var('txn.req_fp.path')   or '/'
    local method = txn:get_var('txn.req_fp.method') or 'ge'
    local query  = txn:get_var('txn.req_fp.query')  or ''
    local ver    = txn:get_var('txn.req_fp.ver')    or '1.1'
    local raw_hdrs = txn:get_var('txn.req_fp.hdrs') or ''

    -- Response-phase data (available now).
    local status = txn.f:status() or 0

    local parts = {}
    local function add(v) parts[#parts + 1] = tostring(v) end

    -- 1. path_b62
    add(base62_encode(path))

    -- 2. method2
    add(method:sub(1, 2):lower())

    -- 3. http_ver
    add(http_ver_code(ver))

    -- 4. path_depth
    add(string.format('%02d', get_path_depth(path)))

    -- 5-7. param_keys / param_types / param_lens
    local params = parse_params(query)
    if #params == 0 then
        add('nil'); add('nil'); add('0')
    else
        local keys, types, lens = {}, {}, {}
        for _, p in ipairs(params) do
            keys[#keys + 1]  = p.name:sub(1, 1)
            types[#types + 1] = detect_type(p.value)
            lens[#lens + 1]  = tostring(#p.value)
        end
        add(table.concat(keys))
        add(table.concat(types))
        add(table.concat(lens, '-'))
    end

    -- Parse request headers from the captured raw block.
    local hdr_count, hdr_list, hdrs = parse_headers(raw_hdrs)

    -- 8. req_ctype
    add(get_req_ctype(hdrs))

    -- 9-10. hdr_count / hdr_list
    add(string.format('%02d', hdr_count))
    add(hdr_list)

    -- 11. accept_lang
    add(get_accept_lang(hdrs))

    -- 12. auth_type
    add(get_auth_type(hdrs))

    -- 13. cookie
    local cookie_val = hdrs['cookie']
    add((cookie_val and cookie_val ~= '') and 'c' or 'n')

    -- 14. cookie_fields
    add(get_cookie_fields(hdrs))

    -- 15. referer
    add(get_referer_flag(hdrs))

    -- 16. status
    add(status)

    -- 17. body_bytes (response Content-Length only).
    -- See haproxy/lua/req_fp.lua for full rationale: we do NOT fall back to
    -- res.body_len because it forces HAProxy to buffer the entire response
    -- body, causing timeouts on large concurrent responses.
    local res_raw = txn.f:res_hdrs() or ''
    local _, _, res_hdrs = parse_headers(res_raw)
    local cl_val = res_hdrs['content-length']
    local bytes  = cl_val and (tonumber(cl_val) or 0) or 0
    add(bytes > 0 and bytes or 0)

    return table.concat(parts, '_')
end

-- ---- Action registration ---------------------------------------------------

-- Phase 1: capture request data before the request buffer is freed.
core.register_action('req_fp_capture', { 'http-req' }, function(txn)
    local ok, err = pcall(capture_request, txn)
    if not ok then
        core.Warning("req_fp.lua: capture failed: " .. tostring(err))
    end
end)

-- Phase 2: build the fingerprint using captured request data + response data.
core.register_action('req_fp', { 'http-res' }, function(txn)
    local ok, result = pcall(build_fingerprint, txn)
    if not ok then
        core.Warning("req_fp.lua: fingerprint failed: " .. tostring(result))
        txn:set_var('txn.req_fp', 'err')
    else
        txn:set_var('txn.req_fp', result)
    end
end)
