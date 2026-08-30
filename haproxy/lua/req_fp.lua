--[[
  SPDX-License-Identifier: Apache-2.0 WITH Commons-Clause
  Copyright (c) 2026 Austin Kauffman

  haproxy_req_fp - HAProxy request fingerprint module (v2)

  Registers two Lua actions:
    - "req_fp_capture" (http-req phase) — captures request data into txn vars
    - "req_fp"          (http-res phase) — builds the 17-field fingerprint
                                              using captured request data +
                                              response data, stores in txn.req_fp

  Two-phase design: HAProxy frees the request buffer before the http-res
  phase, so request headers/query/etc. are captured in http-req and stored
  in transaction variables for use in http-res.

  Uses txn.sf: (string sample-fetches) for maximum portability.

  v2 changes (API Armor + req_fp_parse_body):
    - When txn.api_body is set (API Armor conditional body buffering active),
      OR txn.req_fp_body is set (req_fp_parse_body enabled independently),
      the body is parsed for params:
        application/json          → top-level field names + types + lengths
        application/x-www-form-…  → parsed like query string
        application/graphql       → no param extraction (Rust module handles it)
      Body params are MERGED into the existing param_keys/param_types/param_lens
      fields alongside query params. This is a BREAKING CHANGE to the fingerprint
      format when body parsing is enabled — existing baselines must be re-learned.
      When neither txn var is set (body parsing disabled), behavior is identical
      to v1 (query-only).
    - Subfield txn vars are set for Security Rules access:
        Request-phase:  txn.req_fp.ctype, .param_keys, .param_types, .param_lens,
                        .path_depth, .method, .hdr_count, .hdr_list, .auth_type,
                        .cookie, .referer, .body_depth
        Response-phase: txn.req_fp.status, .body_bytes, .full (complete fingerprint)

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
                    v2: includes body params when API Armor buffers the body
    param_types   - type code per value, same order; "nil" if none
                    v2: includes body param types when API Armor buffers the body
    param_lens    - decoded value lengths, dash-separated; "0" if none
                    v2: includes body param lengths when API Armor buffers the body
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

-- ---- JSON body parser (hand-rolled, minimal) -------------------------------

-- Parses a JSON string into a Lua value (table, string, number, bool, nil).
-- Supports objects, arrays, strings, numbers, true, false, null.
-- This is a minimal parser sufficient for extracting top-level field names
-- and types from API request bodies. It does NOT aim for full JSON spec
-- compliance (no unicode escape handling, no number edge cases).
local function json_skip_whitespace(s, i)
    while i <= #s do
        local c = s:sub(i, i)
        if c == ' ' or c == '\t' or c == '\n' or c == '\r' then
            i = i + 1
        else
            break
        end
    end
    return i
end

local function json_parse_string(s, i)
    -- s[i] == '"'
    i = i + 1
    local buf = {}
    while i <= #s do
        local c = s:sub(i, i)
        if c == '"' then
            return table.concat(buf), i + 1
        elseif c == '\\' and i + 1 <= #s then
            local next_c = s:sub(i + 1, i + 1)
            if next_c == 'n' then buf[#buf + 1] = '\n'
            elseif next_c == 't' then buf[#buf + 1] = '\t'
            elseif next_c == 'r' then buf[#buf + 1] = '\r'
            elseif next_c == '"' then buf[#buf + 1] = '"'
            elseif next_c == '\\' then buf[#buf + 1] = '\\'
            elseif next_c == '/' then buf[#buf + 1] = '/'
            else buf[#buf + 1] = next_c end
            i = i + 2
        else
            buf[#buf + 1] = c
            i = i + 1
        end
    end
    return nil, i  -- unterminated
end

local json_parse_value  -- forward declare for recursion

local function json_parse_object(s, i)
    -- s[i] == '{'
    i = i + 1
    local obj = {}
    i = json_skip_whitespace(s, i)
    if i <= #s and s:sub(i, i) == '}' then return obj, i + 1 end
    while i <= #s do
        i = json_skip_whitespace(s, i)
        if s:sub(i, i) ~= '"' then return nil, i end
        local key, next_i = json_parse_string(s, i)
        if not key then return nil, i end
        i = json_skip_whitespace(s, next_i)
        if s:sub(i, i) ~= ':' then return nil, i end
        i = json_skip_whitespace(s, i + 1)
        local val
        val, i = json_parse_value(s, i)
        if val == nil and s:sub(i, i) ~= 'n' then
            -- null is valid; other parse failures are errors
            -- but we store nil for null, so check context
        end
        obj[key] = val
        i = json_skip_whitespace(s, i)
        local c = s:sub(i, i)
        if c == ',' then
            i = i + 1
        elseif c == '}' then
            return obj, i + 1
        else
            return nil, i
        end
    end
    return nil, i
end

local function json_parse_array(s, i)
    -- s[i] == '['
    i = i + 1
    local arr = {}
    i = json_skip_whitespace(s, i)
    if i <= #s and s:sub(i, i) == ']' then return arr, i + 1 end
    while i <= #s do
        i = json_skip_whitespace(s, i)
        local val
        val, i = json_parse_value(s, i)
        arr[#arr + 1] = val
        i = json_skip_whitespace(s, i)
        local c = s:sub(i, i)
        if c == ',' then
            i = i + 1
        elseif c == ']' then
            return arr, i + 1
        else
            return nil, i
        end
    end
    return nil, i
end

local function json_parse_number(s, i)
    local start = i
    if s:sub(i, i) == '-' then i = i + 1 end
    while i <= #s do
        local c = s:sub(i, i)
        if c:match('[0-9eE+.-]') then
            i = i + 1
        else
            break
        end
    end
    local num_str = s:sub(start, i - 1)
    local num = tonumber(num_str)
    if not num then return nil, i end
    return num, i
end

json_parse_value = function(s, i)
    i = json_skip_whitespace(s, i)
    if i > #s then return nil, i end
    local c = s:sub(i, i)
    if c == '{' then return json_parse_object(s, i)
    elseif c == '[' then return json_parse_array(s, i)
    elseif c == '"' then return json_parse_string(s, i)
    elseif c == '-' or c:match('[0-9]') then return json_parse_number(s, i)
    elseif s:sub(i, i + 3) == 'true' then return true, i + 4
    elseif s:sub(i, i + 4) == 'false' then return false, i + 5
    elseif s:sub(i, i + 3) == 'null' then return nil, i + 4
    end
    return nil, i
end

-- Parse a JSON string. Returns (value, error).
local function parse_json(s)
    if not s or #s == 0 then return nil, 'empty' end
    local val, i = json_parse_value(s, 1)
    if val == nil and s:sub(1, 4) ~= 'null' then
        return nil, 'parse error'
    end
    return val, nil
end

-- ---- JSON body field extraction ---------------------------------------------

-- JSON type code mapping (extends the query string type codes)
local function json_type_code(val)
    if val == nil then return 'n' end  -- null
    if type(val) == 'boolean' then return 'b' end
    if type(val) == 'number' then
        if math.floor(val) == val then return 'i' end
        return 'f'
    end
    if type(val) == 'string' then return 's' end
    if type(val) == 'table' then
        -- Check if it's an array (sequential integer keys starting at 1)
        local is_array = true
        local count = 0
        for k, _ in pairs(val) do
            count = count + 1
            if type(k) ~= 'number' then is_array = false break end
        end
        if is_array and count > 0 then return 'l' end
        return 'o'  -- object
    end
    return 's'
end

-- Compute max nesting depth of a JSON value (objects/arrays).
local function json_depth(val, current)
    current = current or 0
    if type(val) ~= 'table' then return current end
    local max_d = current
    for _, v in pairs(val) do
        local d = json_depth(v, current + 1)
        if d > max_d then max_d = d end
    end
    return max_d
end

-- Extract top-level field names and types from a parsed JSON object.
-- Returns (params_array, depth) where params_array is sorted by name.
local function extract_json_fields(obj)
    if type(obj) ~= 'table' then return {}, 0 end
    local params = {}
    local depth = json_depth(obj)
    -- Check if it's an array (no named fields)
    local is_array = true
    local count = 0
    for k, _ in pairs(obj) do
        count = count + 1
        if type(k) ~= 'number' then is_array = false break end
    end
    if is_array then return {}, depth end  -- arrays have no named fields
    for k, v in pairs(obj) do
        if type(k) == 'string' and #params < MAX_PARAMS then
            -- For the value length, use a string representation length
            local val_str = tostring(v)
            if type(v) == 'string' then val_str = v end
            params[#params + 1] = { name = k, value = val_str }
        end
    end
    table.sort(params, function(a, b) return a.name < b.name end)
    return params, depth
end

-- Detect content type from headers and return 'json', 'form', 'graphql', or nil
local function detect_body_ctype(hdrs)
    local ct = hdrs['content-type']
    if not ct then return nil end
    ct = ct:lower()
    if ct:find('application/json') or ct:find('application/%+%w*json') then return 'json' end
    if ct:find('application/x%-www%-form%-urlencoded') then return 'form' end
    if ct:find('application/graphql') then return 'graphql' end
    return nil
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
    local path   = txn.f:path()    or '/'
    local method = txn.f:method()  or 'ge'
    local query  = txn.f:query()   or ''
    local ver    = txn.f:req_ver() or '1.1'

    txn:set_var('txn.req_fp.hdrs', raw_hdrs)
    txn:set_var('txn.req_fp.path', path)
    txn:set_var('txn.req_fp.method', method)
    txn:set_var('txn.req_fp.query', query)
    txn:set_var('txn.req_fp.ver', ver)

    -- Parse headers now for request-phase subfield txn vars.
    local hdr_count, hdr_list, hdrs = parse_headers(raw_hdrs)
    local ctype  = get_req_ctype(hdrs)
    local alang  = get_accept_lang(hdrs)
    local atype  = get_auth_type(hdrs)
    local cookie = hdrs['cookie']
    local cflag  = (cookie and cookie ~= '') and 'c' or 'n'
    local cfields = get_cookie_fields(hdrs)
    local referer = get_referer_flag(hdrs)
    local pdepth  = get_path_depth(path)

    -- v2: Parse request body when API Armor has buffered it (txn.api_body)
    -- or when req_fp_parse_body has buffered it independently (txn.req_fp_body).
    -- Body params are merged with query params into the same param_keys/
    -- param_types/param_lens fields. When neither txn var is set (body parsing
    -- disabled), falls back to query-only (v1 behavior).
    local body_depth = 0
    local all_params = parse_params(query)

    local api_body = txn:get_var('txn.api_body')
    if not api_body or #api_body == 0 then
        api_body = txn:get_var('txn.req_fp_body')
    end
    if api_body and #api_body > 0 then
        local bctype = detect_body_ctype(hdrs)
        if bctype == 'json' then
            local parsed, err = parse_json(api_body)
            if parsed and type(parsed) == 'table' then
                local body_params, bd = extract_json_fields(parsed)
                body_depth = bd
                -- Merge body params with query params
                for _, p in ipairs(body_params) do
                    if #all_params < MAX_PARAMS then
                        all_params[#all_params + 1] = p
                    end
                end
                table.sort(all_params, function(a, b) return a.name < b.name end)
            end
        elseif bctype == 'form' then
            local form_params = parse_params(api_body)
            for _, p in ipairs(form_params) do
                if #all_params < MAX_PARAMS then
                    all_params[#all_params + 1] = p
                end
            end
            table.sort(all_params, function(a, b) return a.name < b.name end)
        elseif bctype == 'graphql' then
            -- GraphQL body is a query string, not key-value params.
            -- Shallow extraction: treat the whole body as a single "query" param.
            -- The Rust graphql module does deeper analysis; this is just for req_fp.
            -- We skip param extraction for GraphQL bodies (the query hash from the
            -- Rust module is the primary signal).
        end
    end

    -- Build param subfield strings from merged params.
    local param_keys, param_types, param_lens
    if #all_params == 0 then
        param_keys  = 'nil'
        param_types = 'nil'
        param_lens  = '0'
    else
        local keys, types, lens = {}, {}, {}
        for _, p in ipairs(all_params) do
            keys[#keys + 1]  = p.name:sub(1, 1)
            types[#types + 1] = detect_type(p.value)
            lens[#lens + 1]  = tostring(#p.value)
        end
        param_keys  = table.concat(keys)
        param_types = table.concat(types)
        param_lens  = table.concat(lens, '-')
    end

    -- Store merged params for build_fingerprint to use.
    txn:set_var('txn.req_fp.params_keys', param_keys)
    txn:set_var('txn.req_fp.params_types', param_types)
    txn:set_var('txn.req_fp.params_lens', param_lens)

    -- Set request-phase subfield txn vars for Security Rules access.
    txn:set_var('txn.req_fp.ctype', ctype)
    txn:set_var('txn.req_fp.param_keys', param_keys)
    txn:set_var('txn.req_fp.param_types', param_types)
    txn:set_var('txn.req_fp.param_lens', param_lens)
    txn:set_var('txn.req_fp.path_depth', string.format('%02d', pdepth))
    txn:set_var('txn.req_fp.method', method)
    txn:set_var('txn.req_fp.hdr_count', string.format('%02d', hdr_count))
    txn:set_var('txn.req_fp.hdr_list', hdr_list)
    txn:set_var('txn.req_fp.auth_type', atype)
    txn:set_var('txn.req_fp.cookie', cflag)
    txn:set_var('txn.req_fp.referer', referer)
    txn:set_var('txn.req_fp.body_depth', tostring(body_depth))
end

-- ---- Phase 2: Build fingerprint (http-res) ----------------------------------

local function build_fingerprint(txn)
    -- Retrieve request data captured in phase 1.
    local path   = txn:get_var('txn.req_fp.path')   or '/'
    local method = txn:get_var('txn.req_fp.method') or 'ge'
    local ver    = txn:get_var('txn.req_fp.ver')    or '1.1'
    local raw_hdrs = txn:get_var('txn.req_fp.hdrs') or ''

    -- Retrieve pre-computed merged params from capture_request (v2).
    -- These include both query string AND body params (when API Armor buffered
    -- the body). Falls back to re-parsing query-only if capture didn't run.
    local param_keys  = txn:get_var('txn.req_fp.params_keys')
    local param_types = txn:get_var('txn.req_fp.params_types')
    local param_lens  = txn:get_var('txn.req_fp.params_lens')

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

    -- 5-7. param_keys / param_types / param_lens (merged query + body)
    if param_keys and param_keys ~= '' then
        add(param_keys)
        add(param_types or 'nil')
        add(param_lens or '0')
    else
        -- Fallback: re-parse query only (v1 behavior when capture didn't set vars)
        local query = txn:get_var('txn.req_fp.query') or ''
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

    -- 17. body_bytes (response Content-Length, with res.body_len fallback)
    -- NOTE: res.hdrs captures the backend's response headers as received by
    -- HAProxy, before HAProxy buffers the body and may inject Content-Length.
    -- If the backend uses chunked encoding or sends no Content-Length, this
    -- field will be 0 even though the client receives a Content-Length header
    -- (added by HAProxy's response buffering). As a fallback, when the parsed
    -- Content-Length is 0/absent we use res.body_len, which returns the length
    -- of the response body HAProxy has buffered so far. This is reliable when
    -- the body has already been buffered (e.g. small responses, or when other
    -- http-response rules force buffering) but may still be 0 for streamed
    -- responses; no wait-for-body directive is emitted to avoid changing the
    -- proxy's buffering/streaming behavior.
    local res_raw = txn.f:res_hdrs() or ''
    local _, _, res_hdrs = parse_headers(res_raw)
    local cl_val = res_hdrs['content-length']
    local bytes  = cl_val and (tonumber(cl_val) or 0) or 0
    if bytes <= 0 then
        local body_len = txn.f:res_body_len() or 0
        if body_len > 0 then bytes = body_len end
    end
    add(bytes > 0 and bytes or 0)

    local fingerprint = table.concat(parts, '_')

    -- Set response-phase subfield txn vars for Security Rules access.
    txn:set_var('txn.req_fp.status', tostring(status))
    txn:set_var('txn.req_fp.body_bytes', tostring(bytes > 0 and bytes or 0))
    txn:set_var('txn.req_fp.full', fingerprint)

    return fingerprint
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
