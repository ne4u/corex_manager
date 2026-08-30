-- ja4.lua — JA4 TLS fingerprint sample-fetch for HAProxy
--
-- Computes the JA4 fingerprint from the TLS ClientHello by parsing the raw
-- cipher suite, extension, and signature-algorithm lists exposed by HAProxy's
-- ssl_fc_*_bin fetches (HAProxy 3.1+). The algorithm follows the FoxIO JA4
-- specification: https://github.com/FoxIO-LLC/ja4
--
-- Adapted from the FriendlyCaptcha/ja4-haproxy action-based implementation
-- (https://github.com/FriendlyCaptcha/ja4-haproxy, MPL 2.0) into a sample-fetch
-- so it can be referenced inline in ACLs, e.g.:
--   { lua.ja4_fp -f /path/to/ja4_list.lst }
--
-- JA4 Algorithm: Copyright (c) 2023 FoxIO (BSD 3-Clause License)
--
-- Requirements:
--   - HAProxy 3.1+ built with Lua support (lua5.4 runtime)
--   - `tune.ssl.capture-buffer-size` set in the global section (e.g. 336)
--     so that ssl_fc_cipherlist_bin / ssl_fc_extlist_bin / ssl_fc_sigalgs_bin
--     return data. Without it the binary fetches are empty and the fingerprint
--     degenerates to all-zero hashes.
--   - `tune.lua.bool-sample-conversion normal` set before lua-load so that
--     ssl_fc_has_sni returns a real boolean.
--   - TLS connection (returns empty string on plaintext listeners)
--
-- The JA4 fingerprint format:
--   {proto}{version}{sni}{cipher_count}{ext_count}{alpn}_{cipher_hash}_{ext_hash}
-- Example: t13d1516h2_8daaf6152771_b186095e22b6

-- Fallback fingerprint used when an error occurs during computation.
local FALLBACK_FINGERPRINT = "t00i000000_000000000000_000000000000"

-- Lookup table for IANA TLS params. Computed once on load (not every request).
local HEX_LOOKUP = {}

-- 0x0000 to 0x0a00 :: Base range
for i = 0, 2560 do
    HEX_LOOKUP[i] = string.format("%04x", i)
end
-- 0x1300 to 0x13ff :: TLS 1.3 cipher suites
for i = 4864, 5119 do
    HEX_LOOKUP[i] = string.format("%04x", i)
end
-- 0xc000 to 0xc1ff :: EC/ARIA/Camellia/CCM/GOSTR cipher suites
for i = 49152, 49663 do
    HEX_LOOKUP[i] = string.format("%04x", i)
end
-- 0xcc00 to 0xccff :: ChaCha20 cipher suites
for i = 52224, 52479 do
    HEX_LOOKUP[i] = string.format("%04x", i)
end
-- 0xd000 to 0xd0ff :: ECDHE-PSK cipher suites
for i = 53248, 53503 do
    HEX_LOOKUP[i] = string.format("%04x", i)
end
-- 0x5600 :: TLS_FALLBACK_SCSV
HEX_LOOKUP[22016] = "5600"
-- Isolated high extension values
HEX_LOOKUP[64768] = "fd00" -- ech_outer_extensions
HEX_LOOKUP[65037] = "fe0d" -- encrypted_client_hello
HEX_LOOKUP[65281] = "ff01" -- renegotiation_info

local TLS_VERSIONS = {
    [0xfeff] = "d1", -- DTLS 1.0
    [0xfefd] = "d2", -- DTLS 1.2
    [0xfefc] = "d3", -- DTLS 1.3
    [0x0304] = "13", -- TLSv1.3
    [0x0303] = "12", -- TLSv1.2
    [0x0302] = "11", -- TLSv1.1
    [0x0301] = "10", -- TLSv1.0
    [0x0300] = "s3", -- SSLv3
    [0x0002] = "s2", -- SSLv2
}

local DTLS_VERSIONS = {
    [0xfeff] = true, -- DTLS 1.0
    [0xfefd] = true, -- DTLS 1.2
    [0xfefc] = true, -- DTLS 1.3
}

-- Extensions excluded from the JA4_c hash (SNI=0, ALPN=16).
local EXCLUDED_EXTENSIONS = {
    [0] = true,
    [16] = true,
}

-- Zero-padded 2-digit lookup for cipher/extension counts (0-99).
local PAD2 = {}
for i = 0, 99 do
    PAD2[i] = string.format("%02d", i)
end

local function sha256_truncated(c, input)
    -- lower() is necessary as txn.c:hex returns uppercase characters
    return string.lower(string.sub(c:hex(c:digest(input, "sha256")), 1, 12))
end

-- Core JA4 computation. Returns the 36-char fingerprint string.
-- The `1` argument passed to the ssl_fc_*_bin fetches enables GREASE filtering.
local function compute_ja4(txn)
    --------------------------------------------
    -- Detect protocol (t=TLS, d=DTLS, q=QUIC)
    --------------------------------------------
    local protocol_id = txn.f:ssl_fc_protocol_hello_id()
    local is_dtls = DTLS_VERSIONS[protocol_id]
    local protocol
    if is_dtls then
        protocol = "d"
    else
        local http_version = txn.f:req_ver()
        if http_version and string.sub(http_version, 1, 1) == "3" then
            protocol = "q"
        else
            protocol = "t"
        end
    end

    -------------------------------------------------------------------------
    -- Detect TLS version from supported_versions (fallback to protocol_id)
    -------------------------------------------------------------------------
    local version
    local supported_versions = txn.f:ssl_fc_supported_versions_bin(1)
    if supported_versions and #supported_versions >= 2 then
        local newest_version = nil
        for i = 1, #supported_versions - 1, 2 do
            -- `>` means big-endian byte order. `I2` means unsigned 2-byte int.
            local ver = string.unpack(">I2", supported_versions, i)
            if TLS_VERSIONS[ver] then
                if
                    not newest_version
                    or (is_dtls and ver < newest_version)
                    or (not is_dtls and ver > newest_version)
                then
                    newest_version = ver
                end
            end
        end
        if newest_version then
            version = TLS_VERSIONS[newest_version]
        end
    end
    if not version then
        version = TLS_VERSIONS[protocol_id] or "00"
    end

    --------------------------------------------------------------
    -- Extract ALPN (first and last char of negotiated protocol)
    --------------------------------------------------------------
    local alpn
    local alpn_value = txn.f:ssl_fc_alpn()
    if not alpn_value or alpn_value == "" then
        alpn = "00"
    else
        local first_char, last_char = string.sub(alpn_value, 1, 1), string.sub(alpn_value, -1)
        local b1 = string.byte(first_char)
        local b2 = string.byte(last_char)
        local alnum1 = (b1 >= 48 and b1 <= 57) or (b1 >= 65 and b1 <= 90) or (b1 >= 97 and b1 <= 122)
        local alnum2 = (b2 >= 48 and b2 <= 57) or (b2 >= 65 and b2 <= 90) or (b2 >= 97 and b2 <= 122)
        if not alnum1 or not alnum2 then
            first_char = string.sub(string.format("%02x", b1), 1, 1)
            last_char = string.sub(string.format("%02x", b2), -1)
        end
        alpn = first_char .. last_char
    end

    ------------------
    -- Parse ciphers
    ------------------
    local ciphers = {}
    local cipher_bin = txn.f:ssl_fc_cipherlist_bin(1)
    if cipher_bin and #cipher_bin >= 2 then
        local count = 0
        for i = 1, #cipher_bin - 1, 2 do
            count = count + 1
            local value = string.unpack(">I2", cipher_bin, i)
            ciphers[count] = HEX_LOOKUP[value] or string.format("%04x", value)
        end
        table.sort(ciphers)
    end

    ---------------------
    -- Parse extensions
    ---------------------
    local extensions = {}
    local extension_count = 0
    local ext_bin = txn.f:ssl_fc_extlist_bin(1)
    if ext_bin and #ext_bin >= 2 then
        local count = 0
        for i = 1, #ext_bin - 1, 2 do
            extension_count = extension_count + 1
            local value = string.unpack(">I2", ext_bin, i)
            local hex = HEX_LOOKUP[value] or string.format("%04x", value)
            if not EXCLUDED_EXTENSIONS[value] then
                count = count + 1
                extensions[count] = hex
            end
        end
        table.sort(extensions)
    end

    -------------------------------
    -- Parse signature algorithms
    -------------------------------
    local signature_algorithms = {}
    local sigalg_bin = txn.f:ssl_fc_sigalgs_bin(1)
    if sigalg_bin and #sigalg_bin >= 2 then
        local count = 0
        for i = 1, #sigalg_bin - 1, 2 do
            count = count + 1
            local value = string.unpack(">I2", sigalg_bin, i)
            signature_algorithms[count] = HEX_LOOKUP[value] or string.format("%04x", value)
        end
    end

    local cipher_list = table.concat(ciphers, ",")
    local extension_list = table.concat(extensions, ",")
    local signature_algorithm_list = table.concat(signature_algorithms, ",")

    -----------------------------------
    -- Prepare JA4_a (various fields)
    -----------------------------------
    local has_sni = txn.f:ssl_fc_has_sni()

    -- By default HAProxy converts bools to ints when passing them to Lua.
    -- One Lua gotcha is that 0 is truthy! With `tune.lua.bool-sample-conversion
    -- normal` (HAProxy 3.1+) we get a real bool. We handle both cases.
    local fingerprint_prefix = protocol
        .. version
        .. ((has_sni == true or has_sni == 1) and "d" or "i")
        .. PAD2[math.min(#ciphers, 99)]
        .. PAD2[math.min(extension_count, 99)]
        .. alpn

    ----------------------------------------------------
    -- Prepare JA4_b (truncated hash of cipher suites)
    ----------------------------------------------------
    local cipher_hash
    if cipher_list == "" then
        cipher_hash = "000000000000"
    else
        cipher_hash = sha256_truncated(txn.c, cipher_list)
    end

    --------------------------------------------------------------------
    -- Prepare JA4_c (truncated hash of extensions and sig algorithms)
    --------------------------------------------------------------------
    local extension_hash
    if extension_list == "" then
        extension_hash = "000000000000"
    elseif signature_algorithm_list ~= "" then
        local hash_input = extension_list .. "_" .. signature_algorithm_list
        extension_hash = sha256_truncated(txn.c, hash_input)
    else
        extension_hash = sha256_truncated(txn.c, extension_list)
    end

    return fingerprint_prefix .. "_" .. cipher_hash .. "_" .. extension_hash
end

-- Register the sample-fetch function "ja4_fp".
-- Used in HAProxy config as: lua.ja4_fp  (e.g. { lua.ja4_fp -f ja4.lst })
core.register_fetches("ja4_fp", function(txn)
    -- Plaintext listener: no TLS, no fingerprint.
    local ssl_fc = txn.f:ssl_fc()
    if not ssl_fc then
        return ""
    end

    -- pcall so an uncaught Lua error doesn't 50x the request; return the
    -- fallback fingerprint so downstream rules still get a well-formed value.
    local success, result = pcall(compute_ja4, txn)
    if not success then
        core.Warning("ja4.lua: fingerprint failed: " .. tostring(result))
        return FALLBACK_FINGERPRINT
    end
    return result
end)
