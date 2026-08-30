-- ACME HTTP-01 challenge file server.
-- Reads challenge token files from the shared webroot volume at request time
-- so acme.sh --webroot can write them dynamically during issuance without
-- requiring a HAProxy reload.
--
-- Registered fetches:
--   lua.acme_challenge_file  — returns file content or nil if not found
--
-- The webroot path is read from the txn.acme_webroot variable (set by the
-- generated HAProxy config). The challenge token is read from txn.acme_file.

local function read_challenge_file(txn)
    local token = txn:get_var("txn.acme_file")
    if not token or token == "" then
        return nil
    end
    -- Reject anything that isn't a valid ACME challenge token (base64url:
    -- alphanumeric, hyphen, underscore). This prevents path traversal.
    if token:match("[^%w_-]") then
        return nil
    end
    local webroot = txn:get_var("txn.acme_webroot")
    if not webroot or webroot == "" then
        return nil
    end
    local path = webroot .. "/.well-known/acme-challenge/" .. token
    local f = io.open(path, "rb")
    if not f then
        return nil
    end
    local content = f:read("*all")
    f:close()
    if not content or content == "" then
        return nil
    end
    return content
end

core.register_fetches("acme_challenge_file", read_challenge_file)
