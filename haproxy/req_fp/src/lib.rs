//! HAProxy request fingerprint module — Rust Lua module.
//!
//! Registers two Lua actions:
//!   - "req_fp_capture" (http-req phase) — captures request data into txn vars
//!   - "req_fp"          (http-res phase) — builds the 17-field fingerprint
//!                                              using captured request data +
//!                                              response data, stores in txn.req_fp
//!
//! Two-phase design: HAProxy frees the request buffer before the http-res
//! phase, so request headers/query/etc. are captured in http-req and stored
//! in transaction variables for use in http-res.
//!
//! Fingerprint format (17 underscore-separated fields):
//!   {path_b62}_{method2}_{http_ver}_{path_depth}_
//!   {param_keys}_{param_types}_{param_lens}_{req_ctype}_
//!   {hdr_count}_{hdr_list}_{accept_lang}_{auth_type}_
//!   {cookie}_{cookie_fields}_{referer}_
//!   {status}_{body_bytes}
//!
//! See the Lua predecessor (haproxy/lua/req_fp.lua) for the full field
//! documentation. This Rust port preserves byte-exact fingerprint
//! compatibility with the Lua v2 implementation.

use std::collections::HashMap;

use haproxy_api::{Action, Core, LogLevel, Txn};
use mlua::prelude::*;
use once_cell::sync::Lazy;
use regex::Regex;

// ---- Constants -------------------------------------------------------------

const MAX_PARAMS: usize = 32;
const PATH_MAX: usize = 2048;
const B62_CHARS: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

// ---- Pre-compiled regexes for value type detection -------------------------

static RE_DATETIME: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}").unwrap()
});
static RE_DT_TZ: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[Zz]$|[\+\-]\d{2}:?\d{2}$").unwrap()
});
static RE_DATE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\d{4}-\d{2}-\d{2}$").unwrap());
static RE_TIME: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\d{2}:\d{2}:\d{2}").unwrap());
static RE_INT: Lazy<Regex> = Lazy::new(|| Regex::new(r"^-?\d+$").unwrap());
static RE_FLOAT: Lazy<Regex> = Lazy::new(|| Regex::new(r"^-?\d*\.\d+$").unwrap());

// ---- Base62 encoder --------------------------------------------------------

/// Treats the bytes of `s` as a big-endian integer and encodes it in base62.
/// Caps input at PATH_MAX bytes. Returns "0" for empty input.
fn base62_encode(s: &[u8]) -> String {
    let bytes = if s.len() > PATH_MAX { &s[..PATH_MAX] } else { s };
    if bytes.is_empty() {
        return "0".to_string();
    }

    // n is a Vec of byte-width "digits" representing the big-endian integer.
    // Long division by 62 is performed until the value reaches zero.
    let mut n: Vec<u8> = bytes.to_vec();
    let mut out: Vec<u8> = Vec::new();

    while !n.is_empty() {
        let mut rem: u32 = 0;
        let mut new_n: Vec<u8> = Vec::with_capacity(n.len());
        for &digit in &n {
            let val = rem * 256 + digit as u32;
            let q = val / 62;
            rem = val % 62;
            if q > 0 || !new_n.is_empty() {
                new_n.push(q as u8);
            }
        }
        out.push(B62_CHARS[rem as usize]);
        n = new_n;
    }
    out.reverse();
    // Safety: B62_CHARS is ASCII, so the output is valid UTF-8.
    String::from_utf8(out).unwrap_or_else(|_| "0".to_string())
}

// ---- Value type detector ---------------------------------------------------

/// Detect the value type code for a string value.
/// Type codes: int(i) float(f) string(s) char(c) bool(b) time(t)
///             date(d) datetime+tz(z) empty(e) object(o) list(l)
fn detect_type(v: &str) -> char {
    if v.is_empty() {
        return 'e';
    }
    let first = v.chars().next().unwrap();
    if first == '{' {
        return 'o';
    }
    if first == '[' {
        return 'l';
    }
    let lv = v.to_ascii_lowercase();
    if lv == "true" || lv == "false" {
        return 'b';
    }
    // datetime with timezone (must check before plain date)
    if RE_DATETIME.is_match(v) {
        if RE_DT_TZ.is_match(v) {
            return 'z';
        }
    }
    if RE_DATE.is_match(v) {
        return 'd';
    }
    if RE_TIME.is_match(v) {
        return 't';
    }
    if RE_INT.is_match(v) {
        return 'i';
    }
    if RE_FLOAT.is_match(v) {
        return 'f';
    }
    if v.chars().count() == 1 {
        return 'c';
    }
    's'
}

// ---- Query/body parameter parser -------------------------------------------

/// Parses a query-string or form-urlencoded byte string into a sorted array
/// of (name, value) pairs, capped at MAX_PARAMS entries.
fn parse_params(qs: &str) -> Vec<(String, String)> {
    if qs.is_empty() {
        return Vec::new();
    }
    let mut params: Vec<(String, String)> = Vec::new();
    // Use form_urlencoded for correct percent-decoding.
    for (key, value) in form_urlencoded::parse(qs.as_bytes()) {
        if !key.is_empty() && params.len() < MAX_PARAMS {
            params.push((key.into_owned(), value.into_owned()));
        }
    }
    params.sort_by(|a, b| a.0.cmp(&b.0));
    params
}

// ---- JSON body field extraction --------------------------------------------

/// Compute max nesting depth of a JSON value (objects/arrays).
fn json_depth(val: &serde_json::Value, current: u32) -> u32 {
    match val {
        serde_json::Value::Object(map) => {
            let mut max_d = current;
            for (_, v) in map {
                let d = json_depth(v, current + 1);
                if d > max_d {
                    max_d = d;
                }
            }
            max_d
        }
        serde_json::Value::Array(arr) => {
            let mut max_d = current;
            for v in arr {
                let d = json_depth(v, current + 1);
                if d > max_d {
                    max_d = d;
                }
            }
            max_d
        }
        _ => current,
    }
}

/// Stringify a JSON value for length measurement (matches Lua's tostring).
fn json_val_str(val: &serde_json::Value) -> String {
    match val {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        other => other.to_string(),
    }
}

/// Extract top-level field names and stringified values from a parsed JSON
/// object. Returns (params, depth) where params is sorted by name.
/// Arrays return empty params (no named fields).
fn extract_json_fields(obj: &serde_json::Value) -> (Vec<(String, String)>, u32) {
    let depth = json_depth(obj, 0);
    let map = match obj.as_object() {
        Some(m) => m,
        None => return (Vec::new(), depth), // arrays/scalars have no named fields
    };
    let mut params: Vec<(String, String)> = Vec::new();
    for (key, val) in map {
        if params.len() < MAX_PARAMS {
            params.push((key.clone(), json_val_str(val)));
        }
    }
    params.sort_by(|a, b| a.0.cmp(&b.0));
    (params, depth)
}

// ---- HTTP version mapper ---------------------------------------------------

fn http_ver_code(ver: &str) -> &str {
    match ver {
        "0.9" => "09",
        "1.0" => "10",
        "1.1" => "11",
        "2" | "2.0" => "20",
        "3" | "3.0" => "30",
        _ => "11",
    }
}

// ---- Path depth ------------------------------------------------------------

fn get_path_depth(path: &str) -> u32 {
    let count = path.matches('/').count() as u32;
    count.min(99)
}

// ---- Header parsing from raw header block ----------------------------------

/// Parses a raw HTTP header block (from req.hdrs or res.hdrs) into:
///   (count, sorted_initials, header_table)
/// header_table is a lowercased-name → first-value mapping.
/// Both req.hdrs and res.hdrs return header lines only (no request/status line).
fn parse_headers(raw: &str) -> (usize, String, HashMap<String, String>) {
    if raw.is_empty() {
        return (0, "nil".to_string(), HashMap::new());
    }

    let mut chars: Vec<char> = Vec::new();
    let mut hdrs: HashMap<String, String> = HashMap::new();

    for line in raw.split(|c| c == '\r' || c == '\n') {
        if line.is_empty() {
            continue;
        }
        // Header line: "Name: value"
        if let Some(colon_idx) = line.find(':') {
            let name = &line[..colon_idx];
            let value = line[colon_idx + 1..].trim_start();
            let lname = name.to_ascii_lowercase();
            // Only record the first occurrence (matches Lua's `if not hdrs[lname]`).
            if !hdrs.contains_key(&lname) {
                hdrs.insert(lname.clone(), value.to_string());
                if chars.len() < MAX_PARAMS {
                    if let Some(first_char) = lname.chars().next() {
                        chars.push(first_char);
                    }
                }
            }
        }
    }

    let count = chars.len().min(99);
    if count == 0 {
        return (0, "nil".to_string(), hdrs);
    }
    chars.sort();
    (count, chars.into_iter().collect(), hdrs)
}

// ---- Request Content-Type subtype ------------------------------------------

/// Returns first 4 lowercase alpha chars of the Content-Type subtype (after '/').
/// Falls back to full value if no '/'. Returns "0000" if header absent.
fn get_req_ctype(hdrs: &HashMap<String, String>) -> String {
    let val = match hdrs.get("content-type") {
        Some(v) if !v.is_empty() => v,
        _ => return "0000".to_string(),
    };
    // Extract subtype: text after '/', up to ';'
    let subtype = match val.find('/') {
        Some(idx) => &val[idx + 1..],
        None => val,
    };
    let subtype = match subtype.find(';') {
        Some(idx) => &subtype[..idx],
        None => subtype,
    };
    let mut out: String = subtype
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .take(4)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    while out.len() < 4 {
        out.push('0');
    }
    out
}

// ---- Accept-Language -------------------------------------------------------

/// Returns first 4 lowercase alpha chars of the primary language tag.
/// Stops at the first ',' or ';'. Returns "0000" if header absent.
fn get_accept_lang(hdrs: &HashMap<String, String>) -> String {
    let val = match hdrs.get("accept-language") {
        Some(v) if !v.is_empty() => v,
        _ => return "0000".to_string(),
    };
    let mut out: String = String::new();
    for c in val.chars() {
        if c == ',' || c == ';' {
            break;
        }
        if c.is_ascii_alphabetic() {
            out.push(c.to_ascii_lowercase());
            if out.len() == 4 {
                break;
            }
        }
    }
    while out.len() < 4 {
        out.push('0');
    }
    out
}

// ---- Authorization type ----------------------------------------------------

fn get_auth_type(hdrs: &HashMap<String, String>) -> char {
    let val = match hdrs.get("authorization") {
        Some(v) if !v.is_empty() => v,
        _ => return 'n',
    };
    let lv = val.to_ascii_lowercase();
    if lv.starts_with("basic") {
        'b'
    } else if lv.starts_with("bearer") {
        't'
    } else if lv.starts_with("digest") {
        'd'
    } else {
        'o'
    }
}

// ---- Referer classifier ----------------------------------------------------

/// Strips port from a host string and lowercases it.
fn normalize_host(h: &str) -> String {
    // Strip trailing :port
    let lower = h.to_ascii_lowercase();
    match lower.rfind(':') {
        Some(idx) => lower[..idx].to_string(),
        None => lower,
    }
}

fn get_referer_flag(hdrs: &HashMap<String, String>) -> char {
    let ref_val = match hdrs.get("referer") {
        Some(v) if !v.is_empty() => v,
        _ => return 'n',
    };
    let host_val = match hdrs.get("host") {
        Some(v) if !v.is_empty() => v,
        _ => return 'x',
    };
    let srv_host = normalize_host(host_val);
    // Extract host from the Referer URL: https?://([^/?#]+)
    let ref_lower = ref_val.to_ascii_lowercase();
    let after_scheme = if let Some(idx) = ref_lower.find("://") {
        &ref_lower[idx + 3..]
    } else {
        return 'x';
    };
    let ref_host_raw = match after_scheme.find(|c: char| c == '/' || c == '?' || c == '#') {
        Some(idx) => &after_scheme[..idx],
        None => after_scheme,
    };
    if ref_host_raw.is_empty() {
        return 'x';
    }
    let ref_host = normalize_host(ref_host_raw);
    if ref_host == srv_host {
        's'
    } else {
        'x'
    }
}

// ---- Cookie fields builder -------------------------------------------------

/// Returns a sorted string of first-char initials of cookie field names.
fn get_cookie_fields(hdrs: &HashMap<String, String>) -> String {
    let cookie_val = match hdrs.get("cookie") {
        Some(v) if !v.is_empty() => v,
        _ => return "nil".to_string(),
    };
    let mut chars: Vec<char> = Vec::new();
    for pair in cookie_val.split(';') {
        let trimmed = pair.trim_start();
        // Extract name: up to '=' or whitespace
        let name: String = trimmed
            .chars()
            .take_while(|c| *c != '=' && !c.is_whitespace())
            .collect();
        if !name.is_empty() && chars.len() < MAX_PARAMS {
            if let Some(first_char) = name.chars().next() {
                chars.push(first_char.to_ascii_lowercase());
            }
        }
    }
    if chars.is_empty() {
        return "nil".to_string();
    }
    chars.sort();
    chars.into_iter().collect()
}

// ---- Body content type detection -------------------------------------------

/// Detect content type from headers: 'json', 'form', 'graphql', or None.
fn detect_body_ctype(hdrs: &HashMap<String, String>) -> Option<&'static str> {
    let ct = hdrs.get("content-type")?;
    let ct_lower = ct.to_ascii_lowercase();
    if ct_lower.contains("application/json") || ct_lower.contains("application/+json") {
        return Some("json");
    }
    if ct_lower.contains("application/x-www-form-urlencoded") {
        return Some("form");
    }
    if ct_lower.contains("application/graphql") {
        return Some("graphql");
    }
    None
}

// ---- Phase 1: Capture request data (http-req) ------------------------------

fn capture_request(txn: &Txn) -> LuaResult<()> {
    // Fetch all request-phase data now; the request buffer will be freed
    // before the http-res phase runs.
    let raw_hdrs = txn.f.get_str("req_hdrs", ()).unwrap_or_default();
    let path = txn.f.get_str("path", ()).unwrap_or_else(|_| "/".to_string());
    let method = txn.f.get_str("method", ()).unwrap_or_else(|_| "ge".to_string());
    let query = txn.f.get_str("query", ()).unwrap_or_default();
    let ver = txn.f.get_str("req_ver", ()).unwrap_or_else(|_| "1.1".to_string());

    txn.set_var("txn.req_fp.hdrs", raw_hdrs.clone())?;
    txn.set_var("txn.req_fp.path", path.clone())?;
    txn.set_var("txn.req_fp.method", method.clone())?;
    txn.set_var("txn.req_fp.query", query.clone())?;
    txn.set_var("txn.req_fp.ver", ver.clone())?;

    // Parse headers now for request-phase subfield txn vars.
    let (hdr_count, hdr_list, hdrs) = parse_headers(&raw_hdrs);
    let ctype = get_req_ctype(&hdrs);
    let atype = get_auth_type(&hdrs);
    let cookie = hdrs.get("cookie").map(|v| !v.is_empty()).unwrap_or(false);
    let cflag = if cookie { 'c' } else { 'n' };
    let referer = get_referer_flag(&hdrs);
    let pdepth = get_path_depth(&path);

    // v2: Parse request body when API Armor has buffered it (txn.api_body)
    // or when req_fp_parse_body has buffered it independently (txn.req_fp_body).
    let mut body_depth: u32 = 0;
    let mut all_params = parse_params(&query);

    let api_body: String = txn
        .get_var("txn.api_body")
        .unwrap_or_default();
    let api_body = if api_body.is_empty() {
        txn.get_var("txn.req_fp_body").unwrap_or_default()
    } else {
        api_body
    };

    if !api_body.is_empty() {
        let bctype = detect_body_ctype(&hdrs);
        if bctype == Some("json") {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&api_body) {
                if parsed.is_object() {
                    let (body_params, bd) = extract_json_fields(&parsed);
                    body_depth = bd;
                    for p in body_params {
                        if all_params.len() < MAX_PARAMS {
                            all_params.push(p);
                        }
                    }
                    all_params.sort_by(|a, b| a.0.cmp(&b.0));
                }
            }
        } else if bctype == Some("form") {
            let form_params = parse_params(&api_body);
            for p in form_params {
                if all_params.len() < MAX_PARAMS {
                    all_params.push(p);
                }
            }
            all_params.sort_by(|a, b| a.0.cmp(&b.0));
        }
        // GraphQL: skip param extraction (the Rust graphql module handles deeper analysis).
    }

    // Build param subfield strings from merged params.
    let (param_keys, param_types, param_lens) = if all_params.is_empty() {
        ("nil".to_string(), "nil".to_string(), "0".to_string())
    } else {
        let keys: String = all_params
            .iter()
            .map(|(name, _)| name.chars().next().unwrap_or(' '))
            .collect();
        let types: String = all_params
            .iter()
            .map(|(_, value)| detect_type(value))
            .collect();
        let lens: String = all_params
            .iter()
            .map(|(_, value)| value.chars().count().to_string())
            .collect::<Vec<_>>()
            .join("-");
        (keys, types, lens)
    };

    // Store merged params for build_fingerprint to use.
    txn.set_var("txn.req_fp.params_keys", param_keys.clone())?;
    txn.set_var("txn.req_fp.params_types", param_types.clone())?;
    txn.set_var("txn.req_fp.params_lens", param_lens.clone())?;

    // Set request-phase subfield txn vars for Security Rules access.
    txn.set_var("txn.req_fp.ctype", ctype)?;
    txn.set_var("txn.req_fp.param_keys", param_keys)?;
    txn.set_var("txn.req_fp.param_types", param_types)?;
    txn.set_var("txn.req_fp.param_lens", param_lens)?;
    txn.set_var("txn.req_fp.path_depth", format!("{:02}", pdepth))?;
    txn.set_var("txn.req_fp.method", method)?;
    txn.set_var("txn.req_fp.hdr_count", format!("{:02}", hdr_count))?;
    txn.set_var("txn.req_fp.hdr_list", hdr_list)?;
    txn.set_var("txn.req_fp.auth_type", atype.to_string())?;
    txn.set_var("txn.req_fp.cookie", cflag.to_string())?;
    txn.set_var("txn.req_fp.referer", referer.to_string())?;
    txn.set_var("txn.req_fp.body_depth", body_depth.to_string())?;

    Ok(())
}

// ---- Phase 2: Build fingerprint (http-res) ---------------------------------

fn build_fingerprint(txn: &Txn) -> LuaResult<String> {
    // Retrieve request data captured in phase 1.
    let path: String = txn
        .get_var("txn.req_fp.path")
        .unwrap_or_else(|_| "/".to_string());
    let method: String = txn
        .get_var("txn.req_fp.method")
        .unwrap_or_else(|_| "ge".to_string());
    let ver: String = txn
        .get_var("txn.req_fp.ver")
        .unwrap_or_else(|_| "1.1".to_string());
    let raw_hdrs: String = txn.get_var("txn.req_fp.hdrs").unwrap_or_default();

    // Retrieve pre-computed merged params from capture_request (v2).
    let param_keys: String = txn.get_var("txn.req_fp.params_keys").unwrap_or_default();
    let param_types: String = txn.get_var("txn.req_fp.params_types").unwrap_or_default();
    let param_lens: String = txn.get_var("txn.req_fp.params_lens").unwrap_or_default();

    // Response-phase data (available now).
    let status: u16 = txn.f.get("status", ()).unwrap_or(0);

    let mut parts: Vec<String> = Vec::with_capacity(17);

    // 1. path_b62
    parts.push(base62_encode(path.as_bytes()));

    // 2. method2
    parts.push(method.chars().take(2).map(|c| c.to_ascii_lowercase()).collect());

    // 3. http_ver
    parts.push(http_ver_code(&ver).to_string());

    // 4. path_depth
    parts.push(format!("{:02}", get_path_depth(&path)));

    // 5-7. param_keys / param_types / param_lens (merged query + body)
    if !param_keys.is_empty() {
        parts.push(param_keys);
        parts.push(if param_types.is_empty() { "nil".to_string() } else { param_types });
        parts.push(if param_lens.is_empty() { "0".to_string() } else { param_lens });
    } else {
        // Fallback: re-parse query only (v1 behavior when capture didn't set vars)
        let query: String = txn.get_var("txn.req_fp.query").unwrap_or_default();
        let params = parse_params(&query);
        if params.is_empty() {
            parts.push("nil".to_string());
            parts.push("nil".to_string());
            parts.push("0".to_string());
        } else {
            let keys: String = params
                .iter()
                .map(|(name, _)| name.chars().next().unwrap_or(' '))
                .collect();
            let types: String = params
                .iter()
                .map(|(_, value)| detect_type(value))
                .collect();
            let lens: String = params
                .iter()
                .map(|(_, value)| value.chars().count().to_string())
                .collect::<Vec<_>>()
                .join("-");
            parts.push(keys);
            parts.push(types);
            parts.push(lens);
        }
    }

    // Parse request headers from the captured raw block.
    let (hdr_count, hdr_list, hdrs) = parse_headers(&raw_hdrs);

    // 8. req_ctype
    parts.push(get_req_ctype(&hdrs));

    // 9-10. hdr_count / hdr_list
    parts.push(format!("{:02}", hdr_count));
    parts.push(hdr_list);

    // 11. accept_lang
    parts.push(get_accept_lang(&hdrs));

    // 12. auth_type
    parts.push(get_auth_type(&hdrs).to_string());

    // 13. cookie
    let cookie_val = hdrs.get("cookie").map(|v| !v.is_empty()).unwrap_or(false);
    parts.push(if cookie_val { "c".to_string() } else { "n".to_string() });

    // 14. cookie_fields
    parts.push(get_cookie_fields(&hdrs));

    // 15. referer
    parts.push(get_referer_flag(&hdrs).to_string());

    // 16. status
    parts.push(status.to_string());

    // 17. body_bytes (response Content-Length only).
    //
    // We intentionally do NOT fall back to res.body_len here. Accessing
    // res_body_len in an http-response Lua action forces HAProxy to buffer
    // the entire response body before the action can complete. For large
    // concurrent responses (e.g. 20 × 11MB OSD bundle files with chunked
    // transfer-encoding), this causes massive memory buffering, client
    // timeouts (termination: PH), and 500 errors.
    //
    // For chunked responses (no Content-Length), body_bytes will be "0" in
    // the fingerprint. The actual response size is still captured in the
    // HAProxy access log's bytes_out field, so no data is lost.
    let res_raw = txn.f.get_str("res_hdrs", ()).unwrap_or_default();
    let (_, _, res_hdrs) = parse_headers(&res_raw);
    let bytes: u64 = res_hdrs
        .get("content-length")
        .and_then(|cl| cl.parse::<u64>().ok())
        .unwrap_or(0);
    parts.push(bytes.to_string());

    let fingerprint = parts.join("_");

    // Set response-phase subfield txn vars for Security Rules access.
    txn.set_var("txn.req_fp.status", status.to_string())?;
    txn.set_var("txn.req_fp.body_bytes", bytes.to_string())?;
    txn.set_var("txn.req_fp.full", fingerprint.clone())?;

    Ok(fingerprint)
}

// ---- Action wrappers (error handling) --------------------------------------

fn capture_action(lua: &Lua, txn: Txn) -> LuaResult<()> {
    match capture_request(&txn) {
        Ok(()) => Ok(()),
        Err(e) => {
            let core = Core::new(lua);
            if let Ok(c) = core {
                let _ = c.log(
                    LogLevel::Warning,
                    format!("req_fp: capture failed: {}", e.to_string()),
                );
            }
            Ok(())
        }
    }
}

fn build_action(lua: &Lua, txn: Txn) -> LuaResult<()> {
    match build_fingerprint(&txn) {
        Ok(fingerprint) => {
            txn.set_var("txn.req_fp", fingerprint)?;
            Ok(())
        }
        Err(e) => {
            let core = Core::new(lua);
            if let Ok(c) = core {
                let _ = c.log(
                    LogLevel::Warning,
                    format!("req_fp: fingerprint failed: {}", e.to_string()),
                );
            }
            txn.set_var("txn.req_fp", "err")?;
            Ok(())
        }
    }
}

// ---- Registration ----------------------------------------------------------

/// Registers the "req_fp_capture" and "req_fp" Lua actions with HAProxy.
pub fn register(lua: &Lua) -> LuaResult<()> {
    let core = Core::new(lua)?;
    core.register_action(
        "req_fp_capture",
        &[Action::HttpReq],
        0,
        capture_action,
    )?;
    core.register_action("req_fp", &[Action::HttpRes], 0, build_action)?;
    Ok(())
}

// ---- Tests -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base62_empty() {
        assert_eq!(base62_encode(b""), "0");
    }

    #[test]
    fn test_base62_single_byte() {
        // 0 → '0', 1 → '1', 61 → 'z'
        assert_eq!(base62_encode(b"\x00"), "0");
        assert_eq!(base62_encode(b"\x01"), "1");
        assert_eq!(base62_encode(&[61u8]), "z");
    }

    #[test]
    fn test_base62_known_path() {
        // "/" → byte 0x2F = 47 → base62 char at index 47 = 'l'
        // (0-9=10, A-Z=26 → index 36='a', 47='l')
        assert_eq!(base62_encode(b"/"), "l");
        // "/api" → bytes [0x2F, 0x61, 0x70, 0x69]
        // = 47*256^3 + 97*256^2 + 112*256 + 105
        // = 796,177,449
        let result = base62_encode(b"/api");
        // Verify it's non-empty and not "0"
        assert!(!result.is_empty());
        assert_ne!(result, "0");
    }

    #[test]
    fn test_base62_path_max_cap() {
        let long = vec![b'a'; PATH_MAX + 100];
        let result = base62_encode(&long);
        // Should not panic and should produce a valid string
        assert!(!result.is_empty());
    }

    #[test]
    fn test_detect_type_empty() {
        assert_eq!(detect_type(""), 'e');
    }

    #[test]
    fn test_detect_type_object() {
        assert_eq!(detect_type("{\"a\":1}"), 'o');
    }

    #[test]
    fn test_detect_type_list() {
        assert_eq!(detect_type("[1,2]"), 'l');
    }

    #[test]
    fn test_detect_type_bool() {
        assert_eq!(detect_type("true"), 'b');
        assert_eq!(detect_type("FALSE"), 'b');
    }

    #[test]
    fn test_detect_type_datetime_tz() {
        assert_eq!(detect_type("2024-01-15T10:30:00Z"), 'z');
        assert_eq!(detect_type("2024-01-15T10:30:00+02:00"), 'z');
        assert_eq!(detect_type("2024-01-15T10:30:00-0500"), 'z');
    }

    #[test]
    fn test_detect_type_datetime_no_tz() {
        // datetime without tz → falls through to other checks; not 'z'
        // It doesn't match date (has T), doesn't match time (starts with year)
        // → string
        assert_eq!(detect_type("2024-01-15T10:30:00"), 's');
    }

    #[test]
    fn test_detect_type_date() {
        assert_eq!(detect_type("2024-01-15"), 'd');
    }

    #[test]
    fn test_detect_type_time() {
        assert_eq!(detect_type("10:30:00"), 't');
        assert_eq!(detect_type("10:30:00.123"), 't');
    }

    #[test]
    fn test_detect_type_int() {
        assert_eq!(detect_type("42"), 'i');
        assert_eq!(detect_type("-17"), 'i');
        assert_eq!(detect_type("0"), 'i');
    }

    #[test]
    fn test_detect_type_float() {
        assert_eq!(detect_type("3.14"), 'f');
        assert_eq!(detect_type("-0.5"), 'f');
    }

    #[test]
    fn test_detect_type_char() {
        assert_eq!(detect_type("x"), 'c');
    }

    #[test]
    fn test_detect_type_string() {
        assert_eq!(detect_type("hello"), 's');
        assert_eq!(detect_type("hello world"), 's');
    }

    #[test]
    fn test_parse_params_empty() {
        assert!(parse_params("").is_empty());
    }

    #[test]
    fn test_parse_params_basic() {
        let params = parse_params("b=2&a=1");
        assert_eq!(params.len(), 2);
        assert_eq!(params[0], ("a".to_string(), "1".to_string()));
        assert_eq!(params[1], ("b".to_string(), "2".to_string()));
    }

    #[test]
    fn test_parse_params_url_decode() {
        let params = parse_params("name=hello+world&x=test%20value");
        assert_eq!(params.len(), 2);
        assert_eq!(params[0], ("name".to_string(), "hello world".to_string()));
        assert_eq!(params[1], ("x".to_string(), "test value".to_string()));
    }

    #[test]
    fn test_parse_params_empty_key_skipped() {
        let params = parse_params("=nokey&good=val");
        assert_eq!(params.len(), 1);
        assert_eq!(params[0], ("good".to_string(), "val".to_string()));
    }

    #[test]
    fn test_parse_params_max_cap() {
        let qs: String = (0..50)
            .map(|i| format!("k{}=v{}", i, i))
            .collect::<Vec<_>>()
            .join("&");
        let params = parse_params(&qs);
        assert_eq!(params.len(), MAX_PARAMS);
    }

    #[test]
    fn test_parse_params_no_value() {
        let params = parse_params("flag&a=1");
        assert_eq!(params.len(), 2);
        // "flag" has no =, value is empty
        assert_eq!(params[0], ("a".to_string(), "1".to_string()));
        assert_eq!(params[1], ("flag".to_string(), "".to_string()));
    }

    #[test]
    fn test_json_depth_flat() {
        let v: serde_json::Value = serde_json::from_str("{\"a\":1,\"b\":2}").unwrap();
        assert_eq!(json_depth(&v, 0), 1);
    }

    #[test]
    fn test_json_depth_nested() {
        let v: serde_json::Value =
            serde_json::from_str("{\"a\":{\"b\":{\"c\":1}}}").unwrap();
        assert_eq!(json_depth(&v, 0), 3);
    }

    #[test]
    fn test_json_depth_array() {
        let v: serde_json::Value = serde_json::from_str("[1,[2,[3]]]").unwrap();
        assert_eq!(json_depth(&v, 0), 3);
    }

    #[test]
    fn test_json_depth_scalar() {
        let v: serde_json::Value = serde_json::from_str("42").unwrap();
        assert_eq!(json_depth(&v, 0), 0);
    }

    #[test]
    fn test_extract_json_fields_object() {
        let v: serde_json::Value =
            serde_json::from_str("{\"name\":\"test\",\"age\":30}").unwrap();
        let (params, depth) = extract_json_fields(&v);
        assert_eq!(params.len(), 2);
        assert_eq!(params[0].0, "age");
        assert_eq!(params[1].0, "name");
        assert_eq!(depth, 1);
    }

    #[test]
    fn test_extract_json_fields_array_empty() {
        let v: serde_json::Value = serde_json::from_str("[1,2,3]").unwrap();
        let (params, _) = extract_json_fields(&v);
        assert!(params.is_empty());
    }

    #[test]
    fn test_extract_json_fields_max_cap() {
        let json: String = format!(
            "{{{}}}",
            (0..50)
                .map(|i| format!("\"k{}\":\"v{}\"", i, i))
                .collect::<Vec<_>>()
                .join(",")
        );
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let (params, _) = extract_json_fields(&v);
        assert_eq!(params.len(), MAX_PARAMS);
    }

    #[test]
    fn test_http_ver_code() {
        assert_eq!(http_ver_code("0.9"), "09");
        assert_eq!(http_ver_code("1.0"), "10");
        assert_eq!(http_ver_code("1.1"), "11");
        assert_eq!(http_ver_code("2"), "20");
        assert_eq!(http_ver_code("2.0"), "20");
        assert_eq!(http_ver_code("3"), "30");
        assert_eq!(http_ver_code("3.0"), "30");
        assert_eq!(http_ver_code("unknown"), "11");
    }

    #[test]
    fn test_get_path_depth() {
        assert_eq!(get_path_depth("/"), 1);
        assert_eq!(get_path_depth("/api/v1/users"), 3);
        assert_eq!(get_path_depth("/a"), 1);
        assert_eq!(get_path_depth("nopath"), 0);
    }

    #[test]
    fn test_get_path_depth_cap() {
        let deep = "/".repeat(150);
        assert_eq!(get_path_depth(&deep), 99);
    }

    #[test]
    fn test_parse_headers_empty() {
        let (count, list, hdrs) = parse_headers("");
        assert_eq!(count, 0);
        assert_eq!(list, "nil");
        assert!(hdrs.is_empty());
    }

    #[test]
    fn test_parse_headers_basic() {
        let raw = "Host: example.com\r\nAccept: text/html\r\nUser-Agent: curl/8.0\r\n";
        let (count, list, hdrs) = parse_headers(raw);
        assert_eq!(count, 3);
        // Sorted first chars: a, h, u
        assert_eq!(list, "ahu");
        assert_eq!(hdrs.get("host").unwrap(), "example.com");
        assert_eq!(hdrs.get("accept").unwrap(), "text/html");
    }

    #[test]
    fn test_parse_headers_dedup() {
        let raw = "X-Custom: first\r\nX-Custom: second\r\n";
        let (count, _, hdrs) = parse_headers(raw);
        // Only first occurrence recorded
        assert_eq!(count, 1);
        assert_eq!(hdrs.get("x-custom").unwrap(), "first");
    }

    #[test]
    fn test_parse_headers_newline_only() {
        let raw = "Host: example.com\nAccept: text/html\n";
        let (count, list, _) = parse_headers(raw);
        assert_eq!(count, 2);
        assert_eq!(list, "ah");
    }

    #[test]
    fn test_get_req_ctype_absent() {
        let hdrs = HashMap::new();
        assert_eq!(get_req_ctype(&hdrs), "0000");
    }

    #[test]
    fn test_get_req_ctype_json() {
        let mut hdrs = HashMap::new();
        hdrs.insert("content-type".to_string(), "application/json".to_string());
        assert_eq!(get_req_ctype(&hdrs), "json");
    }

    #[test]
    fn test_get_req_ctype_form() {
        let mut hdrs = HashMap::new();
        hdrs.insert(
            "content-type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        );
        // subtype = "x-www-form-urlencoded", first 4 alpha = "xwww"
        assert_eq!(get_req_ctype(&hdrs), "xwww");
    }

    #[test]
    fn test_get_req_ctype_with_charset() {
        let mut hdrs = HashMap::new();
        hdrs.insert(
            "content-type".to_string(),
            "text/html; charset=utf-8".to_string(),
        );
        // subtype after / = "html", up to ; = "html", first 4 alpha = "html"
        assert_eq!(get_req_ctype(&hdrs), "html");
    }

    #[test]
    fn test_get_accept_lang_absent() {
        let hdrs = HashMap::new();
        assert_eq!(get_accept_lang(&hdrs), "0000");
    }

    #[test]
    fn test_get_accept_lang_basic() {
        let mut hdrs = HashMap::new();
        hdrs.insert("accept-language".to_string(), "en-US".to_string());
        assert_eq!(get_accept_lang(&hdrs), "enus");
    }

    #[test]
    fn test_get_accept_lang_with_q() {
        let mut hdrs = HashMap::new();
        hdrs.insert("accept-language".to_string(), "fr;q=0.9".to_string());
        assert_eq!(get_accept_lang(&hdrs), "fr00");
    }

    #[test]
    fn test_get_auth_type_none() {
        let hdrs = HashMap::new();
        assert_eq!(get_auth_type(&hdrs), 'n');
    }

    #[test]
    fn test_get_auth_type_basic() {
        let mut hdrs = HashMap::new();
        hdrs.insert("authorization".to_string(), "Basic dXNlcjpwYXNz".to_string());
        assert_eq!(get_auth_type(&hdrs), 'b');
    }

    #[test]
    fn test_get_auth_type_bearer() {
        let mut hdrs = HashMap::new();
        hdrs.insert("authorization".to_string(), "Bearer token123".to_string());
        assert_eq!(get_auth_type(&hdrs), 't');
    }

    #[test]
    fn test_get_auth_type_digest() {
        let mut hdrs = HashMap::new();
        hdrs.insert("authorization".to_string(), "Digest abc=123".to_string());
        assert_eq!(get_auth_type(&hdrs), 'd');
    }

    #[test]
    fn test_get_auth_type_other() {
        let mut hdrs = HashMap::new();
        hdrs.insert("authorization".to_string(), "Custom scheme".to_string());
        assert_eq!(get_auth_type(&hdrs), 'o');
    }

    #[test]
    fn test_normalize_host() {
        assert_eq!(normalize_host("Example.COM:8080"), "example.com");
        assert_eq!(normalize_host("example.com"), "example.com");
    }

    #[test]
    fn test_get_referer_flag_none() {
        let hdrs = HashMap::new();
        assert_eq!(get_referer_flag(&hdrs), 'n');
    }

    #[test]
    fn test_get_referer_flag_same_domain() {
        let mut hdrs = HashMap::new();
        hdrs.insert("host".to_string(), "example.com".to_string());
        hdrs.insert("referer".to_string(), "https://example.com/page".to_string());
        assert_eq!(get_referer_flag(&hdrs), 's');
    }

    #[test]
    fn test_get_referer_flag_cross_domain() {
        let mut hdrs = HashMap::new();
        hdrs.insert("host".to_string(), "example.com".to_string());
        hdrs.insert("referer".to_string(), "https://evil.com/x".to_string());
        assert_eq!(get_referer_flag(&hdrs), 'x');
    }

    #[test]
    fn test_get_referer_flag_no_host() {
        let mut hdrs = HashMap::new();
        hdrs.insert("referer".to_string(), "https://example.com/page".to_string());
        assert_eq!(get_referer_flag(&hdrs), 'x');
    }

    #[test]
    fn test_get_cookie_fields_absent() {
        let hdrs = HashMap::new();
        assert_eq!(get_cookie_fields(&hdrs), "nil");
    }

    #[test]
    fn test_get_cookie_fields_basic() {
        let mut hdrs = HashMap::new();
        hdrs.insert("cookie".to_string(), "session=abc; theme=dark; user=42".to_string());
        // First chars: s, t, u → sorted: stu
        assert_eq!(get_cookie_fields(&hdrs), "stu");
    }

    #[test]
    fn test_get_cookie_fields_empty() {
        let mut hdrs = HashMap::new();
        hdrs.insert("cookie".to_string(), "".to_string());
        assert_eq!(get_cookie_fields(&hdrs), "nil");
    }

    #[test]
    fn test_detect_body_ctype_json() {
        let mut hdrs = HashMap::new();
        hdrs.insert("content-type".to_string(), "application/json".to_string());
        assert_eq!(detect_body_ctype(&hdrs), Some("json"));
    }

    #[test]
    fn test_detect_body_ctype_json_with_suffix() {
        // The Lua pattern 'application/%+%w*json' matches "application/+json"
        // (literal + after /, then word chars, then json).
        // "application/vnd.api+json" does NOT match (vnd.api between / and +json
        // contains a dot, which is not a %w char).
        let mut hdrs = HashMap::new();
        hdrs.insert(
            "content-type".to_string(),
            "application/+json".to_string(),
        );
        assert_eq!(detect_body_ctype(&hdrs), Some("json"));
    }

    #[test]
    fn test_detect_body_ctype_form() {
        let mut hdrs = HashMap::new();
        hdrs.insert(
            "content-type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        );
        assert_eq!(detect_body_ctype(&hdrs), Some("form"));
    }

    #[test]
    fn test_detect_body_ctype_graphql() {
        let mut hdrs = HashMap::new();
        hdrs.insert("content-type".to_string(), "application/graphql".to_string());
        assert_eq!(detect_body_ctype(&hdrs), Some("graphql"));
    }

    #[test]
    fn test_detect_body_ctype_none() {
        let mut hdrs = HashMap::new();
        hdrs.insert("content-type".to_string(), "text/plain".to_string());
        assert_eq!(detect_body_ctype(&hdrs), None);
    }

    #[test]
    fn test_detect_body_ctype_absent() {
        let hdrs = HashMap::new();
        assert_eq!(detect_body_ctype(&hdrs), None);
    }
}
