# haproxy-req-fp

`haproxy-req-fp` adds HTTP request/response fingerprinting to
[HAProxy] 3.2+ Community Edition using the [Lua Filter API].

It is implemented as a native Lua module written in Rust using [mlua] and
[haproxy-api] crates. Two Lua actions are registered:

- `lua.req_fp_capture` (http-req phase) — captures request data into txn vars
- `lua.req_fp` (http-res phase) — builds the 17-field fingerprint using
  captured request data + response data, stored in `txn.req_fp`

[HAProxy]: https://www.haproxy.org
[Lua Filter API]: https://www.arpalert.org/src/haproxy-lua-api/3.0/index.html
[mlua]: https://github.com/mlua-rs/mlua
[haproxy-api]: https://github.com/khvzak/haproxy-api-rs

## Fingerprint Format

17 underscore-separated fields:

```
{path_b62}_{method2}_{http_ver}_{path_depth}_
{param_keys}_{param_types}_{param_lens}_{req_ctype}_
{hdr_count}_{hdr_list}_{accept_lang}_{auth_type}_
{cookie}_{cookie_fields}_{referer}_
{status}_{body_bytes}
```

See the source (`src/lib.rs`) for full field definitions and value type codes.

## Usage and Configuration

The module is loaded via the combined `modules.lua` loader (single
`lua-load-per-thread`) to avoid `dlopen` symbol conflicts with other Rust
cdylib modules. The loader requires the module and calls `register()`:

```lua
local req_fp = require("haproxy_req_fp_module")
req_fp.register()
```

### HAProxy Configuration

```
global
    master-worker
    lua-prepend-path /etc/haproxy/?.so cpath
    lua-load-per-thread /path/to/modules.lua

frontend http-in
    http-request lua.req_fp_capture
    http-response lua.req_fp
    log-format "%ci [%t] %[var(txn.req_fp)]"
```

## Dependencies

- `serde_json` — JSON body parsing (top-level field names, types, depth)
- `form_urlencoded` — query-string and form-urlencoded body parsing
- `regex` + `once_cell` — value type detection (datetime, date, time, int, float)

## License

Apache-2.0 WITH Commons-Clause. See [LICENSE](LICENSE).
