# haproxy-compression (vendored)

> **Based on** https://github.com/khvzak/haproxy-brotli (MIT license, by Alex Orlenko)
> Extended into a unified brotli + zstd compression filter for HAProxy 3.2+.
> Built as part of the HAProxy Docker image multi-stage build (see
> `haproxy/Dockerfile`). The `tests/` workspace member from upstream was excluded.

# haproxy-compression

`haproxy-compression` adds brotli and zstd response compression to
[HAProxy] 3.2+ Community Edition using the [Lua Filter API].

It is implemented as a native Lua module written in Rust using [mlua] and
[haproxy-api] crates. A single `lua.compress` filter negotiates between brotli
and zstd based on the request's `Accept-Encoding` header and which encoders
are enabled via filter arguments.

[HAProxy]: https://www.haproxy.org
[Lua Filter API]: https://www.arpalert.org/src/haproxy-lua-api/3.0/index.html
[mlua]: https://github.com/mlua-rs/mlua
[haproxy-api]: https://github.com/khvzak/haproxy-api-rs

## Usage and Configuration

Please check the `module` directory for the cdylib entry point. A loader
script (`compress.lua`) is generated/copied into the HAProxy image:

```lua
local compress = require("haproxy_compression_module")
compress.register()
```

### HAProxy Configuration

```
global
    master-worker
    lua-prepend-path /etc/haproxy/?.so cpath
    lua-load-per-thread compress.lua

...

listen http-in
    bind *:8080
    # Enable both brotli and zstd; negotiate per Accept-Encoding
    filter lua.compress br zstd offload type:text/,application/json
```

Only `GET`/`POST` requests whose preferred `Accept-Encoding` is one of the
enabled encodings will be compressed. Responses are only compressed when:
- the status is `200`,
- no `Content-Encoding` is already set,
- `Cache-Control` does not include `no-transform`,
- the `Content-Type` matches one of the configured prefixes (or all types if
  none specified), and is not `multipart/*`.

### Configuration Options

The `filter lua.compress` directive supports the following options:

| Option | Description | Default |
| --- | --- | --- |
| `br` | Enable brotli encoding. | off (enabled if neither `br` nor `zstd` given) |
| `zstd` | Enable zstd encoding. | off (enabled if neither `br` nor `zstd` given) |
| `offload` | Strip `Accept-Encoding` so backend servers don't compress. | off |
| `type:` | Comma-separated MIME-type prefixes to compress. | empty = all types |
| `quality:` | Brotli quality level (0-11). | 5 |
| `window:` | Brotli sliding window size in bits (10-24). | 22 |
| `level:` | Zstd compression level (1-22). | 3 |

## License

This project is licensed under the [MIT license](LICENSE).
