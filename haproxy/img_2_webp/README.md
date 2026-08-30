# haproxy-img-2-webp

`haproxy-img-2-webp` adds on-the-fly image-to-WebP conversion to
[HAProxy] 3.2+ Community Edition using the [Lua Filter API].

It is implemented as a native Lua module written in Rust using [mlua] and
[haproxy-api] crates. A single `lua.img_2_webp` filter performs content
negotiation based on the request's `Accept` header — when the client accepts
`image/webp` and the response is an eligible image (JPEG, PNG, or GIF
first-frame), the response body is decoded and re-encoded as WebP.

[HAProxy]: https://www.haproxy.org
[Lua Filter API]: https://www.arpalert.org/src/haproxy-lua-api/3.0/index.html
[mlua]: https://github.com/mlua-rs/mlua
[haproxy-api]: https://github.com/khvzak/haproxy-api-rs

## Usage and Configuration

The module is loaded via the combined `modules.lua` loader (see
`haproxy/Dockerfile`). The filter is declared per-backend:

```
backend my_static_be
    filter lua.img_2_webp quality:80 max_size:10000000 max_dim:4096
```

### How It Works

1. **Request phase**: The filter parses the `Accept` header. If
   `image/webp` is present with a non-zero q-value, the request is eligible.
2. **Response phase**: If the response is `200 OK`, has a `Content-Type` of
   `image/jpeg`, `image/png`, or `image/gif`, has no existing
   `Content-Encoding`, and no `Cache-Control: no-transform`, the filter
   activates and buffers the response body.
3. **Body phase**: At end-of-message, the buffered body is decoded via the
   [image] crate and re-encoded as WebP via the [webp] crate (libwebp). The
   `Content-Type` is updated to `image/webp`, `Vary: Accept` is added, and
   the ETag is converted to weak. If conversion fails (decode error,
   dimensions too large, body too large), the original body passes through
   unchanged.

   **Encoding strategy**: PNG sources use lossless WebP encoding (PNG is
   lossless — lossy re-encoding can increase file size for small or simple
   images). JPEG and GIF sources use lossy WebP at the configured `quality`.
   A size guard passes through the original bytes if the WebP output is not
   smaller than the original — the `Content-Type` stays `image/webp` but
   browsers sniff the actual format from magic bytes for `<img>` tags.

### Caching

The filter emits `Vary: Accept` so HAProxy's native memory cache and Varnish
disk cache create separate entries for WebP vs original responses. Ensure
`process-vary on` and `max-secondary-entries > 0` on the backend's cache
config when using image conversion with caching.

### Configuration Options

The `filter lua.img_2_webp` directive supports the following options:

| Option | Description | Default |
| --- | --- | --- |
| `quality:` | WebP encoding quality (0-100). Applies to JPEG/GIF sources only; PNG always uses lossless encoding. | 80 |
| `max_size:` | Maximum response body size in bytes to convert. Larger bodies pass through. | 10000000 (10 MB) |
| `max_dim:` | Maximum image dimension (width or height in pixels). Larger images pass through. | 4096 |
| `type:` | Comma-separated source MIME-type prefixes eligible for conversion. | image/jpeg,image/png,image/gif |

### FCGI Limitation

Lua filters cannot coexist with `use-fcgi-app` due to HAProxy 3.4's
`fcgi_flt_check` bug. Image conversion is skipped (with a warning comment)
for FCGI backends, same as compression and response transforms.

## License

This project is licensed under the [MIT license](LICENSE).
