//! HAProxy filter for on-the-fly image-to-WebP conversion.
//!
//! Registers the `lua.img_2_webp` filter, declared per-backend:
//!   `filter lua.img_2_webp quality:80 max_size:10000000 max_dim:4096`
//!
//! The filter performs content negotiation based on the request's `Accept`
//! header. When the client accepts `image/webp` and the response is an
//! eligible image (JPEG, PNG, or GIF first-frame), the response body is
//! buffered, decoded, re-encoded as WebP, and emitted with updated
//! `Content-Type` and `Vary` headers.
//!
//! The full body is buffered before conversion (image decode/encode is not
//! streamable), then the converted result is emitted **incrementally** across
//! successive `http_payload` callbacks.
//!
//! # Why output is emitted incrementally
//!
//! The obvious implementation — buffer everything, then hand the result back in
//! one `msg:set()` call — cannot work for bodies near or above `tune.bufsize`.
//! HAProxy's `hlua_http_msg_set_data()` / `hlua_http_msg_send()` both cap the
//! copy at the channel's free HTX space and, critically, **fail silently**:
//!
//! ```c
//! if (sz > htx_free_data_space(htx))
//!         lua_pushinteger(L, -1);   /* copies NOTHING, raises nothing */
//! ```
//!
//! Since the filter has already removed the original body from the channel by
//! that point, a refused copy yields an empty response body with no log output
//! at all. With HAProxy's default `tune.bufsize` of 16384 that capped
//! conversion at roughly 12 KB — smaller than most real images.
//!
//! # The unset_eom strategy
//!
//! Incremental emission uses `msg:send()` (which both inserts and immediately
//! forwards data). After `send()`, `htx->data == co_data(res)`. Normally, if
//! `HTX_FL_EOM` is also set, HAProxy's `http_response_forward_body()` analyzer
//! advances `msg_state` to `HTTP_MSG_ENDING` and never calls `http_payload`
//! again — any remaining output is silently lost.
//!
//! The fix is to **unset EOM** after conversion (`msg:unset_eom()`). With EOM
//! unset, the analyzer sees `htx->data == co_data` but no EOM, so it goes to
//! `missing_data_or_waiting` and re-calls `http_payload` after the mux drains
//! the buffer. When all converted output has been sent, we **re-set EOM**
//! (`msg:set_eom()`), and the analyzer naturally advances to ENDING — the
//! message is complete.
//!
//! The maximum convertible image is therefore bounded by `max_size`, not by
//! `tune.bufsize`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

use haproxy_api::{Core, FilterMethod, FilterResult, Headers, HttpMessage, Txn, UserFilter};
use mlua::prelude::*;
use image::GenericImageView;

/// Global cumulative counter of bytes saved by WebP image conversion.
///
/// Accumulated at conversion completion as `original_size - webp_size` (only
/// when the WebP output is actually smaller). Read via the `show webp-stats`
/// CLI command registered in `register()`. Resets to 0 on HAProxy restart
/// (same as HAProxy's native cumulative counters — the backend computes
/// deltas to derive per-interval savings).
static BYTES_SAVED: AtomicU64 = AtomicU64::new(0);

/// Whether verbose per-callback tracing is enabled (`IMG_2_WEBP_DEBUG=1`).
///
/// The incremental emission path depends on HAProxy re-invoking `http_payload`
/// as the channel drains, which is impossible to reason about from the outside.
/// This makes that sequence observable without a debug build.
fn trace_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var("IMG_2_WEBP_DEBUG").is_ok())
}

macro_rules! trace {
    ($($arg:tt)*) => {
        if trace_enabled() {
            let msg = format!("img_2_webp: TRACE {}\n", format!($($arg)*));
            unsafe {
                libc::write(2, msg.as_ptr() as *const _, msg.len());
            }
        }
    };
}

/// MIME types eligible for conversion (checked as prefixes on Content-Type).
const DEFAULT_SOURCE_TYPES: &[&str] = &["image/jpeg", "image/png", "image/gif"];

/// Smallest chunk we will attempt to hand to HAProxy. If even this is refused,
/// the channel is full and we wait for the next callback.
const MIN_SEND_CHUNK: usize = 1024;

/// Maximum `send()` attempts within a single `http_payload` callback. Bounds the
/// chunk-halving probe so a pathological channel state cannot spin forever
/// inside one callback.
const MAX_SEND_ATTEMPTS: u32 = 64;

/// Consecutive `http_payload` callbacks that may make zero flush progress before
/// the filter gives up holding the message open.
///
/// Without this the filter could hold a stream open indefinitely if it never
/// regains buffer space. HAProxy's own timeouts would eventually fire, but this
/// bounds it explicitly and — crucially — logs the condition. Giving up
/// truncates the body, which is why the threshold is generous and the event is
/// logged at ERROR level.
const MAX_STALLED_CALLBACKS: u32 = 10_000;

/// A Lua filter that converts JPEG/PNG/GIF images to WebP on the fly.
#[derive(Default)]
pub struct Img2WebpFilter {
    /// True when the client accepts image/webp (parsed from Accept on request).
    want_webp: bool,
    /// True when the response is eligible and conversion is active.
    active: bool,
    /// Buffered response body (accumulated until EOM, then converted).
    body_buf: Vec<u8>,
    /// Converted output awaiting emission.
    out: Vec<u8>,
    /// How many bytes of `out` have been sent via `msg:send()`.
    out_pos: usize,
    /// True once conversion has run, so it happens exactly once per response.
    converted: bool,
    /// Chunk size for `send()` attempts. Halved when the channel refuses a
    /// chunk, so we adapt to the actual free space.
    chunk: usize,
    /// Consecutive callbacks that made zero progress (liveness guard).
    stalled: u32,
    /// Parsed filter options.
    options: Img2WebpOptions,
}

/// Options for the image conversion filter.
#[derive(Debug, Clone, mlua::FromLua)]
struct Img2WebpOptions {
    /// WebP encoding quality (0.0-100.0). 100 = lossless-ish, 0 = worst.
    quality: f32,
    /// Maximum response body size (bytes) to attempt converting. Larger
    /// responses pass through unchanged to avoid OOM and high latency.
    max_size: usize,
    /// Maximum image dimension (width or height in pixels). Larger images
    /// pass through unchanged.
    max_dim: u32,
    /// Source MIME-type prefixes eligible for conversion.
    source_types: Vec<String>,
    /// Initial chunk size for handing converted output back to HAProxy.
    ///
    /// This is only a starting hint, no longer a hard ceiling: output is emitted
    /// incrementally and the chunk size is halved automatically whenever the
    /// channel refuses a chunk. Setting it near the usable HTX data space
    /// (`tune.bufsize` minus `tune.maxrewrite` and the response headers) just
    /// avoids a few wasted probe attempts on the first flush.
    max_buffer: usize,
}

impl LuaUserData for Img2WebpOptions {}

impl Default for Img2WebpOptions {
    fn default() -> Self {
        Img2WebpOptions {
            quality: 80.0,
            max_size: 10_000_000, // 10 MB
            max_dim: 4096,
            source_types: DEFAULT_SOURCE_TYPES.iter().map(|s| s.to_string()).collect(),
            max_buffer: 12_288, // conservative for the default tune.bufsize of 16384
        }
    }
}

impl Img2WebpFilter {
    fn process_request_headers(&mut self, msg: HttpMessage) -> LuaResult<()> {
        // Only GET requests are eligible (images are fetched via GET).
        // We check the method via txn in the caller; here we parse Accept.
        let headers = msg.get_headers()?;
        self.want_webp = Self::accepts_webp(&headers);
        Ok(())
    }

    fn process_response_headers(&mut self, lua: &Lua, txn: Txn, msg: HttpMessage) -> LuaResult<()> {
        if !self.want_webp {
            return Ok(());
        }

        // Only convert 200 OK responses.
        if txn.f.get::<u16>("status", ())? != 200 {
            return Ok(());
        }

        let headers = msg.get_headers()?;

        // Skip if Content-Encoding is already set (e.g. gzip-compressed image).
        let has_encoding = headers
            .get_first::<LuaValue>("content-encoding")?
            .is_some();
        if has_encoding {
            return Ok(());
        }

        // Skip if Cache-Control includes no-transform.
        let no_transform = headers
            .get::<String>("cache-control")?
            .iter()
            .any(|v| v.contains("no-transform"));
        if no_transform {
            return Ok(());
        }

        // Check content type against eligible source types.
        let content_type = headers
            .get_first::<String>("content-type")?
            .unwrap_or_default()
            .to_ascii_lowercase();
        if content_type.is_empty() {
            return Ok(());
        }

        let type_matches = self
            .options
            .source_types
            .iter()
            .any(|prefix| content_type.starts_with(prefix.as_str()));
        if !type_matches {
            return Ok(());
        }

        // Require a known Content-Length and enforce max_size up front.
        //
        // The decision must be made here, in the http_headers phase, because
        // Content-Type is committed here and cannot be changed later. Deciding
        // at EOM instead would mean either a mislabelled body or an aborted
        // response. Chunked backend responses (no Content-Length) therefore pass
        // through unconverted.
        //
        // Note this is bounded by max_size only — NOT by tune.bufsize. Output is
        // emitted incrementally (see flush()), so buffer size no longer limits
        // the convertible image size.
        let content_length = match headers.get_first::<u32>("content-length").unwrap_or(None) {
            Some(cl) => cl as usize,
            None => return Ok(()),
        };
        if content_length > self.options.max_size {
            return Ok(());
        }

        // Activate conversion.
        self.active = true;
        self.body_buf.clear();
        self.out.clear();
        self.out_pos = 0;
        self.converted = false;
        self.stalled = 0;
        self.chunk = self.options.max_buffer.max(MIN_SEND_CHUNK);

        // Emit Vary: Accept so caches create separate entries for WebP vs original.
        // Only add if not already present (case-insensitive) to avoid duplicates.
        let vary_values = headers.get::<String>("vary")?;
        let already_has = vary_values
            .iter()
            .any(|v| v.to_ascii_lowercase().contains("accept"));
        if !already_has {
            msg.add_header("Vary", "Accept")?;
        }

        // Convert strong ETag to weak (converted body differs from original).
        match headers.get::<String>("etag")? {
            etag if etag.len() > 1 => {
                // Multiple ETags — skip conversion to avoid cache confusion.
                self.active = false;
            }
            etag if etag.len() == 1 && etag[0].starts_with('"') => {
                msg.set_header("etag", format!("W/{}", etag[0]))?;
            }
            _ => {}
        }

        if self.active {
            // Set Content-Type here, NOT in http_payload. HAProxy's
            // hlua_http_msg_set_header() guards on the message state:
            //
            //     if (msg->msg_state > HTTP_MSG_BODY)
            //             WILL_LJMP(lua_error(L));
            //
            // Once the payload callbacks are running the headers have already
            // been forwarded, msg_state has advanced past HTTP_MSG_BODY, and
            // the call raises. Because it uses bare lua_error() the raised
            // error object is whatever is on top of the stack — the value
            // argument — so it surfaces in the logs as the baffling
            // "runtime error: image/webp".
            //
            // That error aborted http_payload before msg.set() could emit the
            // converted bytes, but after msg.remove() had already discarded
            // the raw body, so the client got a chunked/HTTP2 response with a
            // promised body and zero bytes of it -> ERR_HTTP2_PROTOCOL_ERROR.
            // All header rewrites must happen in the http_headers phase (this
            // is what the compression filter does with content-encoding).
            //
            // Consequence: we must commit to WebP before knowing whether the
            // decode/encode will succeed. If conversion later fails we pass
            // the original bytes through (see http_payload), which leaves a
            // Content-Type mismatch — so activation above is kept
            // deliberately strict (200 only, known image/* type, no existing
            // Content-Encoding, no no-transform, size within max_size).
            msg.set_header("content-type", "image/webp")?;

            // Switch to chunked transfer (converted length is unknown).
            // HAProxy drops Content-Length and handles framing itself.
            msg.set_body_len(None)?;
            Self::register_data_filter(lua, txn, msg.channel()?)?;
        }

        Ok(())
    }

    /// Parse the Accept header and return true if image/webp is accepted
    /// (q-value > 0).
    fn accepts_webp(headers: &Headers) -> bool {
        let accept_values = match headers.get::<String>("accept") {
            Ok(vals) => vals,
            Err(_) => return false,
        };
        for v in &accept_values {
            for tok in v.split(',').map(str::trim) {
                if tok.is_empty() {
                    continue;
                }
                // Split media type and parameters (e.g. "image/webp;q=0.8")
                let (media, params) = match tok.split_once(';') {
                    Some((m, p)) => (m.trim(), p.trim()),
                    None => (tok, ""),
                };
                if media.eq_ignore_ascii_case("image/webp") {
                    // Check q-value if present
                    if params.is_empty() {
                        return true;
                    }
                    for param in params.split(';').map(str::trim) {
                        if let Some((key, val)) = param.split_once('=') {
                            if key.trim().eq_ignore_ascii_case("q") {
                                let q = val.trim().parse::<f32>().unwrap_or(1.0);
                                return q > 0.0;
                            }
                        }
                    }
                    // No q parameter — default to 1.0 (acceptable)
                    return true;
                }
            }
        }
        false
    }

    /// Convert the buffered image bytes to WebP. Returns None on any error
    /// (decode failure, dimension limit, encode failure) — the caller passes
    /// through the original body in that case. Returns the original body if
    /// the WebP encoding is not smaller (lossy WebP can be larger than a
    /// small or already-compressed PNG).
    fn convert_to_webp(&self, body: &[u8]) -> Option<Vec<u8>> {
        // Decode the image from memory.
        let img = image::load_from_memory(body).ok()?;

        // Check dimensions against max_dim.
        let (w, h) = img.dimensions();
        if w > self.options.max_dim || h > self.options.max_dim {
            return None;
        }

        // Detect the source format to pick the right encoding strategy.
        // PNG is lossless — re-encoding as lossy WebP can introduce artifacts
        // that *increase* file size for small/simple images. Lossless WebP
        // is typically 20-30% smaller than PNG for the same pixel data.
        // JPEG and GIF are already lossy, so lossy WebP at the configured
        // quality is the right choice.
        let is_png = body.starts_with(b"\x89PNG\r\n\x1a\n");
        let encoder = webp::Encoder::from_image(&img).ok()?;
        let encoded = if is_png {
            encoder.encode_lossless()
        } else {
            encoder.encode(self.options.quality)
        };
        let webp_bytes = encoded.to_vec();

        // Size guard: if the WebP output is not smaller than the original,
        // serve the original bytes. The Content-Type was already committed
        // to image/webp in the http_headers phase and cannot be reverted,
        // but browsers sniff image format from magic bytes for <img> tags,
        // so a PNG body labelled image/webp still renders correctly.
        if webp_bytes.len() >= body.len() {
            trace!(
                "convert_to_webp: webp {} >= original {}, serving original",
                webp_bytes.len(),
                body.len()
            );
            return Some(body.to_vec());
        }

        Some(webp_bytes)
    }

    /// Bytes of converted output still owed to the client (not yet forwarded).
    fn pending(&self) -> usize {
        self.out.len().saturating_sub(self.out_pos)
    }

    /// Produce the bytes to emit for the buffered body.
    ///
    /// Returns the WebP encoding on success. On failure the original bytes are
    /// returned as a passthrough — but note Content-Type was already committed
    /// to `image/webp` in the http_headers phase and cannot be reverted, so the
    /// body would be mislabelled. Both failure paths are therefore logged, and
    /// activation is kept strict to make them rare.
    fn build_output(&self) -> Vec<u8> {
        if self.body_buf.len() > self.options.max_size {
            eprintln!(
                "img_2_webp: WARNING - body of {} bytes exceeds max_size {}; serving \
                 original bytes still labelled image/webp",
                self.body_buf.len(),
                self.options.max_size
            );
            return self.body_buf.clone();
        }
        match self.convert_to_webp(&self.body_buf) {
            Some(webp) => webp,
            None => {
                eprintln!(
                    "img_2_webp: WARNING - conversion of {} bytes failed (decode error or \
                     dimensions above max_dim {}); serving original bytes still labelled \
                     image/webp",
                    self.body_buf.len(),
                    self.options.max_dim
                );
                self.body_buf.clone()
            }
        }
    }

    /// Push converted output into the channel using `send()`.
    ///
    /// `send()` both inserts and immediately forwards data. After it returns,
    /// `htx->data == co_data(res)`. Normally this would make HAProxy's
    /// `http_response_forward_body()` analyzer advance to `HTTP_MSG_ENDING`
    /// (because `htx->data == co_data && HTX_FL_EOM`). But we **unset EOM**
    /// after conversion (see `http_payload`), so the analyzer sees
    /// `htx->data == co_data` but NO EOM → it goes to
    /// `missing_data_or_waiting` and re-calls `http_payload` after the mux
    /// drains the buffer.
    ///
    /// When all output has been sent, we **re-set EOM**. The analyzer then
    /// sees `htx->data == co_data && HTX_FL_EOM` → ENDING → `http_end` →
    /// Continue. The message completes naturally.
    fn flush(&mut self, msg: &HttpMessage) -> LuaResult<usize> {
        let before = self.out_pos;
        let mut attempts = 0;

        while self.out_pos < self.out.len() && attempts < MAX_SEND_ATTEMPTS {
            attempts += 1;
            let n = self.chunk.min(self.out.len() - self.out_pos);
            let sent = msg.send(&self.out[self.out_pos..self.out_pos + n])?;
            trace!(
                "flush attempt={} chunk_req={} sent={} out_pos={}/{}",
                attempts,
                n,
                sent,
                self.out_pos,
                self.out.len()
            );
            if sent > 0 {
                self.out_pos += sent as usize;
                continue;
            }
            // Refused. Try a smaller chunk; if we are already at the floor the
            // channel has no room at all, so stop and wait for the next call.
            if self.chunk > MIN_SEND_CHUNK {
                self.chunk = (self.chunk / 2).max(MIN_SEND_CHUNK);
                continue;
            }
            trace!("flush: channel full at MIN_SEND_CHUNK, breaking");
            break;
        }

        if self.out_pos > before {
            self.stalled = 0;
        } else if self.pending() > 0 {
            self.stalled += 1;
            if self.stalled >= MAX_STALLED_CALLBACKS {
                eprintln!(
                    "img_2_webp: ERROR - gave up after {} callbacks with no flush progress; \
                     {} of {} bytes were never sent and the response body is TRUNCATED. The \
                     channel never freed space (client not reading, or downstream stalled).",
                    self.stalled,
                    self.pending(),
                    self.out.len()
                );
                // Release the message rather than holding the stream forever.
                self.out_pos = self.out.len();
            }
        }
        Ok(self.out_pos - before)
    }

    fn parse_args(args: LuaTable) -> LuaResult<Img2WebpOptions> {
        // Fetch already-parsed options (HAProxy caches args at index 0).
        if let Ok(options) = args.raw_get::<Img2WebpOptions>(0) {
            return Ok(options);
        }

        let mut options = Img2WebpOptions::default();
        for arg in args.clone().sequence_values::<String>() {
            let arg = arg?;
            if let Some(val) = arg.strip_prefix("quality:") {
                if let Ok(q) = val.trim().parse::<f32>() {
                    options.quality = q.clamp(0.0, 100.0);
                }
            } else if let Some(val) = arg.strip_prefix("max_size:") {
                if let Ok(s) = val.trim().parse::<usize>() {
                    options.max_size = s;
                }
            } else if let Some(val) = arg.strip_prefix("max_dim:") {
                if let Ok(d) = val.trim().parse::<u32>() {
                    options.max_dim = d;
                }
            } else if let Some(val) = arg.strip_prefix("max_buffer:") {
                if let Ok(b) = val.trim().parse::<usize>() {
                    options.max_buffer = b;
                }
            } else if let Some(val) = arg.strip_prefix("type:") {
                options.source_types = val
                    .split(',')
                    .map(|s| s.trim().to_ascii_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
        }
        args.raw_set(0, options.clone())?;
        Ok(options)
    }
}

impl UserFilter for Img2WebpFilter {
    // HTTP_END is required: it is the hook that holds the response open until
    // all converted output has been flushed (see the module docs).
    const METHODS: u8 =
        FilterMethod::HTTP_HEADERS | FilterMethod::HTTP_PAYLOAD | FilterMethod::HTTP_END;

    fn new(_: &Lua, args: LuaTable) -> LuaResult<Self> {
        Ok(Img2WebpFilter {
            options: Self::parse_args(args)?,
            ..Default::default()
        })
    }

    fn http_headers(&mut self, lua: &Lua, txn: Txn, msg: HttpMessage) -> LuaResult<FilterResult> {
        if !msg.is_resp()? {
            self.process_request_headers(msg)?;
        } else {
            self.process_response_headers(lua, txn, msg)?;
        }
        Ok(FilterResult::Continue)
    }

    fn http_payload(&mut self, _: &Lua, _: Txn, msg: HttpMessage) -> LuaResult<Option<usize>> {
        if !self.active {
            return Ok(None);
        }

        let eom = msg.eom().unwrap_or(false);
        trace!(
            "http_payload ENTER body_buf={} out={} out_pos={} pending={} chunk={} eom={} converted={}",
            self.body_buf.len(),
            self.out.len(),
            self.out_pos,
            self.pending(),
            self.chunk,
            eom,
            self.converted
        );

        // Buffer any available data and remove it from the incoming buffer
        // so it isn't forwarded unconverted.
        if let Some(chunk) = msg.body(None, Some(-1))? {
            let chunk_bytes = chunk.as_bytes();
            let chunk: &[u8] = &chunk_bytes;
            if !chunk.is_empty() {
                trace!("http_payload buffering {} bytes from input", chunk.len());
                self.body_buf.extend_from_slice(chunk);
                // Remove the raw chunk so it isn't sent unconverted.
                msg.remove(None, None)?;
            }
        }

        // Convert exactly once at EOM. After conversion, unset EOM so the
        // analyzer doesn't advance to HTTP_MSG_ENDING (which would prevent
        // further http_payload calls). We'll re-set EOM when all output is sent.
        if eom && !self.converted {
            self.converted = true;
            self.out = self.build_output();
            self.out_pos = 0;
            // Accumulate bytes saved into the global counter. Only count
            // when the WebP output is actually smaller than the original
            // (build_output returns the original bytes on passthrough/failure).
            let original_size = self.body_buf.len() as u64;
            let webp_size = self.out.len() as u64;
            if webp_size < original_size {
                BYTES_SAVED.fetch_add(original_size - webp_size, Ordering::Relaxed);
            }
            trace!(
                "http_payload EOM -> converted, out={} bytes, body_buf={} bytes",
                self.out.len(),
                self.body_buf.len()
            );
            // Unset EOM to keep the message in DATA state. The analyzer
            // checks `htx->data == co_data && HTX_FL_EOM` to advance to
            // ENDING. With EOM unset, it goes to `missing_data_or_waiting`
            // instead, re-calling http_payload after the mux drains.
            msg.set_eom(false)?;
            trace!("http_payload unset EOM to prevent premature ENDING");
        }

        // Drain whatever the channel will accept right now.
        if self.converted {
            let sent = self.flush(&msg)?;
            trace!(
                "http_payload EXIT sent={} out_pos={} pending={} stalled={}",
                sent,
                self.out_pos,
                self.pending(),
                self.stalled
            );
            // When all output is sent, re-set EOM so the analyzer can
            // advance to ENDING and complete the response.
            if self.pending() == 0 {
                msg.set_eom(true)?;
                trace!("http_payload re-set EOM, all output sent");
            }
            return Ok(Some(sent));
        }

        trace!("http_payload EXIT (not yet converted) pending=0");
        // Always report 0 forwarded: the original input was removed above, and
        // converted output is forwarded by send() itself. Returning None here
        // would make HAProxy forward `cur_len` bytes, double-counting the data
        // send() already accounted for.
        Ok(Some(0))
    }

    /// Holds the response open until all converted output has been flushed.
    ///
    /// With the unset_eom strategy, `http_end` should only be reached when all
    /// output has been sent (EOM is re-set, analyzer advances to ENDING). If
    /// reached with pending data (defensive), return `Wait` to re-run the
    /// analyzer, which re-calls `http_payload`.
    fn http_end(&mut self, _: &Lua, _: Txn, msg: HttpMessage) -> LuaResult<FilterResult> {
        if !msg.is_resp()? || !self.active {
            return Ok(FilterResult::Continue);
        }
        trace!(
            "http_end ENTER pending={} out_pos={}/{}",
            self.pending(),
            self.out_pos,
            self.out.len()
        );
        if self.pending() > 0 {
            trace!("http_end -> Wait (still {} bytes pending)", self.pending());
            return Ok(FilterResult::Wait);
        }
        trace!("http_end -> Continue (fully flushed)");
        self.active = false;
        Ok(FilterResult::Continue)
    }
}

/// Registers an "img_2_webp" filter in the given haproxy context.
///
/// Also registers a `show webp-stats` CLI command that returns the cumulative
/// bytes-saved counter. The backend queries this via the HAProxy socket to
/// compute per-interval bandwidth-saved deltas.
///
/// With `lua-load-per-thread`, this function runs on every thread. HAProxy
/// requires CLI commands to be registered on all threads (or none), so we
/// register unconditionally. The `BYTES_SAVED` counter is a global atomic
/// shared across all threads.
pub fn register(lua: &Lua, _options: Option<LuaTable>) -> LuaResult<String> {
    trace!("register() called, trace_enabled={}", trace_enabled());
    let core = Core::new(lua)?;
    core.register_filter::<Img2WebpFilter>("img_2_webp")?;

    // Expose the counter as a global Lua function so the CLI callback
    // (a Lua chunk) can read it.
    lua.globals().set(
        "_webp_bytes_saved",
        lua.create_function(|_, ()| Ok(BYTES_SAVED.load(Ordering::Relaxed)))?,
    )?;
    // Register the CLI command. The callback receives an AppletTCP as
    // the first argument; output is sent via applet:send().
    core.register_lua_cli(
        &["show", "webp-stats"],
        "show webp-stats: display cumulative bytes saved by WebP image conversion",
        r#"
        local applet = ...
        applet:send("bytes_saved: " .. tostring(_webp_bytes_saved()) .. "\n")
        "#,
    )?;

    trace!("register() done");
    Ok("rust_register_ok".to_string())
}
