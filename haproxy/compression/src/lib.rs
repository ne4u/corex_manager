use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};

use brotlic::{BrotliEncoderOptions, CompressorWriter, Quality, WindowSize};
use haproxy_api::{Core, FilterMethod, FilterResult, Headers, HttpMessage, Txn, UserFilter};
use mlua::prelude::{Lua, LuaResult, LuaTable, LuaUserData, LuaValue};
use zstd::stream::Encoder as ZstdEncoder;

/// Initial chunk size for send()-based EOM flush. Conservative for the default
/// tune.bufsize of 16384 — using a larger value causes send() to fail
/// immediately when the channel buffer is smaller than the chunk.
const EOM_SEND_CHUNK: usize = 12288;

/// Minimum chunk size for send()-based EOM flush. Allows progress even when
/// the channel's available HTX data space is very small (e.g. after headers or
/// with a small tune.bufsize).
const EOM_MIN_SEND_CHUNK: usize = 1024;

/// Maximum send() attempts within a single http_payload callback to avoid
/// spinning if the channel repeatedly refuses data.
const EOM_MAX_SEND_ATTEMPTS: u32 = 64;

/// Maximum consecutive http_payload callbacks with zero forward progress
/// before giving up on the EOM flush. Prevents holding a stream forever when
/// the client/downstream is not draining.
const EOM_MAX_STALLED_CALLBACKS: u32 = 100;

/// Global cumulative counter of bytes saved by brotli/zstd compression.
///
/// Accumulated at end-of-message as `original_size - compressed_size`. Read
/// via the `show compress-stats` CLI command registered in `register()`.
/// Resets to 0 on HAProxy restart (same as HAProxy's native cumulative
/// counters — the backend computes deltas to derive per-interval savings).
static BYTES_SAVED: AtomicU64 = AtomicU64::new(0);

/// Which encoder to use for the current response. Both variants wrap a
/// `Vec<u8>` inner writer and expose `get_ref()`/`get_mut()` so we can drain
/// compressed bytes mid-stream, and a `finish`-style method to finalize.
enum Encoder {
    Brotli(CompressorWriter<Vec<u8>>),
    Zstd(ZstdEncoder<'static, Vec<u8>>),
}

impl Write for Encoder {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Encoder::Brotli(w) => w.write(buf),
            Encoder::Zstd(w) => w.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Encoder::Brotli(w) => w.flush(),
            Encoder::Zstd(w) => w.flush(),
        }
    }
}

impl Encoder {
    /// Mutably borrow the inner output buffer. Compressed bytes produced by
    /// `write()` accumulate here; the payload callback drains them into
    /// `pending_out` via `Vec::append`.
    fn get_mut(&mut self) -> &mut Vec<u8> {
        match self {
            Encoder::Brotli(w) => w.get_mut(),
            Encoder::Zstd(w) => w.get_mut(),
        }
    }

    /// Finalize the encoder and return the compressed bytes.
    /// For brotli this is `into_inner`; for zstd we must call `finish`
    /// to write the end-of-frame marker.
    fn finish(self) -> std::io::Result<Vec<u8>> {
        match self {
            // brotlic::CompressorWriter::into_inner returns
            // Result<Vec<u8>, IntoInnerError<CompressorWriter<Vec<u8>>>>
            // — map the IntoInnerError to io::Error.
            Encoder::Brotli(w) => w.into_inner().map_err(std::io::Error::other),
            Encoder::Zstd(w) => w.finish(),
        }
    }
}

/// A Lua filter that applies brotli or zstd compression to HTTP responses.
pub struct CompressionFilter {
    enabled: bool,
    /// The encoding negotiated for this request ("br" or "zstd").
    encoding: String,
    writer: Option<Encoder>,
    /// Cumulative count of original (uncompressed) bytes written to the
    /// encoder for this response. Used at EOM to compute bytes saved.
    original_bytes: u64,
    options: CompressionFilterOptions,
    // --- Output staging (send()-based forwarding of compressed output) ---
    /// Compressed bytes produced by the encoder but not yet sent. Input is
    /// streamed through the encoder per payload callback (never flush()ed
    /// mid-stream — brotli flush() emits partial metadata blocks that cause
    /// ERR_CONTENT_DECODING_FAILED under HTTP/2 multiplexing) and produced
    /// output is staged here for send() draining.
    pending_out: Vec<u8>,
    /// Current read position within `pending_out`.
    pending_pos: usize,
    /// True when we've entered the EOM flush phase (encoder finalized,
    /// EOM unset, pending_out being drained via send()).
    eom_flushing: bool,
    /// Current send() chunk size during the EOM flush phase. Halved on
    /// backpressure to make progress with small available HTX space.
    flush_chunk: usize,
    /// Consecutive EOM-flush callbacks with no forward progress.
    flush_stalled: u32,
}

/// Options for the compression filter.
#[derive(Debug, Clone, mlua::FromLua)]
struct CompressionFilterOptions {
    brotli: bool,
    zstd: bool,
    quality: u8,
    window: u8,
    level: i32,
    offload: bool,
    content_types: Vec<String>,
}

impl LuaUserData for CompressionFilterOptions {}

impl Default for CompressionFilter {
    fn default() -> Self {
        CompressionFilter {
            enabled: false,
            encoding: String::new(),
            writer: None,
            original_bytes: 0,
            options: CompressionFilterOptions::default(),
            pending_out: Vec::new(),
            pending_pos: 0,
            eom_flushing: false,
            flush_chunk: EOM_SEND_CHUNK,
            flush_stalled: 0,
        }
    }
}

impl Default for CompressionFilterOptions {
    fn default() -> Self {
        CompressionFilterOptions {
            brotli: false,
            zstd: false,
            quality: 5,
            window: WindowSize::default().bits(),
            level: 3,
            offload: false,
            content_types: Vec::new(),
        }
    }
}

impl CompressionFilter {
    fn process_request_headers(&mut self, txn: Txn, msg: HttpMessage) -> LuaResult<()> {
        // Only GET/POST requests are eligible for compression.
        if !matches!(&*txn.f.get_str("method", ())?, "GET" | "POST") {
            self.enabled = false;
            return Ok(());
        }

        // Negotiate the preferred encoding among the enabled ones.
        let (encoding, qval) = Self::preferred_encoding(
            msg.get_headers()?,
            self.options.brotli,
            self.options.zstd,
        )?;
        self.enabled = qval > 0.0 && !encoding.is_empty();
        self.encoding = encoding.clone();

        if self.enabled && self.options.offload {
            // Strip Accept-Encoding so the backend doesn't compress.
            msg.del_header("accept-encoding")?;
        }

        Ok(())
    }

    fn process_response_headers(&mut self, lua: &Lua, txn: Txn, msg: HttpMessage) -> LuaResult<()> {
        // We encode only "200" responses.
        if !self.enabled || txn.f.get::<u16>("status", ())? != 200 {
            return Ok(());
        }

        let headers = msg.get_headers()?;
        // Do not encode when `content-encoding` is already present.
        let mut skip_encoding = headers.get_first::<LuaValue>("content-encoding")?.is_some();
        // Do not encode when `cache-control` includes `no-transform`.
        skip_encoding |= headers
            .get::<String>("cache-control")?
            .iter()
            .any(|v| v.contains("no-transform"));
        // Check content type.
        if !skip_encoding {
            let content_type = headers
                .get_first::<String>("content-type")?
                .unwrap_or_default()
                .to_ascii_lowercase();
            skip_encoding = content_type.is_empty() || content_type.starts_with("multipart");
            if !skip_encoding {
                let mut found = self.options.content_types.is_empty();
                for prefix in &self.options.content_types {
                    if content_type.starts_with(prefix) {
                        found = true;
                        break;
                    }
                }
                skip_encoding = !found;
            }
        }
        // Do not encode responses with no defined transfer length
        // (close-delimited bodies): their end is signalled only by the
        // connection closing and HTX_FL_EOM is never set, so the filter
        // cannot reliably detect end-of-body to finalize the compressed
        // stream. Mirrors HAProxy's native compression filter which requires
        // HTTP_MSGF_XFER_LEN.
        skip_encoding |= !headers.get_first::<LuaValue>("content-length")?.is_some()
            && !headers
                .get::<String>("transfer-encoding")?
                .iter()
                .any(|v| v.to_ascii_lowercase().contains("chunked"));

        if skip_encoding {
            return Ok(());
        }

        // Convert a strong ETag to a weak ETag (compressed body differs).
        match headers.get::<String>("etag")? {
            etag if etag.len() > 1 => return Ok(()),
            etag if etag.len() == 1 && etag[0].starts_with('"') => {
                msg.set_header("etag", format!("W/{}", etag[0]))?;
            }
            _ => {}
        }

        let size_hint = headers
            .get_first::<u32>("content-length")
            .unwrap_or(None)
            .unwrap_or(0);

        // Build the encoder for the negotiated encoding.
        let buf = Vec::with_capacity(4096);
        let encoder = match self.encoding.as_str() {
            "br" => {
                let enc = BrotliEncoderOptions::new()
                    .quality(Quality::new(self.options.quality).unwrap_or(Quality::worst()))
                    .window_size(
                        WindowSize::new(self.options.window).unwrap_or(WindowSize::default()),
                    )
                    .size_hint(size_hint)
                    .build()
                    .expect("Failed to build brotli encoder");
                Encoder::Brotli(CompressorWriter::with_encoder(enc, buf))
            }
            "zstd" => {
                let level = self.options.level.clamp(1, 22);
                let enc = ZstdEncoder::new(buf, level)
                    .expect("Failed to build zstd encoder");
                Encoder::Zstd(enc)
            }
            _ => return Ok(()),
        };
        self.writer = Some(encoder);

        // Update response headers.
        msg.set_header("content-encoding", self.encoding.as_str())?;
        // Add Vary: Accept-Encoding if not already present (case-insensitive).
        // Uses add_header to append to existing Vary values (e.g. "Vary: Accept"
        // from img_2_webp) rather than replacing them. set_header would collapse
        // multiple Vary headers into one, losing values added by other filters.
        let vary_values = headers.get::<String>("vary")?;
        let already_has = vary_values
            .iter()
            .any(|v| v.to_ascii_lowercase().contains("accept-encoding"));
        if !already_has {
            msg.add_header("Vary", "Accept-Encoding")?;
        }
        // Switch to chunked transfer encoding (compressed length is unknown).
        msg.set_body_len(None)?;

        Self::register_data_filter(lua, txn, msg.channel()?)
    }

    /// Send pending compressed output (from the EOM flush phase) via msg.send().
    ///
    /// `msg.send()` inserts data at the filter position and immediately
    /// forwards it. It returns the number of bytes sent, or -1 when the
    /// channel's free HTX space is too small for the requested chunk.
    ///
    /// To avoid getting stuck when the buffer only has a small amount of free
    /// space, the requested chunk size is halved on each refusal until it
    /// reaches `EOM_MIN_SEND_CHUNK`. If the channel still cannot accept the
    /// minimum chunk, we stop and wait for the next `http_payload` callback.
    fn flush_pending(&mut self, lua: &Lua, msg: &HttpMessage) -> LuaResult<usize> {
        let before = self.pending_pos;
        let mut attempts = 0;

        while self.pending_pos < self.pending_out.len() && attempts < EOM_MAX_SEND_ATTEMPTS {
            attempts += 1;
            let remaining = self.pending_out.len() - self.pending_pos;
            let n = remaining.min(self.flush_chunk);
            let sent = msg.send(&self.pending_out[self.pending_pos..self.pending_pos + n])?;
            if sent > 0 {
                self.pending_pos += sent as usize;
                // Reset chunk to the default after forward progress so the next
                // callback starts with the largest feasible chunk.
                self.flush_chunk = EOM_SEND_CHUNK;
                continue;
            }
            // send() returned 0 or -1 (channel full). Try a smaller chunk.
            if self.flush_chunk > EOM_MIN_SEND_CHUNK {
                self.flush_chunk = (self.flush_chunk / 2).max(EOM_MIN_SEND_CHUNK);
                continue;
            }
            // No room even for the minimum chunk; stop and wait for the next
            // http_payload callback after the mux drains the buffer.
            break;
        }

        if self.pending_pos > before {
            self.flush_stalled = 0;
        } else if self.eom_flushing && self.pending_pos < self.pending_out.len() {
            self.flush_stalled += 1;
            if self.flush_stalled >= EOM_MAX_STALLED_CALLBACKS {
                if let Ok(core) = Core::new(lua) {
                    let _ = core.log(
                        haproxy_api::LogLevel::Err,
                        format!(
                            "compression: EOM flush stalled for {} callbacks; giving up with {} of {} bytes unsent",
                            self.flush_stalled,
                            self.pending_out.len() - self.pending_pos,
                            self.pending_out.len()
                        ),
                    );
                }
                // Release the message rather than holding the stream forever.
                // We re-set EOM so the response stream terminates cleanly even
                // though the tail was truncated; the client sees a partial body.
                self.eom_flushing = false;
                self.pending_out.clear();
                self.pending_pos = 0;
                self.flush_chunk = EOM_SEND_CHUNK;
                msg.set_eom(true)?;
            }
        }

        Ok(self.pending_pos - before)
    }

    /// Parse the Accept-Encoding header and return the preferred encoding
    /// among the enabled ones, along with its q-value. Returns ("", 0.0) if
    /// none of the offered encodings are enabled/acceptable.
    fn preferred_encoding(
        headers: Headers,
        brotli_enabled: bool,
        zstd_enabled: bool,
    ) -> LuaResult<(String, f32)> {
        let accept_encoding = headers.get::<String>("accept-encoding")?;
        // (encoding, q-value) for each offered token.
        let mut offered: Vec<(&str, f32)> = Vec::new();
        for v in accept_encoding.iter() {
            for tok in v.split(',').map(str::trim) {
                if tok.is_empty() {
                    continue;
                }
                let (enc, qval) = match tok.split_once(";q=") {
                    Some((e, q)) => {
                        let q = match q.trim().parse::<f32>() {
                            Ok(f) if (0.0..=1.0).contains(&f) => f,
                            _ => 0.0, // invalid q-value → unacceptable
                        };
                        (e.trim(), q)
                    }
                    None => (tok, 1.0),
                };
                offered.push((enc, qval));
            }
        }

        // Pick the highest-q enabled encoding. Ties prefer br over zstd
        // (matches the upstream brotli module's tie-break behavior).
        let mut best: (String, f32) = (String::new(), 0.0);
        for (enc, qval) in offered {
            if qval <= 0.0 {
                continue;
            }
            let supported = match enc {
                "br" => brotli_enabled,
                "zstd" => zstd_enabled,
                _ => false,
            };
            if !supported {
                continue;
            }
            if qval > best.1 || (qval == best.1 && enc == "br" && best.0 != "br") {
                best = (enc.to_string(), qval);
            }
        }
        Ok(best)
    }

    fn parse_args(args: LuaTable) -> LuaResult<CompressionFilterOptions> {
        // Fetch already-parsed options (HAProxy caches args at index 0).
        if let Ok(options) = args.raw_get::<CompressionFilterOptions>(0) {
            return Ok(options);
        }

        let mut options = CompressionFilterOptions::default();
        let mut saw_br = false;
        let mut saw_zstd = false;
        for arg in args.clone().sequence_values::<String>() {
            match &*arg? {
                "br" => {
                    options.brotli = true;
                    saw_br = true;
                }
                "zstd" => {
                    options.zstd = true;
                    saw_zstd = true;
                }
                "offload" => options.offload = true,
                arg if arg.starts_with("type:") => {
                    options.content_types = arg[5..]
                        .split(',')
                        .map(|s| s.trim().to_ascii_lowercase())
                        .filter(|s| !s.is_empty())
                        .collect();
                }
                arg if arg.starts_with("quality:") => {
                    if let Ok(quality) = arg[8..].trim().parse::<u8>() {
                        options.quality = quality.clamp(0, 11);
                    }
                }
                arg if arg.starts_with("window:") => {
                    if let Ok(window) = arg[7..].trim().parse::<u8>() {
                        options.window = window.clamp(10, 24);
                    }
                }
                arg if arg.starts_with("level:") => {
                    if let Ok(level) = arg[6..].trim().parse::<i32>() {
                        options.level = level.clamp(1, 22);
                    }
                }
                _ => {}
            }
        }
        // If neither br nor zstd was specified, enable both (default).
        if !saw_br && !saw_zstd {
            options.brotli = true;
            options.zstd = true;
        }
        args.raw_set(0, options.clone())?;
        Ok(options)
    }
}

impl UserFilter for CompressionFilter {
    const METHODS: u8 = FilterMethod::HTTP_HEADERS | FilterMethod::HTTP_PAYLOAD | FilterMethod::HTTP_END;

    fn new(_: &Lua, args: LuaTable) -> LuaResult<Self> {
        Ok(CompressionFilter {
            options: Self::parse_args(args)?,
            ..Default::default()
        })
    }

    fn http_headers(&mut self, lua: &Lua, txn: Txn, msg: HttpMessage) -> LuaResult<FilterResult> {
        if !msg.is_resp()? {
            self.process_request_headers(txn, msg)?;
        } else {
            self.process_response_headers(lua, txn, msg)?;
        }
        Ok(FilterResult::Continue)
    }

    fn http_payload(&mut self, lua: &Lua, _: Txn, msg: HttpMessage) -> LuaResult<Option<usize>> {
        // --- EOM flush phase: drain pending compressed output via send() ---
        // Entered at end-of-message when the encoder's final output could not
        // be flushed in a single callback. EOM is unset while output remains
        // so the response cannot terminate early. send() returns -1 or 0 on
        // backpressure (not an error), so we can retry without a 500.
        if self.eom_flushing {
            let _sent = self.flush_pending(lua, &msg)?;
            if self.pending_pos >= self.pending_out.len() {
                // All compressed output sent — re-set EOM.
                self.pending_out.clear();
                self.pending_pos = 0;
                self.eom_flushing = false;
                msg.set_eom(true)?;
                return Ok(None);
            }
            // Still have pending output — hold the stream.
            return Ok(Some(0));
        }

        // If compression is not active for this response, pass through.
        if !self.enabled || self.writer.is_none() {
            return Ok(None);
        }

        // Sample EOM before touching the body: msg.remove() may discard
        // trailing non-DATA blocks (the EOM/EOT marker), and msg.body()
        // returns nil once the channel is input-closed with no data left —
        // e.g. when the final DATA block was consumed in an earlier callback
        // and only the EOM marker arrives in this one. Handling EOM only
        // inside `if let Some(chunk) = body()` would silently drop the whole
        // response body in that case.
        let eom = msg.eom()?;

        // Drain output produced by an earlier chunk before consuming more
        // input. send() inserts at the filter's current offset — before any
        // held input — so ordering is preserved, and holding the input while
        // output is pending applies backpressure to the upstream producer.
        if self.pending_pos < self.pending_out.len() {
            self.flush_pending(lua, &msg)?;
            if self.pending_pos < self.pending_out.len() {
                // Could not finish draining. If input is still held in the
                // channel the response cannot end anyway (unconsumed data
                // blocks the ENDING state), so plain backpressure suffices.
                // With no input left, the EOM marker alone would let the
                // response complete while output is still pending — hide it
                // and finish via the flush phase.
                if eom && msg.input()? == 0 {
                    msg.set_eom(false)?;
                    self.eom_flushing = true;
                }
                return Ok(Some(0));
            }
            self.pending_out.clear();
            self.pending_pos = 0;
        }

        // Consume available input: feed it to the encoder, move whatever
        // output it produced into pending_out, and remove the raw bytes from
        // the channel. Compressing incrementally spreads the CPU cost over
        // every payload callback instead of one large synchronous burst at
        // EOM — a multi-MB compress call blocks the worker thread long
        // enough to starve other streams (e.g. SPOE/WAF processing), which
        // surfaced as intermittent 500s under load.
        if let Some(chunk) = msg.body(None, Some(-1))? {
            let chunk = chunk.as_bytes();
            if !chunk.is_empty() {
                let writer = self
                    .writer
                    .as_mut()
                    .expect("Compression writer must exist");
                writer
                    .write_all(&chunk)
                    .expect("Failed to write to compression encoder");
                self.original_bytes += chunk.len() as u64;
                self.pending_out.append(writer.get_mut());
            }
            msg.remove(None, None)?;

            // The input's buffer space is now free — flush what was produced.
            self.flush_pending(lua, &msg)?;
            if self.pending_pos < self.pending_out.len() {
                if eom {
                    // All input is consumed; EOM would end the response while
                    // output is still pending. Hide EOM and let the flush
                    // phase drain the remainder.
                    msg.set_eom(false)?;
                    self.eom_flushing = true;
                }
                return Ok(Some(0));
            }
            self.pending_out.clear();
            self.pending_pos = 0;
        }

        if !eom {
            return Ok(None);
        }

        // End of message: all input has been consumed (or none ever arrived).
        // Finalize the encoder and flush the tail through the same machinery.
        let encoder = self
            .writer
            .take()
            .expect("Compression writer must exist at EOM");
        let data = encoder
            .finish()
            .expect("Failed to finalize compression encoder");

        // Accumulate bytes saved (original - compressed).
        let compressed_size = data.len() as u64;
        if self.original_bytes > compressed_size {
            BYTES_SAVED.fetch_add(self.original_bytes - compressed_size, Ordering::Relaxed);
        }

        self.pending_out = data;
        self.pending_pos = 0;
        self.flush_pending(lua, &msg)?;
        if self.pending_pos < self.pending_out.len() {
            msg.set_eom(false)?;
            self.eom_flushing = true;
            return Ok(Some(0));
        }
        self.pending_out.clear();
        Ok(None)
    }

    fn http_end(&mut self, _lua: &Lua, _txn: Txn, _msg: HttpMessage) -> LuaResult<FilterResult> {
        // If we're in the EOM flush phase with pending compressed output,
        // return Wait to re-run the analyzer, which re-calls http_payload
        // where flush_pending() can make progress.
        if self.eom_flushing && self.pending_pos < self.pending_out.len() {
            return Ok(FilterResult::Wait);
        }
        Ok(FilterResult::Continue)
    }
}

/// Registers a "compress" filter in the given haproxy context.
///
/// Also registers a `show compress-stats` CLI command that returns the
/// cumulative bytes-saved counter. The backend queries this via the HAProxy
/// socket to compute per-interval bandwidth-saved deltas.
///
/// With `lua-load-per-thread`, this function runs on every thread. HAProxy
/// requires CLI commands to be registered on all threads (or none), so we
/// register unconditionally. The `BYTES_SAVED` counter is a global atomic
/// shared across all threads.
pub fn register(lua: &Lua, _options: Option<LuaTable>) -> LuaResult<()> {
    let core = Core::new(lua)?;
    core.register_filter::<CompressionFilter>("compress")?;

    // Expose the counter as a global Lua function so the CLI callback
    // (a Lua chunk) can read it.
    lua.globals().set(
        "_compress_bytes_saved",
        lua.create_function(|_, ()| Ok(BYTES_SAVED.load(Ordering::Relaxed)))?,
    )?;
    // Register the CLI command. The callback receives an AppletTCP as
    // the first argument; output is sent via applet:send().
    core.register_lua_cli(
        &["show", "compress-stats"],
        "show compress-stats: display cumulative bytes saved by brotli/zstd compression",
        r#"
        local applet = ...
        applet:send("bytes_saved: " .. tostring(_compress_bytes_saved()) .. "\n")
        "#,
    )?;

    Ok(())
}
