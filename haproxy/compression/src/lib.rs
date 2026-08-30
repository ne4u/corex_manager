use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};

use brotlic::{BrotliEncoderOptions, CompressorWriter, Quality, WindowSize};
use haproxy_api::{Core, FilterMethod, FilterResult, Headers, HttpMessage, Txn, UserFilter};
use mlua::prelude::{Lua, LuaResult, LuaTable, LuaUserData, LuaValue};
use zstd::stream::Encoder as ZstdEncoder;

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
    /// Borrow the inner output buffer (compressed bytes produced so far).
    fn get_ref(&self) -> &Vec<u8> {
        match self {
            Encoder::Brotli(w) => w.get_ref(),
            Encoder::Zstd(w) => w.get_ref(),
        }
    }

    /// Mutably borrow the inner output buffer (for draining via `clear()`).
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
            Encoder::Brotli(w) => w.into_inner().map_err(|e| std::io::Error::other(e)),
            Encoder::Zstd(w) => w.finish(),
        }
    }
}

/// A Lua filter that applies brotli or zstd compression to HTTP responses.
#[derive(Default)]
pub struct CompressionFilter {
    enabled: bool,
    /// The encoding negotiated for this request ("br" or "zstd").
    encoding: String,
    writer: Option<Encoder>,
    /// Cumulative count of original (uncompressed) bytes written to the
    /// encoder for this response. Used at EOM to compute bytes saved.
    original_bytes: u64,
    options: CompressionFilterOptions,
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
        msg.add_header("vary", "accept-encoding")?;
        // Switch to chunked transfer encoding (compressed length is unknown).
        msg.set_body_len(None)?;

        Self::register_data_filter(lua, txn, msg.channel()?)
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
    const METHODS: u8 = FilterMethod::HTTP_HEADERS | FilterMethod::HTTP_PAYLOAD;

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

    fn http_payload(&mut self, _: &Lua, _: Txn, msg: HttpMessage) -> LuaResult<Option<usize>> {
        if let Some(chunk) = msg.body(None, Some(-1))? {
            // `body()` returns a `LuaString`; `as_bytes()` yields a
            // `BorrowedBytes` which holds a strong ref to the Lua state and
            // derefs to `&[u8]`. Bind it so the borrow lives for the whole
            // callback (the temporary would otherwise drop immediately).
            let chunk_bytes = chunk.as_bytes();
            let chunk: &[u8] = &chunk_bytes;
            {
                let writer = self
                    .writer
                    .as_mut()
                    .expect("Compression writer must exist when payload arrives");
                if !chunk.is_empty() {
                    writer
                        .write_all(chunk)
                        .expect("Failed to write to compression encoder");
                    writer.flush().expect("Failed to flush compression encoder");
                    // Track original (uncompressed) bytes for bandwidth-saved calculation.
                    self.original_bytes += chunk.len() as u64;
                }
            }
            if !msg.eom()? {
                // Mid-stream: drain whatever the encoder has produced so far.
                let pending = {
                    let writer = self
                        .writer
                        .as_mut()
                        .expect("Compression writer must exist mid-stream");
                    let buf = writer.get_ref().clone();
                    writer.get_mut().clear();
                    buf
                };
                if !pending.is_empty() {
                    msg.set(pending, None, None)?;
                } else if !chunk.is_empty() {
                    // No compressed output yet (encoder buffering) — remove
                    // the raw chunk so it isn't sent uncompressed.
                    msg.remove(None, None)?;
                }
            } else {
                // End of message: finalize the encoder and emit all output.
                let encoder = self
                    .writer
                    .take()
                    .expect("Compression writer must exist at EOM");
                let data = encoder
                    .finish()
                    .expect("Failed to finalize compression encoder");
                // Accumulate bytes saved (original - compressed) into the
                // global counter. Saturating sub guards against the edge
                // case where compressed > original (rare but possible with
                // tiny inputs or encoder overhead).
                let compressed_size = data.len() as u64;
                if self.original_bytes > compressed_size {
                    BYTES_SAVED.fetch_add(self.original_bytes - compressed_size, Ordering::Relaxed);
                }
                msg.set(data, None, None)?;
            }
        }
        Ok(None)
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
