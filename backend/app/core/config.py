from typing import Optional

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache


class Settings(BaseSettings):
    APP_NAME: str = "coreX Manager"
    DATABASE_URL: str = "sqlite:///data/haproxy_manager.db"
    HAPROXY_CONFIG_PATH: str = "data/haproxy.cfg"
    HAPROXY_SOCKET_PATH: str = "/var/run/haproxy.sock"
    HAPROXY_MASTER_SOCKET_PATH: str = "/var/run/haproxy-master.sock"
    CERT_DIR: str = "certs"

    # HAProxy Data Plane API
    DATAPLANE_API_URL: str = "https://haproxy:5555/v3"
    DATAPLANE_API_USER: str = "admin"
    DATAPLANE_API_PASSWORD: Optional[str] = None
    DATAPLANE_API_ENABLED: bool = True
    # Optional CA bundle path for verifying the Data Plane API TLS cert.
    # If unset, TLS verification is skipped (self-signed internal cert).
    DATAPLANE_API_CA_BUNDLE: Optional[str] = None

    # acme.sh
    ACME_SH_ENABLED: bool = True
    ACME_SH_HOME: str = "/app/certs/.acme.sh"
    ACME_SH_BIN: str = "/app/certs/.acme.sh/acme.sh"
    ACME_SH_CA: str = "letsencrypt"  # or zerossl, etc.

    # ACME HTTP-01 challenge — HAProxy serves challenge files directly from the
    # shared webroot volume (primary method). The API container fallback is only
    # used for backward compatibility with existing --standalone renewals.
    ACME_WEBROOT_PATH: str = "/app/data/acme-webroot"
    ACME_CHALLENGE_BACKEND_HOST: str = "api"
    ACME_CHALLENGE_BACKEND_PORT: int = 80

    # Coraza SPOA WAF
    CORAZA_SPOA_ENABLED: bool = True
    CORAZA_SPOA_HOST: str = "coraza-spoa"
    CORAZA_SPOA_PORT: int = 9000
    CORAZA_SPOA_TARGETS: Optional[str] = None  # comma-separated host:port pairs for HA
    CORAZA_SPOA_APP: str = "haproxy-waf"
    CORAZA_SPOE_CONFIG_PATH: str = "data/coraza.cfg"

    # Metrics
    # 100k is a sane default for a high-throughput LB (e.g. 80k RPS with
    # sub-second backend latency and headroom). Tune down on small hosts.
    HAPROXY_MAXCONN: int = 100000
    METRICS_SAMPLE_INTERVAL_SECONDS: int = 30
    METRICS_RETENTION_DAYS: int = 7

    # WAF metrics
    CORAZA_SPOA_LOG_PATH: str = "data/coraza-spoa.log"
    CORAZA_SPOA_CONFIG_PATH: str = "data/coraza-spoa.yaml"
    CORAZA_SPOA_AUTO_RESTART: bool = True

    # Cap CAPTCHA service
    CAPTCHA_SERVICE_URL: str = "http://cap:3000"
    CAPTCHA_SERVICE_PUBLIC_URL: str = "http://localhost:3000"
    CAPTCHA_CHALLENGE_URL: str = "/_cap/challenge"
    CAPTCHA_SITE_KEY: Optional[str] = None
    CAPTCHA_SECRET: Optional[str] = None
    # Path prefix for proxying captcha traffic through the HAProxy listener
    CAPTCHA_PROXY_PATH: str = "/_cap"
    # CDN URL for the @cap.js/widget script (pinned version; change to @latest or self-host as needed)
    CAPTCHA_WIDGET_CDN_URL: str = "https://cdn.jsdelivr.net/npm/@cap.js/widget@0.1.57/cap.min.js"
    # Backend API host/port for the challenge page and verify endpoint proxy
    CAPTCHA_API_BACKEND_HOST: str = "api"
    CAPTCHA_API_BACKEND_PORT: int = 8000
    # reCAPTCHA (Google) — env-var fallbacks; UI can override via settings table
    RECAPTCHA_SITE_KEY: Optional[str] = None
    RECAPTCHA_SECRET: Optional[str] = None
    RECAPTCHA_VERSION: str = "v2"  # "v2" or "v3"
    RECAPTCHA_MIN_SCORE: float = 0.5  # v3 only: minimum score (0.0-1.0) to accept
    # Cloudflare Turnstile — env-var fallbacks; UI can override via settings table
    TURNSTILE_SITE_KEY: Optional[str] = None
    TURNSTILE_SECRET: Optional[str] = None
    # CAPTCHA challenge event retention (challenge_events table pruned on startup)
    CAPTCHA_CHALLENGE_RETENTION_DAYS: int = 7
    WAF_METRICS_SAMPLE_INTERVAL_SECONDS: int = 10
    WAF_METRICS_RETENTION_DAYS: int = 7
    # Raw coraza-spoa.log retention (max lines kept; 0 = unlimited).
    # The log file is pruned by the WAF metrics sampler on every cycle.
    WAF_LOG_RETENTION_LINES: int = 500

    # WAF rule snapshot retention (per-rule max; 0 = unlimited)
    WAF_RULE_VERSION_MAX_PER_RULE: int = 10

    # WAF remote rule set downloader
    CUSTOM_RULES_DIR: str = "data/custom-rules"
    RULE_SET_DOWNLOAD_INTERVAL_SECONDS: int = 300

    # WAF SIEM forwarder
    SIEM_FORWARDER_POLL_INTERVAL_SECONDS: int = 5
    SIEM_FORWARDER_BATCH_SIZE: int = 100

    # WAF CRS downloader
    CRS_DIR: str = "data/crs"
    CRS_GITHUB_API: str = "https://api.github.com/repos/coreruleset/coreruleset/releases/latest"
    CRS_SNAPSHOT_MAX: int = 5

    # Rate limiting
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW: int = 60

    # Task queue
    TASK_QUEUE_ENABLED: bool = True

    # Certificate auto-renewal
    AUTO_RENEW_ENABLED: bool = True
    AUTO_RENEW_INTERVAL_SECONDS: int = 86400  # once per day

    SECRET_KEY: str
    # Valkey (Redis-compatible) cache/store
    VALKEY_HOST: str = "localhost"
    VALKEY_PORT: int = 6379
    VALKEY_DB: int = 0
    VALKEY_PASSWORD: Optional[str] = None
    GEOIP_DB_PATH: str = "data/GeoLite2-Country.mmdb"
    ASN_DB_PATH: str = "data/GeoLite2-ASN.mmdb"
    GEOIP_CITY_DB_PATH: str = "data/GeoLite2-City.mmdb"
    MAXMIND_LICENSE_KEY: Optional[str] = None
    GEOIP_DOWNLOAD_INTERVAL_HOURS: int = 24
    # haproxy-geoip2 Rust Lua module — the primary GeoIP engine. Reads MMDB files
    # directly via the maxminddb Rust crate, registers lua.geoip2-lookup-city/asn
    # converters, and hot-reloads DBs in-place without a full HAProxy restart.
    # When disabled, falls back to native geoip2 converter, then map_ip files.
    GEOIP_LUA_MODULE_ENABLED: bool = True
    GEOIP_LUA_RELOAD_INTERVAL_SECONDS: int = 3600  # 1h hot-reload cycle
    # HAProxy map_ip fallback files (legacy last-resort when the Rust Lua module
    # is disabled AND HAProxy lacks the geoip2 converter).
    # Populated by write_haproxy_maps() in services/geoip.py and seeded empty by
    # haproxy/entrypoint.sh. Relative paths resolve to /app/data/... in-container.
    GEOIP_COUNTRY_MAP_PATH: str = "data/geo_country.map"
    GEOIP_ASN_MAP_PATH: str = "data/geo_asn.map"
    LOG_LEVEL: str = "INFO"

    # Security Lists
    SECURITY_LISTS_DIR: str = "data/lists"
    SECURITY_LISTS_FEED_POLL_INTERVAL_SECONDS: int = 300

    # Security Rules
    SECURITY_RULES_BLOCK_STATUS: int = 403

    # SSL Labs API (for certificate host scanning)
    SSLLABS_API_BASE: str = "https://api.ssllabs.com/api/v4"

    # Lua fingerprint scripts (toggled via Global Options GUI; stored in DB settings)
    JA4_ENABLED: bool = True
    REQ_FP_ENABLED: bool = False
    REQ_FP_PARSE_BODY: bool = False  # parse form/JSON bodies into req_fp params (adds body buffering)
    REQ_FP_MAX_BODY_BYTES: int = 1048576  # 1MB max body size when req_fp_parse_body is on
    REQ_FP_ENFORCE_MAX_BODY: bool = False  # reject oversized bodies with 413 instead of skipping body parsing
    REQ_FP_MODULE_ENABLED: bool = True  # use Rust Lua module (true) vs no fingerprinting (false, dev escape hatch)

    # Response compression (toggled via Global Options GUI; stored in DB settings).
    # When enabled, the haproxy-compression Rust Lua module is loaded
    # (lua-load-per-thread compress.lua) and both brotli and zstd become
    # selectable per-backend. gzip/deflate use HAProxy's native
    # `filter compression` (no Rust module) and are always available.
    COMPRESSION_ENABLED: bool = False

    # Disk cache (toggled via Global Options GUI; stored in DB settings).
    # When enabled, the disk cache (file-backed) option becomes available
    # per-backend in the Caching page. Memory cache (HAProxy native) is always
    # available and does not require this toggle.
    DISK_CACHE_ENABLED: bool = False

    # Response transforms (toggled via Global Options GUI; stored in DB settings).
    # When enabled, the haproxy-resp-transform Rust Lua module is loaded
    # (via the combined modules.lua loader) and replace/inject/mask rules
    # become selectable per-backend. Valkey connection params for tokenize
    # mode are reused from VALKEY_HOST/PORT/DB/PASSWORD and injected into
    # the generated modules.lua loader (no separate setting needed).
    RESP_TRANSFORM_ENABLED: bool = False
    RESP_TRANSFORM_DIR: str = "/app/data/resp-transform"
    RESP_TRANSFORM_RELOAD_INTERVAL_SECONDS: int = 30
    # Fallback AES key env var name for tokenize-mode rules when Valkey is down.
    # The Rust module reads this env var to get the AES-256 key for fail-to-encrypt.
    # The env var itself must be set on the haproxy service (not the backend).
    RESP_TRANSFORM_FALLBACK_KEY_ENV: str = "RESP_TRANSFORM_KEY"

    # Image conversion (toggled via Global Options GUI; stored in DB settings).
    # When enabled, the haproxy-img-2-webp Rust Lua module is loaded
    # (via the combined modules.lua loader) and on-the-fly JPEG/PNG/GIF to
    # WebP conversion becomes selectable per-backend. The filter performs
    # content negotiation based on the Accept header — no rewrite rules or
    # src-link replacement needed. Converted responses are cached by HAProxy's
    # native memory cache / Varnish disk cache (Vary: Accept ensures separate
    # cache entries for WebP vs original).
    IMG_2_WEBP_ENABLED: bool = False
    IMG_2_WEBP_DEFAULT_QUALITY: int = 80
    IMG_2_WEBP_MAX_FILE_SIZE: int = 10_000_000  # 10 MB
    IMG_2_WEBP_MAX_DIMENSIONS: int = 4096
    # Optional `tune.bufsize` override for image conversion. 0 = do not emit
    # tune.bufsize at all and assume HAProxy's 16384 default (the safe default).
    #
    # The img_2_webp filter must buffer the whole body and re-insert the
    # converted result in ONE `msg:set()` call, which HAProxy caps at
    # `htx_free_data_space()`. Exceeding it makes msg:set() return -1 and copy
    # nothing — a silently empty response body. So the largest convertible
    # image is bounded by tune.bufsize, NOT by IMG_2_WEBP_MAX_FILE_SIZE.
    #
    # WARNING: tune.bufsize is GLOBAL and HAProxy allocates roughly 2 buffers
    # per connection, so the worst-case buffer memory is
    # `maxconn * 2 * tune.bufsize`. With HAPROXY_MAXCONN=100000 that is ~3.3 GB
    # at the 16384 default and ~52 GB at 262144. Raise this ONLY together with
    # a suitably lowered HAPROXY_MAXCONN, and verify actual memory headroom.
    # Images larger than the resulting ceiling are served unconverted, which is
    # a safe, working fallback — so leaving this at 0 costs correctness nothing.
    IMG_2_WEBP_BUFSIZE: int = 0
    # HAProxy's built-in tune.bufsize default, used to derive the filter's
    # max_buffer ceiling when IMG_2_WEBP_BUFSIZE is 0.
    HAPROXY_DEFAULT_BUFSIZE: int = 16_384
    # Safety margin subtracted from the effective bufsize to account for
    # tune.maxrewrite (1024) and the response header block, which share the same
    # buffer. Capped at a quarter of the bufsize so small buffers stay sane.
    IMG_2_WEBP_BUFFER_RESERVE: int = 32_768  # 32 KB

    # Cache metrics sampler
    CACHE_METRICS_SAMPLE_INTERVAL_SECONDS: int = 30
    CACHE_METRICS_RETENTION_DAYS: int = 7

    # Disk cache container (internal — not exposed in the GUI)
    VARNISH_CONTAINER_NAME: str = "varnish"
    VARNISH_PORT: int = 6081
    VARNISH_VCL_PATH: str = "data/varnish/default.vcl"
    VARNISH_STORAGE_SIZE: str = "1G"

    # Audit
    AUDIT_PAYLOAD_MAX_BYTES: int = 16384

    # Page Protect (Cloudflare Page Shield-style client-side security)
    PAGE_PROTECT_SAMPLER_INTERVAL_SECONDS: int = 10
    PAGE_PROTECT_REPORT_BODY_MAX_BYTES: int = 16384
    PAGE_PROTECT_HASH_TIMEOUT_SECONDS: int = 10
    PAGE_PROTECT_HASH_USER_AGENT: str = "HAProxy-Manager-PageProtect/1.0"
    PAGE_PROTECT_DEFAULT_REPORT_PATH: str = "/_csp-report"
    PAGE_PROTECT_BEACON_JS_PATH: str = "/app/data/page-protect-beacon.js"

    # API Armor (Cloudflare API Shield-parity: GraphQL, schema validation, auth,
    # behavioral profiling). Toggled via Global Options GUI; stored in DB settings.
    # When enabled, conditional body buffering is activated on api_armor-enabled
    # listeners/backends, the Rust Lua module is loaded (or Lua fallback), and
    # req_fp v2 parses request bodies (merging body params into existing fields).
    API_ARMOR_ENABLED: bool = False
    # Max request body size for API Armor inspection (bytes). Runtime-editable
    # via the API Armor settings UI (DB setting api_armor_max_body_bytes).
    API_ARMOR_MAX_BODY_BYTES: int = 1048576  # 1MB
    # Rust Lua module vs pure-Lua fallback toggle (DB setting api_armor_module_enabled).
    API_ARMOR_MODULE_ENABLED: bool = True
    # API Armor data directory (schemas, api-keys, JWKS, profiles, profiling log).
    API_ARMOR_DIR: str = "data/api-armor"
    # Separate profiling log — written by the Rust body_parser module, tailed by
    # the ApiArmorProfiler sampler. Mirrors the Coraza SPOA log pattern.
    # Only written when schema learning or profiling learning is enabled.
    API_ARMOR_PROFILE_LOG_PATH: str = "data/api-armor/profiling.log"
    API_ARMOR_PROFILE_LOG_MAX_BODY_BYTES: int = 4096  # truncate bodies in profiling log
    API_ARMOR_PROFILE_LOG_MAX_SIZE_MB: int = 100  # prune file when it exceeds this
    # Schema learning (infers JSON Schemas from observed traffic)
    API_ARMOR_SCHEMA_LEARN_INTERVAL_SECONDS: int = 30
    API_ARMOR_SCHEMA_LEARN_MIN_SAMPLES: int = 100
    API_ARMOR_SCHEMA_LEARN_RETENTION_DAYS: int = 30
    # Behavioral profiling (multi-dimensional per-endpoint baselines)
    API_ARMOR_PROFILE_RETENTION_DAYS: int = 30
    API_ARMOR_PROFILER_INTERVAL_SECONDS: int = 30

    # Platform Logging
    HAPROXY_LOG_DEFAULT_STDOUT: bool = True  # emit log stdout format raw daemon if no LogDestination configured
    HAPROXY_LOG_VIEWER_ENABLED: bool = True  # enable the /logs/recent Docker SDK log tailing endpoint
    HAPROXY_LOG_MAX_LEN: int = 65535  # max HAProxy log line length (HAProxy default 1024 truncates CSP report bodies)
    HAPROXY_CONTAINER_NAME: str = "corex"  # container name for Docker SDK log retrieval

    # GUI session configuration
    SESSION_TIMEOUT_MINUTES: int = 30
    SESSION_WARNING_SECONDS: int = 60

    # Password complexity + rotation policy (overridable via the settings
    # table at runtime; these are the env/config fallback defaults).
    PASSWORD_MIN_LENGTH: int = 8
    PASSWORD_REQUIRE_UPPERCASE: bool = False
    PASSWORD_REQUIRE_LOWERCASE: bool = False
    PASSWORD_REQUIRE_DIGIT: bool = False
    PASSWORD_REQUIRE_SYMBOL: bool = False
    # Number of months before a password is considered expired (0 = disabled).
    PASSWORD_ROTATION_MONTHS: int = 0

    # MCP Gateway
    MCP_GATEWAY_ENABLED: bool = False
    MCP_GATEWAY_LISTEN: str = "0.0.0.0:8081"
    MCP_GATEWAY_INTERNAL_HOST: str = "mcp-gateway"
    MCP_GATEWAY_INTERNAL_PORT: int = 8081
    MCP_EVENTS_LOG_PATH: str = "data/mcp/events.ndjson"
    MCP_CONFIG_PATH: str = "data/mcp/config.json"
    MCP_CATALOG_REFRESH_SECONDS: int = 60
    MCP_UPSTREAM_PORT: int = 8090
    MCP_METRICS_SAMPLE_INTERVAL_SECONDS: int = 30
    MCP_METRICS_RETENTION_DAYS: int = 7
    MCP_SECRETS_KEY: Optional[str] = None  # 32+ byte key for Fernet; separate from SECRET_KEY
    MCP_JWT_ISSUER: Optional[str] = None
    MCP_JWT_AUDIENCE: Optional[str] = None
    MCP_JWT_JWKS_URL: Optional[str] = None
    MCP_ALLOWED_ORIGINS: Optional[str] = None  # comma-separated list
    MCP_LOG_PAYLOADS: bool = False
    MCP_DEFAULT_RPM: int = 60
    # MCP Server (coreX Manager's own MCP server exposing the control plane)
    MCP_SELF_REGISTER: bool = True  # auto-register the coreX Manager MCP server into the gateway
    MCP_SERVICE_TOKEN: Optional[str] = None  # shared secret for rate-limit bypass on in-process MCP calls
    MCP_SERVER_INTERNAL_HOST: str = "mcp-server"
    MCP_SERVER_INTERNAL_PORT: int = 8082

    @field_validator("SECRET_KEY")
    @classmethod
    def _validate_secret_key(cls, v: str) -> str:
        if len(v.encode("utf-8")) < 32:
            raise ValueError(
                "SECRET_KEY must be at least 32 bytes (UTF-8) for HS256 JWT security. "
                'Generate one with: python -c "import secrets; print(secrets.token_urlsafe(32))"'
            )
        return v

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


@lru_cache()
def get_settings() -> Settings:
    return Settings()
