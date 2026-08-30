"""Security Lists: validation helpers, dynamic-feed parser, and list-file writer.

A Security List is a named collection of entries (IP/CIDR, ASN, or country code).
Dynamic feeds auto-populate Network or ASN lists from a remote URL.
"""
import csv
import io
import ipaddress
import os
import re
import threading
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from sqlalchemy.orm import Session

from ..core.config import get_settings
from .country_names import COUNTRY_NAMES

settings = get_settings()


# ---------------------------------------------------------------------------
# Filename safety
# ---------------------------------------------------------------------------

_FILENAME_RE = re.compile(r"[^A-Za-z0-9_.-]")


def safe_filename(name: str) -> str:
    """Sanitize a list name into a safe filename component (no path traversal)."""
    if not isinstance(name, str):
        name = str(name)
    cleaned = _FILENAME_RE.sub("_", name).strip("._") or "unnamed"
    # Reject any residual traversal attempts after sanitization.
    if cleaned in (".", ".."):
        cleaned = "unnamed"
    return cleaned


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

_ASN_RE = re.compile(r"^(?:AS)?(\d+)$", re.IGNORECASE)
_MAX_ASN = 4294967295


def validate_network_value(value: str) -> str:
    """Validate and canonicalize a single IP address or CIDR block.

    Returns the canonical string form. Raises ValueError on invalid input.
    """
    if not value or not isinstance(value, str):
        raise ValueError("Value is required")
    v = value.strip()
    if not v:
        raise ValueError("Value is required")
    # Try a single IP first.
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        pass
    # Then a CIDR / network.
    try:
        net = ipaddress.ip_network(v, strict=False)
        return str(net)
    except ValueError:
        pass
    raise ValueError(f"Invalid IP or CIDR: {value}")


def validate_asn_value(value: str) -> str:
    """Validate and normalize an ASN. Accepts 'AS12345' or '12345'.

    Returns the normalized 'AS<n>' form. Raises ValueError on invalid input.
    """
    if not value or not isinstance(value, str):
        raise ValueError("ASN is required")
    m = _ASN_RE.match(value.strip())
    if not m:
        raise ValueError(f"Invalid ASN format: {value}")
    n = int(m.group(1))
    if n < 1 or n > _MAX_ASN:
        raise ValueError(f"ASN out of range (1-{_MAX_ASN}): {value}")
    return f"AS{n}"


# ---------------------------------------------------------------------------
# Country code validation (ISO 3166-1 alpha-2 + optional MaxMind DB check)
# ---------------------------------------------------------------------------

# ISO 3166-1 alpha-2 officially assigned country codes.
ISO_ALPHA2_CODES: Set[str] = {
    "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS", "AT", "AU",
    "AW", "AX", "AZ", "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BL",
    "BM", "BN", "BO", "BQ", "BR", "BS", "BT", "BV", "BW", "BY", "BZ", "CA", "CC",
    "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN", "CO", "CR", "CU", "CV",
    "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO", "DZ", "EC", "EE", "EG",
    "EH", "ER", "ES", "ET", "FI", "FJ", "FK", "FM", "FO", "FR", "GA", "GB", "GD",
    "GE", "GF", "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS", "GT",
    "GU", "GW", "GY", "HK", "HM", "HN", "HR", "HT", "HU", "ID", "IE", "IL", "IM",
    "IN", "IO", "IQ", "IR", "IS", "IT", "JE", "JM", "JO", "JP", "KE", "KG", "KH",
    "KI", "KM", "KN", "KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC", "LI", "LK",
    "LR", "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MF", "MG", "MH",
    "MK", "ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", "MW",
    "MX", "MY", "MZ", "NA", "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR",
    "NU", "NZ", "OM", "PA", "PE", "PF", "PG", "PH", "PK", "PL", "PM", "PN", "PR",
    "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU", "RW", "SA", "SB", "SC",
    "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN", "SO", "SR", "SS",
    "ST", "SV", "SX", "SY", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TL",
    "TM", "TN", "TO", "TR", "TT", "TV", "TW", "TZ", "UA", "UG", "UM", "US", "UY",
    "UZ", "VA", "VC", "VE", "VG", "VI", "VN", "VU", "WF", "WS", "YE", "YT", "ZA",
    "ZM", "ZW",
}

_country_cache_lock = threading.Lock()
_country_cache: Optional[Dict[str, str]] = None
_country_cache_db_mtime: Optional[float] = None


def _load_country_cache() -> Optional[Dict[str, str]]:
    """Load a mapping of country code -> name from the MaxMind Country DB.

    Returns None if the DB is absent or unreadable. The result is cached and
    refreshed when the DB file mtime changes.
    """
    global _country_cache, _country_cache_db_mtime
    db_path = settings.GEOIP_DB_PATH
    if not db_path or not os.path.exists(db_path):
        return None
    try:
        mtime = os.path.getmtime(db_path)
    except OSError:
        return None
    with _country_cache_lock:
        if _country_cache is not None and _country_cache_db_mtime == mtime:
            return _country_cache
        code_to_name: Dict[str, str] = {}
        try:
            import geoip2.database

            with geoip2.database.Reader(os.path.abspath(db_path)) as reader:
                for _network, record in reader.networks():
                    iso = record.country.iso_code
                    name = record.country.name
                    if iso:
                        code_to_name[iso.upper()] = name or iso.upper()
        except Exception:
            return None
        _country_cache = code_to_name
        _country_cache_db_mtime = mtime
        return _country_cache


def get_known_country_codes() -> Optional[Set[str]]:
    """Return the set of country codes present in the MaxMind Country DB.

    Returns None if the DB is absent. The result is cached and refreshed when
    the DB file mtime changes.
    """
    cache = _load_country_cache()
    if cache is None:
        return None
    return set(cache.keys())


def get_country_options() -> List[Dict[str, str]]:
    """Return a sorted list of {code, name} country options.

    If the MaxMind Country DB is present, the list is derived from it and
    sorted by country name. Otherwise, a static ISO 3166-1 alpha-2 fallback
    mapping is used.
    """
    cache = _load_country_cache()
    if cache is None:
        cache = COUNTRY_NAMES
    options = [
        {"code": code, "name": name}
        for code, name in cache.items()
        if code in ISO_ALPHA2_CODES
    ]
    options.sort(key=lambda o: (o["name"].lower(), o["code"]))
    return options


def validate_country_code(value: str) -> str:
    """Validate an ISO 3166-1 alpha-2 country code.

    If the MaxMind Country DB is present, additionally require the code to be
    present in it. If the DB is absent, accept any valid-format code.

    Returns the uppercased code. Raises ValueError on invalid input.
    """
    if not value or not isinstance(value, str):
        raise ValueError("Country code is required")
    code = value.strip().upper()
    if len(code) != 2 or not code.isalpha():
        raise ValueError(f"Country code must be 2 letters: {value}")
    if code not in ISO_ALPHA2_CODES:
        raise ValueError(f"Unknown ISO 3166-1 alpha-2 country code: {code}")
    known = get_known_country_codes()
    if known is not None and code not in known:
        raise ValueError(f"Country code {code} not present in MaxMind database")
    return code


# ---------------------------------------------------------------------------
# JA4 fingerprint validation
# ---------------------------------------------------------------------------

# JA4 format: {proto}{version}{sni}{cipher_count}{ext_count}{alpn}_{cipher_hash}_{ext_hash}
#   proto:         t (TCP), q (QUIC), d (DTLS)
#   version:       2 alphanumeric chars (e.g. 13, 12, 11, 10, s1, 00)
#   sni:           d (domain/SNI present) or i (IP/no SNI)
#   cipher_count:  2 digits (00-99)
#   ext_count:     2 digits (00-99)
#   alpn:          2 alphanumeric chars (first+last char of first ALPN, or 00)
#   cipher_hash:   12 lowercase hex chars (truncated SHA256)
#   ext_hash:      12 lowercase hex chars (truncated SHA256)
# Example: t13d1516h2_8daaf6152771_b186095e22b6
_JA4_RE = re.compile(r"^[tqd][a-z0-9]{2}[di]\d{2}\d{2}[a-z0-9]{2}_[a-f0-9]{12}_[a-f0-9]{12}$")


def validate_ja4_value(value: str) -> str:
    """Validate a JA4 TLS fingerprint string.

    Returns the normalized (lowercased) fingerprint. Raises ValueError on
    invalid input.
    """
    if not value or not isinstance(value, str):
        raise ValueError("JA4 fingerprint is required")
    v = value.strip().lower()
    if not _JA4_RE.match(v):
        raise ValueError(
            f"Invalid JA4 fingerprint format: {value}. "
            "Expected format: {proto}{version}{sni}{ciphers}{exts}{alpn}_{hash1}_{hash2} "
            "(e.g. t13d1516h2_8daaf6152771_b186095e22b6)"
        )
    return v


# ---------------------------------------------------------------------------
# Pattern (regex) validation
# ---------------------------------------------------------------------------

def validate_pattern_value(value: str) -> str:
    """Validate a regex pattern entry for a Pattern security list.

    Best-effort validation: compile with Python's ``re`` module to catch
    obvious typos. HAProxy uses POSIX ERE, which is close enough for
    validation purposes (Python accepts a superset).

    Returns the raw string as-is (no normalization). Raises ValueError on
    invalid input (empty, contains literal newlines, or fails to compile).
    """
    if not value or not isinstance(value, str):
        raise ValueError("Pattern is required")
    v = value.strip()
    if not v:
        raise ValueError("Pattern is required")
    # Newlines would break the one-pattern-per-line file format.
    if "\n" in v or "\r" in v:
        raise ValueError(f"Pattern must not contain newlines: {value!r}")
    try:
        re.compile(v)
    except re.error as exc:
        raise ValueError(f"Invalid regex pattern: {value} ({exc})")
    return v


# ---------------------------------------------------------------------------
# Dynamic feed parser
# ---------------------------------------------------------------------------

def _get_validator(list_type: Optional[str]) -> Optional[Callable[[str], str]]:
    """Return the validator for a given list type, or None."""
    if list_type == "network":
        return validate_network_value
    if list_type == "asn":
        return validate_asn_value
    if list_type == "ja4":
        return validate_ja4_value
    if list_type == "geo":
        return validate_country_code
    if list_type == "pattern":
        return validate_pattern_value
    return None


def _is_valid_for_list_type(value: str, list_type: Optional[str]) -> bool:
    """Return True if ``value`` is a valid entry for ``list_type``."""
    validator = _get_validator(list_type)
    if not validator:
        return False
    try:
        validator(value.strip())
        return True
    except ValueError:
        return False


def parse_feed_text(text: str, list_type: Optional[str] = None) -> List[Tuple[str, Optional[str]]]:
    """Parse dynamic-feed text into (value, optional note) rows.

    Splits on newlines. Blank lines and lines starting with '#' are ignored.

    When ``list_type`` is provided, each line is treated as a potential CSV row:
    the first field is the entry value and the second field is treated as a note
    unless it is itself a valid value for ``list_type``. Any remaining fields are
    joined into the note. Header rows are automatically removed: the first
    non-comment, non-blank line is skipped if none of its fields validate for
    ``list_type``.

    When ``list_type`` is not provided, the feed is treated as a plain token
    list: lines are split on comma, semicolon, pipe, tab, and runs of
    whitespace, and every token is returned with a ``None`` note.
    """
    if not text:
        return []
    rows: List[Tuple[str, Optional[str]]] = []
    first_line = True
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        # When list_type is not provided, treat the feed as a plain token list
        # and split on all common delimiters. When list_type is provided, use
        # CSV quoting for lines that contain commas so notes can contain commas.
        if list_type is None or "," not in line:
            fields = [p for p in re.split(r"[,;|\t\s]+", line) if p]
        else:
            reader = csv.reader(io.StringIO(line), skipinitialspace=True)
            try:
                fields = next(reader)
            except StopIteration:
                fields = []

        if not fields:
            continue

        # Skip a leading header row when all fields fail validation.
        if first_line and list_type and not any(_is_valid_for_list_type(f, list_type) for f in fields):
            first_line = False
            continue
        first_line = False

        # Value + note when the second field is not a valid entry for this list type.
        if list_type and len(fields) >= 2:
            first = fields[0].strip()
            if _is_valid_for_list_type(first, list_type) and not _is_valid_for_list_type(fields[1], list_type):
                note = ", ".join(f.strip() for f in fields[1:])
                rows.append((first, note))
                continue

        for f in fields:
            f = f.strip()
            if f and not f.startswith("#"):
                rows.append((f, None))
    return rows


# ---------------------------------------------------------------------------
# List-file writer (consumed by HAProxy config generation)
# ---------------------------------------------------------------------------

def generate_security_list_file_contents(db: Session) -> Dict[str, str]:
    """Return ``{rel_path: content}`` for every security list, without writing.

    ``rel_path`` is relative to ``SECURITY_LISTS_DIR``, e.g.
    ``"network/blocklist.lst"``. Content is one value per line with a trailing
    newline. Used by the config-status check to detect unapplied list edits
    without touching disk.
    """
    from ..models.models import NetworkList, AsnList, GeoList, Ja4List, PatternList

    out: Dict[str, str] = {}
    for _, model_cls, subdir in (
        ("network", NetworkList, "network"),
        ("asn", AsnList, "asn"),
        ("geo", GeoList, "geo"),
        ("ja4", Ja4List, "ja4"),
        ("pattern", PatternList, "pattern"),
    ):
        for lst in db.query(model_cls).all():
            fname = safe_filename(lst.name) + ".lst"
            rel = f"{subdir}/{fname}"
            values = [e.value for e in lst.entries]
            out[rel] = "".join(f"{v}\n" for v in values)
    return out


def write_security_list_files(db: Session) -> Dict[str, Any]:
    """Write each Security List to a file on disk under SECURITY_LISTS_DIR.

    Network lists -> {dir}/network/{name}.lst  (one IP/CIDR per line)
    ASN lists     -> {dir}/asn/{name}.lst      (one ASN per line, AS<n> form)
    Geo lists     -> {dir}/geo/{name}.lst      (one country code per line)
    JA4 lists     -> {dir}/ja4/{name}.lst      (one JA4 fingerprint per line)
    Pattern lists -> {dir}/pattern/{name}.lst  (one regex per line)

    Both the live file (``{name}.lst``) and an applied snapshot
    (``{name}.lst.applied``) are written so the config-status check can detect
    unapplied list edits. Stale files for deleted/renamed lists are removed.

    Returns a summary dict with paths written and counts.
    """
    from ..models.models import NetworkList, AsnList, GeoList, Ja4List, PatternList

    base = settings.SECURITY_LISTS_DIR
    subdirs = ("network", "asn", "geo", "ja4", "pattern")
    summary: Dict[str, Any] = {"network": [], "asn": [], "geo": [], "ja4": [], "pattern": []}

    for sub in subdirs:
        os.makedirs(os.path.join(base, sub), exist_ok=True)

    contents = generate_security_list_file_contents(db)
    written_paths: Set[str] = set()
    for rel, content in contents.items():
        path = os.path.join(base, rel)
        with open(path, "w") as f:
            f.write(content)
        with open(f"{path}.applied", "w") as f:
            f.write(content)
        written_paths.add(path)
        kind = rel.split("/", 1)[0]
        summary[kind].append({"path": path, "count": content.count("\n")})

    # Remove stale .lst / .lst.applied files for lists that no longer exist
    # (deleted or renamed). Without this the applied snapshot would linger and
    # the config-status check would permanently report unapplied changes.
    for sub in subdirs:
        sub_dir = os.path.join(base, sub)
        if not os.path.isdir(sub_dir):
            continue
        for fn in os.listdir(sub_dir):
            if not fn.endswith(".lst"):
                continue
            p = os.path.join(sub_dir, fn)
            if p not in written_paths:
                for stale in (p, f"{p}.applied"):
                    if os.path.exists(stale):
                        try:
                            os.remove(stale)
                        except OSError:
                            pass

    return summary


# ---------------------------------------------------------------------------
# "In use" reference detection (for delete protection)
# ---------------------------------------------------------------------------

# Map list_type -> model class. Lazy import to avoid circular imports
# (security_rules imports security_lists for safe_filename).
def _list_model(list_type: str):
    from ..models.models import NetworkList, AsnList, GeoList, Ja4List, PatternList
    return {
        "network": NetworkList,
        "asn": AsnList,
        "geo": GeoList,
        "ja4": Ja4List,
        "pattern": PatternList,
    }.get(list_type)


def find_list_references(db: Session, list_type: str, list_id: int) -> Dict[str, Any]:
    """Collect every reference to a security list.

    Returns a dict with:
      - ``feed``: the DynamicFeed targeting this list (network/asn/ja4), or None.
      - ``rule_refs``: list of human-readable strings naming security rules
        that reference this list via an ``in_list`` condition.
      - ``setting_refs``: list of human-readable strings for setting-based
        references (e.g. the Restore Client IP trusted-source setting).

    The feed reference is force-bypassable; rule/setting references are not.
    """
    from ..models.models import DynamicFeed
    from .settings import get_setting as _get_setting

    model = _list_model(list_type)
    refs: Dict[str, Any] = {"feed": None, "rule_refs": [], "setting_refs": []}
    if model is None:
        return refs

    obj = db.get(model, list_id)
    if obj is None:
        return refs
    list_name = obj.name

    # Dynamic feed ownership (network/asn/ja4 only).
    feed = (
        db.query(DynamicFeed)
        .filter(DynamicFeed.list_type == list_type, DynamicFeed.target_list_id == list_id)
        .first()
    )
    refs["feed"] = feed

    # Security rule references (in_list AST nodes).
    from .security_rules import rules_referencing_list
    for rule in rules_referencing_list(db, list_type, list_name):
        refs["rule_refs"].append(f"security rule '{rule.name}'")

    # Setting-based references.
    if list_type == "network":
        trusted = _get_setting(db, "restore_client_ip_trusted_network_list")
        if trusted:
            trusted_names = [n.strip() for n in trusted.split(",") if n.strip()]
            if list_name in trusted_names:
                refs["setting_refs"].append(
                    "Restore Client IP trusted-source setting (Global Options)"
                )

    return refs


def build_in_use_message(list_name: str, refs: Dict[str, Any]) -> Optional[str]:
    """Combine rule + setting references into a single 409 body.

    Returns None when there are no rule/setting references (the feed reference
    is handled separately by the caller with its own force-bypassable message).
    """
    parts: List[str] = list(refs.get("rule_refs", [])) + list(refs.get("setting_refs", []))
    if not parts:
        return None
    return (
        f"List '{list_name}' is in use by: {', '.join(parts)}. "
        f"Remove those references before deleting."
    )
