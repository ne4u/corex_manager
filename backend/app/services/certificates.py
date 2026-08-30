import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone, timedelta
from typing import List, Optional
from sqlalchemy.orm import Session
from ..core.config import get_settings
from ..models.models import Certificate
from .acme_cas import resolve_ca_server
from .dns_providers import (
    get_active_acme_client,
    get_provider_code,
    get_provider_credentials_config,
    validate_dns_credentials,
)

settings = get_settings()

# acme.sh has a known bug where it emits hundreds of
# "[: INFO: integer expression expected" lines to stderr. These are noise
# from the acme.sh script itself (a bad `[ "$var" -eq N ]` test) and drown
# out the real error message. It also appends a generic "Please add '--debug'"
# and "See: https://..." footer to every error. Filter both out.
_ACME_NOISE_RE = re.compile(r"\[: (INFO|DEBUG|ERROR): integer expression expected")
_ACME_FOOTER_RE = re.compile(r"Please add '--debug' or '--log' to see more information\.|See: https://github\.com/acmesh-official/acme\.sh/wiki/How-to-debug-acme\.sh")


def _clean_acme_output(output: str) -> str:
    """Remove acme.sh's noise lines and generic debug footer from error output."""
    if not output:
        return output
    lines = output.splitlines()
    cleaned = [l for l in lines if not _ACME_NOISE_RE.search(l) and not _ACME_FOOTER_RE.search(l)]
    return "\n".join(cleaned).strip() or output


def _acme_sh_bin() -> str:
    return shutil.which("acme.sh") or settings.ACME_SH_BIN


def _acme_keylength(key_type: Optional[str]) -> str:
    mapping = {
        "rsa-2048": "2048",
        "rsa-3072": "3072",
        "rsa-4096": "4096",
        "rsa-8192": "8192",
        "ecdsa-p256": "ec-256",
        "ecdsa-p384": "ec-384",
        "ecdsa-p521": "ec-521",
    }
    return mapping.get(key_type or "ecdsa-p384", "ec-384")


def _acme_sh_base(ca: Optional[str] = None, accountemail: Optional[str] = None) -> List[str]:
    server = resolve_ca_server(ca, "acme.sh") or settings.ACME_SH_CA
    return [
        _acme_sh_bin(),
        "--home", settings.ACME_SH_HOME,
        "--cert-home", settings.ACME_SH_HOME,
        "--accountemail", accountemail or "admin@example.com",
        "--server", server,
    ]


def _safe_cert_name(value: str) -> str:
    """Sanitize a value used in a certificate directory/file path."""
    if not isinstance(value, str):
        value = str(value)
    # Reject path traversal and absolute paths
    if os.path.isabs(value) or ".." in value or "/" in value or "\\" in value or "\x00" in value:
        raise ValueError("Invalid certificate domain/name")
    return re.sub(r"[^A-Za-z0-9_.-]", "_", value)


def _cert_dir(cert: Certificate) -> str:
    return os.path.join(settings.CERT_DIR, _safe_cert_name(cert.domain or cert.name))


def _haproxy_bundle_path(cert: Certificate) -> str:
    return os.path.join(_cert_dir(cert), "haproxy.pem")


def _ca_bundle_path(cert: Certificate) -> str:
    return os.path.join(_cert_dir(cert), "ca.pem")


def delete_cert_files(domain_or_name: str) -> None:
    """Remove a certificate's files from disk by domain or name."""
    cert_dir = os.path.join(settings.CERT_DIR, _safe_cert_name(domain_or_name))
    if os.path.isdir(cert_dir):
        shutil.rmtree(cert_dir, ignore_errors=True)


def _write_haproxy_bundle(cert: Certificate) -> None:
    """Combine the private key and fullchain into a single PEM for HAProxy crt."""
    cert_dir = _cert_dir(cert)
    key_path = os.path.join(cert_dir, "privkey.pem")
    fullchain_path = os.path.join(cert_dir, "fullchain.pem")
    bundle_path = _haproxy_bundle_path(cert)
    if not os.path.exists(key_path):
        raise FileNotFoundError(f"Private key not found at {key_path}")
    if not os.path.exists(fullchain_path):
        raise FileNotFoundError(f"Fullchain not found at {fullchain_path}")
    with open(bundle_path, "w") as f:
        fullchain = open(fullchain_path).read()
        f.write(fullchain)
        if fullchain and not fullchain.endswith("\n"):
            f.write("\n")
        f.write(open(key_path).read())


def migrate_cert_bundles(db: Session) -> None:
    """On startup, rebuild HAProxy-compatible bundles for any existing certs that still
    reference the old fullchain/cert path. This also fixes certs uploaded before the
    haproxy.pem bundle logic was introduced.
    """
    from sqlalchemy import select
    try:
        certs = db.execute(select(Certificate)).scalars().all()
    except Exception:
        logger.exception("Unable to migrate certificate bundles")
        return
    for cert in certs:
        if not cert.domain:
            continue
        try:
            cert_dir = _cert_dir(cert)
            haproxy_path = _haproxy_bundle_path(cert)
            if cert.cert_path == haproxy_path and os.path.exists(haproxy_path):
                continue
            fullchain_path = os.path.join(cert_dir, "fullchain.pem")
            privkey_path = os.path.join(cert_dir, "privkey.pem")
            if not os.path.exists(fullchain_path) or not os.path.exists(privkey_path):
                continue
            _write_haproxy_bundle(cert)
            cert.cert_path = haproxy_path
            db.add(cert)
        except Exception:
            logger.exception("Failed to migrate certificate bundle for %s", cert.domain)
    try:
        db.commit()
    except Exception:
        logger.exception("Failed to commit certificate bundle migration")
        db.rollback()


def _sync_cert_metadata(cert: Certificate):
    # Parse NotBefore/NotAfter, CN, and SANs from PEM if possible using openssl
    fullchain = os.path.join(_cert_dir(cert), "fullchain.pem")
    if os.path.exists(fullchain) and shutil.which("openssl"):
        try:
            out = subprocess.check_output(
                ["openssl", "x509", "-in", fullchain, "-noout", "-dates"],
                text=True
            )
            for line in out.splitlines():
                if line.startswith("notBefore="):
                    cert.not_before = _parse_openssl_date(line.split("=", 1)[1])
                elif line.startswith("notAfter="):
                    cert.not_after = _parse_openssl_date(line.split("=", 1)[1])
        except Exception:
            pass

        try:
            subject = subprocess.check_output(
                ["openssl", "x509", "-in", fullchain, "-noout", "-subject", "-nameopt", "RFC2253"],
                text=True
            )
            subject_value = subject.strip().split("=", 1)[1]
            for part in subject_value.split(","):
                part = part.strip()
                if part.startswith("CN="):
                    cert.subject_cn = part.split("=", 1)[1]
                    break
        except Exception:
            cert.subject_cn = None

        try:
            san_out = subprocess.check_output(
                ["openssl", "x509", "-in", fullchain, "-noout", "-ext", "subjectAltName"],
                text=True
            )
            sans = []
            for line in san_out.splitlines():
                sans.extend(re.findall(r"DNS:([^,\s]+)", line))
            cert.sans = ", ".join(sans) if sans else None
        except Exception:
            cert.sans = None


def _parse_openssl_date(s: str) -> Optional[datetime]:
    try:
        # OpenSSL always prints GMT; strip the timezone and return a naive UTC datetime
        return datetime.strptime(s.strip(), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=None)
    except Exception:
        return None


def generate_certificate(cert: Certificate, db: Session, issue: bool = True) -> dict:
    # Validate domain before any filesystem or certbot operation
    _safe_cert_name(cert.domain)
    cert_dir = _cert_dir(cert)
    os.makedirs(cert_dir, exist_ok=True)
    if cert.kind == "ca":
        cert.cert_path = _ca_bundle_path(cert)
        cert.key_path = None
        cert.chain_path = _ca_bundle_path(cert)
    else:
        cert.cert_path = _haproxy_bundle_path(cert)
        cert.key_path = os.path.join(cert_dir, "privkey.pem")
        cert.chain_path = os.path.join(cert_dir, "chain.pem")

    if cert.provider == "custom":
        return {"status": "ok", "message": "Custom certificate paths registered", "cert": cert}

    if cert.provider == "letsencrypt" and issue:
        if settings.ACME_SH_ENABLED:
            return _run_acme_sh(cert, db)
        return _run_certbot(cert, db)

    return {"status": "ok", "message": "Certificate paths registered", "cert": cert}


def _install_acme_sh_cert(cert: Certificate, cert_dir: str) -> dict:
    """Copy an acme.sh issued cert into the project cert directory."""
    install_cmd = _acme_sh_base(cert.acme_ca, cert.email) + [
        "--install-cert", "-d", cert.domain,
        "--cert-file", os.path.join(cert_dir, "cert.pem"),
        "--key-file", os.path.join(cert_dir, "privkey.pem"),
        "--fullchain-file", os.path.join(cert_dir, "fullchain.pem"),
        "--ca-file", os.path.join(cert_dir, "chain.pem"),
        "--reloadcmd", "echo 'certificate installed'",
    ]
    install = subprocess.run(install_cmd, capture_output=True, text=True)
    if install.returncode != 0:
        return {"status": "error", "message": _clean_acme_output(install.stderr or install.stdout)}
    try:
        _write_haproxy_bundle(cert)
    except Exception as exc:
        return {"status": "error", "message": f"Failed to build HAProxy bundle: {exc}"}
    return {"status": "ok"}


def _run_acme_sh(cert: Certificate, db: Session) -> dict:
    _safe_cert_name(cert.domain)
    cert_dir = _cert_dir(cert)
    os.makedirs(cert_dir, exist_ok=True)
    os.makedirs(settings.ACME_SH_HOME, exist_ok=True)

    domains = [cert.domain]
    if cert.is_wildcard:
        domains.append(f"*.{cert.domain}")

    cmd = _acme_sh_base(cert.acme_ca, cert.email) + ["--issue"]
    cmd.extend(["-d", cert.domain])
    if cert.is_wildcard:
        cmd.extend(["-d", f"*.{cert.domain}"])
    cmd.extend(["--keylength", _acme_keylength(cert.key_type)])

    env = os.environ.copy()
    if cert.acme_challenge == "dns":
        config = get_provider_credentials_config(cert.dns_provider, "acme.sh")
        if not config:
            return {"status": "error", "message": f"DNS provider {cert.dns_provider} not supported by acme.sh"}
        validation = validate_dns_credentials(cert.dns_provider, cert.dns_credentials, "acme.sh")
        if validation:
            return {"status": "error", "message": validation}
        code = config.get("code")
        if config.get("custom_code"):
            code = (cert.dns_credentials or {}).get("_provider_code")
            if not code:
                return {"status": "error", "message": "Custom DNS provider code is required for acme.sh"}
        cmd.extend(["--dns", code])
        if cert.dns_credentials:
            for k, v in cert.dns_credentials.items():
                if not k.startswith("_"):
                    env[k] = v
    else:
        # Use webroot mode so acme.sh writes challenge files to the shared
        # volume that HAProxy serves directly — no port 80 listener needed in
        # the API container, eliminating the backend proxy security risk.
        webroot = settings.ACME_WEBROOT_PATH
        os.makedirs(webroot, exist_ok=True)
        cmd.extend(["--webroot", webroot])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, env=env)
        if result.returncode != 0:
            return {"status": "error", "message": _clean_acme_output(result.stderr or result.stdout)}

        install = _install_acme_sh_cert(cert, cert_dir)
        if install.get("status") != "ok":
            return install

        _sync_cert_metadata(cert)
        db.commit()
        return {"status": "ok", "message": "Certificate issued via acme.sh", "cert": cert}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def _run_certbot(cert: Certificate, db: Session) -> dict:
    _safe_cert_name(cert.domain)
    cert_dir = _cert_dir(cert)
    acme_client = "certbot"
    work_dir = tempfile.mkdtemp(prefix="certbot-")
    logs_dir = os.path.join(work_dir, "logs")
    config_dir = os.path.join(work_dir, "config")
    os.makedirs(logs_dir, exist_ok=True)
    os.makedirs(config_dir, exist_ok=True)

    domains = [cert.domain]
    if cert.is_wildcard:
        domains.append(f"*.{cert.domain}")

    cmd = [
        "certbot", "certonly", "--non-interactive", "--agree-tos",
        "--email", cert.email or "admin@example.com",
        "--work-dir", work_dir,
        "--logs-dir", logs_dir,
        "--config-dir", config_dir,
    ]
    ca_server = resolve_ca_server(cert.acme_ca, acme_client)
    if ca_server:
        cmd.extend(["--server", ca_server])

    key_type = cert.key_type or "ecdsa-p384"
    if key_type.startswith("rsa-"):
        cmd.extend(["--key-type", "rsa", "--rsa-key-size", key_type.split("-", 1)[1]])
    elif key_type.startswith("ecdsa-"):
        curve_map = {"p256": "secp256r1", "p384": "secp384r1", "p521": "secp521r1"}
        curve = curve_map.get(key_type.split("-", 1)[1], key_type.split("-", 1)[1])
        cmd.extend(["--key-type", "ecdsa", "--elliptic-curve", curve])

    if cert.acme_challenge == "dns":
        config = get_provider_credentials_config(cert.dns_provider, "certbot")
        if not config:
            return {"status": "error", "message": f"DNS provider {cert.dns_provider} not supported by certbot"}
        validation = validate_dns_credentials(cert.dns_provider, cert.dns_credentials, "certbot")
        if validation:
            return {"status": "error", "message": validation}
        plugin = config.get("plugin")
        if config.get("custom_plugin"):
            plugin = (cert.dns_credentials or {}).get("_plugin")
            if not plugin:
                return {"status": "error", "message": "Custom certbot DNS plugin name is required"}
        plugin_flag = plugin.replace("_", "-")
        cmd.append(f"--dns-{plugin_flag}")
        if cert.dns_credentials:
            cred_path = os.path.join(work_dir, "credentials.ini")
            with open(cred_path, "w") as f:
                for k, v in cert.dns_credentials.items():
                    if not k.startswith("_"):
                        f.write(f"{k} = {v}\n")
            os.chmod(cred_path, 0o600)
            cmd.extend([f"--dns-{plugin_flag}-credentials", cred_path])
    else:
        # Use webroot mode so certbot writes challenge files to the shared
        # volume that HAProxy serves directly — no port 80 listener needed.
        webroot = settings.ACME_WEBROOT_PATH
        os.makedirs(webroot, exist_ok=True)
        cmd.extend(["--webroot", "--webroot-path", webroot, "--preferred-challenges", "http"])

    for d in domains:
        cmd.extend(["-d", d])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            return {"status": "error", "message": _clean_acme_output(result.stderr or result.stdout)}

        src_dir = os.path.join(config_dir, "live", domains[0])
        for src_name, dst_name in [
            ("fullchain.pem", "fullchain.pem"),
            ("privkey.pem", "privkey.pem"),
            ("chain.pem", "chain.pem"),
        ]:
            src = os.path.join(src_dir, src_name)
            dst = os.path.join(cert_dir, dst_name)
            if os.path.exists(src):
                shutil.copy2(src, dst)

        try:
            _write_haproxy_bundle(cert)
        except Exception as exc:
            return {"status": "error", "message": f"Failed to build HAProxy bundle: {exc}"}

        _sync_cert_metadata(cert)
        db.commit()
        return {"status": "ok", "message": "Certificate issued", "cert": cert}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def _renew_acme_sh(cert: Certificate, db: Session) -> dict:
    cert_dir = _cert_dir(cert)
    cmd = _acme_sh_base(cert.acme_ca, cert.email) + ["--renew", "-d", cert.domain]
    env = os.environ.copy()
    if cert.acme_challenge == "dns" and cert.dns_credentials:
        for k, v in cert.dns_credentials.items():
            if not k.startswith("_"):
                env[k] = v
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, env=env)
        if result.returncode != 0:
            return {"status": "error", "message": _clean_acme_output(result.stderr or result.stdout)}
        # Re-install the renewed cert to the project cert directory and rebuild bundle
        install = _install_acme_sh_cert(cert, cert_dir)
        if install.get("status") != "ok":
            return install
        _sync_cert_metadata(cert)
        db.commit()
        return {"status": "ok", "message": "Certificate renewed via acme.sh", "cert": cert}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def renew_certificates(db: Session) -> dict:
    results = []
    now = datetime.now(timezone.utc)
    for cert in db.query(Certificate).filter(Certificate.auto_renew == True, Certificate.provider == "letsencrypt").all():
        if cert.not_after:
            # not_after may be naive (SQLite strips tzinfo); treat it as UTC
            not_after = cert.not_after
            if not_after.tzinfo is None:
                not_after = not_after.replace(tzinfo=timezone.utc)
            if not_after - now > timedelta(days=30):
                continue
        if settings.ACME_SH_ENABLED:
            results.append({"cert": cert.name, "result": _renew_acme_sh(cert, db)})
        else:
            results.append({"cert": cert.name, "result": _run_certbot(cert, db)})
    return {"status": "ok", "results": results}


def upload_custom_certificate(cert: Certificate, key: str, chain: str, fullchain: str, db: Session) -> dict:
    cert_dir = _cert_dir(cert)
    os.makedirs(cert_dir, exist_ok=True)

    if cert.kind == "ca":
        if key.strip():
            return {"status": "error", "message": "CA certificate must not include a private key"}
        if not fullchain.strip() and not chain.strip():
            return {"status": "error", "message": "CA certificate requires a certificate chain"}

        # Validate the CA/chain PEM(s) before writing.
        temp_files = []
        try:
            if fullchain.strip():
                fullchain_tmp = tempfile.NamedTemporaryFile("w", delete=False, suffix=".pem")
                fullchain_tmp.write(fullchain)
                fullchain_tmp.close()
                temp_files.append(fullchain_tmp.name)
                subprocess.run(
                    ["openssl", "x509", "-noout", "-in", fullchain_tmp.name],
                    check=True, capture_output=True, text=True,
                )
            if chain.strip():
                chain_tmp = tempfile.NamedTemporaryFile("w", delete=False, suffix=".pem")
                chain_tmp.write(chain)
                chain_tmp.close()
                temp_files.append(chain_tmp.name)
                subprocess.run(
                    ["openssl", "x509", "-noout", "-in", chain_tmp.name],
                    check=True, capture_output=True, text=True,
                )
        except subprocess.CalledProcessError as e:
            return {"status": "error", "message": f"Invalid CA certificate: {e.stderr or e.stdout}"}
        finally:
            for f in temp_files:
                try:
                    os.unlink(f)
                except Exception:
                    pass

        ca_bundle = _ca_bundle_path(cert)
        cert.cert_path = ca_bundle
        cert.key_path = None
        cert.chain_path = ca_bundle

        with open(ca_bundle, "w") as f:
            if fullchain.strip():
                f.write(fullchain)
                if not fullchain.endswith("\n"):
                    f.write("\n")
            if chain.strip():
                f.write(chain)
                if not chain.endswith("\n"):
                    f.write("\n")

        _sync_cert_metadata(cert)
        db.commit()
        return {"status": "ok", "message": "CA certificate uploaded", "cert": cert}

    if not fullchain.strip() or not key.strip():
        return {"status": "error", "message": "Fullchain and private key are required"}

    cert.cert_path = _haproxy_bundle_path(cert)
    cert.key_path = os.path.join(cert_dir, "privkey.pem")
    cert.chain_path = os.path.join(cert_dir, "chain.pem")

    # Validate cert/key pair (and optional chain) in temporary files before writing to final paths
    temp_files = []
    try:
        fullchain_tmp = tempfile.NamedTemporaryFile("w", delete=False, suffix=".pem")
        fullchain_tmp.write(fullchain)
        fullchain_tmp.close()
        temp_files.append(fullchain_tmp.name)

        key_tmp = tempfile.NamedTemporaryFile("w", delete=False, suffix=".pem")
        key_tmp.write(key)
        key_tmp.close()
        temp_files.append(key_tmp.name)

        if chain.strip():
            chain_tmp = tempfile.NamedTemporaryFile("w", delete=False, suffix=".pem")
            chain_tmp.write(chain)
            chain_tmp.close()
            temp_files.append(chain_tmp.name)
            subprocess.run(
                ["openssl", "x509", "-noout", "-in", chain_tmp.name],
                check=True, capture_output=True, text=True
            )

        subprocess.run(
            ["openssl", "x509", "-noout", "-in", fullchain_tmp.name],
            check=True, capture_output=True, text=True
        )
        subprocess.run(
            ["openssl", "pkey", "-noout", "-in", key_tmp.name],
            check=True, capture_output=True, text=True
        )

        pubkey_cert = subprocess.run(
            ["openssl", "x509", "-noout", "-pubkey", "-in", fullchain_tmp.name],
            check=True, capture_output=True, text=True
        ).stdout.strip()
        pubkey_key = subprocess.run(
            ["openssl", "pkey", "-pubout", "-in", key_tmp.name],
            check=True, capture_output=True, text=True
        ).stdout.strip()
        if pubkey_cert != pubkey_key:
            return {"status": "error", "message": "Private key does not match certificate"}
    except subprocess.CalledProcessError as e:
        return {"status": "error", "message": f"Invalid certificate or key: {e.stderr or e.stdout}"}
    finally:
        for f in temp_files:
            try:
                os.unlink(f)
            except Exception:
                pass

    with open(os.path.join(cert_dir, "fullchain.pem"), "w") as f:
        f.write(fullchain)
    with open(cert.key_path, "w") as f:
        f.write(key)
    with open(cert.chain_path, "w") as f:
        f.write(chain)
    with open(cert.cert_path, "w") as f:
        if fullchain and not fullchain.endswith("\n"):
            f.write(fullchain + "\n")
        else:
            f.write(fullchain)
        f.write(key)

    _sync_cert_metadata(cert)
    db.commit()
    return {"status": "ok", "message": "Custom certificate uploaded", "cert": cert}
