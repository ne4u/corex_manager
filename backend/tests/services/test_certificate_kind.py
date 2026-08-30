import os
import subprocess
import tempfile

from app.models.models import Certificate
from app.services.certificates import _cert_dir, upload_custom_certificate
from app.services import haproxy
from tests.factories import make_backend, make_listener, make_server


def _generate_self_signed_cert():
    """Return a (cert_pem, key_pem) pair from a temporary self-signed certificate."""
    with tempfile.TemporaryDirectory() as d:
        key_path = os.path.join(d, "key.pem")
        cert_path = os.path.join(d, "cert.pem")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", key_path, "-out", cert_path, "-days", "1",
                "-subj", "/CN=test",
            ],
            check=True, capture_output=True, text=True,
        )
        with open(cert_path) as f:
            cert = f.read()
        with open(key_path) as f:
            key = f.read()
    return cert, key


def test_upload_custom_certificate_ca_kind(db, monkeypatch, tmp_path):
    cert_pem, _ = _generate_self_signed_cert()
    cert = Certificate(name="test-ca", domain="test-ca", provider="custom", kind="ca")
    db.add(cert)
    db.flush()

    import app.services.certificates as cert_service
    cert_dir = tmp_path / "certs"
    cert_dir.mkdir()
    monkeypatch.setattr(cert_service.settings, "CERT_DIR", str(cert_dir))
    res = upload_custom_certificate(cert, "", "", cert_pem, db)
    assert res["status"] == "ok"
    assert cert.kind == "ca"
    assert cert.cert_path.endswith("ca.pem")
    assert cert.key_path is None
    assert os.path.exists(cert.cert_path)
    with open(cert.cert_path) as f:
        assert "BEGIN CERTIFICATE" in f.read()


def test_upload_custom_certificate_rejects_key_for_ca(db):
    cert_pem, key_pem = _generate_self_signed_cert()
    cert = Certificate(name="test-ca", domain="test-ca", provider="custom", kind="ca")
    db.add(cert)
    db.flush()
    res = upload_custom_certificate(cert, key_pem, "", cert_pem, db)
    assert res["status"] == "error"
    assert "must not include a private key" in res["message"]


def test_generate_backend_uses_certificate_fks(db):
    backend = make_backend(db)
    make_listener(db, backend=backend)

    ca_cert = Certificate(name="test-ca", domain="test-ca", provider="custom", kind="ca", cert_path="/certs/test-ca/ca.pem")
    client_cert = Certificate(name="test-client", domain="test-client", provider="custom", kind="client", cert_path="/certs/test-client/haproxy.pem")
    db.add(ca_cert)
    db.add(client_cert)
    db.flush()

    server = make_server(db, backend.id)
    server.ssl = True
    server.verify = "required"
    server.ca_certificate_id = ca_cert.id
    server.client_certificate_id = client_cert.id
    db.flush()

    cfg = haproxy.generate_backend(backend, db)
    assert "ca-file /certs/test-ca/ca.pem" in cfg
    assert "crt /certs/test-client/haproxy.pem" in cfg


def test_generate_backend_skips_cert_lines_without_certificate(db):
    backend = make_backend(db)
    make_listener(db, backend=backend)
    server = make_server(db, backend.id)
    server.ssl = True
    server.verify = "required"
    db.flush()

    cfg = haproxy.generate_backend(backend, db)
    assert "ca-file" not in cfg
    assert "crt " not in cfg
