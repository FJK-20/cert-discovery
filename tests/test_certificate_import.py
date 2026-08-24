"""Importação de certificado existente (app/api/routes_import.py) — cola
certificado + chave privada opcional, converge no mesmo acme_store dos
certificados emitidos via ACME/CSR."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from fastapi.testclient import TestClient

from app.acme.store import AcmeStore
from app.audit.log import audit_log
from app.auth.sessions import TokenStore
from app.auth.store import UserStore
from app.core.ratelimit import SlidingWindowRateLimiter
from app.main import app
from app.pki import keys as pki_keys

ADMIN = {"username": "admin", "password": "supersecretpw"}


def _self_signed_cert(domains: list[str], key) -> str:
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, domains[0])])
    san = x509.SubjectAlternativeName([x509.DNSName(d) for d in domains])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=10))
        .not_valid_after(datetime.now(UTC) + timedelta(days=80))
        .add_extension(san, critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _client(tmp_path, monkeypatch) -> TestClient:
    session_store = TokenStore(ttl_seconds=3600)
    unlimited = SlidingWindowRateLimiter(max_requests=1000, window_seconds=300)
    monkeypatch.setattr("app.auth.routes_auth.user_store", UserStore(tmp_path))
    monkeypatch.setattr("app.auth.dependencies.user_store", UserStore(tmp_path))
    monkeypatch.setattr("app.auth.routes_saml.user_store", UserStore(tmp_path))
    monkeypatch.setattr("app.auth.routes_auth.session_store", session_store)
    monkeypatch.setattr("app.auth.routes_auth.pending_login_store", TokenStore(ttl_seconds=300))
    monkeypatch.setattr("app.auth.dependencies.session_store", session_store)
    monkeypatch.setattr("app.auth.routes_auth._rate_limiter", unlimited)
    store = AcmeStore(tmp_path)
    monkeypatch.setattr("app.api.routes_import.acme_store", store)
    monkeypatch.setattr("app.api.routes_acme.acme_store", store)
    monkeypatch.setattr(audit_log, "_data_dir", tmp_path)
    client = TestClient(app)
    client.post("/api/auth/setup", json=ADMIN)
    return client


def test_import_certificate_with_matching_key(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    key = pki_keys.generate_private_key()
    cert_pem = _self_signed_cert(["imported.example.com"], key)
    key_pem = pki_keys.serialize_private_key(key)

    response = client.post(
        "/api/import/certificate",
        json={"certificate_pem": cert_pem, "private_key_pem": key_pem},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["domain"] == "imported.example.com"
    assert body["has_private_key"] is True

    certs = client.get("/api/acme/certificates").json()
    imported = next(c for c in certs if c["id"] == body["certificate_id"])
    assert imported["environment"] == "imported"
    assert imported["dns_mode"] is None
    assert imported["has_private_key"] is True
    assert imported["key_algorithm"] == "RSA"
    assert imported["key_size"] == pki_keys.KEY_SIZE
    assert imported["subject_cn"] == "imported.example.com"
    assert imported["sans"] == ["imported.example.com"]
    assert imported["serial_number"]
    assert len(imported["sha256_fingerprint"]) == 64

    privkey_response = client.get(f"/api/acme/certificates/{body['certificate_id']}/privkey.pem")
    assert privkey_response.status_code == 200


def test_import_certificate_without_private_key_is_monitor_only(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    key = pki_keys.generate_private_key()
    cert_pem = _self_signed_cert(["monitor-only.example.com"], key)

    response = client.post("/api/import/certificate", json={"certificate_pem": cert_pem})
    assert response.status_code == 201
    body = response.json()
    assert body["has_private_key"] is False

    certs = client.get("/api/acme/certificates").json()
    imported = next(c for c in certs if c["id"] == body["certificate_id"])
    assert imported["has_private_key"] is False

    privkey_response = client.get(f"/api/acme/certificates/{body['certificate_id']}/privkey.pem")
    assert privkey_response.status_code == 404


def test_import_rejects_mismatched_key(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    key = pki_keys.generate_private_key()
    other_key = pki_keys.generate_private_key()
    cert_pem = _self_signed_cert(["mismatch.example.com"], key)
    other_key_pem = pki_keys.serialize_private_key(other_key)

    response = client.post(
        "/api/import/certificate",
        json={"certificate_pem": cert_pem, "private_key_pem": other_key_pem},
    )
    assert response.status_code == 400
    assert "não corresponde" in response.json()["detail"]


def test_import_rejects_garbage_certificate(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    response = client.post(
        "/api/import/certificate", json={"certificate_pem": "not a real certificate"}
    )
    assert response.status_code == 400


def test_import_uses_certificates_real_not_valid_before_not_import_time(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    key = pki_keys.generate_private_key()
    cert_pem = _self_signed_cert(["aged.example.com"], key)

    response = client.post("/api/import/certificate", json={"certificate_pem": cert_pem})
    cert_id = response.json()["certificate_id"]

    certs = client.get("/api/acme/certificates").json()
    imported = next(c for c in certs if c["id"] == cert_id)
    issued_at = datetime.fromisoformat(imported["issued_at"])
    # o certificado de teste foi gerado com not_valid_before 10 dias atrás
    # — o issued_at guardado precisa refletir isso, não o momento da
    # importação (senão o cálculo da janela de renovação em
    # app/acme/scheduler.py subestima quanto da validade já passou).
    assert issued_at < datetime.now(UTC) - timedelta(days=5)


def test_import_requires_operator_role(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.post(
        "/api/auth/users",
        json={"username": "viewer", "password": "readonlypw", "role": "leitor"},
    )
    client.post("/api/auth/logout")
    client.post("/api/auth/login", json={"username": "viewer", "password": "readonlypw"})

    key = pki_keys.generate_private_key()
    cert_pem = _self_signed_cert(["forbidden.example.com"], key)
    response = client.post("/api/import/certificate", json={"certificate_pem": cert_pem})
    assert response.status_code == 403
