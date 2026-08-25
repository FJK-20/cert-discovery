"""DELETE /api/acme/certificates/{id} (app/api/routes_acme.py) — pedido
real do usuário ao ver a lista de Certificados em produção poluída com
dezenas de certificados de teste sem jeito nenhum de removê-los pela UI."""

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


def _self_signed_cert(domain: str, key) -> str:
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, domain)])
    san = x509.SubjectAlternativeName([x509.DNSName(domain)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=60))
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


def _import_a_certificate(client: TestClient, domain: str = "junk-test.example.com") -> str:
    key = pki_keys.generate_private_key()
    cert_pem = _self_signed_cert(domain, key)
    response = client.post("/api/import/certificate", json={"certificate_pem": cert_pem})
    assert response.status_code == 201
    return response.json()["certificate_id"]


def test_admin_can_delete_a_certificate(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    cert_id = _import_a_certificate(client)

    response = client.delete(f"/api/acme/certificates/{cert_id}")
    assert response.status_code == 200

    certs = client.get("/api/acme/certificates").json()
    assert all(c["id"] != cert_id for c in certs)
    assert client.get(f"/api/acme/certificates/{cert_id}/fullchain.pem").status_code == 404


def test_delete_unknown_certificate_returns_404(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    response = client.delete("/api/acme/certificates/does-not-exist")
    assert response.status_code == 404


def test_operador_can_delete_a_certificate(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    cert_id = _import_a_certificate(client)
    client.post(
        "/api/auth/users",
        json={"username": "op", "password": "operadorpw123", "role": "operador"},
    )
    client.post("/api/auth/logout")
    client.post("/api/auth/login", json={"username": "op", "password": "operadorpw123"})

    response = client.delete(f"/api/acme/certificates/{cert_id}")
    assert response.status_code == 200


def test_leitor_cannot_delete_a_certificate(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    cert_id = _import_a_certificate(client)
    client.post(
        "/api/auth/users",
        json={"username": "viewer", "password": "readonlypw", "role": "leitor"},
    )
    client.post("/api/auth/logout")
    client.post("/api/auth/login", json={"username": "viewer", "password": "readonlypw"})

    response = client.delete(f"/api/acme/certificates/{cert_id}")
    assert response.status_code == 403
    # continua existindo
    certs = client.get("/api/acme/certificates").json()
    assert any(c["id"] == cert_id for c in certs)


def test_delete_is_audit_logged(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    cert_id = _import_a_certificate(client, domain="audited.example.com")

    client.delete(f"/api/acme/certificates/{cert_id}")

    entries = client.get("/api/audit-log").json()
    matching = [e for e in entries if e["action"] == "certificate_deleted"]
    assert len(matching) == 1
    assert "audited.example.com" in matching[0]["detail"]
    assert cert_id in matching[0]["detail"]
