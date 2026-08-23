"""Rotas de CSR manual (app/api/routes_csr.py) — não tinha cobertura de
integração nenhuma antes (só as funções de cripto puras em test_pki.py).
Fecha esse gap e cobre o campo novo de motivo/chamado (Fase 8)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from fastapi.testclient import TestClient

from app.audit.log import audit_log
from app.auth.sessions import TokenStore
from app.auth.store import UserStore
from app.core.ratelimit import SlidingWindowRateLimiter
from app.main import app
from app.pki import keys as pki_keys

ADMIN = {"username": "admin", "password": "supersecretpw"}


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
    monkeypatch.setattr(audit_log, "_data_dir", tmp_path)
    client = TestClient(app)
    client.post("/api/auth/setup", json=ADMIN)
    return client


def _sign_csr_pem(csr_pem: str, key) -> str:
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(csr.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=90))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("app.example.com")]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def test_create_download_complete_csr_round_trip(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    created = client.post("/api/csr", json={"domains": ["app.example.com"]})
    assert created.status_code == 201
    csr_id = created.json()["id"]

    listed = client.get("/api/csr").json()
    assert any(c["id"] == csr_id for c in listed)

    download = client.get(f"/api/csr/{csr_id}/download")
    assert download.status_code == 200
    assert "BEGIN CERTIFICATE REQUEST" in download.text

    # completar exige que o certificado bata com a chave que o app gerou
    # pro CSR (certificate_matches_key) — assina o cert de teste com essa
    # mesma chave, lida direto do CSR pendente.
    from app.pki.store import pending_csr_store

    pending = pending_csr_store.load(csr_id)
    real_key = serialization.load_pem_private_key(pending.private_key_pem.encode(), password=None)
    cert_pem = _sign_csr_pem(pending.csr_pem, real_key)

    completed = client.post(
        f"/api/csr/{csr_id}/complete",
        json={"certificate_pem": cert_pem, "reason": "renovação anual", "ticket_number": "CHG-42"},
    )
    assert completed.status_code == 200
    cert_id = completed.json()["certificate_id"]

    certs = client.get("/api/acme/certificates").json()
    assert any(c["id"] == cert_id for c in certs)

    entries = client.get("/api/audit-log").json()
    completed_entry = next(e for e in entries if e["action"] == "csr_completed")
    assert "renovação anual" in completed_entry["detail"]
    assert "CHG-42" in completed_entry["detail"]


def test_complete_csr_rejects_mismatched_certificate(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    created = client.post("/api/csr", json={"domains": ["app.example.com"]})
    csr_id = created.json()["id"]

    other_key = pki_keys.generate_private_key()
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "app.example.com")])
    wrong_cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(other_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=90))
        .sign(other_key, hashes.SHA256())
    )
    cert_pem = wrong_cert.public_bytes(serialization.Encoding.PEM).decode()

    response = client.post(f"/api/csr/{csr_id}/complete", json={"certificate_pem": cert_pem})
    assert response.status_code == 400


def test_discard_csr(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    created = client.post("/api/csr", json={"domains": ["app.example.com"]})
    csr_id = created.json()["id"]
    assert client.delete(f"/api/csr/{csr_id}").status_code == 200
    assert not any(c["id"] == csr_id for c in client.get("/api/csr").json())


def test_csr_create_requires_operator_role(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.post(
        "/api/auth/users",
        json={"username": "viewer", "password": "readonlypw", "role": "leitor"},
    )
    client.post("/api/auth/logout")
    client.post("/api/auth/login", json={"username": "viewer", "password": "readonlypw"})
    response = client.post("/api/csr", json={"domains": ["app.example.com"]})
    assert response.status_code == 403
