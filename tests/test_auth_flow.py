"""Teste de integração do fluxo completo: cadastro -> MFA obrigatório ->
login em duas etapas -> proteção da API de scan -> logout.

Os singletons globais (admin_store/session_store/pending_login_store/rate
limiter) são substituídos por instâncias isoladas por teste via monkeypatch,
para não vazar estado entre testes nem depender do disco real. O
`job_manager.create` também é substituído por um fake: este arquivo testa a
camada de autenticação, não o pipeline de scan (já coberto em outros testes).
"""

from fastapi.testclient import TestClient

from app.auth import totp
from app.auth.sessions import TokenStore
from app.auth.store import AdminStore
from app.core.ratelimit import SlidingWindowRateLimiter
from app.main import app

ADMIN = {"username": "admin", "password": "supersecretpw"}
SCAN_BODY = {"domain": "example.com", "consent": True}


class _FakeJob:
    id = "fake-job-id"


async def _fake_create(domain, manual_hosts=None):
    return _FakeJob()


def _client(tmp_path, monkeypatch) -> TestClient:
    session_store = TokenStore(ttl_seconds=3600)
    unlimited = SlidingWindowRateLimiter(max_requests=1000, window_seconds=300)
    monkeypatch.setattr("app.auth.routes_auth.admin_store", AdminStore(tmp_path))
    monkeypatch.setattr("app.auth.routes_auth.session_store", session_store)
    monkeypatch.setattr("app.auth.routes_auth.pending_login_store", TokenStore(ttl_seconds=300))
    monkeypatch.setattr("app.auth.routes_auth._rate_limiter", unlimited)
    monkeypatch.setattr("app.auth.dependencies.session_store", session_store)
    monkeypatch.setattr("app.jobs.manager.job_manager.create", _fake_create)
    return TestClient(app)


def _state(client: TestClient) -> str:
    return client.get("/api/auth/status").json()["state"]


def _scan_status(client: TestClient) -> int:
    return client.post("/api/scan", json=SCAN_BODY).status_code


def test_status_is_needs_setup_when_no_admin(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    assert _state(client) == "needs_setup"


def test_scan_requires_authentication(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    assert _scan_status(client) == 401


def test_full_setup_flow_forces_mfa_before_granting_access(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)

    setup_response = client.post("/api/auth/setup", json=ADMIN)
    assert setup_response.status_code == 201
    secret = setup_response.json()["secret"]

    # cadastro criado, mas MFA ainda não confirmado: acesso continua bloqueado
    assert _state(client) == "setup_pending_mfa"
    assert _scan_status(client) == 401

    wrong_code = client.post("/api/auth/setup/verify-mfa", json={"code": "000000"})
    assert wrong_code.status_code == 401
    assert _state(client) == "setup_pending_mfa"

    correct_code = totp.totp_now(secret)
    confirmed = client.post("/api/auth/setup/verify-mfa", json={"code": correct_code})
    assert confirmed.status_code == 200
    assert _state(client) == "authenticated"
    assert _scan_status(client) == 200


def test_cannot_register_second_admin(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)

    second = client.post("/api/auth/setup", json={"username": "other", "password": "anotherpw"})
    assert second.status_code == 400


def test_login_flow_requires_password_and_mfa(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)

    setup_response = client.post("/api/auth/setup", json=ADMIN)
    secret = setup_response.json()["secret"]
    client.post("/api/auth/setup/verify-mfa", json={"code": totp.totp_now(secret)})

    client.post("/api/auth/logout")
    assert _state(client) == "needs_login"
    assert _scan_status(client) == 401

    bad_login = {"username": "admin", "password": "wrong"}
    assert client.post("/api/auth/login", json=bad_login).status_code == 401

    login_response = client.post("/api/auth/login", json=ADMIN)
    assert login_response.status_code == 200
    pending_token = login_response.json()["pending_token"]

    # senha certa mas MFA errado: ainda não autenticado
    bad_mfa = {"pending_token": pending_token, "code": "000000"}
    assert client.post("/api/auth/login/verify-mfa", json=bad_mfa).status_code == 401
    assert _state(client) == "needs_login"

    good_mfa = {"pending_token": pending_token, "code": totp.totp_now(secret)}
    assert client.post("/api/auth/login/verify-mfa", json=good_mfa).status_code == 200
    assert _state(client) == "authenticated"
    assert _scan_status(client) == 200
