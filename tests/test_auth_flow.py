"""Teste de integração do fluxo completo: cadastro (MFA opcional, desligado
por padrão) -> login em uma etapa -> ativação de MFA (exige provar o código
antes de valer) -> login em duas etapas -> desativação -> proteção da API de
scan -> logout.

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


def test_setup_grants_immediate_access_without_mfa(tmp_path, monkeypatch):
    """MFA é opcional e desligado por padrão: o cadastro já autentica na
    hora, sem etapa intermediária forçada."""
    client = _client(tmp_path, monkeypatch)

    setup_response = client.post("/api/auth/setup", json=ADMIN)
    assert setup_response.status_code == 201
    assert setup_response.json() == {"ok": True}

    assert _state(client) == "authenticated"
    assert _scan_status(client) == 200
    assert client.get("/api/auth/mfa/status").json() == {"enabled": False}


def test_cannot_register_second_admin(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)

    second = client.post("/api/auth/setup", json={"username": "other", "password": "anotherpw"})
    assert second.status_code == 400


def test_login_single_step_when_mfa_disabled(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)

    client.post("/api/auth/logout")
    assert _state(client) == "needs_login"
    assert _scan_status(client) == 401

    bad_login = {"username": "admin", "password": "wrong"}
    assert client.post("/api/auth/login", json=bad_login).status_code == 401

    login_response = client.post("/api/auth/login", json=ADMIN)
    assert login_response.status_code == 200
    assert login_response.json() == {"mfa_required": False}
    assert _state(client) == "authenticated"
    assert _scan_status(client) == 200


def test_mfa_enroll_requires_valid_code_before_enabling(tmp_path, monkeypatch):
    """Não pode ficar ativado "no escuro": o segredo só vira o oficial da
    conta depois de confirmar um código correto."""
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)

    enroll = client.post("/api/auth/mfa/enroll")
    assert enroll.status_code == 200
    secret = enroll.json()["secret"]
    assert client.get("/api/auth/mfa/status").json() == {"enabled": False}

    wrong = client.post("/api/auth/mfa/enroll/confirm", json={"code": "000000"})
    assert wrong.status_code == 401
    assert client.get("/api/auth/mfa/status").json() == {"enabled": False}

    confirmed = client.post(
        "/api/auth/mfa/enroll/confirm", json={"code": totp.totp_now(secret)}
    )
    assert confirmed.status_code == 200
    assert client.get("/api/auth/mfa/status").json() == {"enabled": True}


def test_mfa_enroll_confirm_without_pending_enrollment_fails(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)

    response = client.post("/api/auth/mfa/enroll/confirm", json={"code": "123456"})
    assert response.status_code == 400


def test_mfa_endpoints_require_authentication(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)
    client.post("/api/auth/logout")

    assert client.get("/api/auth/mfa/status").status_code == 401
    assert client.post("/api/auth/mfa/enroll").status_code == 401
    assert client.post("/api/auth/mfa/disable", json={"password": "x"}).status_code == 401


def test_login_flow_requires_password_and_mfa_once_enabled(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)
    secret = client.post("/api/auth/mfa/enroll").json()["secret"]
    client.post("/api/auth/mfa/enroll/confirm", json={"code": totp.totp_now(secret)})

    client.post("/api/auth/logout")
    assert _state(client) == "needs_login"
    assert _scan_status(client) == 401

    bad_login = {"username": "admin", "password": "wrong"}
    assert client.post("/api/auth/login", json=bad_login).status_code == 401

    login_response = client.post("/api/auth/login", json=ADMIN)
    assert login_response.status_code == 200
    body = login_response.json()
    assert body["mfa_required"] is True
    pending_token = body["pending_token"]
    assert _state(client) == "needs_login"

    # senha certa mas MFA errado: ainda não autenticado
    bad_mfa = {"pending_token": pending_token, "code": "000000"}
    assert client.post("/api/auth/login/verify-mfa", json=bad_mfa).status_code == 401
    assert _state(client) == "needs_login"

    good_mfa = {"pending_token": pending_token, "code": totp.totp_now(secret)}
    assert client.post("/api/auth/login/verify-mfa", json=good_mfa).status_code == 200
    assert _state(client) == "authenticated"
    assert _scan_status(client) == 200


def test_disable_mfa_requires_correct_password_and_reverts_to_single_step_login(
    tmp_path, monkeypatch
):
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)
    secret = client.post("/api/auth/mfa/enroll").json()["secret"]
    client.post("/api/auth/mfa/enroll/confirm", json={"code": totp.totp_now(secret)})
    assert client.get("/api/auth/mfa/status").json() == {"enabled": True}

    wrong_password = client.post("/api/auth/mfa/disable", json={"password": "wrong"})
    assert wrong_password.status_code == 401
    assert client.get("/api/auth/mfa/status").json() == {"enabled": True}

    disabled = client.post("/api/auth/mfa/disable", json={"password": ADMIN["password"]})
    assert disabled.status_code == 200
    assert client.get("/api/auth/mfa/status").json() == {"enabled": False}

    client.post("/api/auth/logout")
    login_response = client.post("/api/auth/login", json=ADMIN)
    assert login_response.json() == {"mfa_required": False}
    assert _state(client) == "authenticated"
