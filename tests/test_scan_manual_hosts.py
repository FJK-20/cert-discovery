"""Testa a restrição de escopo de manual_hosts em POST /api/scan (app/api/
routes_scan.py) — achado numa auditoria de robustez: manual_hosts não tinha
vínculo nenhum com o domínio pedido, permitindo até 400 hosts arbitrários
por job saindo do IP do servidor."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.audit.log import audit_log
from app.auth.sessions import TokenStore
from app.auth.store import UserStore
from app.core.ratelimit import SlidingWindowRateLimiter
from app.main import app

ADMIN = {"username": "admin", "password": "supersecretpw"}


class _FakeJob:
    id = "fake-job-id"


async def _fake_create(domain, manual_hosts=None, *, enumerate_subdomains=False):
    return _FakeJob()


def _client(tmp_path, monkeypatch) -> TestClient:
    session_store = TokenStore(ttl_seconds=3600)
    unlimited = SlidingWindowRateLimiter(max_requests=1000, window_seconds=300)
    monkeypatch.setattr("app.auth.routes_auth.user_store", UserStore(tmp_path))
    monkeypatch.setattr("app.auth.dependencies.user_store", UserStore(tmp_path))
    monkeypatch.setattr("app.auth.routes_auth.session_store", session_store)
    monkeypatch.setattr("app.auth.routes_auth.pending_login_store", TokenStore(ttl_seconds=300))
    monkeypatch.setattr("app.auth.dependencies.session_store", session_store)
    monkeypatch.setattr("app.auth.routes_auth._rate_limiter", unlimited)
    monkeypatch.setattr("app.api.routes_scan._rate_limiter", unlimited)
    monkeypatch.setattr("app.jobs.manager.job_manager.create", _fake_create)
    monkeypatch.setattr(audit_log, "_data_dir", tmp_path)
    client = TestClient(app)
    client.post("/api/auth/setup", json=ADMIN)
    return client


def test_manual_hosts_outside_the_requested_domain_are_rejected(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    response = client.post(
        "/api/scan",
        json={
            "domain": "example.com",
            "consent": True,
            "manual_hosts": ["app.example.com", "internal.corp.local"],
        },
    )
    assert response.status_code == 400
    assert "internal.corp.local" in response.json()["detail"]
    assert "app.example.com" not in response.json()["detail"]


def test_manual_hosts_within_the_requested_domain_are_accepted(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    response = client.post(
        "/api/scan",
        json={
            "domain": "example.com",
            "consent": True,
            "manual_hosts": ["app.example.com", "api.example.com", "example.com"],
        },
    )
    assert response.status_code == 200


def test_manual_hosts_matching_only_as_a_suffix_are_still_rejected(tmp_path, monkeypatch):
    # "notexample.com" não é subdomínio de "example.com" — checagem
    # precisa ser por ponto (".example.com"), não por sufixo de string.
    client = _client(tmp_path, monkeypatch)
    response = client.post(
        "/api/scan",
        json={"domain": "example.com", "consent": True, "manual_hosts": ["notexample.com"]},
    )
    assert response.status_code == 400
