"""`cookie_should_be_secure` (app/auth/dependencies.py) — achado na auditoria
de robustez: `CERTDISC_COOKIE_SECURE` é uma decisão de deploy única (liga
pra todo cookie ou pra nenhum), mas a instância real de produção deste
projeto serve tanto HTTP puro na LAN quanto HTTPS público via Cloudflare
Tunnel — ligar a variável globalmente quebraria o login na LAN. O fix é
por requisição: se ESTA chegou por HTTPS (direto, ou via
`X-Forwarded-Proto` de um proxy/túnel), marca o cookie como `Secure` de
qualquer forma, sem depender da variável global.
"""

from __future__ import annotations

import dataclasses

from fastapi.testclient import TestClient

from app.audit.log import audit_log
from app.auth.sessions import TokenStore
from app.auth.store import UserStore
from app.core.config import settings as real_settings
from app.core.ratelimit import SlidingWindowRateLimiter
from app.main import app

ADMIN = {"username": "admin", "password": "supersecretpw"}


def _client(tmp_path, monkeypatch) -> TestClient:
    session_store = TokenStore(ttl_seconds=3600)
    unlimited = SlidingWindowRateLimiter(max_requests=1000, window_seconds=300)
    monkeypatch.setattr("app.auth.routes_auth.user_store", UserStore(tmp_path))
    monkeypatch.setattr("app.auth.dependencies.user_store", UserStore(tmp_path))
    monkeypatch.setattr("app.auth.routes_auth.session_store", session_store)
    monkeypatch.setattr("app.auth.dependencies.session_store", session_store)
    monkeypatch.setattr(
        "app.auth.routes_auth.pending_login_store", TokenStore(ttl_seconds=300)
    )
    monkeypatch.setattr("app.auth.routes_auth._rate_limiter", unlimited)
    monkeypatch.setattr("app.auth.routes_auth._account_rate_limiter", unlimited)
    monkeypatch.setattr(audit_log, "_data_dir", tmp_path)
    return TestClient(app)


def _set_cookie_header(response) -> str:
    values = response.headers.get_list("set-cookie")
    (session_cookie,) = [v for v in values if v.startswith("certdisc_session=")]
    return session_cookie


def test_plain_http_without_forwarded_proto_is_not_secure(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    response = client.post("/api/auth/setup", json=ADMIN)
    assert response.status_code == 201
    assert "Secure" not in _set_cookie_header(response)


def test_forwarded_proto_https_marks_cookie_secure(tmp_path, monkeypatch):
    # Simula o Cloudflare Tunnel: TLS termina na borda, e o túnel repassa
    # pro processo local por HTTP puro anunciando o esquema original nesse
    # cabeçalho — é assim que a instância pública real deste projeto roda.
    client = _client(tmp_path, monkeypatch)
    response = client.post(
        "/api/auth/setup", json=ADMIN, headers={"X-Forwarded-Proto": "https"}
    )
    assert response.status_code == 201
    assert "Secure" in _set_cookie_header(response)


def test_cookie_secure_env_forces_secure_regardless_of_scheme(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    forced = dataclasses.replace(real_settings, cookie_secure=True)
    monkeypatch.setattr("app.auth.dependencies.settings", forced)
    response = client.post("/api/auth/setup", json=ADMIN)
    assert response.status_code == 201
    assert "Secure" in _set_cookie_header(response)
