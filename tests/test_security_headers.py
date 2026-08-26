"""Testa app/core/security_headers.py — cabeçalhos de segurança presentes
em toda resposta, e HSTS só quando o deploy está atrás de HTTPS
(CERTDISC_COOKIE_SECURE)."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.security_headers import SecurityHeadersMiddleware


def _app(*, hsts_enabled: bool) -> FastAPI:
    app = FastAPI()
    app.add_middleware(SecurityHeadersMiddleware, hsts_enabled=hsts_enabled)

    @app.get("/ping")
    async def ping():
        return {"ok": True}

    return app


def test_security_headers_present_on_every_response():
    client = TestClient(_app(hsts_enabled=False))
    response = client.get("/ping")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert "Referrer-Policy" in response.headers


def test_csp_has_no_unsafe_inline_anywhere():
    client = TestClient(_app(hsts_enabled=False))
    response = client.get("/ping")
    assert "unsafe-inline" not in response.headers["Content-Security-Policy"]


def test_hsts_absent_when_not_behind_https():
    client = TestClient(_app(hsts_enabled=False))
    response = client.get("/ping")
    assert "Strict-Transport-Security" not in response.headers


def test_hsts_present_when_behind_https():
    client = TestClient(_app(hsts_enabled=True))
    response = client.get("/ping")
    assert "max-age=31536000" in response.headers["Strict-Transport-Security"]


def test_hsts_present_for_https_request_even_without_global_flag():
    # Achado numa auditoria de robustez: HSTS estava amarrado só à flag
    # global (CERTDISC_COOKIE_SECURE) — numa instância que serve LAN por
    # HTTP puro e domínio público por HTTPS via proxy/túnel ao mesmo tempo
    # (caso real da produção deste projeto), ligar a flag globalmente
    # quebraria a LAN, então ela ficava desligada e o domínio público
    # também nunca recebia HSTS. Decisão por requisição via
    # X-Forwarded-Proto (mesmo padrão de cookie_should_be_secure) fecha
    # isso sem precisar da flag global.
    client = TestClient(_app(hsts_enabled=False))
    response = client.get("/ping", headers={"X-Forwarded-Proto": "https"})
    assert "max-age=31536000" in response.headers["Strict-Transport-Security"]
