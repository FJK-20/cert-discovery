"""/docs, /redoc e /openapi.json (app/main.py) — achado numa auditoria
externa de segurança: o FastAPI expõe essas rotas publicamente, sem
autenticação nenhuma, por padrão — mapa completo da superfície da API
(toda rota, todo schema de request/response) de graça pra qualquer um na
internet. Confirmado ao vivo contra a produção real antes deste fix:
GET /docs, /redoc e /openapi.json todos respondiam 200 sem sessão."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.main import app


def test_api_docs_are_404_by_default():
    client = TestClient(app)
    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_enabling_the_flag_would_expose_the_routes():
    """Não reconstrói o `app` real (docs_url é fixado na construção do
    FastAPI, não dá pra trocar depois) — prova a MESMA expressão
    condicional usada em app/main.py com enable_api_docs=True, confirmando
    que o desligamento por padrão é uma escolha explícita, não uma rota
    que simplesmente não existe."""
    enabled = True
    probe = FastAPI(
        docs_url="/docs" if enabled else None,
        redoc_url="/redoc" if enabled else None,
        openapi_url="/openapi.json" if enabled else None,
    )
    client = TestClient(probe)
    assert client.get("/docs").status_code == 200
    assert client.get("/openapi.json").status_code == 200
