from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.acme.scheduler import scheduler
from app.api.routes_acme import router as acme_router
from app.api.routes_audit import router as audit_router
from app.api.routes_csr import router as csr_router
from app.api.routes_notify import router as notify_router
from app.api.routes_scan import router as scan_router
from app.auth.dependencies import SESSION_COOKIE_NAME, get_authenticated_username
from app.auth.routes_auth import router as auth_router
from app.core.config import settings
from app.core.db import init_db
from app.core.security_headers import SecurityHeadersMiddleware

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"


@asynccontextmanager
async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
    # Histórico persistente de scans e tentativas de renovação (SQLite) —
    # cria as tabelas se ainda não existirem.
    init_db(Path(settings.data_dir))
    # Verifica periodicamente certificados entrando na janela de
    # renovação — ver app/acme/scheduler.py pra regra de negócio completa.
    scheduler.start()
    yield


app = FastAPI(
    title="Certificate Discovery Platform",
    description="Descoberta e inventário de certificados TLS via CT logs + handshake ao vivo.",
    lifespan=_lifespan,
)
app.add_middleware(SecurityHeadersMiddleware, hsts_enabled=settings.cookie_secure)
app.include_router(auth_router)
app.include_router(scan_router)
app.include_router(acme_router)
app.include_router(csr_router)
app.include_router(notify_router)
app.include_router(audit_router)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
async def index(request: Request) -> FileResponse:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if get_authenticated_username(token) is not None:
        return FileResponse(str(STATIC_DIR / "index.html"))
    # Sem admin cadastrado, cadastro pendente de MFA, ou sem login: a própria
    # auth.html decide o que mostrar consultando GET /api/auth/status.
    return FileResponse(str(STATIC_DIR / "auth.html"))


@app.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok"}
