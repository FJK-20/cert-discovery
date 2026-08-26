from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.acme import selfdns
from app.acme.scheduler import scheduler
from app.api.routes_acme import router as acme_router
from app.api.routes_audit import router as audit_router
from app.api.routes_catalog import router as catalog_router
from app.api.routes_csr import router as csr_router
from app.api.routes_import import router as import_router
from app.api.routes_notify import router as notify_router
from app.api.routes_scan import router as scan_router
from app.auth.dependencies import SESSION_COOKIE_NAME, get_authenticated_username
from app.auth.routes_auth import router as auth_router
from app.auth.routes_saml import router as saml_router
from app.core.config import settings
from app.core.db import get_connection, init_db
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
    # Servidor DNS próprio pro DnsMode.SELF_HOSTED_DNS — só sobe se
    # CERTDISC_SELFDNS_ENABLED estiver ligado (ver app/acme/selfdns.py).
    await selfdns.start()
    yield
    selfdns.stop()


app = FastAPI(
    title="Certificate Manager",
    description=(
        "Gerenciador de certificados TLS de ciclo completo — descoberta, "
        "emissão/renovação via ACME, SSO e auditoria."
    ),
    lifespan=_lifespan,
)
app.add_middleware(SecurityHeadersMiddleware, hsts_enabled=settings.cookie_secure)
app.include_router(auth_router)
app.include_router(saml_router)
app.include_router(scan_router)
app.include_router(acme_router)
app.include_router(csr_router)
app.include_router(import_router)
app.include_router(notify_router)
app.include_router(audit_router)
app.include_router(catalog_router)
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
    """Liveness — responde sempre que o processo está de pé, de propósito
    não toca em disco/banco (um soluço de storage não deveria fazer um
    orquestrador matar/reiniciar o processo à toa — é isso que /readyz
    abaixo é pra checar)."""
    return {"status": "ok"}


@app.get("/readyz")
async def readyz() -> JSONResponse:
    """Readiness — confirma que o diretório de dados está acessível e
    gravável (útil em orquestradores tipo Kubernetes pra não mandar
    tráfego pra uma réplica com o volume montado errado/sem permissão,
    algo que /healthz sozinho nunca detectaria)."""
    try:
        await asyncio.to_thread(lambda: get_connection(Path(settings.data_dir)).close())
    except Exception:
        return JSONResponse(
            status_code=503, content={"status": "not ready", "reason": "data_dir inacessível"}
        )
    return JSONResponse(status_code=200, content={"status": "ready"})
