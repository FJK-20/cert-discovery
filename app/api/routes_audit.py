"""Leitura do log de auditoria (app/audit/log.py) — só admins veem, e só
leitura (o log em si é append-only, sem rota de escrita/edição aqui)."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.audit.log import audit_log
from app.auth.dependencies import require_admin

router = APIRouter(prefix="/api/audit-log", dependencies=[Depends(require_admin)])


@router.get("")
async def list_audit_log(limit: int = 100) -> list[dict]:
    return audit_log.recent(min(max(limit, 1), 300))
