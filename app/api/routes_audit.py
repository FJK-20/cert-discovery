"""Leitura do log de auditoria (app/audit/log.py) — admin ou auditor
enxergam, e só leitura (o log em si é append-only, sem rota de escrita/
edição aqui). Inclui verificação de integridade da cadeia de hashes —
ver app/audit/log.py."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.audit.log import audit_log
from app.auth.dependencies import require_auditor

router = APIRouter(prefix="/api/audit-log", dependencies=[Depends(require_auditor)])


@router.get("")
async def list_audit_log(limit: int = 100) -> list[dict]:
    return audit_log.recent(min(max(limit, 1), 300))


@router.get("/verify")
async def verify_audit_log() -> dict:
    """Confirma que a cadeia de hashes do log não foi adulterada — cada
    linha guarda o hash da anterior, então qualquer edição/remoção fora da
    API (ex: alguém mexendo direto no arquivo SQLite) quebra a cadeia a
    partir do ponto alterado."""
    ok, broken_at = audit_log.verify_chain()
    return {"ok": ok, "broken_at_id": broken_at}
