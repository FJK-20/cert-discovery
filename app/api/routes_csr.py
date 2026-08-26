"""Fluxo manual de CSR: gera a chave e o CSR aqui, a pessoa leva pra
qualquer CA (interna da empresa, comprada manualmente, o que não falar
ACME) e depois cola o certificado assinado de volta. Complementa a
emissão automática via ACME (app/api/routes_acme.py) — os dois caminhos
convergem no mesmo `acme_store` de certificados emitidos."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.acme.store import IssuedCertificate, acme_store
from app.audit.log import audit_log
from app.auth.dependencies import require_operator, require_session
from app.core.ratelimit import SlidingWindowRateLimiter
from app.pki import csr as pki_csr
from app.pki import keys as pki_keys
from app.pki.store import PendingCsr, pending_csr_store

router = APIRouter(prefix="/api/csr", dependencies=[Depends(require_session)])

_rate_limiter = SlidingWindowRateLimiter(max_requests=10, window_seconds=300)


class CreateCsrRequest(BaseModel):
    domains: list[str] = Field(..., min_length=1, max_length=100)
    organization_id: str | None = None
    system_id: str | None = None
    project_id: str | None = None


class CompleteCsrRequest(BaseModel):
    certificate_pem: str = Field(..., min_length=1, max_length=200_000)
    # Rastro de auditoria (Fase 8) — por que esse certificado específico
    # foi pedido. Metadado só de auditoria: não afeta a lógica de emissão,
    # não vira um sistema de aprovação separado (a ação em si continua
    # exigindo só o papel operador de sempre).
    reason: str = Field("", max_length=500)
    ticket_number: str = Field("", max_length=100)


def _client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _normalize_domains(raw: list[str]) -> list[str]:
    seen: set[str] = set()
    normalized = []
    for item in raw:
        domain = item.strip().lower().rstrip(".")
        if not domain or "/" in domain or " " in domain:
            raise HTTPException(status_code=400, detail=f"Domínio inválido: {item!r}")
        if domain not in seen:
            seen.add(domain)
            normalized.append(domain)
    if not normalized:
        raise HTTPException(status_code=400, detail="Informe ao menos um domínio.")
    return normalized


def _snapshot(pending: PendingCsr) -> dict:
    return {
        "id": pending.id,
        "domains": pending.domains,
        "csr_pem": pending.csr_pem,
        "created_at": pending.created_at,
        "organization_id": pending.organization_id,
        "system_id": pending.system_id,
        "project_id": pending.project_id,
    }


@router.post("", status_code=201)
async def create_csr(
    payload: CreateCsrRequest, request: Request, username: str = Depends(require_operator)
) -> dict:
    if not _rate_limiter.allow(_client_key(request)):
        raise HTTPException(
            status_code=429, detail="Muitos CSRs gerados — aguarde alguns minutos."
        )
    domains = _normalize_domains(payload.domains)

    key = pki_keys.generate_private_key()
    csr_pem = pki_csr.build_csr(domains, key).decode()
    pending = PendingCsr(
        domains=domains,
        private_key_pem=pki_keys.serialize_private_key(key),
        csr_pem=csr_pem,
        organization_id=payload.organization_id,
        system_id=payload.system_id,
        project_id=payload.project_id,
    )
    pending_csr_store.save(pending)
    audit_log.record(username=username, action="csr_created", detail=", ".join(domains))
    return _snapshot(pending)


@router.get("")
async def list_pending_csrs() -> list[dict]:
    return [_snapshot(p) for p in pending_csr_store.list()]


@router.get("/{csr_id}/download")
async def download_csr(csr_id: str):
    pending = pending_csr_store.load(csr_id)
    if pending is None:
        raise HTTPException(status_code=404, detail="CSR não encontrado (pode ter sido concluído).")
    filename = f"{pending.domains[0]}.csr"
    return StreamingResponse(
        iter([pending.csr_pem]),
        media_type="application/x-pem-file",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.post("/{csr_id}/complete")
async def complete_csr(
    csr_id: str, payload: CompleteCsrRequest, username: str = Depends(require_operator)
) -> dict:
    pending = pending_csr_store.load(csr_id)
    if pending is None:
        raise HTTPException(status_code=404, detail="CSR não encontrado (pode ter sido concluído).")

    cert_pem = payload.certificate_pem.strip()
    try:
        matches = pki_csr.certificate_matches_key(cert_pem, pending.private_key_pem)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Certificado inválido: {exc}") from exc

    if not matches:
        raise HTTPException(
            status_code=400,
            detail="Esse certificado não corresponde à chave gerada para este CSR "
            "— confirme que colou o certificado certo.",
        )

    # Achado numa auditoria de robustez: bater a chave só prova que o
    # certificado responde a ESTE par de chaves — não que ainda é válido
    # nem que cobre o domínio pedido. Sem isso, um certificado
    # autoassinado expirado colado por engano entrava no inventário como
    # se fosse uma emissão de CA válida e fresca.
    try:
        pki_csr.validate_completed_certificate(cert_pem, pending.domains)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    domains, not_after = pki_csr.certificate_info(cert_pem)
    cert = IssuedCertificate(
        id=csr_id,
        domain=domains[0] if domains else pending.domains[0],
        environment="manual",
        issued_at=pending.created_at,
        not_after=not_after,
        fullchain_pem=cert_pem,
        private_key_pem=pending.private_key_pem,
        organization_id=pending.organization_id,
        system_id=pending.system_id,
        project_id=pending.project_id,
    )
    acme_store.save_certificate(cert)
    pending_csr_store.delete(csr_id)
    detail = cert.domain
    if payload.reason.strip():
        detail += f" — motivo: {payload.reason.strip()}"
    if payload.ticket_number.strip():
        detail += f" — chamado: {payload.ticket_number.strip()}"
    audit_log.record(username=username, action="csr_completed", detail=detail)
    return {"ok": True, "certificate_id": cert.id}


@router.delete("/{csr_id}")
async def discard_csr(csr_id: str, username: str = Depends(require_operator)) -> dict:
    pending_csr_store.delete(csr_id)
    audit_log.record(username=username, action="csr_discarded", detail=csr_id)
    return {"ok": True}
