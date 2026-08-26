"""Importação de um certificado que já existe fora da aplicação — migrando
de outra ferramenta, por exemplo. Diferente do fluxo de CSR manual
(app/api/routes_csr.py), a chave aqui já existe do lado do usuário (ou nem
existe, se ele só quer monitorar) em vez de ser gerada por este app.
Converge no mesmo `acme_store`, então aparece em Renovação como qualquer
outro certificado — sem chave privada, entra como "só monitorado": avisa
quando entra na janela de expiração, mas não pode ser baixado nem renovado
automaticamente (mesma regra que já vale pra certificados manuais/CSR sem
`dns_mode`)."""

from __future__ import annotations

import uuid

from cryptography import x509
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.acme.store import IssuedCertificate, acme_store
from app.audit.log import audit_log
from app.auth.dependencies import require_operator, require_session
from app.core.ratelimit import SlidingWindowRateLimiter
from app.pki import csr as pki_csr

router = APIRouter(prefix="/api/import", dependencies=[Depends(require_session)])

# Achado numa auditoria de robustez: este endpoint não tinha limite nenhum
# — qualquer sessão operador+ podia chamar sem parar (cada chamada grava
# um arquivo novo em disco). Mesmo limite que CSR/emissão usam pra uma
# ação equivalente ("cria um certificado gerenciado").
_rate_limiter = SlidingWindowRateLimiter(max_requests=10, window_seconds=300)


def _client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


class ImportCertificateRequest(BaseModel):
    certificate_pem: str = Field(..., min_length=1, max_length=200_000)
    private_key_pem: str | None = Field(None, max_length=200_000)
    organization_id: str | None = None
    system_id: str | None = None
    project_id: str | None = None


@router.post("/certificate", status_code=201)
async def import_certificate(
    payload: ImportCertificateRequest,
    request: Request,
    username: str = Depends(require_operator),
) -> dict:
    if not _rate_limiter.allow(_client_key(request)):
        raise HTTPException(
            status_code=429,
            detail="Muitas importações — aguarde alguns minutos antes de tentar novamente.",
        )
    cert_pem = payload.certificate_pem.strip()
    key_pem = payload.private_key_pem.strip() if payload.private_key_pem else None

    try:
        domains, not_after = pki_csr.certificate_info(cert_pem)
        # not_valid_before real do certificado (não "agora") — importante
        # pro cálculo da janela de renovação em app/acme/scheduler.py, que
        # deriva a validade total de issued_at/not_after; usar "agora" pra
        # um certificado emitido há semanas subestimaria quanto da
        # validade já passou.
        not_before = x509.load_pem_x509_certificate(cert_pem.encode()).not_valid_before_utc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Certificado inválido: {exc}") from exc
    if not domains:
        raise HTTPException(
            status_code=400,
            detail="Certificado sem CN nem SAN — não dá pra identificar o domínio.",
        )

    if key_pem:
        try:
            matches = pki_csr.certificate_matches_key(cert_pem, key_pem)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"Chave privada inválida: {exc}") from exc
        if not matches:
            raise HTTPException(
                status_code=400,
                detail="A chave privada não corresponde a esse certificado "
                "— confirme que colou o par certo.",
            )

    cert = IssuedCertificate(
        id=str(uuid.uuid4()),
        domain=domains[0],
        environment="imported",
        issued_at=not_before.isoformat(),
        not_after=not_after,
        fullchain_pem=cert_pem,
        private_key_pem=key_pem,
        organization_id=payload.organization_id,
        system_id=payload.system_id,
        project_id=payload.project_id,
    )
    acme_store.save_certificate(cert)
    audit_log.record(
        username=username,
        action="certificate_imported",
        detail=f"{cert.domain} ({'com' if key_pem else 'sem'} chave privada)",
    )
    return {
        "ok": True,
        "certificate_id": cert.id,
        "domain": cert.domain,
        "has_private_key": key_pem is not None,
    }
