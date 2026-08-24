from __future__ import annotations

import asyncio
import json

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.acme import azure_dns, cloudflare
from app.acme.history import renewal_history
from app.acme.models import AcmeEnvironment, AcmeJob, AcmeJobState, CertificateAuthority, DnsMode
from app.acme.renewal import renewal_manager
from app.acme.store import AzureDnsCredentials, CaCredentials, DnsCredentials, acme_store
from app.audit.log import audit_log
from app.auth.dependencies import require_admin, require_operator, require_session
from app.core.ratelimit import SlidingWindowRateLimiter

router = APIRouter(prefix="/api/acme", dependencies=[Depends(require_session)])

# Emitir certificado é uma ação mais sensível/cara que um scan comum —
# limite dedicado, mais restrito que o de scans.
_rate_limiter = SlidingWindowRateLimiter(max_requests=5, window_seconds=300)

# "Verificar propagação" no modo manual é só uma consulta DNS — a pessoa
# clica de novo a cada poucos segundos enquanto espera propagar, então
# tem seu próprio limite, bem mais generoso que o de iniciar uma emissão.
_confirm_rate_limiter = SlidingWindowRateLimiter(max_requests=30, window_seconds=60)

_TERMINAL_STATES = {AcmeJobState.DONE, AcmeJobState.FAILED}


class DnsCredentialsRequest(BaseModel):
    api_token: str = Field(..., min_length=1, max_length=500)
    delegation_zone: str | None = Field(default=None, max_length=253)


class ZeroSslCredentialsRequest(BaseModel):
    eab_kid: str = Field(..., min_length=1, max_length=200)
    eab_hmac_key: str = Field(..., min_length=1, max_length=500)


class AzureDnsCredentialsRequest(BaseModel):
    tenant_id: str = Field(..., min_length=1, max_length=100)
    client_id: str = Field(..., min_length=1, max_length=100)
    client_secret: str = Field(..., min_length=1, max_length=500)
    subscription_id: str = Field(..., min_length=1, max_length=100)
    resource_group: str = Field(..., min_length=1, max_length=200)
    zone_name: str = Field(..., min_length=1, max_length=253)


class RenewRequest(BaseModel):
    domain: str = Field(..., min_length=1, max_length=253)
    environment: AcmeEnvironment = AcmeEnvironment.STAGING
    dns_mode: DnsMode = DnsMode.MANUAL
    ca: CertificateAuthority = CertificateAuthority.LETS_ENCRYPT
    organization_id: str | None = None
    system_id: str | None = None
    project_id: str | None = None


def _client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _job_snapshot(job: AcmeJob) -> dict:
    return {
        "id": job.id,
        "domain": job.domain,
        "environment": job.environment.value,
        "dns_mode": job.dns_mode.value,
        "ca": job.ca.value,
        "state": job.state.value,
        "progress_message": job.progress_message,
        "error": job.error,
        "certificate_id": job.certificate_id,
        "dns_record_type": job.dns_record_type,
        "dns_record_name": job.dns_record_name,
        "dns_record_value": job.dns_record_value,
        "organization_id": job.organization_id,
        "system_id": job.system_id,
        "project_id": job.project_id,
    }


@router.get("/status")
async def acme_status() -> dict:
    creds = acme_store.load_dns_credentials()
    azure_creds = acme_store.load_azure_dns_credentials()
    zerossl_creds = acme_store.load_ca_credentials(CertificateAuthority.ZEROSSL.value)
    return {
        "dns_configured": creds is not None,
        "dns_provider": creds.provider if creds else None,
        "delegation_zone": creds.delegation_zone if creds else None,
        "azure_dns_configured": azure_creds is not None,
        "azure_dns_zone": azure_creds.zone_name if azure_creds else None,
        "zerossl_configured": zerossl_creds is not None,
        "accounts": {
            "staging": acme_store.load_account("staging") is not None,
            "production": acme_store.load_account("production") is not None,
            "zerossl": acme_store.load_account("zerossl") is not None,
        },
    }


@router.post("/ca-credentials/zerossl")
async def save_zerossl_credentials(
    payload: ZeroSslCredentialsRequest, username: str = Depends(require_admin)
) -> dict:
    acme_store.save_ca_credentials(
        CaCredentials(
            ca=CertificateAuthority.ZEROSSL.value,
            eab_kid=payload.eab_kid,
            eab_hmac_key=payload.eab_hmac_key,
        )
    )
    audit_log.record(username=username, action="ca_credentials_saved", detail="zerossl")
    return {"ok": True}


@router.post("/dns-credentials/azure")
async def save_azure_dns_credentials(
    payload: AzureDnsCredentialsRequest, username: str = Depends(require_admin)
) -> dict:
    creds = AzureDnsCredentials(
        tenant_id=payload.tenant_id,
        client_id=payload.client_id,
        client_secret=payload.client_secret,
        subscription_id=payload.subscription_id,
        resource_group=payload.resource_group,
        zone_name=payload.zone_name.strip().lower(),
    )
    valid = await asyncio.to_thread(azure_dns.verify_credentials, creds)
    if not valid:
        raise HTTPException(
            status_code=400,
            detail="Não foi possível autenticar no Azure ou encontrar a zona DNS configurada "
            "— confira tenant/client/secret/subscription/resource group/zona.",
        )
    acme_store.save_azure_dns_credentials(creds)
    audit_log.record(username=username, action="dns_credentials_saved", detail="azure_dns")
    return {"ok": True}


@router.post("/dns-credentials")
async def save_dns_credentials(
    payload: DnsCredentialsRequest, username: str = Depends(require_admin)
) -> dict:
    valid = await asyncio.to_thread(cloudflare.verify_token, payload.api_token)
    if not valid:
        raise HTTPException(
            status_code=400,
            detail="Token da Cloudflare inválido ou inativo.",
        )
    delegation_zone = payload.delegation_zone.strip().lower() if payload.delegation_zone else None
    creds = DnsCredentials(
        provider="cloudflare", api_token=payload.api_token, delegation_zone=delegation_zone or None
    )
    acme_store.save_dns_credentials(creds)
    audit_log.record(username=username, action="dns_credentials_saved", detail="cloudflare")
    return {"ok": True}


@router.post("/renew")
async def renew(
    payload: RenewRequest, request: Request, username: str = Depends(require_operator)
) -> dict:
    if not _rate_limiter.allow(_client_key(request)):
        raise HTTPException(
            status_code=429,
            detail="Muitas solicitações de emissão — aguarde alguns minutos.",
        )
    needs_cloudflare = payload.dns_mode in (DnsMode.CLOUDFLARE, DnsMode.CNAME_DELEGATION)
    if needs_cloudflare and acme_store.load_dns_credentials() is None:
        raise HTTPException(
            status_code=400,
            detail="Configure as credenciais de DNS (Cloudflare) antes de emitir um certificado.",
        )
    if payload.dns_mode == DnsMode.AZURE_DNS and acme_store.load_azure_dns_credentials() is None:
        raise HTTPException(
            status_code=400,
            detail="Configure as credenciais do Azure DNS antes de emitir um certificado.",
        )
    if payload.ca == CertificateAuthority.ZEROSSL and acme_store.load_ca_credentials(
        CertificateAuthority.ZEROSSL.value
    ) is None:
        raise HTTPException(
            status_code=400,
            detail="Configure as credenciais EAB da ZeroSSL antes de emitir por essa CA.",
        )

    domain = payload.domain.strip().lower().rstrip(".")
    if not domain or "/" in domain or " " in domain:
        raise HTTPException(status_code=400, detail="Domínio inválido.")

    job = await renewal_manager.create(
        domain,
        payload.environment,
        payload.dns_mode,
        payload.ca,
        organization_id=payload.organization_id,
        system_id=payload.system_id,
        project_id=payload.project_id,
    )
    detail = f"{domain} ({payload.environment.value}, {payload.dns_mode.value}, {payload.ca.value})"
    audit_log.record(username=username, action="certificate_renew_requested", detail=detail)
    return {"job_id": job.id}


@router.post("/renew/{job_id}/confirm-dns")
async def confirm_dns(
    job_id: str, request: Request, username: str = Depends(require_operator)
) -> dict:
    if not _confirm_rate_limiter.allow(_client_key(request)):
        raise HTTPException(
            status_code=429,
            detail="Muitas verificações — aguarde um minuto antes de tentar de novo.",
        )
    ok, message = await renewal_manager.confirm_dns(job_id)
    if not ok:
        raise HTTPException(status_code=409, detail=message)
    return {"ok": True, "message": message}


@router.get("/renew/{job_id}/events")
async def renew_events(job_id: str):
    job = renewal_manager.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job não encontrado (pode ter expirado).")

    async def event_stream():
        last_payload: str | None = None
        while True:
            payload = json.dumps(_job_snapshot(job), ensure_ascii=False)
            if payload != last_payload:
                yield f"data: {payload}\n\n"
                last_payload = payload
            if job.state in _TERMINAL_STATES:
                break
            await asyncio.sleep(0.5)

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@router.get("/renew/{job_id}")
async def renew_snapshot(job_id: str):
    job = renewal_manager.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job não encontrado (pode ter expirado).")
    return _job_snapshot(job)


@router.get("/renewal-history")
async def renewal_history_list(limit: int = 30) -> list[dict]:
    return renewal_history.recent(min(max(limit, 1), 100))


def _key_info(fullchain_pem: str) -> tuple[str | None, int | None]:
    # Derivado do PEM na hora da listagem em vez de guardado no
    # IssuedCertificate — é um dado que já vive dentro do certificado, não
    # precisa de mais um campo pra manter sincronizado.
    try:
        public_key = x509.load_pem_x509_certificate(fullchain_pem.encode()).public_key()
    except ValueError:
        return None, None
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "EC", public_key.key_size
    return None, None


@router.get("/certificates")
async def list_certificates() -> list[dict]:
    result = []
    for c in acme_store.list_certificates():
        key_algorithm, key_size = _key_info(c.fullchain_pem)
        result.append(
            {
                "id": c.id,
                "domain": c.domain,
                "environment": c.environment,
                "issued_at": c.issued_at,
                "not_after": c.not_after,
                "dns_mode": c.dns_mode,
                "ca": c.ca,
                "has_private_key": c.private_key_pem is not None,
                "organization_id": c.organization_id,
                "system_id": c.system_id,
                "project_id": c.project_id,
                "key_algorithm": key_algorithm,
                "key_size": key_size,
            }
        )
    return result


@router.get("/certificates/{cert_id}/fullchain.pem")
async def download_fullchain(cert_id: str):
    cert = acme_store.load_certificate(cert_id)
    if cert is None:
        raise HTTPException(status_code=404, detail="Certificado não encontrado.")
    filename = f"{cert.domain}-fullchain.pem"
    return StreamingResponse(
        iter([cert.fullchain_pem]),
        media_type="application/x-pem-file",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/certificates/{cert_id}/privkey.pem")
async def download_private_key(cert_id: str, _viewer: str = Depends(require_operator)):
    cert = acme_store.load_certificate(cert_id)
    if cert is None:
        raise HTTPException(status_code=404, detail="Certificado não encontrado.")
    if cert.private_key_pem is None:
        raise HTTPException(
            status_code=404,
            detail="Esse certificado foi importado sem chave privada — não há o que baixar.",
        )
    filename = f"{cert.domain}-privkey.pem"
    return StreamingResponse(
        iter([cert.private_key_pem]),
        media_type="application/x-pem-file",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
