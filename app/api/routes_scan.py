from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.audit.log import audit_log
from app.auth.dependencies import require_operator, require_session
from app.core.config import settings
from app.core.ratelimit import SlidingWindowRateLimiter
from app.domain.models import JobState, ScanJob
from app.export.exporters import to_csv, to_json
from app.jobs.history import scan_history
from app.jobs.manager import job_manager

# `dependencies=[Depends(require_session)]` protege TODAS as rotas deste
# router — sem sessão autenticada (login + MFA), a API de scan retorna 401.
router = APIRouter(prefix="/api/scan", dependencies=[Depends(require_session)])
_rate_limiter = SlidingWindowRateLimiter(max_requests=settings.rate_limit_requests_per_minute)

_TERMINAL_STATES = {JobState.DONE, JobState.PARTIAL_TIMEOUT, JobState.FAILED}


class ScanRequest(BaseModel):
    domain: str = Field(..., min_length=1, max_length=253)
    manual_hosts: list[str] = Field(default_factory=list, max_length=500)
    consent: bool = False
    enumerate_subdomains: bool = False


def _client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _job_snapshot(job: ScanJob) -> dict:
    return {
        "id": job.id,
        "domain": job.domain,
        "state": job.state.value,
        "progress_message": job.progress_message,
        "hosts_total": job.hosts_total,
        "hosts_done": job.hosts_done,
        "error": job.error,
        "records": [
            {
                "host": r.host,
                "origin": r.origin.value,
                "status": r.status.value,
                "subject_cn": r.subject_cn,
                "issuer": r.issuer,
                "not_before": r.not_before.isoformat() if r.not_before else None,
                "not_after": r.not_after.isoformat() if r.not_after else None,
                "days_until_expiry": r.days_until_expiry,
                "serial_number": r.serial_number,
                "sha256_fingerprint": r.sha256_fingerprint,
                "sans": r.sans,
                "resolved_ip": r.resolved_ip,
                "note": r.note,
            }
            for r in job.records
        ],
    }


@router.post("")
async def create_scan(
    payload: ScanRequest, request: Request, username: str = Depends(require_operator)
):
    if not payload.consent:
        raise HTTPException(
            status_code=400,
            detail="É necessário confirmar que você tem autorização para testar este domínio.",
        )
    if not _rate_limiter.allow(_client_key(request)):
        raise HTTPException(
            status_code=429,
            detail="Muitas solicitações — aguarde um minuto antes de tentar novamente.",
        )

    domain = payload.domain.strip().lower().rstrip(".")
    if not domain or "/" in domain or " " in domain:
        raise HTTPException(status_code=400, detail="Domínio inválido.")

    job = await job_manager.create(
        domain, payload.manual_hosts, enumerate_subdomains=payload.enumerate_subdomains
    )
    detail = domain + (" (+ subdomínios comuns)" if payload.enumerate_subdomains else "")
    audit_log.record(username=username, action="scan_started", detail=detail)
    return {"job_id": job.id}


@router.get("/history")
async def scan_history_list(limit: int = 15) -> list[dict]:
    return scan_history.list_recent(min(max(limit, 1), 50))


@router.get("/{job_id}/events")
async def scan_events(job_id: str):
    job = job_manager.get(job_id)
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


@router.get("/{job_id}")
async def scan_snapshot(job_id: str):
    job = job_manager.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job não encontrado (pode ter expirado).")
    return _job_snapshot(job)


@router.get("/{job_id}/export.{fmt}")
async def scan_export(job_id: str, fmt: str):
    job = job_manager.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job não encontrado (pode ter expirado).")

    if fmt == "csv":
        filename = f"cert-inventory-{job.domain}.csv"
        return StreamingResponse(
            iter([to_csv(job.records)]),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )
    if fmt == "json":
        filename = f"cert-inventory-{job.domain}.json"
        return StreamingResponse(
            iter([to_json(job.records)]),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )
    raise HTTPException(status_code=400, detail="Formato inválido (use csv ou json).")
