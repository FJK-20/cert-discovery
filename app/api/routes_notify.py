"""Configuração de notificação (webhook/e-mail) e status do agendador de
renovação — ver app/acme/scheduler.py e app/notify/."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.acme.scheduler import scheduler
from app.audit.log import audit_log
from app.auth.dependencies import require_admin, require_session
from app.core.ratelimit import SlidingWindowRateLimiter
from app.notify import notifier
from app.notify.store import NotificationConfig, notification_store

router = APIRouter(prefix="/api", dependencies=[Depends(require_session)])

_test_rate_limiter = SlidingWindowRateLimiter(max_requests=5, window_seconds=300)
_check_now_rate_limiter = SlidingWindowRateLimiter(max_requests=5, window_seconds=300)


class NotificationConfigRequest(BaseModel):
    webhook_url: str | None = Field(default=None, max_length=2000)
    smtp_host: str | None = Field(default=None, max_length=253)
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_use_tls: bool = True
    smtp_username: str | None = Field(default=None, max_length=320)
    smtp_password: str | None = Field(default=None, max_length=500)
    smtp_from: str | None = Field(default=None, max_length=320)
    smtp_to: str | None = Field(default=None, max_length=1000)


def _client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _redacted(config: NotificationConfig | None) -> dict:
    if config is None:
        return {
            "webhook_configured": False,
            "email_configured": False,
            "smtp_host": None,
            "smtp_port": 587,
            "smtp_use_tls": True,
            "smtp_username": None,
            "smtp_from": None,
            "smtp_to": None,
        }
    return {
        "webhook_configured": bool(config.webhook_url),
        "email_configured": bool(config.smtp_host),
        "smtp_host": config.smtp_host,
        "smtp_port": config.smtp_port,
        "smtp_use_tls": config.smtp_use_tls,
        "smtp_username": config.smtp_username,
        "smtp_from": config.smtp_from,
        "smtp_to": config.smtp_to,
        # webhook_url e smtp_password nunca voltam pra interface, mesma
        # disciplina do token da Cloudflare.
    }


@router.get("/notifications/config")
async def get_notification_config() -> dict:
    return _redacted(notification_store.load())


@router.post("/notifications/config")
async def save_notification_config(
    payload: NotificationConfigRequest, username: str = Depends(require_admin)
) -> dict:
    config = NotificationConfig(**payload.model_dump())
    notification_store.save(config)
    audit_log.record(username=username, action="notification_config_saved")
    return _redacted(config)


@router.post("/notifications/test")
async def send_test_notification(request: Request, _admin: str = Depends(require_admin)) -> dict:
    if not _test_rate_limiter.allow(_client_key(request)):
        raise HTTPException(status_code=429, detail="Muitos testes — aguarde alguns minutos.")
    config = notification_store.load()
    if config is None or not (config.webhook_url or config.smtp_host):
        raise HTTPException(
            status_code=400, detail="Configure webhook e/ou e-mail antes de testar."
        )
    sent = notifier.notify(
        "Teste de notificação — Certificate Discovery Platform",
        "Se você recebeu isso, a notificação está configurada corretamente.",
        config,
    )
    if not sent:
        raise HTTPException(
            status_code=502,
            detail="Nenhum canal confirmou o envio — confira host/porta/credenciais.",
        )
    return {"ok": True, "sent_via": sent}


@router.get("/scheduler/status")
async def scheduler_status() -> dict:
    last_check = scheduler.last_check_at
    return {
        "last_check_at": last_check.isoformat() if last_check else None,
        "check_interval_seconds": scheduler.check_interval_seconds,
    }


@router.post("/scheduler/check-now")
async def scheduler_check_now(request: Request, _admin: str = Depends(require_admin)) -> dict:
    if not _check_now_rate_limiter.allow(_client_key(request)):
        raise HTTPException(status_code=429, detail="Muitas verificações — aguarde alguns minutos.")
    results = await scheduler.check_once()
    return {"checked_at": scheduler.last_check_at.isoformat(), "results": results}
