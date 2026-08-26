"""Envia notificação por webhook genérico e/ou e-mail SMTP simples —
disparado quando uma renovação automática falha, ou quando um certificado
que exige confirmação manual está entrando na janela de renovação (ver
app/acme/scheduler.py). Best-effort: uma falha num canal não impede o
outro, e nada aqui nunca propaga uma exceção pro chamador — notificação
que falha não pode derrubar o fluxo de renovação que a disparou."""

from __future__ import annotations

import smtplib
import ssl
from email.mime.text import MIMEText

import httpx

from app.notify.store import NotificationConfig


class NotificationError(Exception):
    """Falha ao enviar por um canal específico — sempre capturada
    internamente por `notify()`, nunca escapa pro chamador."""


def send_webhook(webhook_url: str, subject: str, message: str) -> None:
    try:
        response = httpx.post(
            webhook_url, json={"subject": subject, "message": message}, timeout=10.0
        )
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise NotificationError(f"Falha ao enviar webhook: {exc}") from exc


def send_email(config: NotificationConfig, subject: str, message: str) -> None:
    if not (config.smtp_host and config.smtp_from and config.smtp_to):
        raise NotificationError("Configuração de e-mail incompleta.")
    msg = MIMEText(message)
    msg["Subject"] = subject
    msg["From"] = config.smtp_from
    msg["To"] = config.smtp_to
    try:
        with smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=10) as smtp:
            if config.smtp_use_tls:
                # Achado numa auditoria de robustez: `starttls()` sem
                # `context=` cai no contexto padrão do stdlib
                # (`ssl._create_stdlib_context`), que NÃO verifica
                # certificado (`CERT_NONE`, `check_hostname=False`) — um
                # MITM de rede apresentando certificado próprio passava
                # despercebido, e o login SMTP seguinte entregava a
                # credencial em claro pra ele.
                smtp.starttls(context=ssl.create_default_context())
            if config.smtp_username:
                smtp.login(config.smtp_username, config.smtp_password or "")
            smtp.send_message(msg)
    except (smtplib.SMTPException, OSError) as exc:
        raise NotificationError(f"Falha ao enviar e-mail: {exc}") from exc


def notify(subject: str, message: str, config: NotificationConfig | None) -> list[str]:
    """Tenta cada canal configurado, independente dos outros. Retorna os
    que confirmaram envio — nunca levanta."""
    if config is None:
        return []
    sent = []
    if config.webhook_url:
        try:
            send_webhook(config.webhook_url, subject, message)
            sent.append("webhook")
        except NotificationError:
            pass
    if config.smtp_host:
        try:
            send_email(config, subject, message)
            sent.append("email")
        except NotificationError:
            pass
    return sent
