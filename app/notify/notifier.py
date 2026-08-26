"""Envia notificação por webhook genérico e/ou e-mail SMTP simples —
disparado quando uma renovação automática falha, ou quando um certificado
que exige confirmação manual está entrando na janela de renovação (ver
app/acme/scheduler.py). Best-effort: uma falha num canal não impede o
outro, e nada aqui nunca propaga uma exceção pro chamador — notificação
que falha não pode derrubar o fluxo de renovação que a disparou."""

from __future__ import annotations

import smtplib
import socket
import ssl
from email.mime.text import MIMEText
from urllib.parse import urlparse

import httpx

from app.core.security import is_public_ip
from app.notify.store import NotificationConfig


class NotificationError(Exception):
    """Falha ao enviar por um canal específico — sempre capturada
    internamente por `notify()`, nunca escapa pro chamador."""


def _reject_non_public_webhook(url: str) -> None:
    """Achado numa auditoria de robustez: `is_public_ip()` (app/core/
    security.py) já existe e é usado pelo scanner justamente pra evitar
    SSRF, mas não era aplicado aqui — um admin (ou uma sessão
    comprometida) podia apontar o webhook pra 169.254.169.254 ou qualquer
    IP interno, e cada falha de renovação virava um POST na rede local.

    Resolução feita aqui (bloqueante, tolerável: webhook é best-effort,
    baixo volume, nunca no caminho de uma requisição HTTP quente) em vez
    de reaproveitar o resolver assíncrono do scanner — trade-off
    documentado, não escondido: como o `httpx.post()` abaixo resolve o
    host de novo por conta própria, existe uma janela estreita de DNS
    rebinding entre esta checagem e a conexão real. Pinar a conexão no IP
    já validado (como app/discovery/tls_probe.py faz) fecharia isso de
    vez, mas exigiria um transport HTTP customizado — desproporcional
    pra um webhook configurado só por admin, não pelo scanner."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise NotificationError("URL de webhook precisa ser http:// ou https://.")
    hostname = parsed.hostname
    if not hostname:
        raise NotificationError("URL de webhook inválida.")
    try:
        addrinfo = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise NotificationError(f"Não foi possível resolver o host do webhook: {exc}") from exc
    ips = {info[4][0] for info in addrinfo}
    if not ips or not all(is_public_ip(ip) for ip in ips):
        raise NotificationError(
            "URL de webhook aponta pra um endereço não público — bloqueado (proteção SSRF)."
        )


def send_webhook(webhook_url: str, subject: str, message: str) -> None:
    _reject_non_public_webhook(webhook_url)
    try:
        response = httpx.post(
            webhook_url,
            json={"subject": subject, "message": message},
            timeout=10.0,
            follow_redirects=False,
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
