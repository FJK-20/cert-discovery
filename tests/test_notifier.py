"""Testa app/notify/notifier.py — webhook e SMTP mockados (sem rede
real; o teste ao vivo contra um listener local de verdade fica pra fora
da suíte automatizada, mesmo padrão do resto do projeto)."""

from __future__ import annotations

import smtplib
import ssl

import httpx
import pytest

from app.notify import notifier
from app.notify.store import NotificationConfig


def test_notify_returns_empty_list_without_config():
    assert notifier.notify("assunto", "mensagem", None) == []


def test_notify_sends_webhook_when_configured(monkeypatch):
    calls = []

    def fake_post(url, json, timeout):
        calls.append((url, json))

        class _Resp:
            def raise_for_status(self):
                pass

        return _Resp()

    monkeypatch.setattr(httpx, "post", fake_post)
    config = NotificationConfig(webhook_url="https://example.com/hook")
    sent = notifier.notify("assunto", "mensagem", config)
    assert sent == ["webhook"]
    assert calls == [("https://example.com/hook", {"subject": "assunto", "message": "mensagem"})]


def test_notify_webhook_failure_does_not_raise(monkeypatch):
    def fake_post(url, json, timeout):
        raise httpx.ConnectError("boom")

    monkeypatch.setattr(httpx, "post", fake_post)
    config = NotificationConfig(webhook_url="https://example.com/hook")
    sent = notifier.notify("assunto", "mensagem", config)
    assert sent == []


def test_notify_sends_email_when_configured(monkeypatch):
    sent_messages = []

    class _FakeSMTP:
        def __init__(self, host, port, timeout):
            sent_messages.append({"host": host, "port": port})

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def starttls(self, context=None):
            sent_messages.append(("starttls", context))

        def login(self, username, password):
            sent_messages.append(("login", username, password))

        def send_message(self, msg):
            sent_messages.append(("sent", msg["Subject"], msg["From"], msg["To"]))

    monkeypatch.setattr(smtplib, "SMTP", _FakeSMTP)
    config = NotificationConfig(
        smtp_host="smtp.example.com",
        smtp_port=587,
        smtp_use_tls=True,
        smtp_username="user",
        smtp_password="pw",
        smtp_from="alerts@example.com",
        smtp_to="admin@example.com",
    )
    sent = notifier.notify("assunto", "mensagem", config)
    assert sent == ["email"]
    # Achado numa auditoria de robustez: starttls() sem context= caía no
    # contexto padrão do stdlib, que não verifica certificado nenhum —
    # confirma aqui que um ssl.SSLContext real (que verifica) é passado.
    starttls_calls = [m for m in sent_messages if isinstance(m, tuple) and m[0] == "starttls"]
    assert len(starttls_calls) == 1
    context = starttls_calls[0][1]
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert ("login", "user", "pw") in sent_messages
    assert ("sent", "assunto", "alerts@example.com", "admin@example.com") in sent_messages


def test_notify_email_failure_does_not_raise(monkeypatch):
    class _FailingSMTP:
        def __init__(self, host, port, timeout):
            raise OSError("connection refused")

    monkeypatch.setattr(smtplib, "SMTP", _FailingSMTP)
    config = NotificationConfig(
        smtp_host="smtp.example.com", smtp_from="a@example.com", smtp_to="b@example.com"
    )
    sent = notifier.notify("assunto", "mensagem", config)
    assert sent == []


def test_notify_tries_both_channels_independently(monkeypatch):
    def failing_post(url, json, timeout):
        raise httpx.ConnectError("x")

    monkeypatch.setattr(httpx, "post", failing_post)

    class _FakeSMTP:
        def __init__(self, host, port, timeout):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def starttls(self, context=None):
            pass

        def send_message(self, msg):
            pass

    monkeypatch.setattr(smtplib, "SMTP", _FakeSMTP)
    config = NotificationConfig(
        webhook_url="https://example.com/hook",
        smtp_host="smtp.example.com",
        smtp_from="a@example.com",
        smtp_to="b@example.com",
    )
    sent = notifier.notify("assunto", "mensagem", config)
    assert sent == ["email"]  # webhook falhou, email não — os dois foram tentados


@pytest.mark.parametrize(
    "config",
    [
        NotificationConfig(smtp_host=None, smtp_from="a@example.com", smtp_to="b@example.com"),
        NotificationConfig(smtp_host="smtp.example.com", smtp_from=None, smtp_to="b@example.com"),
        NotificationConfig(smtp_host="smtp.example.com", smtp_from="a@example.com", smtp_to=None),
    ],
)
def test_send_email_rejects_incomplete_config(config):
    with pytest.raises(notifier.NotificationError):
        notifier.send_email(config, "assunto", "mensagem")
