"""Testa app/acme/scheduler.py: a regra de negócio da janela de renovação
(1/3 da validade restante), qual certificado de cada domínio entra na
checagem, e a decisão entre tentar renovar sozinho (cloudflare/
cname_delegation) vs só notificar (manual/CSR). O gerenciador ACME real
(que fala com a CA) é substituído por um fake — aqui só a coordenação do
agendador está sob teste."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

from app.acme import scheduler as scheduler_module
from app.acme.history import RenewalHistoryStore
from app.acme.models import AcmeJob, AcmeJobState
from app.acme.scheduler import RenewalScheduler, latest_per_domain, renewal_threshold
from app.acme.store import AcmeStore, IssuedCertificate
from app.notify.store import NotificationConfig, NotificationStore


def _cert(
    domain: str,
    *,
    days_ago_issued: int,
    days_until_expiry: int,
    dns_mode: str | None = "cloudflare",
    cert_id: str | None = None,
) -> IssuedCertificate:
    now = datetime.now(UTC)
    return IssuedCertificate(
        id=cert_id or f"{domain}-{days_ago_issued}",
        domain=domain,
        environment="staging",
        issued_at=(now - timedelta(days=days_ago_issued)).isoformat(),
        not_after=(now + timedelta(days=days_until_expiry)).isoformat(),
        fullchain_pem="FAKE",
        private_key_pem="FAKE",
        dns_mode=dns_mode,
    )


def test_renewal_threshold_is_one_third_before_expiry():
    # 90 dias de validade -> limiar 30 dias antes de expirar
    cert = _cert("example.com", days_ago_issued=0, days_until_expiry=90)
    threshold = renewal_threshold(cert)
    not_after = datetime.fromisoformat(cert.not_after)
    assert abs((not_after - threshold) - timedelta(days=30)) < timedelta(seconds=5)


def test_renewal_threshold_none_without_not_after():
    cert = _cert("example.com", days_ago_issued=0, days_until_expiry=90)
    cert.not_after = None
    assert renewal_threshold(cert) is None


def test_latest_per_domain_picks_most_recent_issued_at():
    old = _cert("example.com", days_ago_issued=60, days_until_expiry=30, cert_id="old")
    new = _cert("example.com", days_ago_issued=1, days_until_expiry=89, cert_id="new")
    other = _cert("other.com", days_ago_issued=1, days_until_expiry=89, cert_id="other")
    result = latest_per_domain([old, new, other])
    ids = {c.id for c in result}
    assert ids == {"new", "other"}


class _FakeManager:
    """Substitui AcmeRenewalManager — não fala com a CA de verdade. Cada
    chamada de create() devolve um job cujo estado final é decidido pelo
    teste via `outcomes` (por domínio)."""

    def __init__(self, outcomes: dict[str, tuple[str, str | None]]):
        self._outcomes = outcomes
        self.created_for: list[str] = []

    async def create(self, domain, environment, dns_mode, ca=None, *, trigger="manual"):
        self.created_for.append(domain)
        state, error = self._outcomes.get(domain, ("done", None))
        job = AcmeJob(domain=domain, environment=environment, dns_mode=dns_mode)
        job.state = AcmeJobState(state)
        job.error = error
        return job


def _notify_store_with(tmp_path, **kwargs) -> NotificationStore:
    store = NotificationStore(tmp_path)
    store.save(NotificationConfig(**kwargs))
    return store


def _capture_notify(monkeypatch) -> list[tuple[str, str]]:
    captured: list[tuple[str, str]] = []

    def fake_notify(subject, message, config):
        captured.append((subject, message))

    monkeypatch.setattr(scheduler_module.notifier, "notify", fake_notify)
    return captured


def test_check_once_skips_certs_not_yet_due(tmp_path):
    store = AcmeStore(tmp_path)
    store.save_certificate(_cert("far.example.com", days_ago_issued=1, days_until_expiry=89))
    manager = _FakeManager({})
    sched = RenewalScheduler(
        store=store, manager=manager, notify_store=NotificationStore(tmp_path / "notif"),
        history=RenewalHistoryStore(tmp_path / "history"),
        check_interval_seconds=9999,
    )
    results = asyncio.run(sched.check_once())
    assert results == []
    assert manager.created_for == []


def test_check_once_auto_renews_cloudflare_mode_cert(tmp_path):
    store = AcmeStore(tmp_path)
    store.save_certificate(
        _cert("due.example.com", days_ago_issued=61, days_until_expiry=29, dns_mode="cloudflare")
    )
    manager = _FakeManager({"due.example.com": ("done", None)})
    sched = RenewalScheduler(
        store=store, manager=manager, notify_store=NotificationStore(tmp_path / "notif"),
        history=RenewalHistoryStore(tmp_path / "history"),
        check_interval_seconds=9999,
    )
    results = asyncio.run(sched.check_once())
    assert manager.created_for == ["due.example.com"]
    assert len(results) == 1
    assert results[0]["domain"] == "due.example.com"
    assert results[0]["action"] == "renewed"


def test_check_once_notifies_on_auto_renewal_failure(tmp_path, monkeypatch):
    captured = _capture_notify(monkeypatch)

    store = AcmeStore(tmp_path)
    store.save_certificate(
        _cert(
            "fails.example.com",
            days_ago_issued=61,
            days_until_expiry=29,
            dns_mode="cname_delegation",
        )
    )
    manager = _FakeManager({"fails.example.com": ("failed", "Cloudflare recusou a requisição")})
    notify_store = _notify_store_with(tmp_path / "notif", webhook_url="https://example.com/hook")
    sched = RenewalScheduler(
        store=store, manager=manager, notify_store=notify_store,
        history=RenewalHistoryStore(tmp_path / "history"),
        check_interval_seconds=9999,
    )
    results = asyncio.run(sched.check_once())

    assert results[0]["action"] == "renewal_failed"
    assert len(captured) == 1
    subject, message = captured[0]
    assert "fails.example.com" in subject
    assert "Cloudflare recusou a requisição" in message


def test_check_once_notifies_manual_mode_without_attempting_renewal(tmp_path, monkeypatch):
    captured = _capture_notify(monkeypatch)

    store = AcmeStore(tmp_path)
    store.save_certificate(
        _cert("manual.example.com", days_ago_issued=61, days_until_expiry=29, dns_mode="manual")
    )
    manager = _FakeManager({})
    notify_store = _notify_store_with(tmp_path / "notif", webhook_url="https://example.com/hook")
    sched = RenewalScheduler(
        store=store, manager=manager, notify_store=notify_store,
        history=RenewalHistoryStore(tmp_path / "history"),
        check_interval_seconds=9999,
    )
    results = asyncio.run(sched.check_once())

    assert manager.created_for == []  # nunca tenta renovar sozinho
    assert results[0]["action"] == "manual_renewal_notified"
    assert len(captured) == 1
    assert "manual.example.com" in captured[0][0]


def test_check_once_notifies_csr_manual_cert_without_dns_mode(tmp_path, monkeypatch):
    captured = _capture_notify(monkeypatch)
    store = AcmeStore(tmp_path)
    store.save_certificate(
        _cert("csr.example.com", days_ago_issued=61, days_until_expiry=29, dns_mode=None)
    )
    manager = _FakeManager({})
    notify_store = _notify_store_with(tmp_path / "notif", webhook_url="https://example.com/hook")
    sched = RenewalScheduler(
        store=store, manager=manager, notify_store=notify_store,
        history=RenewalHistoryStore(tmp_path / "history"),
        check_interval_seconds=9999,
    )
    asyncio.run(sched.check_once())
    assert manager.created_for == []
    assert captured


def test_check_once_backs_off_after_recent_failure(tmp_path):
    store = AcmeStore(tmp_path)
    store.save_certificate(
        _cert("due.example.com", days_ago_issued=61, days_until_expiry=29, dns_mode="cloudflare")
    )
    history = RenewalHistoryStore(tmp_path / "history")
    history.start(
        attempt_id="prev-1",
        domain="due.example.com",
        environment="staging",
        dns_mode="cloudflare",
        trigger="scheduler",
        attempt_number=1,
    )
    history.finish("prev-1", state="failed", error="falha simulada")

    manager = _FakeManager({"due.example.com": ("done", None)})
    sched = RenewalScheduler(
        store=store, manager=manager, notify_store=NotificationStore(tmp_path / "notif"),
        history=history,
        check_interval_seconds=9999,
    )
    results = asyncio.run(sched.check_once())

    assert manager.created_for == []  # ainda dentro da janela de backoff
    assert results[0]["action"] == "renewal_backoff"


def test_check_once_gives_up_after_max_retries_and_notifies(tmp_path, monkeypatch):
    captured = _capture_notify(monkeypatch)
    store = AcmeStore(tmp_path)
    store.save_certificate(
        _cert(
            "chronic.example.com", days_ago_issued=61, days_until_expiry=29, dns_mode="cloudflare"
        )
    )
    history = RenewalHistoryStore(tmp_path / "history")
    for i in range(scheduler_module._MAX_AUTO_RETRIES):
        attempt_id = f"prev-{i}"
        history.start(
            attempt_id=attempt_id,
            domain="chronic.example.com",
            environment="staging",
            dns_mode="cloudflare",
            trigger="scheduler",
            attempt_number=i + 1,
        )
        history.finish(attempt_id, state="failed", error=f"falha {i}")

    manager = _FakeManager({})
    notify_store = _notify_store_with(tmp_path / "notif", webhook_url="https://example.com/hook")

    def far_future():
        # Bem além de qualquer janela de backoff, pra provar que é o
        # limite de tentativas (não a janela) que barra aqui.
        return datetime.now(UTC) + timedelta(hours=10)

    sched = RenewalScheduler(
        store=store, manager=manager, notify_store=notify_store,
        history=history, check_interval_seconds=9999, now=far_future,
    )
    results = asyncio.run(sched.check_once())

    assert manager.created_for == []  # desistiu de tentar sozinho
    assert results[0]["action"] == "renewal_exhausted"
    assert len(captured) == 1
    assert "esgot" in captured[0][0].lower() or "esgot" in captured[0][1].lower()
