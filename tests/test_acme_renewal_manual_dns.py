"""Testa a coordenação do modo manual em AcmeRenewalManager — a thread de
emissão bloqueia em AWAITING_DNS até confirm_dns() destravar (ou expira).
`issue_certificate` real fala com a CA de verdade, então é substituído por
um fake que só exercita os callbacks (set_dns_challenge/wait_for_dns_ready/
clear_dns_challenge), igual ao que a lib real receberia."""

from __future__ import annotations

import asyncio
import dataclasses

from app.acme import renewal as renewal_module
from app.acme.history import RenewalHistoryStore
from app.acme.issuance import IssuedResult
from app.acme.models import AcmeEnvironment, AcmeJobState, DnsMode
from app.acme.store import AcmeStore


def _fake_issue_certificate(
    *,
    domain,
    environment,
    directory_url,
    store,
    set_dns_challenge,
    clear_dns_challenge,
    wait_for_dns_ready,
    total_budget_seconds,
    on_progress,
):
    on_progress("preparando...")
    handle = set_dns_challenge(f"_acme-challenge.{domain}", "fake-validation-value")
    wait_for_dns_ready()
    clear_dns_challenge(handle)
    return IssuedResult(fullchain_pem="FAKE CERT", private_key_pem="FAKE KEY", not_after=None)


async def _wait_until(condition, *, timeout=5.0, step=0.02):
    elapsed = 0.0
    while elapsed < timeout:
        if condition():
            return True
        await asyncio.sleep(step)
        elapsed += step
    return False


def test_manual_mode_blocks_until_confirm_dns_succeeds(tmp_path, monkeypatch):
    monkeypatch.setattr(renewal_module, "issue_certificate", _fake_issue_certificate)
    manager = renewal_module.AcmeRenewalManager(
        store=AcmeStore(tmp_path), history=RenewalHistoryStore(tmp_path)
    )

    async def scenario():
        job = await manager.create("app.example.com", AcmeEnvironment.STAGING, DnsMode.MANUAL)

        assert await _wait_until(lambda: job.state == AcmeJobState.AWAITING_DNS)
        assert job.dns_record_name == "_acme-challenge.app.example.com"
        assert job.dns_record_value == "fake-validation-value"

        # DNS ainda não propagou: confirm_dns não destrava, job continua esperando
        async def not_found(hostname, expected, *, timeout):
            return False

        monkeypatch.setattr(renewal_module.dns_check, "txt_record_contains", not_found)
        ok, message = await manager.confirm_dns(job.id)
        assert ok is False
        assert "não encontrado" in message
        assert job.state == AcmeJobState.AWAITING_DNS

        # agora o registro está lá: confirm_dns destrava a thread bloqueada
        async def found(hostname, expected, *, timeout):
            assert hostname == job.dns_record_name
            assert expected == job.dns_record_value
            return True

        monkeypatch.setattr(renewal_module.dns_check, "txt_record_contains", found)
        ok, _ = await manager.confirm_dns(job.id)
        assert ok is True

        assert await _wait_until(lambda: job.state in (AcmeJobState.DONE, AcmeJobState.FAILED))
        assert job.state == AcmeJobState.DONE, job.error
        assert job.certificate_id is not None

    asyncio.run(scenario())


def test_manual_mode_times_out_if_never_confirmed(tmp_path, monkeypatch):
    monkeypatch.setattr(renewal_module, "issue_certificate", _fake_issue_certificate)
    fast_settings = dataclasses.replace(renewal_module.settings, acme_manual_dns_budget_seconds=0.2)
    monkeypatch.setattr(renewal_module, "settings", fast_settings)
    manager = renewal_module.AcmeRenewalManager(
        store=AcmeStore(tmp_path), history=RenewalHistoryStore(tmp_path)
    )

    async def scenario():
        job = await manager.create("app.example.com", AcmeEnvironment.STAGING, DnsMode.MANUAL)
        assert await _wait_until(lambda: job.state == AcmeJobState.AWAITING_DNS)

        assert await _wait_until(
            lambda: job.state == AcmeJobState.FAILED, timeout=3.0
        )
        assert "esgotado" in job.error.lower()

    asyncio.run(scenario())


def test_confirm_dns_rejects_unknown_job(tmp_path):
    manager = renewal_module.AcmeRenewalManager(
        store=AcmeStore(tmp_path), history=RenewalHistoryStore(tmp_path)
    )

    async def scenario():
        ok, message = await manager.confirm_dns("does-not-exist")
        assert ok is False
        assert "não encontrado" in message

    asyncio.run(scenario())
