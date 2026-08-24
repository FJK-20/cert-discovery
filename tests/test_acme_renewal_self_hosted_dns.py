"""Testa o modo self_hosted_dns: mesmo mecanismo de "primeira vez pede
confirmação de um CNAME, depois automático" que cname_delegation, mas sem
credencial de terceiro nenhuma — o desafio é publicado no dict em memória
de app/acme/selfdns.py em vez de numa API externa. `issue_certificate` é
substituído por um fake (não fala com a CA de verdade) — só a coordenação
de app/acme/renewal.py está sob teste."""

from __future__ import annotations

import asyncio
import dataclasses

from app.acme import renewal as renewal_module
from app.acme import selfdns
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
    eab_kid=None,
    eab_hmac_key=None,
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


def _enable_selfdns(monkeypatch, zone: str = "acme.example.org"):
    fast_settings = dataclasses.replace(
        renewal_module.settings,
        acme_dns_propagation_wait_seconds=0.05,
        selfdns_enabled=True,
        selfdns_zone=zone,
    )
    monkeypatch.setattr(renewal_module, "settings", fast_settings)
    monkeypatch.setattr(selfdns, "settings", fast_settings)


def test_self_hosted_dns_first_time_requires_confirmation_then_becomes_automatic(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(renewal_module, "issue_certificate", _fake_issue_certificate)
    _enable_selfdns(monkeypatch)
    selfdns._challenges.clear()

    store = AcmeStore(tmp_path)
    manager = renewal_module.AcmeRenewalManager(
        store=store, history=RenewalHistoryStore(tmp_path)
    )

    async def not_yet_configured(hostname, expected, *, timeout):
        return False

    monkeypatch.setattr(renewal_module.dns_check, "cname_matches", not_yet_configured)

    async def scenario():
        job = await manager.create(
            "app.example.com", AcmeEnvironment.STAGING, DnsMode.SELF_HOSTED_DNS
        )

        assert await _wait_until(lambda: job.state == AcmeJobState.AWAITING_DNS)
        assert job.dns_record_type == "CNAME"
        assert job.dns_record_name == "_acme-challenge.app.example.com"
        expected_target = selfdns.target_hostname("app.example.com")
        assert job.dns_record_value == expected_target

        async def now_configured(hostname, expected, *, timeout):
            assert hostname == job.dns_record_name
            assert expected == expected_target
            return True

        monkeypatch.setattr(renewal_module.dns_check, "cname_matches", now_configured)
        ok, _ = await manager.confirm_dns(job.id)
        assert ok is True

        assert await _wait_until(lambda: job.state in (AcmeJobState.DONE, AcmeJobState.FAILED))
        assert job.state == AcmeJobState.DONE, job.error
        # o desafio some do dict em memória depois de usado (limpo no finally
        # de issue_certificate via clear_dns_challenge)
        assert expected_target not in selfdns._challenges

    asyncio.run(scenario())


def test_self_hosted_dns_publishes_and_clears_challenge_in_memory(tmp_path, monkeypatch):
    monkeypatch.setattr(renewal_module, "issue_certificate", _fake_issue_certificate)
    _enable_selfdns(monkeypatch)
    selfdns._challenges.clear()

    seen_during_issuance = {}
    original_set = selfdns.set_challenge

    def spy_set_challenge(domain, value):
        original_set(domain, value)
        seen_during_issuance["value"] = selfdns._challenges.get(selfdns.target_hostname(domain))

    monkeypatch.setattr(renewal_module.selfdns, "set_challenge", spy_set_challenge)

    store = AcmeStore(tmp_path)
    manager = renewal_module.AcmeRenewalManager(
        store=store, history=RenewalHistoryStore(tmp_path)
    )

    async def already_configured(hostname, expected, *, timeout):
        return True

    monkeypatch.setattr(renewal_module.dns_check, "cname_matches", already_configured)

    async def scenario():
        job = await manager.create(
            "app.example.com", AcmeEnvironment.STAGING, DnsMode.SELF_HOSTED_DNS
        )
        assert await _wait_until(lambda: job.state in (AcmeJobState.DONE, AcmeJobState.FAILED))
        assert job.state == AcmeJobState.DONE, job.error
        assert seen_during_issuance["value"] == "fake-validation-value"

    asyncio.run(scenario())


def test_self_hosted_dns_already_configured_skips_confirmation(tmp_path, monkeypatch):
    monkeypatch.setattr(renewal_module, "issue_certificate", _fake_issue_certificate)
    _enable_selfdns(monkeypatch)
    selfdns._challenges.clear()

    store = AcmeStore(tmp_path)
    manager = renewal_module.AcmeRenewalManager(
        store=store, history=RenewalHistoryStore(tmp_path)
    )

    async def already_configured(hostname, expected, *, timeout):
        return True

    monkeypatch.setattr(renewal_module.dns_check, "cname_matches", already_configured)

    async def scenario():
        job = await manager.create(
            "app.example.com", AcmeEnvironment.STAGING, DnsMode.SELF_HOSTED_DNS
        )
        assert await _wait_until(lambda: job.state in (AcmeJobState.DONE, AcmeJobState.FAILED))
        assert job.state == AcmeJobState.DONE, job.error
        # nunca passou por AWAITING_DNS — automático de ponta a ponta
        assert job.dns_record_name is None

    asyncio.run(scenario())


def test_self_hosted_dns_fails_fast_when_not_enabled(tmp_path, monkeypatch):
    monkeypatch.setattr(renewal_module, "issue_certificate", _fake_issue_certificate)
    disabled_settings = dataclasses.replace(
        renewal_module.settings, selfdns_enabled=False, selfdns_zone=""
    )
    monkeypatch.setattr(renewal_module, "settings", disabled_settings)

    store = AcmeStore(tmp_path)
    manager = renewal_module.AcmeRenewalManager(
        store=store, history=RenewalHistoryStore(tmp_path)
    )

    async def scenario():
        job = await manager.create(
            "app.example.com", AcmeEnvironment.STAGING, DnsMode.SELF_HOSTED_DNS
        )
        assert await _wait_until(lambda: job.state == AcmeJobState.FAILED)
        assert "servidor dns próprio" in job.error.lower()

    asyncio.run(scenario())
