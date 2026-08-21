"""Testa o modo cname_delegation: primeira vez pede confirmação de um
CNAME (mesmo mecanismo de bloqueio do modo manual, mas checando CNAME em
vez de TXT); depois de configurado, detecta o CNAME já existente e segue
automático sem nenhuma confirmação. `issue_certificate` é substituído por
um fake (não fala com a CA de verdade); `cloudflare.*` também é
substituído (não fala com a Cloudflare de verdade) — só a coordenação de
app/acme/renewal.py está sob teste."""

from __future__ import annotations

import asyncio
import dataclasses

from app.acme import renewal as renewal_module
from app.acme.issuance import IssuedResult
from app.acme.models import AcmeEnvironment, AcmeJobState, DnsMode
from app.acme.store import AcmeStore, DnsCredentials


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


def _save_delegation_creds(store: AcmeStore, delegation_zone: str = "delegate.example.org") -> None:
    creds = DnsCredentials(
        provider="cloudflare", api_token="fake-token", delegation_zone=delegation_zone
    )
    store.save_dns_credentials(creds)


def _fast_propagation_settings(monkeypatch):
    fast_settings = dataclasses.replace(
        renewal_module.settings, acme_dns_propagation_wait_seconds=0.05
    )
    monkeypatch.setattr(renewal_module, "settings", fast_settings)


def _mock_cloudflare(monkeypatch):
    calls = {"created": [], "deleted": []}

    def fake_find_zone_id(domain, token):
        assert token == "fake-token"
        return "zone123"

    def fake_create_txt_record(zone_id, name, content, token):
        calls["created"].append((zone_id, name, content))
        return "record123"

    def fake_delete_txt_record(zone_id, record_id, token):
        calls["deleted"].append((zone_id, record_id))

    monkeypatch.setattr(renewal_module.cloudflare, "find_zone_id", fake_find_zone_id)
    monkeypatch.setattr(renewal_module.cloudflare, "create_txt_record", fake_create_txt_record)
    monkeypatch.setattr(renewal_module.cloudflare, "delete_txt_record", fake_delete_txt_record)
    return calls


def test_cname_delegation_first_time_requires_confirmation_then_becomes_automatic(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(renewal_module, "issue_certificate", _fake_issue_certificate)
    # wait_for_dns_ready() reaproveita o sleep fixo do modo cloudflare (15s
    # em produção) — sem isso o teste teria que esperar de verdade.
    _fast_propagation_settings(monkeypatch)
    calls = _mock_cloudflare(monkeypatch)

    store = AcmeStore(tmp_path)
    _save_delegation_creds(store)
    manager = renewal_module.AcmeRenewalManager(store=store)

    async def not_yet_delegated(hostname, expected, *, timeout):
        return False

    monkeypatch.setattr(renewal_module.dns_check, "cname_matches", not_yet_delegated)

    async def scenario():
        job = await manager.create(
            "app.example.com", AcmeEnvironment.STAGING, DnsMode.CNAME_DELEGATION
        )

        assert await _wait_until(lambda: job.state == AcmeJobState.AWAITING_DNS)
        assert job.dns_record_type == "CNAME"
        assert job.dns_record_name == "_acme-challenge.app.example.com"
        expected_target = renewal_module._delegation_target(
            "app.example.com", "delegate.example.org"
        )
        assert job.dns_record_value == expected_target

        async def now_delegated(hostname, expected, *, timeout):
            assert hostname == job.dns_record_name
            assert expected == expected_target
            return True

        monkeypatch.setattr(renewal_module.dns_check, "cname_matches", now_delegated)
        ok, _ = await manager.confirm_dns(job.id)
        assert ok is True

        assert await _wait_until(lambda: job.state in (AcmeJobState.DONE, AcmeJobState.FAILED))
        assert job.state == AcmeJobState.DONE, job.error
        # o TXT do desafio foi criado no ALVO da delegação, não no domínio emitido
        assert calls["created"] == [("zone123", expected_target, "fake-validation-value")]
        assert calls["deleted"] == [("zone123", "record123")]

    asyncio.run(scenario())


def test_cname_delegation_already_configured_skips_confirmation(tmp_path, monkeypatch):
    monkeypatch.setattr(renewal_module, "issue_certificate", _fake_issue_certificate)
    _fast_propagation_settings(monkeypatch)
    _mock_cloudflare(monkeypatch)

    store = AcmeStore(tmp_path)
    _save_delegation_creds(store)
    manager = renewal_module.AcmeRenewalManager(store=store)

    async def already_delegated(hostname, expected, *, timeout):
        return True

    monkeypatch.setattr(renewal_module.dns_check, "cname_matches", already_delegated)

    async def scenario():
        job = await manager.create(
            "app.example.com", AcmeEnvironment.STAGING, DnsMode.CNAME_DELEGATION
        )
        assert await _wait_until(lambda: job.state in (AcmeJobState.DONE, AcmeJobState.FAILED))
        assert job.state == AcmeJobState.DONE, job.error
        # nunca passou por AWAITING_DNS — automático de ponta a ponta
        assert job.dns_record_name is None

    asyncio.run(scenario())


def test_cname_delegation_fails_fast_without_delegation_zone_configured(tmp_path, monkeypatch):
    monkeypatch.setattr(renewal_module, "issue_certificate", _fake_issue_certificate)
    store = AcmeStore(tmp_path)
    store.save_dns_credentials(DnsCredentials(provider="cloudflare", api_token="fake-token"))
    manager = renewal_module.AcmeRenewalManager(store=store)

    async def scenario():
        job = await manager.create(
            "app.example.com", AcmeEnvironment.STAGING, DnsMode.CNAME_DELEGATION
        )
        assert await _wait_until(lambda: job.state == AcmeJobState.FAILED)
        assert "zona de delegação" in job.error.lower()

    asyncio.run(scenario())
