"""Testa o modo azure_cname_delegation: mesmo mecanismo de
cname_delegation (primeira vez pede confirmação de um CNAME, depois
automático), mas publicando o desafio numa zona Azure DNS em vez de
Cloudflare — reaproveita a MESMA credencial que o modo "direto"
(azure_dns) já usa, só que apontada pra uma zona pequena dedicada em vez
do domínio principal. `issue_certificate` é substituído por um fake (não
fala com a CA de verdade); `azure_dns.*` também é substituído (não fala
com o Azure de verdade) — só a coordenação de app/acme/renewal.py está
sob teste."""

from __future__ import annotations

import asyncio
import dataclasses

from app.acme import renewal as renewal_module
from app.acme.history import RenewalHistoryStore
from app.acme.issuance import IssuedResult
from app.acme.models import AcmeEnvironment, AcmeJobState, DnsMode
from app.acme.store import AcmeStore, AzureDnsCredentials


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


def _save_azure_delegation_creds(
    store: AcmeStore, zone_name: str = "acme-delegate.example.org"
) -> None:
    creds = AzureDnsCredentials(
        tenant_id="tenant",
        client_id="client",
        client_secret="secret",
        subscription_id="sub",
        resource_group="rg",
        zone_name=zone_name,
    )
    store.save_azure_dns_credentials(creds)


def _fast_propagation_settings(monkeypatch):
    fast_settings = dataclasses.replace(
        renewal_module.settings, acme_dns_propagation_wait_seconds=0.05
    )
    monkeypatch.setattr(renewal_module, "settings", fast_settings)


def _mock_azure_dns(monkeypatch):
    calls = {"created": [], "deleted": []}

    def fake_create_txt_record(creds, record_name, value):
        assert creds.zone_name == "acme-delegate.example.org"
        calls["created"].append((record_name, value))
        return record_name.split(".acme-delegate.example.org")[0]

    def fake_delete_txt_record(creds, relative_name):
        calls["deleted"].append(relative_name)

    monkeypatch.setattr(renewal_module.azure_dns, "create_txt_record", fake_create_txt_record)
    monkeypatch.setattr(renewal_module.azure_dns, "delete_txt_record", fake_delete_txt_record)
    return calls


def test_azure_cname_delegation_first_time_requires_confirmation_then_becomes_automatic(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(renewal_module, "issue_certificate", _fake_issue_certificate)
    _fast_propagation_settings(monkeypatch)
    calls = _mock_azure_dns(monkeypatch)

    store = AcmeStore(tmp_path)
    _save_azure_delegation_creds(store)
    manager = renewal_module.AcmeRenewalManager(
        store=store, history=RenewalHistoryStore(tmp_path)
    )

    async def not_yet_delegated(hostname, expected, *, timeout):
        return False

    monkeypatch.setattr(renewal_module.dns_check, "cname_matches", not_yet_delegated)

    async def scenario():
        job = await manager.create(
            "app.example.com", AcmeEnvironment.STAGING, DnsMode.AZURE_CNAME_DELEGATION
        )

        assert await _wait_until(lambda: job.state == AcmeJobState.AWAITING_DNS)
        assert job.dns_record_type == "CNAME"
        assert job.dns_record_name == "_acme-challenge.app.example.com"
        expected_target = renewal_module._delegation_target(
            "app.example.com", "acme-delegate.example.org"
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
        assert calls["created"] == [(expected_target, "fake-validation-value")]
        assert len(calls["deleted"]) == 1

    asyncio.run(scenario())


def test_azure_cname_delegation_already_configured_skips_confirmation(tmp_path, monkeypatch):
    monkeypatch.setattr(renewal_module, "issue_certificate", _fake_issue_certificate)
    _fast_propagation_settings(monkeypatch)
    _mock_azure_dns(monkeypatch)

    store = AcmeStore(tmp_path)
    _save_azure_delegation_creds(store)
    manager = renewal_module.AcmeRenewalManager(
        store=store, history=RenewalHistoryStore(tmp_path)
    )

    async def already_delegated(hostname, expected, *, timeout):
        return True

    monkeypatch.setattr(renewal_module.dns_check, "cname_matches", already_delegated)

    async def scenario():
        job = await manager.create(
            "app.example.com", AcmeEnvironment.STAGING, DnsMode.AZURE_CNAME_DELEGATION
        )
        assert await _wait_until(lambda: job.state in (AcmeJobState.DONE, AcmeJobState.FAILED))
        assert job.state == AcmeJobState.DONE, job.error
        # nunca passou por AWAITING_DNS — automático de ponta a ponta
        assert job.dns_record_name is None

    asyncio.run(scenario())


def test_azure_cname_delegation_fails_fast_without_credentials_configured(tmp_path, monkeypatch):
    monkeypatch.setattr(renewal_module, "issue_certificate", _fake_issue_certificate)
    store = AcmeStore(tmp_path)
    manager = renewal_module.AcmeRenewalManager(
        store=store, history=RenewalHistoryStore(tmp_path)
    )

    async def scenario():
        job = await manager.create(
            "app.example.com", AcmeEnvironment.STAGING, DnsMode.AZURE_CNAME_DELEGATION
        )
        assert await _wait_until(lambda: job.state == AcmeJobState.FAILED)
        assert "azure dns" in job.error.lower()

    asyncio.run(scenario())
