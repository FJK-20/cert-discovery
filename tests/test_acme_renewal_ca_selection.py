"""Testa o eixo "qual CA" (app.acme.models.CertificateAuthority) na
AcmeRenewalManager — independente do eixo "qual modo de validação DNS",
já coberto em tests/test_acme_renewal_manual_dns.py e
tests/test_acme_renewal_cname_delegation.py. Cobre só a lógica de
despacho (app/acme/renewal.py), não o fluxo ACME completo."""

from __future__ import annotations

import pytest

from app.acme.history import RenewalHistoryStore
from app.acme.issuance import IssuanceError
from app.acme.models import AcmeEnvironment, AcmeJob, CertificateAuthority, DnsMode
from app.acme.renewal import AcmeRenewalManager
from app.acme.store import AcmeStore, CaCredentials
from app.core.config import settings


def _manager(tmp_path, store=None) -> AcmeRenewalManager:
    return AcmeRenewalManager(
        store=store or AcmeStore(tmp_path), history=RenewalHistoryStore(tmp_path)
    )


def test_directory_url_dispatches_by_ca(tmp_path):
    manager = _manager(tmp_path)
    le_staging = AcmeJob(
        domain="x.com", environment=AcmeEnvironment.STAGING, ca=CertificateAuthority.LETS_ENCRYPT
    )
    le_prod = AcmeJob(
        domain="x.com",
        environment=AcmeEnvironment.PRODUCTION,
        ca=CertificateAuthority.LETS_ENCRYPT,
    )
    zerossl = AcmeJob(
        domain="x.com", environment=AcmeEnvironment.STAGING, ca=CertificateAuthority.ZEROSSL
    )

    assert manager._directory_url(le_staging) == settings.acme_directory_staging
    assert manager._directory_url(le_prod) == settings.acme_directory_production
    # ZeroSSL não tem staging separado — sempre o mesmo diretório, mesmo
    # com environment=STAGING (só bookkeeping/exibição nesse caso).
    assert manager._directory_url(zerossl) == settings.zerossl_directory_url


def test_account_storage_key_avoids_collision_between_cas(tmp_path):
    manager = _manager(tmp_path)
    le_prod = AcmeJob(
        domain="x.com",
        environment=AcmeEnvironment.PRODUCTION,
        ca=CertificateAuthority.LETS_ENCRYPT,
    )
    zerossl = AcmeJob(
        domain="x.com", environment=AcmeEnvironment.PRODUCTION, ca=CertificateAuthority.ZEROSSL
    )

    le_key = manager._account_storage_key(le_prod)
    zerossl_key = manager._account_storage_key(zerossl)
    assert le_key == "production"
    assert zerossl_key == "zerossl"
    assert le_key != zerossl_key  # a conta de uma CA nunca pisa na da outra


def test_eab_credentials_not_required_for_lets_encrypt(tmp_path):
    manager = _manager(tmp_path)
    job = AcmeJob(
        domain="x.com", environment=AcmeEnvironment.STAGING, ca=CertificateAuthority.LETS_ENCRYPT
    )
    assert manager._eab_credentials(job) == (None, None)


def test_eab_credentials_raises_clear_error_when_zerossl_not_configured(tmp_path):
    manager = _manager(tmp_path)
    job = AcmeJob(
        domain="x.com", environment=AcmeEnvironment.STAGING, ca=CertificateAuthority.ZEROSSL
    )
    with pytest.raises(IssuanceError, match="ZeroSSL"):
        manager._eab_credentials(job)


def test_eab_credentials_returned_when_zerossl_configured(tmp_path):
    store = AcmeStore(tmp_path)
    store.save_ca_credentials(CaCredentials(ca="zerossl", eab_kid="kid1", eab_hmac_key="hmac1"))
    manager = _manager(tmp_path, store=store)
    job = AcmeJob(
        domain="x.com", environment=AcmeEnvironment.STAGING, ca=CertificateAuthority.ZEROSSL
    )
    assert manager._eab_credentials(job) == ("kid1", "hmac1")


def test_create_defaults_to_lets_encrypt(tmp_path, monkeypatch):
    import asyncio

    from app.acme import renewal as renewal_module

    # create() dispara um asyncio.create_task de fundo pro fluxo ACME de
    # verdade — substitui _run pra checar só o default do parâmetro `ca`,
    # sem deixar uma tarefa tentando falar com uma CA de verdade pra trás.
    async def _noop_run(self, job):
        return None

    monkeypatch.setattr(renewal_module.AcmeRenewalManager, "_run", _noop_run)

    manager = _manager(tmp_path)
    job = asyncio.run(manager.create("x.com", AcmeEnvironment.STAGING, DnsMode.MANUAL))
    assert job.ca == CertificateAuthority.LETS_ENCRYPT
