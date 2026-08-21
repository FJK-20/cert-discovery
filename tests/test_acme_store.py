"""Round-trip de persistência do AcmeStore, isolado em tmp_path (mesmo
padrão de tests/test_job_manager.py para AdminStore/ScanJobManager)."""

from __future__ import annotations

from app.acme.store import AcmeAccount, AcmeStore, CaCredentials, DnsCredentials, IssuedCertificate


def test_account_round_trip_per_environment(tmp_path):
    store = AcmeStore(tmp_path)
    assert store.load_account("staging") is None

    staging = AcmeAccount(
        environment="staging", account_key_pem="pem-staging", account_uri="uri-staging"
    )
    store.save_account(staging)
    assert store.load_account("staging") == staging
    assert store.load_account("production") is None

    production = AcmeAccount(
        environment="production", account_key_pem="pem-prod", account_uri="uri-prod"
    )
    store.save_account(production)
    # salvar um ambiente não pode sobrescrever o outro
    assert store.load_account("staging") == staging
    assert store.load_account("production") == production


def test_dns_credentials_round_trip(tmp_path):
    store = AcmeStore(tmp_path)
    assert store.load_dns_credentials() is None

    creds = DnsCredentials(provider="cloudflare", api_token="tok123")
    store.save_dns_credentials(creds)
    assert store.load_dns_credentials() == creds


def test_certificate_round_trip_and_listing(tmp_path):
    store = AcmeStore(tmp_path)
    assert store.list_certificates() == []

    cert = IssuedCertificate(
        id="abc",
        domain="app.example.com",
        environment="staging",
        issued_at="2026-01-01T00:00:00+00:00",
        not_after="2026-04-01T00:00:00+00:00",
        fullchain_pem="fullchain",
        private_key_pem="key",
    )
    store.save_certificate(cert)
    assert store.load_certificate("abc") == cert
    assert store.load_certificate("missing") is None
    assert store.list_certificates() == [cert]


def test_ca_credentials_round_trip(tmp_path):
    store = AcmeStore(tmp_path)
    assert store.load_ca_credentials("zerossl") is None

    creds = CaCredentials(ca="zerossl", eab_kid="kid123", eab_hmac_key="hmac-secret-value")
    store.save_ca_credentials(creds)
    assert store.load_ca_credentials("zerossl") == creds
    assert store.load_ca_credentials("some-other-ca") is None


def test_ca_credentials_eab_hmac_key_is_encrypted_on_disk(tmp_path):
    import json

    store = AcmeStore(tmp_path)
    store.save_ca_credentials(CaCredentials(ca="zerossl", eab_kid="kid123", eab_hmac_key="secret"))

    raw = json.loads((tmp_path / "ca_credentials.json").read_text())
    assert raw["zerossl"]["eab_hmac_key"] != "secret"
    assert store.load_ca_credentials("zerossl").eab_hmac_key == "secret"
