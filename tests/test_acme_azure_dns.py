"""Testes do cliente Azure DNS, tudo mockado via monkeypatch em
httpx.request (síncrono, mesma função usada por app/acme/azure_dns.py) —
nenhum teste aqui depende de rede real. Mesmo padrão de
tests/test_acme_cloudflare.py."""

from __future__ import annotations

import httpx
import pytest

from app.acme import azure_dns
from app.acme.store import AzureDnsCredentials

_CREDS = AzureDnsCredentials(
    tenant_id="tenant1",
    client_id="client1",
    client_secret="secret1",
    subscription_id="sub1",
    resource_group="rg1",
    zone_name="example.com",
)


def _response(status_code: int, json_body: dict | None = None) -> httpx.Response:
    return httpx.Response(
        status_code, json=json_body or {}, request=httpx.Request("GET", "https://x")
    )


def test_relative_name_strips_zone_suffix():
    assert azure_dns._relative_name("_acme-challenge.example.com", "example.com") == (
        "_acme-challenge"
    )


def test_relative_name_apex_record_is_at_sign():
    assert azure_dns._relative_name("example.com", "example.com") == "@"


def test_relative_name_raises_for_domain_outside_zone():
    with pytest.raises(azure_dns.AzureDnsError):
        azure_dns._relative_name("_acme-challenge.other.com", "example.com")


def test_get_access_token_returns_token_on_success(monkeypatch):
    def fake_request(method, url, **kwargs):
        assert method == "POST"
        assert "login.microsoftonline.com/tenant1" in url
        return _response(200, {"access_token": "tok123"})

    monkeypatch.setattr(azure_dns.httpx, "request", fake_request)
    assert azure_dns._get_access_token(_CREDS) == "tok123"


def test_get_access_token_raises_on_bad_credentials(monkeypatch):
    monkeypatch.setattr(
        azure_dns.httpx, "request", lambda *a, **k: _response(401, {"error": "invalid_client"})
    )
    with pytest.raises(azure_dns.AzureDnsError):
        azure_dns._get_access_token(_CREDS)


def test_verify_credentials_true_when_zone_reachable(monkeypatch):
    def fake_request(method, url, **kwargs):
        if method == "POST":
            return _response(200, {"access_token": "tok"})
        assert method == "GET"
        assert "dnsZones/example.com" in url
        return _response(200, {"name": "example.com"})

    monkeypatch.setattr(azure_dns.httpx, "request", fake_request)
    assert azure_dns.verify_credentials(_CREDS) is True


def test_verify_credentials_false_when_zone_not_found(monkeypatch):
    def fake_request(method, url, **kwargs):
        if method == "POST":
            return _response(200, {"access_token": "tok"})
        return _response(404, {})

    monkeypatch.setattr(azure_dns.httpx, "request", fake_request)
    assert azure_dns.verify_credentials(_CREDS) is False


def test_verify_credentials_false_on_auth_failure(monkeypatch):
    monkeypatch.setattr(azure_dns.httpx, "request", lambda *a, **k: _response(401, {}))
    assert azure_dns.verify_credentials(_CREDS) is False


def test_create_and_delete_txt_record(monkeypatch):
    calls = []

    def fake_request(method, url, **kwargs):
        calls.append((method, url, kwargs.get("json")))
        if method == "POST":
            return _response(200, {"access_token": "tok"})
        if method == "PUT":
            return _response(200, {})
        assert method == "DELETE"
        return _response(200, {})

    monkeypatch.setattr(azure_dns.httpx, "request", fake_request)
    relative_name = azure_dns.create_txt_record(
        _CREDS, "_acme-challenge.example.com", "challenge-value"
    )
    assert relative_name == "_acme-challenge"

    put_call = next(c for c in calls if c[0] == "PUT")
    expected = {"properties": {"TTL": 60, "TXTRecords": [{"value": ["challenge-value"]}]}}
    assert put_call[2] == expected

    azure_dns.delete_txt_record(_CREDS, relative_name)
    assert any(c[0] == "DELETE" for c in calls)


def test_delete_txt_record_treats_already_gone_as_success(monkeypatch):
    def fake_request(method, url, **kwargs):
        if method == "POST":
            return _response(200, {"access_token": "tok"})
        assert method == "DELETE"
        return _response(204, {})

    monkeypatch.setattr(azure_dns.httpx, "request", fake_request)
    azure_dns.delete_txt_record(_CREDS, "_acme-challenge")  # não deve levantar


def test_create_txt_record_raises_on_failure(monkeypatch):
    def fake_request(method, url, **kwargs):
        if method == "POST":
            return _response(200, {"access_token": "tok"})
        return _response(403, {"error": {"message": "Forbidden"}})

    monkeypatch.setattr(azure_dns.httpx, "request", fake_request)
    with pytest.raises(azure_dns.AzureDnsError):
        azure_dns.create_txt_record(_CREDS, "_acme-challenge.example.com", "value")


def test_network_error_raises_azure_dns_error(monkeypatch):
    def raise_network_error(*a, **k):
        raise httpx.ConnectError("boom")

    monkeypatch.setattr(azure_dns.httpx, "request", raise_network_error)
    with pytest.raises(azure_dns.AzureDnsError):
        azure_dns._get_access_token(_CREDS)
