"""Testes de app/acme/dns_check.py — mockando dns.asyncresolver, sem rede
real (mesmo padrão de tests/test_discovery* pra resolução DNS). Usa
asyncio.run() em vez de pytest-asyncio: o projeto não depende dele, e o
FastAPI TestClient já cobre as rotas async sem precisar de testes async."""

from __future__ import annotations

import asyncio

import dns.exception
import dns.rdata
import dns.rdataclass
import dns.rdatatype

from app.acme import dns_check


def _txt_rdata(value: str):
    return dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TXT, f'"{value}"')


def test_txt_record_contains_true_when_value_present(monkeypatch):
    async def fake_resolve(hostname, rdtype, lifetime):
        assert rdtype == "TXT"
        return [_txt_rdata("wrong-value"), _txt_rdata("expected-value")]

    monkeypatch.setattr(dns_check.dns.asyncresolver, "resolve", fake_resolve)
    found = asyncio.run(
        dns_check.txt_record_contains("_acme-challenge.example.com", "expected-value", timeout=5.0)
    )
    assert found is True


def test_txt_record_contains_false_when_value_absent(monkeypatch):
    async def fake_resolve(hostname, rdtype, lifetime):
        return [_txt_rdata("something-else")]

    monkeypatch.setattr(dns_check.dns.asyncresolver, "resolve", fake_resolve)
    found = asyncio.run(
        dns_check.txt_record_contains("_acme-challenge.example.com", "expected-value", timeout=5.0)
    )
    assert found is False


def test_txt_record_contains_false_on_nxdomain(monkeypatch):
    async def fake_resolve(hostname, rdtype, lifetime):
        raise dns.exception.DNSException("no such domain")

    monkeypatch.setattr(dns_check.dns.asyncresolver, "resolve", fake_resolve)
    found = asyncio.run(
        dns_check.txt_record_contains("_acme-challenge.example.com", "expected-value", timeout=5.0)
    )
    assert found is False
