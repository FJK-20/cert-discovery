"""Testa app/discovery/subdomain_wordlist.py isolado de DNS real —
resolve_ips é mockado. Cobre: só hosts que resolveram entram no
resultado (tentativa sem resolução é silenciosa, não vira "não
resolvido"), e a concorrência é limitada pelo semáforo passado."""

from __future__ import annotations

import asyncio

from app.discovery import subdomain_wordlist


def test_discover_hosts_returns_only_resolving_prefixes(monkeypatch):
    async def fake_resolve_ips(hostname, *, timeout):
        if hostname in ("www.example.com", "api.example.com"):
            return ["203.0.113.10"]
        return []

    monkeypatch.setattr(subdomain_wordlist, "resolve_ips", fake_resolve_ips)

    result = asyncio.run(
        subdomain_wordlist.discover_hosts("example.com", timeout=1.0, max_concurrency=10)
    )
    assert result == {"www.example.com", "api.example.com"}


def test_discover_hosts_returns_empty_set_when_nothing_resolves(monkeypatch):
    async def never_resolves(hostname, *, timeout):
        return []

    monkeypatch.setattr(subdomain_wordlist, "resolve_ips", never_resolves)

    result = asyncio.run(
        subdomain_wordlist.discover_hosts("example.com", timeout=1.0, max_concurrency=10)
    )
    assert result == set()


def test_discover_hosts_respects_concurrency_limit(monkeypatch):
    in_flight = 0
    peak = 0

    async def tracked_resolve_ips(hostname, *, timeout):
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        await asyncio.sleep(0.01)
        in_flight -= 1
        return []

    monkeypatch.setattr(subdomain_wordlist, "resolve_ips", tracked_resolve_ips)

    asyncio.run(
        subdomain_wordlist.discover_hosts("example.com", timeout=1.0, max_concurrency=3)
    )
    assert peak <= 3


def test_wordlist_is_small_and_curated():
    # não é uma lista de milhares de entradas de ferramenta dedicada de
    # enumeração — feature leve e opt-in, não um scanner agressivo por padrão.
    words = subdomain_wordlist.COMMON_SUBDOMAINS
    assert 20 <= len(words) <= 150
    assert len(words) == len(set(words))
    assert "www" in words
