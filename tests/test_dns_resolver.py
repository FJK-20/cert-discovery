import asyncio
from unittest.mock import AsyncMock, patch

import dns.exception

from app.discovery.dns_resolver import resolve_ips, to_idna

_RESOLVE_TARGET = "app.discovery.dns_resolver.dns.asyncresolver.resolve"


def test_to_idna_converts_unicode_hostname():
    result = to_idna("café.example.com")
    assert result is not None
    assert result.isascii()


def test_to_idna_returns_none_for_invalid_hostname():
    assert to_idna("a" * 300) is None


def test_resolve_ips_returns_addresses_from_both_record_types():
    async def run():
        with patch(_RESOLVE_TARGET, new=AsyncMock()) as mock_resolve:
            mock_resolve.side_effect = [
                ["93.184.216.34"],
                ["2606:2800:220:1:248:1893:25c8:1946"],
            ]
            ips = await resolve_ips("example.com", timeout=1)
        assert ips == ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]

    asyncio.run(run())


def test_resolve_ips_returns_empty_list_when_dns_fails():
    async def run():
        with patch(_RESOLVE_TARGET, new=AsyncMock()) as mock_resolve:
            mock_resolve.side_effect = dns.exception.DNSException("no answer")
            ips = await resolve_ips("doesnotresolve.invalid", timeout=1)
        assert ips == []

    asyncio.run(run())
