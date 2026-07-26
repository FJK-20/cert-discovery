import asyncio

import httpx
import pytest

from app.discovery import ctlogs


def test_normalize_hostname_strips_and_lowercases():
    assert ctlogs.normalize_hostname(" WWW.Example.COM. ") == "www.example.com"


def test_normalize_hostname_rejects_entries_with_spaces():
    assert ctlogs.normalize_hostname("not a hostname") is None


def test_extract_hostnames_handles_multiline_name_value_and_dedupes():
    payload = [
        {"common_name": "example.com", "name_value": "example.com\nwww.example.com"},
        {"common_name": "example.com", "name_value": "example.com\napi.example.com"},
    ]
    hostnames = ctlogs._extract_hostnames(payload)
    assert hostnames == {"example.com", "www.example.com", "api.example.com"}


def _client_with_response(handler) -> httpx.AsyncClient:
    transport = httpx.MockTransport(handler)
    return httpx.AsyncClient(transport=transport)


def test_fetch_hostnames_parses_valid_json():
    async def run():
        def handler(request: httpx.Request) -> httpx.Response:
            payload = [{"common_name": "example.com", "name_value": "example.com\nwww.example.com"}]
            return httpx.Response(200, json=payload, headers={"content-type": "application/json"})

        async with _client_with_response(handler) as client:
            hostnames = await ctlogs.fetch_hostnames("example.com", client=client, timeout=5)
        assert hostnames == {"example.com", "www.example.com"}

    asyncio.run(run())


def test_fetch_hostnames_raises_when_service_returns_html_error_with_200():
    async def run():
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, text="<html>crt.sh error</html>", headers={"content-type": "text/html"}
            )

        async with _client_with_response(handler) as client:
            with pytest.raises(ctlogs.CtLogUnavailable):
                await ctlogs.fetch_hostnames("example.com", client=client, timeout=1)

    asyncio.run(run())


def test_fetch_hostnames_raises_on_connect_error():
    async def run():
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("boom", request=request)

        async with _client_with_response(handler) as client:
            with pytest.raises(ctlogs.CtLogUnavailable):
                await ctlogs.fetch_hostnames("example.com", client=client, timeout=1)

    asyncio.run(run())
