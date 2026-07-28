"""Testes do cliente Cloudflare, tudo mockado via monkeypatch em
httpx.request (síncrono, mesma função usada por app/acme/cloudflare.py) —
nenhum teste aqui depende de rede real."""

from __future__ import annotations

import httpx
import pytest

from app.acme import cloudflare


def _response(status_code: int, json_body: dict) -> httpx.Response:
    return httpx.Response(status_code, json=json_body, request=httpx.Request("GET", "https://x"))


def test_verify_token_true_when_active(monkeypatch):
    monkeypatch.setattr(
        cloudflare.httpx,
        "request",
        lambda *a, **k: _response(200, {"success": True, "result": {"status": "active"}}),
    )
    assert cloudflare.verify_token("tok") is True


def test_verify_token_false_when_not_active(monkeypatch):
    monkeypatch.setattr(
        cloudflare.httpx,
        "request",
        lambda *a, **k: _response(200, {"success": True, "result": {"status": "disabled"}}),
    )
    assert cloudflare.verify_token("tok") is False


def test_verify_token_false_on_api_error(monkeypatch):
    monkeypatch.setattr(
        cloudflare.httpx,
        "request",
        lambda *a, **k: _response(400, {"success": False, "errors": [{"message": "bad token"}]}),
    )
    assert cloudflare.verify_token("tok") is False


def test_find_zone_id_tries_progressively_shorter_names(monkeypatch):
    calls = []

    def fake_request(method, url, headers=None, timeout=None, params=None, **kwargs):
        calls.append(params["name"])
        if params["name"] == "example.com":
            return _response(200, {"success": True, "result": [{"id": "zone123"}]})
        return _response(200, {"success": True, "result": []})

    monkeypatch.setattr(cloudflare.httpx, "request", fake_request)
    zone_id = cloudflare.find_zone_id("_acme-challenge.app.example.com", "tok")
    assert zone_id == "zone123"
    assert calls == ["_acme-challenge.app.example.com", "app.example.com", "example.com"]


def test_find_zone_id_raises_when_no_zone_matches(monkeypatch):
    monkeypatch.setattr(
        cloudflare.httpx, "request", lambda *a, **k: _response(200, {"success": True, "result": []})
    )
    with pytest.raises(cloudflare.CloudflareError):
        cloudflare.find_zone_id("example.com", "tok")


def test_create_and_delete_txt_record(monkeypatch):
    def fake_request(method, url, headers=None, timeout=None, **kwargs):
        if method == "POST":
            return _response(200, {"success": True, "result": {"id": "rec1"}})
        assert method == "DELETE"
        return _response(200, {"success": True, "result": {}})

    monkeypatch.setattr(cloudflare.httpx, "request", fake_request)
    record_id = cloudflare.create_txt_record("zone1", "_acme-challenge.example.com", "val", "tok")
    assert record_id == "rec1"
    cloudflare.delete_txt_record("zone1", record_id, "tok")


def test_verify_token_false_on_network_error(monkeypatch):
    def raise_network_error(*a, **k):
        raise httpx.ConnectError("boom")

    monkeypatch.setattr(cloudflare.httpx, "request", raise_network_error)
    assert cloudflare.verify_token("tok") is False


def test_find_zone_id_raises_on_network_error(monkeypatch):
    def raise_network_error(*a, **k):
        raise httpx.ConnectError("boom")

    monkeypatch.setattr(cloudflare.httpx, "request", raise_network_error)
    with pytest.raises(cloudflare.CloudflareError):
        cloudflare.find_zone_id("example.com", "tok")
