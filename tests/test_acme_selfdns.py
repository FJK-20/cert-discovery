"""Testa app/acme/selfdns.py: montagem de resposta DNS crua (sem subir o
listener UDP de verdade — _build_response é uma função pura de bytes pra
bytes, testável direto). Cobre: TXT respondido quando o desafio está
publicado, NXDOMAIN quando não está, REFUSED pra qualquer nome fora da
zona própria (nunca vira open resolver), NODATA pra tipo diferente de TXT
dentro da zona."""

from __future__ import annotations

import asyncio
import dataclasses

import dns.message
import dns.rcode
import dns.rdatatype
import pytest

from app.acme import selfdns


def _make_settings(zone="acme.example.org"):
    return dataclasses.replace(selfdns.settings, selfdns_zone=zone)


def _query(name: str, rdtype=dns.rdatatype.TXT) -> bytes:
    return dns.message.make_query(name, rdtype).to_wire()


def test_target_hostname_is_deterministic_and_stable(monkeypatch):
    monkeypatch.setattr(selfdns, "settings", _make_settings())
    first = selfdns.target_hostname("app.example.com")
    second = selfdns.target_hostname("app.example.com")
    assert first == second
    assert first.endswith(".acme.example.org")


def test_target_hostname_differs_per_domain(monkeypatch):
    monkeypatch.setattr(selfdns, "settings", _make_settings())
    assert selfdns.target_hostname("a.example.com") != selfdns.target_hostname("b.example.com")


def test_responds_txt_when_challenge_is_set(monkeypatch):
    monkeypatch.setattr(selfdns, "settings", _make_settings())
    selfdns._challenges.clear()
    selfdns.set_challenge("app.example.com", "expected-validation-value")

    hostname = selfdns.target_hostname("app.example.com")
    response = dns.message.from_wire(selfdns._build_response(_query(hostname)))

    assert response.rcode() == dns.rcode.NOERROR
    assert len(response.answer) == 1
    txt_values = [b"".join(rr.strings).decode() for rr in response.answer[0]]
    assert txt_values == ["expected-validation-value"]
    selfdns._challenges.clear()


def test_responds_nxdomain_when_no_challenge_set(monkeypatch):
    monkeypatch.setattr(selfdns, "settings", _make_settings())
    selfdns._challenges.clear()

    hostname = selfdns.target_hostname("never-issued.example.com")
    response = dns.message.from_wire(selfdns._build_response(_query(hostname)))

    assert response.rcode() == dns.rcode.NXDOMAIN
    assert not response.answer


def test_refuses_queries_outside_own_zone(monkeypatch):
    monkeypatch.setattr(selfdns, "settings", _make_settings())
    selfdns._challenges.clear()
    # mesmo com um desafio publicado, um nome de OUTRA zona nunca é
    # respondido — não vira open resolver por acidente
    selfdns.set_challenge("app.example.com", "some-value")

    response = dns.message.from_wire(
        selfdns._build_response(_query("_acme-challenge.google.com"))
    )
    assert response.rcode() == dns.rcode.REFUSED
    assert not response.answer
    selfdns._challenges.clear()


def test_returns_nodata_for_non_txt_query_inside_zone(monkeypatch):
    monkeypatch.setattr(selfdns, "settings", _make_settings())
    selfdns._challenges.clear()

    hostname = selfdns.target_hostname("app.example.com")
    response = dns.message.from_wire(
        selfdns._build_response(_query(hostname, dns.rdatatype.A))
    )
    assert response.rcode() == dns.rcode.NOERROR
    assert not response.answer


def test_garbage_bytes_do_not_crash_and_produce_no_response(monkeypatch):
    monkeypatch.setattr(selfdns, "settings", _make_settings())
    assert selfdns._build_response(b"not a real dns message") is None


def test_set_and_clear_challenge_round_trip(monkeypatch):
    monkeypatch.setattr(selfdns, "settings", _make_settings())
    selfdns._challenges.clear()
    selfdns.set_challenge("app.example.com", "value-1")
    assert selfdns._challenges[selfdns.target_hostname("app.example.com")] == "value-1"

    selfdns.clear_challenge("app.example.com")
    assert selfdns.target_hostname("app.example.com") not in selfdns._challenges


# --- _handle_tcp_connection: timeout e teto de conexões concorrentes
# (achado numa auditoria de robustez — porta exposta, não-autenticada
# por desenho, sem timeout nem limite algum antes disso) ---


class _HangingReader:
    """Simula um cliente slowloris: nunca manda dado nenhum."""

    async def readexactly(self, n: int) -> bytes:
        await asyncio.sleep(3600)
        raise AssertionError("não deveria completar — o timeout precisa cortar antes")


class _FakeWriter:
    def __init__(self) -> None:
        self.closed = False
        self.written = b""

    def write(self, data: bytes) -> None:
        self.written += data

    async def drain(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True


@pytest.mark.anyio
async def test_tcp_handler_times_out_on_a_client_that_never_sends_data(monkeypatch):
    monkeypatch.setattr(selfdns, "_TCP_READ_TIMEOUT_SECONDS", 0.05)
    writer = _FakeWriter()
    await selfdns._handle_tcp_connection(_HangingReader(), writer)
    assert writer.closed is True
    assert writer.written == b""


@pytest.mark.anyio
async def test_tcp_handler_rejects_new_connections_when_at_concurrency_limit(monkeypatch):
    async def _never_reads():
        raise AssertionError("não deveria nem tentar ler — limite já estava cheio")

    class _UnusedReader:
        readexactly = staticmethod(lambda n: _never_reads())

    # satura o semáforo por fora, como se _MAX_CONCURRENT_TCP_CONNECTIONS
    # conexões reais já estivessem em andamento.
    semaphore = asyncio.Semaphore(1)
    await semaphore.acquire()
    monkeypatch.setattr(selfdns, "_tcp_connection_semaphore", semaphore)

    writer = _FakeWriter()
    await selfdns._handle_tcp_connection(_UnusedReader(), writer)
    assert writer.closed is True
    assert writer.written == b""
