"""Testa o endpoint SSE de progresso de scan (GET /api/scan/{job_id}/events,
app/api/routes_scan.py) — achado numa auditoria de robustez: sem teto de
tempo nem detecção de desconexão, um job persistido num estado
não-terminal (ex.: reinício do processo no meio de um scan, que nunca mais
avança sozinho) prendia a stream pra sempre — cada conexão aberta pra esse
job ficava presa indefinidamente, consumindo uma task/conexão do único
worker do processo.

Testa a função da rota diretamente (não via TestClient) — streaming real
via HTTP é mais frágil de testar e o que importa aqui é a lógica de saída
do loop, não o transporte HTTP em si."""

from __future__ import annotations

import pytest

from app.api import routes_scan
from app.domain.models import JobState, ScanJob


class _FakeRequest:
    """`is_disconnected()` real do Starlette é assíncrono — mock mínimo
    que desconecta depois de N chamadas, ou nunca."""

    def __init__(self, disconnect_after: int | None = None) -> None:
        self._calls = 0
        self._disconnect_after = disconnect_after

    async def is_disconnected(self) -> bool:
        self._calls += 1
        if self._disconnect_after is None:
            return False
        return self._calls > self._disconnect_after


async def _consume(monkeypatch, job: ScanJob, request: _FakeRequest) -> list[bytes]:
    monkeypatch.setattr(routes_scan.job_manager, "get", lambda job_id: job)
    response = await routes_scan.scan_events(request, job.id)
    return [chunk async for chunk in response.body_iterator]


@pytest.mark.anyio
async def test_sse_stream_ends_normally_when_job_reaches_terminal_state(monkeypatch):
    job = ScanJob(domain="example.com", state=JobState.DONE)
    request = _FakeRequest()
    chunks = await _consume(monkeypatch, job, request)
    assert len(chunks) == 1
    assert '"state": "done"' in chunks[0] or "done" in chunks[0]


@pytest.mark.anyio
async def test_sse_stream_stops_when_client_disconnects_even_if_job_never_finishes(monkeypatch):
    """Job preso num estado não-terminal (nunca chega a DONE/FAILED/
    PARTIAL_TIMEOUT sozinho) — sem a checagem de desconexão, isso travaria
    pra sempre. Aqui o cliente "sai" logo na primeira checagem."""
    job = ScanJob(domain="example.com", state=JobState.RESOLVING_DNS)
    request = _FakeRequest(disconnect_after=0)

    async def instant_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(routes_scan.asyncio, "sleep", instant_sleep)
    chunks = await _consume(monkeypatch, job, request)
    # terminou (a chamada retornou) mesmo com o job preso em estado não-terminal
    # — desconectado antes de qualquer payload, então zero chunks é o
    # comportamento correto (nenhum trabalho desperdiçado pro cliente que já foi).
    assert job.state not in routes_scan._TERMINAL_STATES
    assert chunks == []


@pytest.mark.anyio
async def test_sse_stream_stops_at_hard_deadline_even_without_disconnect_or_terminal_state(
    monkeypatch,
):
    """Reproduz o achado do relatório: job persistido num estado não-
    terminal (reinício no meio de um scan) e um cliente que nunca
    desconecta — antes do fix, isso não tinha NENHUMA saída."""
    job = ScanJob(domain="example.com", state=JobState.RESOLVING_DNS)
    request = _FakeRequest(disconnect_after=None)  # nunca desconecta

    fake_now = [0.0]
    monkeypatch.setattr(routes_scan.time, "monotonic", lambda: fake_now[0])

    async def jump_past_deadline(_seconds: float) -> None:
        fake_now[0] += routes_scan._SSE_MAX_SECONDS + 1

    monkeypatch.setattr(routes_scan.asyncio, "sleep", jump_past_deadline)
    chunks = await _consume(monkeypatch, job, request)
    assert job.state not in routes_scan._TERMINAL_STATES
    assert len(chunks) == 1
