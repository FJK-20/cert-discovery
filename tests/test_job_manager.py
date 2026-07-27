"""Testes da orquestração do ScanJobManager, isolados de rede real: CT logs,
DNS e TLS são mockados. Cobre três comportamentos que só existem no
orquestrador (não em discovery/domain isoladamente): cap de hosts após
dedupe, expiração de jobs antigos (TTL) e o caminho de timeout parcial.
"""

from __future__ import annotations

import asyncio
import dataclasses
from datetime import UTC, datetime, timedelta

from app.core.config import settings as real_settings
from app.discovery import ctlogs
from app.domain.models import JobState, ScanJob
from app.jobs.manager import ScanJobManager


def _patch_settings(monkeypatch, **overrides):
    fake = dataclasses.replace(real_settings, **overrides)
    monkeypatch.setattr("app.jobs.manager.settings", fake)
    return fake


async def _ct_unavailable(domain, *, client, timeout):
    raise ctlogs.CtLogUnavailable("mock: crt.sh indisponível no teste")


async def _never_resolves(hostname, *, timeout):
    return []


def _run_job(monkeypatch, **settings_overrides) -> ScanJob:
    """Aplica os overrides de settings + mock padrão de CT logs, roda
    `_run` para um job com um único host manual, e retorna o job final."""
    _patch_settings(monkeypatch, max_hosts_per_scan=10, **settings_overrides)
    monkeypatch.setattr("app.jobs.manager.ctlogs.fetch_hostnames", _ct_unavailable)

    manager = ScanJobManager()
    job = ScanJob(domain="example.com")
    asyncio.run(manager._run(job, ["a.example.com"]))
    return job


def test_pipeline_caps_hosts_after_dedup(monkeypatch):
    _patch_settings(monkeypatch, max_hosts_per_scan=2, max_concurrent_probes=10)
    monkeypatch.setattr("app.jobs.manager.ctlogs.fetch_hostnames", _ct_unavailable)
    monkeypatch.setattr("app.jobs.manager.resolve_ips", _never_resolves)

    manager = ScanJobManager()
    job = ScanJob(domain="example.com")
    manual_hosts = ["a.example.com", "b.example.com", "c.example.com", "d.example.com"]

    asyncio.run(manager._pipeline(job, manual_hosts))

    # 4 manuais + o próprio domínio (apex) = 5 candidatos únicos, capados em 2.
    assert job.hosts_total == 2
    assert len(job.records) == 2


def test_evict_expired_removes_only_old_jobs():
    manager = ScanJobManager()
    fresh = ScanJob(domain="fresh.example.com")
    old = ScanJob(domain="old.example.com")
    old.created_at = datetime.now(UTC) - timedelta(seconds=real_settings.job_ttl_seconds + 60)
    manager._jobs[fresh.id] = fresh
    manager._jobs[old.id] = old

    manager._evict_expired()

    assert manager.get(fresh.id) is not None
    assert manager.get(old.id) is None


def test_run_marks_partial_timeout_when_budget_exceeded(monkeypatch):
    async def _slow_process_host(self, job, host, semaphore):
        await asyncio.sleep(5)

    monkeypatch.setattr(ScanJobManager, "_process_host", _slow_process_host)
    job = _run_job(monkeypatch, job_total_budget_seconds=0.05)

    assert job.state == JobState.PARTIAL_TIMEOUT


def test_run_marks_failed_on_unexpected_exception(monkeypatch):
    async def _broken_process_host(self, job, host, semaphore):
        raise RuntimeError("falha inesperada simulada")

    monkeypatch.setattr(ScanJobManager, "_process_host", _broken_process_host)
    job = _run_job(monkeypatch, job_total_budget_seconds=5)

    assert job.state == JobState.FAILED
    assert job.error == "falha inesperada simulada"


def test_run_marks_done_on_success(monkeypatch):
    monkeypatch.setattr("app.jobs.manager.resolve_ips", _never_resolves)
    job = _run_job(monkeypatch, job_total_budget_seconds=5)

    assert job.state == JobState.DONE
    assert job.hosts_done == job.hosts_total
