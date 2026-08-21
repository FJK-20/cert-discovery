"""Testa os dois stores de histórico persistente (SQLite) da Fase 3:
ScanHistoryStore (app/jobs/history.py) e RenewalHistoryStore
(app/acme/history.py). Cada teste usa seu próprio tmp_path — nunca toca o
data/ real do projeto."""

from __future__ import annotations

from datetime import UTC, datetime

from app.acme.history import RenewalHistoryStore
from app.domain.models import CertificateRecord, JobState, Origin, ScanJob, Status
from app.jobs.history import ScanHistoryStore


def test_scan_history_round_trips_a_job_with_records(tmp_path):
    store = ScanHistoryStore(tmp_path)
    job = ScanJob(domain="example.com", state=JobState.DONE, hosts_total=1, hosts_done=1)
    job.records.append(
        CertificateRecord(
            host="example.com",
            origin=Origin.LIVE,
            status=Status.OK,
            subject_cn="example.com",
            days_until_expiry=60,
        )
    )
    store.record(job)

    loaded = store.load(job.id)
    assert loaded is not None
    assert loaded.domain == "example.com"
    assert loaded.state == JobState.DONE
    assert len(loaded.records) == 1
    assert loaded.records[0].host == "example.com"
    assert loaded.records[0].status == Status.OK
    assert loaded.records[0].origin == Origin.LIVE


def test_scan_history_load_missing_job_returns_none(tmp_path):
    store = ScanHistoryStore(tmp_path)
    assert store.load("does-not-exist") is None


def test_scan_history_record_upserts_same_job(tmp_path):
    store = ScanHistoryStore(tmp_path)
    job = ScanJob(domain="example.com", state=JobState.PENDING)
    store.record(job)

    job.state = JobState.DONE
    job.progress_message = "Concluído"
    store.record(job)

    loaded = store.load(job.id)
    assert loaded.state == JobState.DONE
    assert loaded.progress_message == "Concluído"


def test_scan_history_list_recent_orders_newest_first(tmp_path):
    store = ScanHistoryStore(tmp_path)
    older = ScanJob(domain="old.example.com")
    newer = ScanJob(domain="new.example.com")
    older.created_at = datetime(2020, 1, 1, tzinfo=UTC)
    newer.created_at = datetime(2020, 1, 2, tzinfo=UTC)
    store.record(older)
    store.record(newer)

    rows = store.list_recent()
    assert [r["domain"] for r in rows] == ["new.example.com", "old.example.com"]


def test_renewal_history_attempts_since_last_success_stops_at_last_done(tmp_path):
    store = RenewalHistoryStore(tmp_path)
    store.start(
        attempt_id="a1",
        domain="example.com",
        environment="staging",
        dns_mode="cloudflare",
        trigger="scheduler",
        attempt_number=1,
    )
    store.finish("a1", state="failed", error="boom")

    store.start(
        attempt_id="a2",
        domain="example.com",
        environment="staging",
        dns_mode="cloudflare",
        trigger="scheduler",
        attempt_number=2,
    )
    store.finish("a2", state="done", certificate_id="cert-1")

    store.start(
        attempt_id="a3",
        domain="example.com",
        environment="staging",
        dns_mode="cloudflare",
        trigger="scheduler",
        attempt_number=1,
    )
    store.finish("a3", state="failed", error="boom again")

    attempts = store.attempts_since_last_success("example.com")
    # Só a3 — a1 ficou pra trás do "done" de a2, que zera a contagem.
    assert [a["id"] for a in attempts] == ["a3"]


def test_renewal_history_attempts_since_last_success_empty_when_never_attempted(tmp_path):
    store = RenewalHistoryStore(tmp_path)
    assert store.attempts_since_last_success("never-tried.example.com") == []


def test_renewal_history_recent_orders_newest_first(tmp_path):
    store = RenewalHistoryStore(tmp_path)
    store.start(
        attempt_id="a1",
        domain="a.example.com",
        environment="staging",
        dns_mode="cloudflare",
        trigger="manual",
        attempt_number=1,
    )
    store.start(
        attempt_id="a2",
        domain="b.example.com",
        environment="staging",
        dns_mode="cloudflare",
        trigger="scheduler",
        attempt_number=1,
    )
    rows = store.recent()
    assert [r["id"] for r in rows] == ["a2", "a1"]
