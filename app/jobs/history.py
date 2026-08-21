"""Histórico persistente de scans (SQLite) — o que faltava pra "histórico
persistente de scans e certificados" da Fase 3 (certificados já eram
persistentes desde a Fase 2, via app/acme/store.py).

`ScanJobManager` continua sendo a fonte da verdade pro job *em andamento*
(mesmo padrão em memória de sempre, consultado via SSE) — aqui só grava um
retrato pra sobreviver a um restart e alimentar a lista "scans recentes"."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from app.core.config import settings
from app.core.db import get_connection
from app.domain.models import CertificateRecord, JobState, Origin, ScanJob, Status


def _record_to_dict(record: CertificateRecord) -> dict:
    return {
        "host": record.host,
        "origin": record.origin.value,
        "status": record.status.value,
        "subject_cn": record.subject_cn,
        "issuer": record.issuer,
        "not_before": record.not_before.isoformat() if record.not_before else None,
        "not_after": record.not_after.isoformat() if record.not_after else None,
        "days_until_expiry": record.days_until_expiry,
        "serial_number": record.serial_number,
        "sha256_fingerprint": record.sha256_fingerprint,
        "sans": record.sans,
        "resolved_ip": record.resolved_ip,
        "note": record.note,
    }


def _parse_dt(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def _dict_to_record(raw: dict) -> CertificateRecord:
    return CertificateRecord(
        host=raw["host"],
        origin=Origin(raw["origin"]),
        status=Status(raw["status"]),
        subject_cn=raw.get("subject_cn"),
        issuer=raw.get("issuer"),
        not_before=_parse_dt(raw.get("not_before")),
        not_after=_parse_dt(raw.get("not_after")),
        days_until_expiry=raw.get("days_until_expiry"),
        serial_number=raw.get("serial_number"),
        sha256_fingerprint=raw.get("sha256_fingerprint"),
        sans=raw.get("sans") or [],
        resolved_ip=raw.get("resolved_ip"),
        note=raw.get("note"),
    )


class ScanHistoryStore:
    def __init__(self, data_dir: Path) -> None:
        self._data_dir = data_dir

    def record(self, job: ScanJob) -> None:
        records_json = json.dumps([_record_to_dict(r) for r in job.records])
        conn = get_connection(self._data_dir)
        try:
            conn.execute(
                """
                INSERT INTO scan_jobs
                    (id, domain, state, progress_message, hosts_total, hosts_done,
                     error, created_at, records_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    state=excluded.state,
                    progress_message=excluded.progress_message,
                    hosts_total=excluded.hosts_total,
                    hosts_done=excluded.hosts_done,
                    error=excluded.error,
                    records_json=excluded.records_json
                """,
                (
                    job.id,
                    job.domain,
                    job.state.value,
                    job.progress_message,
                    job.hosts_total,
                    job.hosts_done,
                    job.error,
                    job.created_at.isoformat(),
                    records_json,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def load(self, job_id: str) -> ScanJob | None:
        conn = get_connection(self._data_dir)
        try:
            row = conn.execute("SELECT * FROM scan_jobs WHERE id = ?", (job_id,)).fetchone()
        finally:
            conn.close()
        if row is None:
            return None
        return ScanJob(
            id=row["id"],
            domain=row["domain"],
            state=JobState(row["state"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            progress_message=row["progress_message"],
            hosts_total=row["hosts_total"],
            hosts_done=row["hosts_done"],
            error=row["error"],
            records=[_dict_to_record(r) for r in json.loads(row["records_json"])],
        )

    def list_recent(self, limit: int = 15) -> list[dict]:
        conn = get_connection(self._data_dir)
        try:
            rows = conn.execute(
                "SELECT id, domain, state, hosts_total, hosts_done, error, created_at "
                "FROM scan_jobs ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        finally:
            conn.close()
        return [dict(row) for row in rows]


scan_history = ScanHistoryStore(Path(settings.data_dir))
