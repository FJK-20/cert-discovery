from __future__ import annotations

import csv
import io
import json
from dataclasses import asdict

from app.domain.models import CertificateRecord

_FIELDS = [
    "host",
    "origin",
    "status",
    "subject_cn",
    "issuer",
    "not_before",
    "not_after",
    "days_until_expiry",
    "serial_number",
    "sha256_fingerprint",
    "sans",
    "resolved_ip",
    "note",
]


def _record_to_row(record: CertificateRecord) -> dict:
    row = asdict(record)
    row["origin"] = record.origin.value
    row["status"] = record.status.value
    row["not_before"] = record.not_before.isoformat() if record.not_before else ""
    row["not_after"] = record.not_after.isoformat() if record.not_after else ""
    row["sans"] = ";".join(record.sans)
    return row


def to_csv(records: list[CertificateRecord]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=_FIELDS)
    writer.writeheader()
    for record in records:
        writer.writerow(_record_to_row(record))
    return buffer.getvalue()


def to_json(records: list[CertificateRecord]) -> str:
    rows = [_record_to_row(record) for record in records]
    for row in rows:
        row["sans"] = row["sans"].split(";") if row["sans"] else []
    return json.dumps(rows, indent=2, ensure_ascii=False)
