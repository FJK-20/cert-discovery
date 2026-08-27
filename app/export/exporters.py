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


# Achado numa auditoria de robustez: subject_cn, issuer e sans vêm do
# certificado servido pelo host sondado — e a sonda aceita qualquer
# certificado por desenho (é o propósito: capturar mesmo um autoassinado/
# inválido pra reportar depois). Um CN começando com um destes caracteres
# é interpretado como fórmula por Excel/LibreOffice/Google Sheets ao abrir
# o CSV exportado (CSV injection) — no computador do analista, não no
# servidor. Mitigação padrão OWASP: prefixo de aspas simples força
# interpretação como texto.
_DANGEROUS_CSV_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _sanitize_csv_cell(value: object) -> object:
    if isinstance(value, str) and value.startswith(_DANGEROUS_CSV_PREFIXES):
        return "'" + value
    return value


def to_csv(records: list[CertificateRecord]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=_FIELDS)
    writer.writeheader()
    for record in records:
        row = {key: _sanitize_csv_cell(value) for key, value in _record_to_row(record).items()}
        writer.writerow(row)
    return buffer.getvalue()


def to_json(records: list[CertificateRecord]) -> str:
    rows = [_record_to_row(record) for record in records]
    for row in rows:
        row["sans"] = row["sans"].split(";") if row["sans"] else []
    return json.dumps(rows, indent=2, ensure_ascii=False)
