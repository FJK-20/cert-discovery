import csv
import io
import json
from datetime import UTC, datetime

from app.domain.models import CertificateRecord, Origin, Status
from app.export.exporters import to_csv, to_json


def _record():
    return CertificateRecord(
        host="app.example.com",
        origin=Origin.LIVE,
        status=Status.WARNING,
        subject_cn="app.example.com",
        issuer="Example CA",
        not_before=datetime(2026, 1, 1, tzinfo=UTC),
        not_after=datetime(2026, 2, 1, tzinfo=UTC),
        days_until_expiry=20,
        serial_number="abc123",
        sha256_fingerprint="deadbeef",
        sans=["app.example.com", "www.example.com"],
        resolved_ip="203.0.113.5",
    )


def test_to_csv_contains_header_and_row():
    output = to_csv([_record()])
    lines = output.strip().splitlines()
    assert lines[0].startswith("host,")
    assert "app.example.com" in lines[1]
    assert "warning" in lines[1]


def test_to_json_round_trips_sans_as_list():
    output = to_json([_record()])
    parsed = json.loads(output)
    assert parsed[0]["host"] == "app.example.com"
    assert parsed[0]["sans"] == ["app.example.com", "www.example.com"]
    assert parsed[0]["status"] == "warning"


def test_to_csv_neutralizes_formula_injection_in_certificate_fields():
    """Achado numa auditoria de robustez: subject_cn/issuer/sans vêm do
    certificado servido pelo host sondado, que pode ser qualquer coisa —
    um CN começando com =, +, -, @ é interpretado como fórmula por
    Excel/LibreOffice/Google Sheets ao abrir o CSV exportado."""
    malicious = CertificateRecord(
        host="app.example.com",
        origin=Origin.LIVE,
        status=Status.OK,
        subject_cn="=HYPERLINK(\"http://evil\")",
        issuer="+1+1",
        not_before=None,
        not_after=None,
        days_until_expiry=None,
        serial_number=None,
        sha256_fingerprint=None,
        sans=["-2+3+cmd", "safe.example.com"],
        resolved_ip=None,
    )
    output = to_csv([malicious])
    reader = csv.DictReader(io.StringIO(output))
    row = next(reader)
    assert row["subject_cn"].startswith("'=")
    assert row["issuer"] == "'+1+1"
    # só o INÍCIO da célula importa pra interpretação como fórmula — o
    # valor de sans já vem concatenado (";".join) antes da sanitização,
    # então um prefixo perigoso só no meio da célula não é perigo real.
    assert row["sans"] == "'-2+3+cmd;safe.example.com"


def test_to_csv_leaves_normal_fields_untouched():
    output = to_csv([_record()])
    lines = output.strip().splitlines()
    assert not lines[1].startswith("'")
    assert "app.example.com" in lines[1]
