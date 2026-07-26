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
