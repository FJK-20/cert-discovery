from app.domain.inventory import build_inventory, renewal_queue
from app.domain.models import CertificateRecord, Origin, Status


def _live(host, status, fingerprint, days=None):
    return CertificateRecord(
        host=host,
        origin=Origin.LIVE,
        status=status,
        sha256_fingerprint=fingerprint,
        days_until_expiry=days,
    )


def test_dedupe_by_fingerprint_merges_hosts():
    records = [
        _live("a.example.com", Status.OK, "abc123", days=100),
        _live("b.example.com", Status.OK, "abc123", days=100),
    ]
    inventory = build_inventory(records)
    assert len(inventory) == 1
    assert "b.example.com" in (inventory[0].note or "")


def test_ct_only_records_are_never_deduped_by_fingerprint():
    records = [
        CertificateRecord(host="a.example.com", origin=Origin.CT_LOG, status=Status.UNRESOLVED),
        CertificateRecord(host="b.example.com", origin=Origin.CT_LOG, status=Status.UNRESOLVED),
    ]
    inventory = build_inventory(records)
    assert len(inventory) == 2


def test_build_inventory_orders_by_urgency():
    records = [
        _live("ok.example.com", Status.OK, "f1", days=200),
        _live("expired.example.com", Status.EXPIRED, "f2", days=-5),
        _live("critical.example.com", Status.CRITICAL, "f3", days=2),
    ]
    inventory = build_inventory(records)
    assert [r.host for r in inventory] == [
        "expired.example.com",
        "critical.example.com",
        "ok.example.com",
    ]


def test_renewal_queue_excludes_ok_and_ct_only():
    records = [
        _live("ok.example.com", Status.OK, "f1", days=200),
        _live("critical.example.com", Status.CRITICAL, "f2", days=2),
        CertificateRecord(host="ct.example.com", origin=Origin.CT_LOG, status=Status.CT_ONLY),
    ]
    queue = renewal_queue(records)
    assert [r.host for r in queue] == ["critical.example.com"]
