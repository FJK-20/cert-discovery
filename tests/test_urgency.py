from datetime import UTC, datetime, timedelta

from app.domain.models import Status
from app.domain.urgency import classify, renewal_priority

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def test_expired_when_in_the_past():
    status, days_left = classify(NOW - timedelta(days=1), now=NOW)
    assert status is Status.EXPIRED
    assert days_left < 0


def test_critical_under_seven_days():
    status, _ = classify(NOW + timedelta(days=3), now=NOW)
    assert status is Status.CRITICAL


def test_warning_under_thirty_days():
    status, _ = classify(NOW + timedelta(days=20), now=NOW)
    assert status is Status.WARNING


def test_ok_when_far_in_the_future():
    status, _ = classify(NOW + timedelta(days=90), now=NOW)
    assert status is Status.OK


def test_boundary_at_seven_days_is_warning_not_critical():
    status, _ = classify(NOW + timedelta(days=7), now=NOW)
    assert status is Status.WARNING


def test_renewal_priority_orders_expired_first():
    assert renewal_priority(Status.EXPIRED) < renewal_priority(Status.CRITICAL)
    assert renewal_priority(Status.CRITICAL) < renewal_priority(Status.WARNING)
    assert renewal_priority(Status.WARNING) < renewal_priority(Status.OK)
    assert renewal_priority(Status.OK) < renewal_priority(Status.CT_ONLY)
