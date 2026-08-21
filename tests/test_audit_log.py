"""Testa app/audit/log.py: log de auditoria append-only (SQLite). Cada
teste usa seu próprio tmp_path — nunca toca o data/ real do projeto."""

from __future__ import annotations

from app.audit.log import AuditLogStore


def test_record_and_recent_round_trip(tmp_path):
    store = AuditLogStore(tmp_path)
    store.record(username="admin", action="scan_started", detail="example.com")

    entries = store.recent()
    assert len(entries) == 1
    assert entries[0]["username"] == "admin"
    assert entries[0]["action"] == "scan_started"
    assert entries[0]["detail"] == "example.com"
    assert entries[0]["created_at"]


def test_record_accepts_none_username_for_system_actions(tmp_path):
    store = AuditLogStore(tmp_path)
    store.record(username=None, action="renewal_exhausted", detail="example.com")

    entries = store.recent()
    assert entries[0]["username"] is None


def test_recent_orders_newest_first(tmp_path):
    store = AuditLogStore(tmp_path)
    store.record(username="admin", action="first", detail="")
    store.record(username="admin", action="second", detail="")

    entries = store.recent()
    assert [e["action"] for e in entries] == ["second", "first"]


def test_recent_respects_limit(tmp_path):
    store = AuditLogStore(tmp_path)
    for i in range(5):
        store.record(username="admin", action=f"action-{i}", detail="")

    entries = store.recent(limit=2)
    assert len(entries) == 2
