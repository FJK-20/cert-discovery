"""Testa app/audit/log.py: log de auditoria append-only (SQLite). Cada
teste usa seu próprio tmp_path — nunca toca o data/ real do projeto."""

from __future__ import annotations

from app.audit.log import AuditLogStore
from app.core.db import get_connection


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


def test_verify_chain_ok_when_untouched(tmp_path):
    store = AuditLogStore(tmp_path)
    for i in range(5):
        store.record(username="admin", action=f"action-{i}", detail="")

    ok, broken_at = store.verify_chain()
    assert ok is True
    assert broken_at is None


def test_verify_chain_empty_log_is_valid(tmp_path):
    store = AuditLogStore(tmp_path)
    ok, broken_at = store.verify_chain()
    assert ok is True
    assert broken_at is None


def test_verify_chain_detects_tampered_detail(tmp_path):
    store = AuditLogStore(tmp_path)
    store.record(username="admin", action="user_created", detail="original")
    store.record(username="admin", action="user_deleted", detail="original")

    conn = get_connection(tmp_path)
    conn.execute("UPDATE audit_log SET detail = 'adulterado' WHERE action = 'user_created'")
    conn.commit()
    conn.close()

    ok, broken_at = store.verify_chain()
    assert ok is False
    assert broken_at is not None


def test_verify_chain_detects_deleted_row(tmp_path):
    store = AuditLogStore(tmp_path)
    store.record(username="admin", action="first", detail="")
    store.record(username="admin", action="second", detail="")
    store.record(username="admin", action="third", detail="")

    conn = get_connection(tmp_path)
    conn.execute("DELETE FROM audit_log WHERE action = 'second'")
    conn.commit()
    conn.close()

    ok, broken_at = store.verify_chain()
    assert ok is False


def test_hash_chain_links_consecutive_entries(tmp_path):
    store = AuditLogStore(tmp_path)
    store.record(username="admin", action="first", detail="")
    store.record(username="admin", action="second", detail="")

    entries = sorted(store.recent(), key=lambda e: e["created_at"])
    assert entries[1]["prev_hash"] == entries[0]["entry_hash"]
    assert entries[0]["prev_hash"] == "0" * 64


def test_legacy_row_without_hash_gets_backfilled_and_chain_stays_valid(tmp_path):
    """Reproduz o estado real encontrado em produção: uma linha gravada
    antes da cadeia de hashes existir (Fase 4) tem prev_hash/entry_hash
    vazios (DEFAULT '' do ALTER TABLE) — sem o backfill em app/core/db.py,
    a primeira linha NOVA encadeava em cima desse '' como se fosse um
    hash válido, corrompendo a cadeia a partir dali.

    `apply_migrations=False` aqui é deliberado: a migração da cadeia de
    hashes (schema_migrations-gated) só deve rodar na primeira conexão
    REAL depois que a linha legada já existe — abrir com a migração
    ligada neste setup marcaria "já migrado" sobre uma tabela ainda vazia,
    e a inserção manual logo abaixo nunca seria corrigida (não é assim
    que uma migração real de produção aconteceria: a linha legada já
    estaria lá antes de o código novo rodar pela primeira vez)."""
    conn = get_connection(tmp_path, apply_migrations=False)
    conn.execute(
        "INSERT INTO audit_log (id, username, action, detail, created_at, prev_hash, entry_hash) "
        "VALUES ('legacy-1', 'admin', 'scan_started', 'example.com', '2026-01-01T00:00:00+00:00', "
        "'', '')"
    )
    conn.commit()
    conn.close()

    # primeira chamada real no store aciona get_connection() -> migração
    # -> backfill, exatamente como aconteceria num restart real depois do
    # deploy da Fase 5
    store = AuditLogStore(tmp_path)
    store.record(username="admin", action="user_created", detail="viewer")

    ok, broken_at = store.verify_chain()
    assert ok is True, f"cadeia deveria estar íntegra, quebrou em {broken_at}"

    entries = sorted(store.recent(), key=lambda e: e["created_at"])
    assert entries[0]["id"] == "legacy-1"
    assert entries[0]["prev_hash"] == "0" * 64
    assert entries[0]["entry_hash"] != ""
    assert entries[1]["prev_hash"] == entries[0]["entry_hash"]


def test_zeroing_entry_hash_does_not_erase_tampering_evidence(tmp_path):
    """Achado numa auditoria de robustez (GitSec Analyzer): a versão
    anterior do backfill era disparada por `entry_hash = ''` — um valor
    que qualquer um com escrita no arquivo SQLite podia gravar. Isso
    deixava o próprio mecanismo de correção virar vetor de ataque: depois
    de adulterar uma linha (o que `verify_chain()` já detectava
    corretamente), bastava zerar o `entry_hash` de qualquer linha —
    inclusive a adulterada — que a aplicação recalculava a cadeia inteira
    por cima do log já falsificado na PRÓXIMA conexão, e `verify_chain()`
    voltava a atestar "íntegro". Este teste reproduz exatamente esse
    ataque e confirma que a migração agora versionada (schema_migrations)
    não é mais re-acionável por um valor gravável em `audit_log`."""
    store = AuditLogStore(tmp_path)
    store.record(username="admin", action="user_created", detail="original")
    store.record(username="admin", action="dns_credentials_saved", detail="cloudflare")
    store.record(username="admin", action="login", detail="admin")

    ok, _ = store.verify_chain()
    assert ok is True

    conn = get_connection(tmp_path)
    # Adultera a linha do meio, exatamente como o relatório reproduziu.
    conn.execute(
        "UPDATE audit_log SET detail = 'adulterado' WHERE action = 'dns_credentials_saved'"
    )
    conn.commit()

    ok, broken_at = store.verify_chain()
    assert ok is False, "a adulteração precisa ser detectada antes do ataque"

    # Tenta reabrir o buraco: zera o entry_hash da própria linha
    # adulterada, como o PoC do relatório fazia.
    conn.execute(
        "UPDATE audit_log SET entry_hash = '' WHERE action = 'dns_credentials_saved'"
    )
    conn.commit()
    conn.close()

    ok, broken_at = store.verify_chain()
    assert ok is False, (
        "zerar um entry_hash não pode fazer a aplicação recalcular a cadeia "
        "por cima do log adulterado — a migração é versionada, não roda de novo"
    )
