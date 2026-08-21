"""Banco embutido (stdlib `sqlite3`, sem serviço externo) pra histórico que
precisa sobreviver a um restart: scans passados e tentativas de renovação.

Certificados/credenciais continuam em arquivos JSON (app/acme/store.py) —
já são persistentes desde a Fase 2, não precisam de SQLite pra isso. O que
faltava era exatamente o que mora aqui: o `ScanJobManager` e o
`AcmeRenewalManager` guardavam job em memória pura, perdido a cada restart.

Uma conexão nova por operação (não uma global compartilhada) — mais simples
e evita lidar com `sqlite3`'s regra de uma conexão por thread numa app que
mistura asyncio com threads (emissão ACME roda em `asyncio.to_thread`).
Volume baixo o suficiente (histórico de scans/renovações, não uma rota
quente) pra isso não ser gargalo.

`get_connection()` recebe `data_dir` explícito (não lê `settings` direto) —
mesmo padrão de `AcmeStore`/`NotificationStore`: quem guarda o estado
default é o singleton lá em cima do módulo dono, os testes injetam um
`tmp_path` próprio em vez de escrever no `data/` real do projeto."""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

# Mesma fórmula de app/audit/log.py — duplicada aqui (não importada) pra
# não criar um ciclo (audit/log.py importa deste módulo, não o contrário).
_AUDIT_GENESIS_HASH = "0" * 64


def _compute_audit_hash(
    prev_hash: str, entry_id: str, username: str | None, action: str, detail: str, created_at: str
) -> str:
    payload = "|".join([prev_hash, entry_id, username or "", action, detail, created_at])
    return hashlib.sha256(payload.encode()).hexdigest()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_jobs (
    id TEXT PRIMARY KEY,
    domain TEXT NOT NULL,
    state TEXT NOT NULL,
    progress_message TEXT NOT NULL DEFAULT '',
    hosts_total INTEGER NOT NULL DEFAULT 0,
    hosts_done INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    created_at TEXT NOT NULL,
    records_json TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_created_at ON scan_jobs(created_at);

CREATE TABLE IF NOT EXISTS renewal_attempts (
    id TEXT PRIMARY KEY,
    domain TEXT NOT NULL,
    environment TEXT NOT NULL,
    dns_mode TEXT,
    trigger_source TEXT NOT NULL,
    attempt_number INTEGER NOT NULL,
    state TEXT NOT NULL,
    error TEXT,
    certificate_id TEXT,
    created_at TEXT NOT NULL,
    finished_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_renewal_attempts_domain ON renewal_attempts(domain);
CREATE INDEX IF NOT EXISTS idx_renewal_attempts_created_at ON renewal_attempts(created_at);

CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    username TEXT,
    action TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    prev_hash TEXT NOT NULL DEFAULT '',
    entry_hash TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);

CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    created_by TEXT,
    created_at TEXT NOT NULL,
    last_used_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);
"""

# Colunas adicionadas depois da criação inicial da tabela — `CREATE TABLE
# IF NOT EXISTS` não altera uma tabela já existente, então uma tabela
# `audit_log` de antes da cadeia de hashes (Fase 5) precisa dessas duas
# colunas adicionadas manualmente. Checagem via PRAGMA (idempotente, sem
# levantar erro se a coluna já existir).
_MIGRATIONS = {
    "audit_log": ["prev_hash TEXT NOT NULL DEFAULT ''", "entry_hash TEXT NOT NULL DEFAULT ''"],
}


def _backfill_audit_log_hashes(conn: sqlite3.Connection) -> None:
    """Linhas gravadas antes da cadeia de hashes existir (Fase 5) ganharam
    `prev_hash`/`entry_hash` vazios só pelo ALTER TABLE (DEFAULT '') — sem
    corrigir, `verify_chain()` marcaria a linha legada como "adulterada"
    só por não ter um hash de verdade, e pior: `record()` teria lido esse
    `entry_hash` vazio como se fosse um hash válido pra encadear a
    primeira linha nova em cima dele (em vez do genesis), corrompendo a
    cadeia a partir dali também.

    Por isso não é um backfill pontual só das linhas vazias — se **qualquer**
    linha tem hash vazio, a tabela inteira é recalculada do zero em ordem
    cronológica a partir do genesis. É idempotente (uma tabela já correta
    não tem `entry_hash = ''` em lugar nenhum, então isso não roda de
    novo) e barato (log de auditoria não é uma tabela de alto volume)."""
    has_blank = conn.execute("SELECT 1 FROM audit_log WHERE entry_hash = '' LIMIT 1").fetchone()
    if not has_blank:
        return

    rows = conn.execute("SELECT * FROM audit_log ORDER BY created_at ASC, rowid ASC").fetchall()
    running_prev = _AUDIT_GENESIS_HASH
    for row in rows:
        entry_hash = _compute_audit_hash(
            running_prev, row["id"], row["username"], row["action"], row["detail"],
            row["created_at"],
        )
        conn.execute(
            "UPDATE audit_log SET prev_hash = ?, entry_hash = ? WHERE id = ?",
            (running_prev, entry_hash, row["id"]),
        )
        running_prev = entry_hash
    conn.commit()


def _run_migrations(conn: sqlite3.Connection) -> None:
    for table, column_defs in _MIGRATIONS.items():
        existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
        for column_def in column_defs:
            column_name = column_def.split()[0]
            if column_name not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column_def}")
    conn.commit()
    _backfill_audit_log_hashes(conn)


def get_connection(data_dir: Path) -> sqlite3.Connection:
    """Toda chamada garante que o schema existe (`CREATE TABLE IF NOT
    EXISTS`, idempotente) — evita depender de alguém ter chamado
    `init_db()` primeiro (ex.: os testes instanciam os managers direto,
    sem passar pelo lifespan do FastAPI onde isso normalmente roda)."""
    data_dir.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(data_dir / "cert_discovery.sqlite3")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.executescript(_SCHEMA)
    _run_migrations(conn)
    return conn


def init_db(data_dir: Path) -> None:
    get_connection(data_dir).close()
