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
import hmac
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from app.core import crypto

# Mesma fórmula de app/audit/log.py — duplicada aqui (não importada) pra
# não criar um ciclo (audit/log.py importa deste módulo, não o contrário).
_AUDIT_GENESIS_HASH = "0" * 64


def _compute_audit_hash(
    key: bytes,
    prev_hash: str,
    entry_id: str,
    username: str | None,
    action: str,
    detail: str,
    created_at: str,
) -> str:
    payload = "|".join([prev_hash, entry_id, username or "", action, detail, created_at])
    return hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()

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

-- Cadastros (Fase 8) — dimensões de contexto pra emissão/importação de
-- certificado (organização, sistema, projeto responsáveis). Organização
-- tem campos próprios (endereço/contato); sistema e projeto são
-- deliberadamente idênticos em formato (nome+descrição+status) — no
-- produto real que inspirou isso os dois já eram só listas nomeadas
-- simples, não cadastros ricos — mas cada um com sua própria tabela
-- (não um discriminador numa tabela só), pra ter identidade e namespace
-- de id próprios como qualquer cadastro de verdade.
CREATE TABLE IF NOT EXISTS organizations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    unit TEXT NOT NULL DEFAULT '',
    city TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT '',
    country TEXT NOT NULL DEFAULT '',
    phone TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    created_by TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_organizations_name ON organizations(name);

CREATE TABLE IF NOT EXISTS systems (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    created_by TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_systems_name ON systems(name);

CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    created_by TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_projects_name ON projects(name);

-- Migrações de schema já aplicadas — deliberadamente separada de
-- audit_log: o gatilho de rodar (ou não) uma migração precisa ser um
-- metadado da própria aplicação, nunca uma coluna de uma tabela de dados
-- que quem tem escrita no arquivo (o mesmo adversário que a cadeia de
-- hashes existe pra detectar) poderia manipular pra forçar uma
-- re-execução. Ver _AUDIT_CHAIN_MIGRATION abaixo.
CREATE TABLE IF NOT EXISTS schema_migrations (
    name TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL
);
"""

# Colunas adicionadas depois da criação inicial da tabela — `CREATE TABLE
# IF NOT EXISTS` não altera uma tabela já existente, então uma tabela
# `audit_log` de antes da cadeia de hashes (Fase 5) precisa dessas duas
# colunas adicionadas manualmente. Checagem via PRAGMA (idempotente, sem
# levantar erro se a coluna já existir).
_MIGRATIONS = {
    "audit_log": ["prev_hash TEXT NOT NULL DEFAULT ''", "entry_hash TEXT NOT NULL DEFAULT ''"],
}


# Achado numa auditoria de robustez: a versão anterior deste backfill era
# disparada por uma condição sobre o PRÓPRIO DADO (`entry_hash = ''`) e
# rodava em toda `get_connection()` — incluindo a que `verify_chain()`
# abre. Isso deixava quem tem escrita no arquivo (o mesmo adversário que a
# cadeia existe pra detectar) reabrir o buraco: bastava zerar o
# `entry_hash` de UMA linha qualquer (inclusive uma que já tinha sido
# adulterada) que a aplicação recalculava a cadeia inteira por cima do log
# já falsificado, e `verify_chain()` voltava a atestar "íntegro". A própria
# rotina de correção virou o vetor de ataque.
#
# O gatilho agora é a tabela `schema_migrations` (metadado da aplicação,
# nunca uma coluna de `audit_log`) — roda no máximo uma vez por banco,
# nunca de novo depois disso, e nenhum valor gravável em `audit_log` pelo
# adversário consegue re-acioná-la.
_AUDIT_CHAIN_MIGRATION = "audit_log_hmac_chain_v1"


def _migration_applied(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute("SELECT 1 FROM schema_migrations WHERE name = ?", (name,)).fetchone()
    return row is not None


def _mark_migration_applied(conn: sqlite3.Connection, name: str) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO schema_migrations (name, applied_at) VALUES (?, ?)",
        (name, datetime.now(UTC).isoformat()),
    )


def _rebuild_audit_chain(conn: sqlite3.Connection, hmac_key: bytes) -> None:
    """Recalcula a cadeia inteira do zero com HMAC-SHA256 (chave: master
    key de app/core/crypto.py) — cobre ao mesmo tempo linhas de antes da
    cadeia existir (Fase 4, prev_hash/entry_hash vazios) e linhas já
    encadeadas com SHA-256 puro (antes desta migração), porque as duas
    viram a mesma baseline HMAC daqui em diante. Também eleva a barra do
    achado anterior: recomputar a cadeia por fora da aplicação agora exige
    a master key, não só os dados da própria tabela."""
    rows = conn.execute("SELECT * FROM audit_log ORDER BY created_at ASC, rowid ASC").fetchall()
    running_prev = _AUDIT_GENESIS_HASH
    for row in rows:
        entry_hash = _compute_audit_hash(
            hmac_key, running_prev, row["id"], row["username"], row["action"], row["detail"],
            row["created_at"],
        )
        conn.execute(
            "UPDATE audit_log SET prev_hash = ?, entry_hash = ? WHERE id = ?",
            (running_prev, entry_hash, row["id"]),
        )
        running_prev = entry_hash
    conn.commit()


def _run_migrations(conn: sqlite3.Connection, data_dir: Path) -> None:
    for table, column_defs in _MIGRATIONS.items():
        existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
        for column_def in column_defs:
            column_name = column_def.split()[0]
            if column_name not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column_def}")
    conn.commit()

    if not _migration_applied(conn, _AUDIT_CHAIN_MIGRATION):
        _rebuild_audit_chain(conn, crypto.load_master_key(data_dir))
        _mark_migration_applied(conn, _AUDIT_CHAIN_MIGRATION)
        conn.commit()


def get_connection(data_dir: Path, *, apply_migrations: bool = True) -> sqlite3.Connection:
    """Toda chamada garante que o schema existe (`CREATE TABLE IF NOT
    EXISTS`, idempotente) — evita depender de alguém ter chamado
    `init_db()` primeiro (ex.: os testes instanciam os managers direto,
    sem passar pelo lifespan do FastAPI onde isso normalmente roda).

    `apply_migrations=False` abre a conexão sem rodar nenhuma migração —
    defesa em profundidade além do fix acima: o caminho de só-leitura
    (`verify_chain()`) nunca deveria ter motivo pra escrever no banco."""
    data_dir.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(data_dir / "cert_discovery.sqlite3")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.executescript(_SCHEMA)
    if apply_migrations:
        _run_migrations(conn, data_dir)
    return conn


def init_db(data_dir: Path) -> None:
    get_connection(data_dir).close()
