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

import sqlite3
from pathlib import Path

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
"""


def get_connection(data_dir: Path) -> sqlite3.Connection:
    """Toda chamada garante que o schema existe (`CREATE TABLE IF NOT
    EXISTS`, idempotente) — evita depender de alguém ter chamado
    `init_db()` primeiro (ex.: os testes instanciam os managers direto,
    sem passar pelo lifespan do FastAPI onde isso normalmente roda)."""
    data_dir.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(data_dir / "cert_discovery.sqlite3")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_SCHEMA)
    return conn


def init_db(data_dir: Path) -> None:
    get_connection(data_dir).close()
