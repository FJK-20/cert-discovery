"""Log de auditoria append-only (SQLite) com cadeia de hashes — "quem fez
o quê, quando" da Fase 4, endurecido na Fase 5 pra ser genuinamente
**tamper-evident**: cada linha guarda o hash da linha anterior mais o
próprio (`prev_hash`/`entry_hash`), então qualquer edição ou remoção de uma
linha antiga — inclusive mexendo direto no arquivo SQLite, por fora da API
— quebra a cadeia a partir daquele ponto, detectável por `verify_chain()`
sem precisar de infraestrutura externa (WORM storage, blockchain, etc.).

Isso não impede alguém com acesso de escrita ao arquivo de *recalcular* a
cadeia inteira depois de adulterar uma linha (não é um substituto de
controle de acesso ao disco) — é uma detecção de violação de integridade,
não uma prevenção. Combinado com permissão 0600 no arquivo e rodando num
único processo, cobre o caso realista de "alguém tentou editar uma linha
sem recalcular tudo depois dela".

Registro nunca levanta exceção pro chamador (uma falha ao gravar auditoria
não pode derrubar a ação que estava sendo auditada — best-effort, mesmo
espírito de app/notify/notifier.py)."""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from pathlib import Path

from app.core.config import settings
from app.core.db import get_connection

_GENESIS_HASH = "0" * 64


def _compute_hash(
    prev_hash: str, entry_id: str, username: str | None, action: str, detail: str, created_at: str
) -> str:
    payload = "|".join([prev_hash, entry_id, username or "", action, detail, created_at])
    return hashlib.sha256(payload.encode()).hexdigest()


class AuditLogStore:
    def __init__(self, data_dir: Path) -> None:
        self._data_dir = data_dir

    def record(self, *, username: str | None, action: str, detail: str = "") -> None:
        conn = get_connection(self._data_dir)
        try:
            # BEGIN IMMEDIATE trava escrita já na abertura da transação —
            # sem isso, duas gravações concorrentes (a emissão ACME roda
            # em thread separada via asyncio.to_thread) poderiam ler o
            # mesmo prev_hash e "bifurcar" a cadeia.
            conn.execute("BEGIN IMMEDIATE")
            last = conn.execute(
                "SELECT entry_hash FROM audit_log ORDER BY created_at DESC, rowid DESC LIMIT 1"
            ).fetchone()
            # `entry_hash` vazio (não NULL) é o retrato de uma linha
            # legada de antes da cadeia existir — a migração em
            # app/core/db.py já devia ter corrigido isso antes desta
            # chamada, mas tratar como "sem linha anterior" aqui também
            # é defesa em profundidade: nunca encadear em cima de um hash
            # vazio como se fosse válido.
            prev_hash = last["entry_hash"] if last and last["entry_hash"] else _GENESIS_HASH
            entry_id = str(uuid.uuid4())
            created_at = datetime.now(UTC).isoformat()
            entry_hash = _compute_hash(prev_hash, entry_id, username, action, detail, created_at)
            conn.execute(
                "INSERT INTO audit_log "
                "(id, username, action, detail, created_at, prev_hash, entry_hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (entry_id, username, action, detail, created_at, prev_hash, entry_hash),
            )
            conn.commit()
        except Exception:
            conn.rollback()
        finally:
            conn.close()

    def recent(self, limit: int = 100) -> list[dict]:
        conn = get_connection(self._data_dir)
        try:
            rows = conn.execute(
                "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        finally:
            conn.close()
        return [dict(row) for row in rows]

    def verify_chain(self) -> tuple[bool, str | None]:
        """Percorre a cadeia inteira em ordem cronológica recomputando
        cada hash. Devolve (True, None) se intacta, ou (False, id da
        primeira linha que não bate) se algo foi adulterado."""
        conn = get_connection(self._data_dir)
        try:
            rows = conn.execute(
                "SELECT * FROM audit_log ORDER BY created_at ASC, rowid ASC"
            ).fetchall()
        finally:
            conn.close()

        expected_prev = _GENESIS_HASH
        for row in rows:
            recomputed = _compute_hash(
                expected_prev, row["id"], row["username"], row["action"], row["detail"],
                row["created_at"],
            )
            if row["prev_hash"] != expected_prev or row["entry_hash"] != recomputed:
                return False, row["id"]
            expected_prev = row["entry_hash"]
        return True, None


audit_log = AuditLogStore(Path(settings.data_dir))
