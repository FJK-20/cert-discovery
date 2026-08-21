"""Log de auditoria append-only (SQLite) — "quem fez o quê, quando" da
Fase 4. Só cresce: a API nunca expõe update/delete, e o registro nunca
levanta exceção pro chamador (uma falha ao gravar auditoria não pode
derrubar a ação que estava sendo auditada — best-effort, mesmo espírito de
app/notify/notifier.py)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

from app.core.config import settings
from app.core.db import get_connection


class AuditLogStore:
    def __init__(self, data_dir: Path) -> None:
        self._data_dir = data_dir

    def record(self, *, username: str | None, action: str, detail: str = "") -> None:
        conn = get_connection(self._data_dir)
        try:
            conn.execute(
                "INSERT INTO audit_log (id, username, action, detail, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), username, action, detail, datetime.now(UTC).isoformat()),
            )
            conn.commit()
        except Exception:
            pass
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


audit_log = AuditLogStore(Path(settings.data_dir))
