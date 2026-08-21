"""Histórico persistente de tentativas de renovação (SQLite) — a "fila de
renovação com estado visível" da Fase 3 (regra de negócio 05: falha
notifica, não falha silenciosa; tem retry com backoff).

Cada `AcmeJob` (emissão manual pela tela de Emissão, ou renovação
disparada pelo scheduler) vira uma linha aqui: criada como `running`
quando o job começa, fechada como `done`/`failed` quando termina. É essa
tabela que o scheduler consulta pra decidir backoff/esgotamento
(`attempts_since_last_success`) e que a tela de Renovação lê pra mostrar
o histórico completo, não só a última mensagem."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from app.core.config import settings
from app.core.db import get_connection


class RenewalHistoryStore:
    def __init__(self, data_dir: Path) -> None:
        self._data_dir = data_dir

    def start(
        self,
        *,
        attempt_id: str,
        domain: str,
        environment: str,
        dns_mode: str | None,
        trigger: str,
        attempt_number: int,
    ) -> None:
        conn = get_connection(self._data_dir)
        try:
            conn.execute(
                """
                INSERT INTO renewal_attempts
                    (id, domain, environment, dns_mode, trigger_source, attempt_number,
                     state, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 'running', ?)
                """,
                (
                    attempt_id,
                    domain,
                    environment,
                    dns_mode,
                    trigger,
                    attempt_number,
                    datetime.now(UTC).isoformat(),
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def finish(
        self,
        attempt_id: str,
        *,
        state: str,
        error: str | None = None,
        certificate_id: str | None = None,
    ) -> None:
        conn = get_connection(self._data_dir)
        try:
            conn.execute(
                """
                UPDATE renewal_attempts
                SET state = ?, error = ?, certificate_id = ?, finished_at = ?
                WHERE id = ?
                """,
                (state, error, certificate_id, datetime.now(UTC).isoformat(), attempt_id),
            )
            conn.commit()
        finally:
            conn.close()

    def attempts_since_last_success(self, domain: str) -> list[dict]:
        """Tentativas mais recentes pra esse domínio, mais antiga primeiro —
        só as que vieram *depois* da última bem-sucedida (ou todas, se nunca
        teve uma). Isso é o que dá o "attempt N de M" e a base do backoff: a
        contagem zera assim que uma renovação dá certo."""
        conn = get_connection(self._data_dir)
        try:
            rows = conn.execute(
                "SELECT * FROM renewal_attempts WHERE domain = ? ORDER BY created_at DESC",
                (domain,),
            ).fetchall()
        finally:
            conn.close()

        attempts = []
        for row in rows:
            if row["state"] == "done":
                break
            attempts.append(dict(row))
        return list(reversed(attempts))

    def recent(self, limit: int = 30) -> list[dict]:
        conn = get_connection(self._data_dir)
        try:
            rows = conn.execute(
                "SELECT * FROM renewal_attempts ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        finally:
            conn.close()
        return [dict(row) for row in rows]


renewal_history = RenewalHistoryStore(Path(settings.data_dir))
