"""API keys com escopo — autenticação alternativa à sessão de cookie, pra
acesso programático (integração externa, scripts, um SIEM puxando o log
de auditoria via API em vez de olhar a tela). A chave nunca é guardada em
texto puro (só o hash SHA-256) nem reexibida depois de criada — perdeu,
revoga e cria outra (é essa a "rotação": revogar a antiga, gerar uma
nova, sem downtime se a nova for criada antes de revogar a velha).

SHA-256 simples (não scrypt) de propósito: diferente de senha escolhida
por humano, a chave já nasce com entropia alta (256 bits aleatórios via
`secrets.token_urlsafe`) — não precisa de hash lento pra resistir a força
bruta, e autenticação por API key pode estar no caminho quente de
integrações externas chamando com frequência."""

from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from app.core.config import settings
from app.core.db import get_connection

_KEY_PREFIX = "certdisc_"


def _hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


@dataclass
class ApiKeyInfo:
    id: str
    name: str
    role: str
    created_by: str | None
    created_at: str
    last_used_at: str | None


class ApiKeyStore:
    def __init__(self, data_dir: Path) -> None:
        self._data_dir = data_dir

    def create(self, *, name: str, role: str, created_by: str | None) -> tuple[str, str]:
        """Devolve (id, chave em texto puro) — a chave só existe nesta
        chamada, nunca mais (nem o próprio admin que criou consegue ver de
        novo depois, só o hash fica guardado)."""
        key_id = str(uuid.uuid4())
        raw_key = _KEY_PREFIX + secrets.token_urlsafe(32)
        conn = get_connection(self._data_dir)
        try:
            conn.execute(
                "INSERT INTO api_keys (id, name, key_hash, role, created_by, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (key_id, name, _hash_key(raw_key), role, created_by, datetime.now(UTC).isoformat()),
            )
            conn.commit()
        finally:
            conn.close()
        return key_id, raw_key

    def _row_to_info(self, row) -> ApiKeyInfo:
        return ApiKeyInfo(
            id=row["id"],
            name=row["name"],
            role=row["role"],
            created_by=row["created_by"],
            created_at=row["created_at"],
            last_used_at=row["last_used_at"],
        )

    def authenticate(self, raw_key: str) -> ApiKeyInfo | None:
        """Valida a chave e atualiza `last_used_at`. Devolve None se
        inválida, com formato errado, ou já revogada."""
        if not raw_key.startswith(_KEY_PREFIX):
            return None
        conn = get_connection(self._data_dir)
        try:
            row = conn.execute(
                "SELECT * FROM api_keys WHERE key_hash = ?", (_hash_key(raw_key),)
            ).fetchone()
            if row is None:
                return None
            conn.execute(
                "UPDATE api_keys SET last_used_at = ? WHERE id = ?",
                (datetime.now(UTC).isoformat(), row["id"]),
            )
            conn.commit()
        finally:
            conn.close()
        return self._row_to_info(row)

    def get(self, key_id: str) -> ApiKeyInfo | None:
        conn = get_connection(self._data_dir)
        try:
            row = conn.execute("SELECT * FROM api_keys WHERE id = ?", (key_id,)).fetchone()
        finally:
            conn.close()
        return self._row_to_info(row) if row else None

    def list_all(self) -> list[ApiKeyInfo]:
        conn = get_connection(self._data_dir)
        try:
            rows = conn.execute("SELECT * FROM api_keys ORDER BY created_at DESC").fetchall()
        finally:
            conn.close()
        return [self._row_to_info(row) for row in rows]

    def revoke(self, key_id: str) -> None:
        conn = get_connection(self._data_dir)
        try:
            conn.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))
            conn.commit()
        finally:
            conn.close()


api_key_store = ApiKeyStore(Path(settings.data_dir))
