"""Tokens em memória: sessão completa (pós-MFA) e login pendente (pós-senha,
antes do código MFA). Mesma filosofia já usada pelo job store: sem banco de
dados, processo único (`--workers 1`), TTL para não crescer indefinidamente.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass

from app.core.config import settings


@dataclass
class _TokenRecord:
    username: str
    expires_at: float


class TokenStore:
    def __init__(self, ttl_seconds: float) -> None:
        self._ttl = ttl_seconds
        self._tokens: dict[str, _TokenRecord] = {}

    def issue(self, username: str) -> str:
        token = secrets.token_urlsafe(32)
        self._tokens[token] = _TokenRecord(username=username, expires_at=time.time() + self._ttl)
        return token

    def peek(self, token: str) -> str | None:
        record = self._tokens.get(token)
        if record is None:
            return None
        if record.expires_at < time.time():
            self._tokens.pop(token, None)
            return None
        return record.username

    def revoke(self, token: str) -> None:
        self._tokens.pop(token, None)


# Sessão completa (pós-MFA): TTL longo. Login pendente (senha ok, aguardando
# código MFA): TTL curto — se abandonado, expira sozinho sem deixar rastro.
session_store = TokenStore(settings.session_ttl_seconds)
pending_login_store = TokenStore(settings.pending_login_ttl_seconds)
