from __future__ import annotations

from fastapi import Cookie, HTTPException, status

from app.auth.sessions import session_store

SESSION_COOKIE_NAME = "certdisc_session"


def get_authenticated_username(session_token: str | None) -> str | None:
    """Não levanta exceção — usado pelo `main.py` para decidir qual página
    servir em `/` (auth.html vs index.html)."""
    if session_token is None:
        return None
    return session_store.peek(session_token)


async def require_session(
    certdisc_session: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> str:
    """Dependency do FastAPI: protege as rotas de scan. Retorna o username."""
    username = get_authenticated_username(certdisc_session)
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Autenticação necessária."
        )
    return username
