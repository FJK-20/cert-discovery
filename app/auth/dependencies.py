from __future__ import annotations

from fastapi import Cookie, Depends, HTTPException, status

from app.auth.sessions import session_store
from app.auth.store import ROLE_ADMIN, user_store

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
    """Dependency do FastAPI: protege qualquer rota que exija estar logado
    (qualquer papel). Retorna o username."""
    username = get_authenticated_username(certdisc_session)
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Autenticação necessária."
        )
    return username


async def require_admin(username: str = Depends(require_session)) -> str:
    """Protege ações de escrita (emitir certificado, rodar scan, mudar
    configuração, gerenciar usuários) — papel `leitor` só tem acesso de
    leitura. Consulta o papel na hora (não guarda no token de sessão), pra
    uma promoção/rebaixamento valer no próximo request, não só no próximo
    login."""
    account = user_store.load(username)
    if account is None or account.role != ROLE_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Ação restrita a administradores."
        )
    return username
