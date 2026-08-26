from __future__ import annotations

from fastapi import Cookie, Depends, Header, HTTPException, Request, status

from app.auth.api_keys import api_key_store
from app.auth.sessions import session_store
from app.auth.store import ROLE_ADMIN, ROLE_AUDITOR, ROLE_OPERADOR, user_store
from app.core.config import settings

SESSION_COOKIE_NAME = "certdisc_session"
_API_KEY_IDENTITY_PREFIX = "apikey:"


def cookie_should_be_secure(request: Request) -> bool:
    """`settings.cookie_secure` é uma decisão de deploy única (liga pra
    todo cookie ou pra nenhum) — não dá pra ligar globalmente numa
    instância que também serve HTTP puro na LAN além de HTTPS público
    (ver README, seção de segurança). Mas se ESTA requisição em particular
    já chegou por HTTPS — direto, ou atrás de um proxy/túnel que anuncia
    isso via `X-Forwarded-Proto` (caso do Cloudflare Tunnel) — marcar o
    cookie como `Secure` só melhora a postura, nunca piora: na pior
    hipótese o cabeçalho está errado e o navegador rejeita o cookie."""
    if settings.cookie_secure:
        return True
    if request.url.scheme == "https":
        return True
    return request.headers.get("x-forwarded-proto", "").lower() == "https"


def get_authenticated_username(session_token: str | None) -> str | None:
    """Não levanta exceção — usado pelo `main.py` para decidir qual página
    servir em `/` (auth.html vs index.html)."""
    if session_token is None:
        return None
    return session_store.peek(session_token)


async def require_session(
    certdisc_session: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
    authorization: str | None = Header(default=None),
) -> str:
    """Dependency do FastAPI: protege qualquer rota que exija estar logado
    (qualquer papel). Aceita sessão de cookie (uso pela própria interface)
    ou `Authorization: Bearer <api key>` (acesso programático — ver
    app/auth/api_keys.py). Retorna a identidade: o username de verdade pra
    sessão de cookie, ou `apikey:<id>` pra uma chave — `_require_role`
    abaixo sabe resolver o papel dos dois formatos."""
    username = get_authenticated_username(certdisc_session)
    if username is not None:
        return username

    if authorization and authorization.startswith("Bearer "):
        raw_key = authorization.removeprefix("Bearer ").strip()
        info = api_key_store.authenticate(raw_key)
        if info is not None:
            return f"{_API_KEY_IDENTITY_PREFIX}{info.id}"

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Autenticação necessária.")


def _resolve_role(identity: str) -> str | None:
    if identity.startswith(_API_KEY_IDENTITY_PREFIX):
        key_id = identity.removeprefix(_API_KEY_IDENTITY_PREFIX)
        info = api_key_store.get(key_id)
        return info.role if info else None
    account = user_store.load(identity)
    return account.role if account else None


def _require_role(*allowed_roles: str):
    """Fábrica de dependency: só deixa passar quem está num dos papéis
    permitidos. Consulta o papel na hora (não guarda no token de sessão),
    pra uma promoção/rebaixamento — ou revogação de API key — valer no
    próximo request, não só no próximo login."""

    async def dependency(username: str = Depends(require_session)) -> str:
        role = _resolve_role(username)
        if role is None or role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Ação não permitida para o seu papel de acesso.",
            )
        return username

    return dependency


# Gerenciar usuários, API keys e configuração sensível do sistema
# (credencial de DNS, canais de notificação) — só admin.
require_admin = _require_role(ROLE_ADMIN)

# Ciclo de vida de certificado no dia a dia (scan, emissão, renovação, CSR,
# baixar chave privada) — admin ou operador.
require_operator = _require_role(ROLE_ADMIN, ROLE_OPERADOR)

# Enxergar o log de auditoria e a lista de usuários (só leitura, fins de
# compliance) — admin ou auditor. Operador e leitor não têm essa visão por
# desenho: segregação de funções, quem opera não é quem audita.
require_auditor = _require_role(ROLE_ADMIN, ROLE_AUDITOR)
