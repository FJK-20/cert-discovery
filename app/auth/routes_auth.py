"""Cadastro do primeiro admin (usuário + senha) com MFA opcional, ativável a
qualquer momento por cada usuário pra si mesmo, e login em uma ou duas
etapas dependendo se o MFA está ligado. A partir do segundo usuário em
diante, só um admin já autenticado pode criar novas contas — não existe
autocadastro aberto (ver `/users` abaixo).

Estados possíveis (calculados a partir do arquivo de usuários + cookie de
sessão, nunca guardados à parte): `needs_setup` (nenhum usuário cadastrado
ainda — primeiro acesso), `needs_login` e `authenticated`. Ativar/desativar
MFA acontece só depois de autenticado (ver rotas `/mfa/*` abaixo), não faz
parte desse cálculo de estado — por isso um cadastro recém-criado já cai
direto em `authenticated`, sem etapa intermediária forçada.

Quatro papéis (`app/auth/store.py`): `admin` (acesso completo, incluindo
gerenciar outros usuários e configuração sensível do sistema), `operador`
(ciclo de vida de certificado no dia a dia — bloqueado via
`Depends(require_operator)` nos routers de negócio), `auditor` (só enxerga
log de auditoria e lista de usuários, nunca age) e `leitor` (só visualiza
inventário/certificados/histórico).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from app.audit.log import audit_log
from app.auth import qr, totp
from app.auth.api_keys import api_key_store
from app.auth.dependencies import (
    SESSION_COOKIE_NAME,
    cookie_should_be_secure,
    get_authenticated_username,
    require_admin,
    require_auditor,
    require_session,
)
from app.auth.passwords import hash_password, verify_password
from app.auth.sessions import pending_login_store, session_store
from app.auth.store import ROLE_ADMIN, ROLE_LEITOR, ROLES, UserAccount, user_store
from app.core.config import settings
from app.core.ratelimit import SlidingWindowRateLimiter

router = APIRouter(prefix="/api/auth")

_rate_limiter = SlidingWindowRateLimiter(
    max_requests=settings.auth_rate_limit_requests,
    window_seconds=settings.auth_rate_limit_window_seconds,
)
# Achado numa auditoria de robustez: o limite acima é só por IP da conexão
# TCP — um deploy atrás de proxy/túnel (o app já prevê isso, ver
# X-Forwarded-Proto em cookie_should_be_secure) faz todo mundo compartilhar
# um balde só, e mesmo sem proxy nenhum, um spray de senha distribuído
# (várias origens, uma conta só) nunca esbarrava em limite nenhum. Balde
# separado, chaveado pela conta tentada — independente de IP/proxy.
_account_rate_limiter = SlidingWindowRateLimiter(
    max_requests=settings.auth_rate_limit_requests,
    window_seconds=settings.auth_rate_limit_window_seconds,
)
_NO_PENDING_ENROLL_MSG = "Nenhuma ativação de MFA em andamento — chame /mfa/enroll primeiro."


class SetupRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=8, max_length=256)


class CreateUserRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=8, max_length=256)
    # Least privilege por padrão: se o chamador não especificar um papel,
    # o pior caso é criar alguém sem poder nenhum, nunca outro admin sem
    # querer.
    role: str = ROLE_LEITOR


class UpdateUserRoleRequest(BaseModel):
    role: str


class CreateApiKeyRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    role: str = ROLE_LEITOR


class MfaCodeRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=6)


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=256)


class LoginMfaRequest(BaseModel):
    pending_token: str
    code: str = Field(..., min_length=6, max_length=6)


class DisableMfaRequest(BaseModel):
    password: str = Field(..., min_length=1, max_length=256)


def _client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _enforce_rate_limit(request: Request) -> None:
    if not _rate_limiter.allow(_client_key(request)):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Muitas tentativas — aguarde alguns minutos antes de tentar novamente.",
        )


def _enforce_account_rate_limit(username: str) -> None:
    if not _account_rate_limiter.allow(username.strip().lower()):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Muitas tentativas para esta conta — aguarde alguns minutos antes de "
            "tentar novamente.",
        )


def _compute_state(request: Request) -> str:
    if user_store.count() == 0:
        return "needs_setup"
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if get_authenticated_username(token) is not None:
        return "authenticated"
    return "needs_login"


def _set_session_cookie(response: Response, token: str, request: Request) -> None:
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        max_age=int(settings.session_ttl_seconds),
        httponly=True,
        samesite="lax",
        secure=cookie_should_be_secure(request),
        path="/",
    )


def _enrollment_payload(secret: str, username: str) -> dict:
    uri = totp.provisioning_uri(secret, account_name=username, issuer=settings.totp_issuer)
    return {
        "provisioning_uri": uri,
        "secret": secret,
        "qr_data_uri": qr.to_svg_data_uri(uri),
    }


@router.get("/status")
async def auth_status(request: Request) -> dict:
    return {"state": _compute_state(request)}


@router.get("/me")
async def me(username: str = Depends(require_session)) -> dict:
    account = user_store.load(username)
    assert account is not None
    return {
        "username": account.username,
        "display_name": account.display_name or account.username,
        "role": account.role,
        "mfa_enabled": account.mfa_enabled,
    }


@router.post("/setup", status_code=status.HTTP_201_CREATED)
async def setup(payload: SetupRequest, request: Request, response: Response) -> dict:
    _enforce_rate_limit(request)
    if _compute_state(request) != "needs_setup":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Já existe um admin cadastrado."
        )

    account = UserAccount(
        username=payload.username.strip(),
        password_hash=hash_password(payload.password),
        role=ROLE_ADMIN,
    )
    user_store.save(account)
    audit_log.record(username=account.username, action="user_setup", detail="primeiro admin")
    token = session_store.issue(account.username)
    _set_session_cookie(response, token, request)
    return {"ok": True}


@router.post("/login")
async def login(payload: LoginRequest, request: Request, response: Response) -> dict:
    _enforce_rate_limit(request)
    _enforce_account_rate_limit(payload.username)
    if _compute_state(request) != "needs_login":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Não é possível fazer login agora."
        )

    username = payload.username.strip()
    account = user_store.load(username)
    if account is not None and account.auth_source != "local":
        # Conta provisionada por SSO nunca tem senha utilizável de
        # propósito (ver app/auth/saml.py) — mensagem clara em vez do
        # "usuário ou senha inválidos" genérico, que confundiria alguém
        # tentando o método de login errado.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Esta conta usa login via SSO — use o botão de SSO em vez de usuário/senha.",
        )
    password_ok = account is not None and verify_password(payload.password, account.password_hash)
    if account is None or not password_ok:
        # Achado numa auditoria de robustez: login bem-sucedido, falhado,
        # código MFA inválido e logout não deixavam rastro nenhum — um
        # spray de senha bem-sucedido contra o admin não aparecia em
        # lugar nenhum, justamente no produto cujo propósito central é
        # log de auditoria. Username tentado (não o payload de senha)
        # registrado mesmo quando a conta não existe — é exatamente o
        # dado que uma investigação precisa ver.
        audit_log.record(username=username, action="login_failed", detail=username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuário ou senha inválidos."
        )

    if not account.mfa_enabled:
        token = session_store.issue(account.username)
        _set_session_cookie(response, token, request)
        audit_log.record(username=account.username, action="login_success", detail="sem MFA")
        return {"mfa_required": False}

    pending_token = pending_login_store.issue(account.username)
    return {"mfa_required": True, "pending_token": pending_token}


@router.post("/login/verify-mfa")
async def login_verify_mfa(payload: LoginMfaRequest, request: Request, response: Response) -> dict:
    _enforce_rate_limit(request)
    username = pending_login_store.peek(payload.pending_token)
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sessão de login expirada — comece novamente.",
        )

    account = user_store.load(username)
    used_counter = (
        totp.verify_totp(account.totp_secret, payload.code, last_counter=account.last_totp_counter)
        if account is not None and account.mfa_enabled
        else None
    )
    if account is None or not account.mfa_enabled or used_counter is None:
        audit_log.record(username=username, action="mfa_failed")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Código inválido.")

    account.last_totp_counter = used_counter
    user_store.save(account)
    pending_login_store.revoke(payload.pending_token)
    token = session_store.issue(username)
    _set_session_cookie(response, token, request)
    audit_log.record(username=username, action="login_success", detail="com MFA")
    return {"ok": True}


@router.post("/logout")
async def logout(request: Request, response: Response) -> dict:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token:
        username = get_authenticated_username(token)
        if username is not None:
            audit_log.record(username=username, action="logout")
        session_store.revoke(token)
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return {"ok": True}


@router.get("/mfa/status")
async def mfa_status(username: str = Depends(require_session)) -> dict:
    account = user_store.load(username)
    assert account is not None
    return {"enabled": account.mfa_enabled}


@router.post("/mfa/enroll")
async def mfa_enroll(request: Request, username: str = Depends(require_session)) -> dict:
    """Gera um novo segredo TOTP e guarda como pendente — só vira o segredo
    ativo (`mfa_enabled=True`) depois de confirmado em `/mfa/enroll/confirm`,
    para nunca ativar o MFA sem antes provar que o código funciona."""
    _enforce_rate_limit(request)
    account = user_store.load(username)
    assert account is not None
    account.pending_totp_secret = totp.generate_secret()
    user_store.save(account)
    return _enrollment_payload(account.pending_totp_secret, account.username)


@router.post("/mfa/enroll/confirm")
async def mfa_enroll_confirm(
    payload: MfaCodeRequest, request: Request, username: str = Depends(require_session)
) -> dict:
    _enforce_rate_limit(request)
    account = user_store.load(username)
    assert account is not None
    if not account.pending_totp_secret:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=_NO_PENDING_ENROLL_MSG)

    used_counter = totp.verify_totp(account.pending_totp_secret, payload.code)
    if used_counter is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Código inválido.")

    account.totp_secret = account.pending_totp_secret
    account.pending_totp_secret = None
    account.mfa_enabled = True
    account.last_totp_counter = used_counter
    user_store.save(account)
    audit_log.record(username=username, action="mfa_enabled")
    return {"ok": True}


@router.post("/mfa/disable")
async def mfa_disable(
    payload: DisableMfaRequest, request: Request, username: str = Depends(require_session)
) -> dict:
    _enforce_rate_limit(request)
    account = user_store.load(username)
    assert account is not None
    if not verify_password(payload.password, account.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Senha inválida.")

    account.mfa_enabled = False
    account.totp_secret = ""
    account.pending_totp_secret = None
    user_store.save(account)
    audit_log.record(username=username, action="mfa_disabled")
    return {"ok": True}


@router.get("/users")
async def list_users(_viewer: str = Depends(require_auditor)) -> list[dict]:
    return [
        {
            "username": u.username,
            "display_name": u.display_name,
            "role": u.role,
            "mfa_enabled": u.mfa_enabled,
        }
        for u in user_store.list_all()
    ]


@router.post("/users", status_code=status.HTTP_201_CREATED)
async def create_user(payload: CreateUserRequest, admin: str = Depends(require_admin)) -> dict:
    if payload.role not in ROLES:
        raise HTTPException(status_code=400, detail=f"Papel inválido — use um de: {ROLES}.")
    username = payload.username.strip()
    if user_store.load(username) is not None:
        raise HTTPException(status_code=400, detail="Já existe um usuário com esse nome.")

    account = UserAccount(
        username=username, password_hash=hash_password(payload.password), role=payload.role
    )
    user_store.save(account)
    audit_log.record(
        username=admin, action="user_created", detail=f"{username} (papel: {payload.role})"
    )
    return {"ok": True}


@router.patch("/users/{username}/role")
async def update_user_role(
    username: str, payload: UpdateUserRoleRequest, admin: str = Depends(require_admin)
) -> dict:
    if payload.role not in ROLES:
        raise HTTPException(status_code=400, detail=f"Papel inválido — use um de: {ROLES}.")
    account = user_store.load(username)
    if account is None:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")
    if (
        account.role == ROLE_ADMIN
        and payload.role != ROLE_ADMIN
        and user_store.count_admins() <= 1
    ):
        raise HTTPException(
            status_code=400, detail="Não é possível rebaixar o último administrador."
        )

    old_role = account.role
    account.role = payload.role
    user_store.save(account)
    audit_log.record(
        username=admin,
        action="user_role_changed",
        detail=f"{username}: {old_role} -> {payload.role}",
    )
    return {"ok": True}


@router.delete("/users/{username}")
async def delete_user(username: str, admin: str = Depends(require_admin)) -> dict:
    if username == admin:
        raise HTTPException(status_code=400, detail="Você não pode remover a si mesmo.")
    account = user_store.load(username)
    if account is None:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")
    if account.role == ROLE_ADMIN and user_store.count_admins() <= 1:
        raise HTTPException(
            status_code=400, detail="Não é possível remover o último administrador."
        )

    user_store.delete(username)
    audit_log.record(username=admin, action="user_deleted", detail=username)
    return {"ok": True}


@router.get("/api-keys")
async def list_api_keys(_viewer: str = Depends(require_auditor)) -> list[dict]:
    return [
        {
            "id": k.id,
            "name": k.name,
            "role": k.role,
            "created_by": k.created_by,
            "created_at": k.created_at,
            "last_used_at": k.last_used_at,
        }
        for k in api_key_store.list_all()
    ]


@router.post("/api-keys", status_code=status.HTTP_201_CREATED)
async def create_api_key(payload: CreateApiKeyRequest, admin: str = Depends(require_admin)) -> dict:
    if payload.role not in ROLES:
        raise HTTPException(status_code=400, detail=f"Papel inválido — use um de: {ROLES}.")
    key_id, raw_key = api_key_store.create(name=payload.name, role=payload.role, created_by=admin)
    audit_log.record(
        username=admin, action="api_key_created", detail=f"{payload.name} (papel: {payload.role})"
    )
    # A chave em texto puro só existe nesta resposta — não fica recuperável
    # depois, nem pelo próprio admin que criou (só o hash é guardado).
    return {"id": key_id, "key": raw_key, "name": payload.name}


@router.delete("/api-keys/{key_id}")
async def revoke_api_key(key_id: str, admin: str = Depends(require_admin)) -> dict:
    info = api_key_store.get(key_id)
    if info is None:
        raise HTTPException(status_code=404, detail="Chave não encontrada.")
    api_key_store.revoke(key_id)
    audit_log.record(username=admin, action="api_key_revoked", detail=info.name)
    return {"ok": True}
