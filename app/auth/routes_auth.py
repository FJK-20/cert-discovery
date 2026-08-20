"""Cadastro de admin (usuário + senha) com MFA opcional, ativável a
qualquer momento pelo próprio admin, e login em uma ou duas etapas
dependendo se o MFA está ligado.

Estados possíveis (calculados a partir do arquivo de admin + cookie de
sessão, nunca guardados à parte): `needs_setup` (nenhum admin cadastrado),
`needs_login` e `authenticated`. Ativar/desativar MFA acontece só depois de
autenticado (ver rotas `/mfa/*` abaixo), não faz parte desse cálculo de
estado — por isso um cadastro recém-criado já cai direto em `authenticated`,
sem etapa intermediária forçada.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from app.auth import qr, totp
from app.auth.dependencies import SESSION_COOKIE_NAME, get_authenticated_username, require_session
from app.auth.passwords import hash_password, verify_password
from app.auth.sessions import pending_login_store, session_store
from app.auth.store import AdminAccount, admin_store
from app.core.config import settings
from app.core.ratelimit import SlidingWindowRateLimiter

router = APIRouter(prefix="/api/auth")

_rate_limiter = SlidingWindowRateLimiter(
    max_requests=settings.auth_rate_limit_requests,
    window_seconds=settings.auth_rate_limit_window_seconds,
)
_NO_PENDING_ENROLL_MSG = "Nenhuma ativação de MFA em andamento — chame /mfa/enroll primeiro."


class SetupRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=8, max_length=256)


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


def _compute_state(request: Request) -> str:
    account = admin_store.load()
    if account is None:
        return "needs_setup"
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if get_authenticated_username(token) is not None:
        return "authenticated"
    return "needs_login"


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        max_age=int(settings.session_ttl_seconds),
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
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


@router.post("/setup", status_code=status.HTTP_201_CREATED)
async def setup(payload: SetupRequest, request: Request, response: Response) -> dict:
    _enforce_rate_limit(request)
    if _compute_state(request) != "needs_setup":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Já existe um admin cadastrado."
        )

    account = AdminAccount(
        username=payload.username.strip(),
        password_hash=hash_password(payload.password),
    )
    admin_store.save(account)
    token = session_store.issue(account.username)
    _set_session_cookie(response, token)
    return {"ok": True}


@router.post("/login")
async def login(payload: LoginRequest, request: Request, response: Response) -> dict:
    _enforce_rate_limit(request)
    if _compute_state(request) != "needs_login":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Não é possível fazer login agora."
        )

    account = admin_store.load()
    assert account is not None
    password_ok = verify_password(payload.password, account.password_hash)
    if payload.username.strip() != account.username or not password_ok:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuário ou senha inválidos."
        )

    if not account.mfa_enabled:
        token = session_store.issue(account.username)
        _set_session_cookie(response, token)
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

    account = admin_store.load()
    if (
        account is None
        or not account.mfa_enabled
        or not totp.verify_totp(account.totp_secret, payload.code)
    ):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Código inválido.")

    pending_login_store.revoke(payload.pending_token)
    token = session_store.issue(username)
    _set_session_cookie(response, token)
    return {"ok": True}


@router.post("/logout")
async def logout(request: Request, response: Response) -> dict:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token:
        session_store.revoke(token)
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return {"ok": True}


@router.get("/mfa/status")
async def mfa_status(username: str = Depends(require_session)) -> dict:
    account = admin_store.load()
    assert account is not None
    return {"enabled": account.mfa_enabled}


@router.post("/mfa/enroll")
async def mfa_enroll(request: Request, username: str = Depends(require_session)) -> dict:
    """Gera um novo segredo TOTP e guarda como pendente — só vira o segredo
    ativo (`mfa_enabled=True`) depois de confirmado em `/mfa/enroll/confirm`,
    para nunca ativar o MFA sem antes provar que o código funciona."""
    _enforce_rate_limit(request)
    account = admin_store.load()
    assert account is not None
    account.pending_totp_secret = totp.generate_secret()
    admin_store.save(account)
    return _enrollment_payload(account.pending_totp_secret, account.username)


@router.post("/mfa/enroll/confirm")
async def mfa_enroll_confirm(
    payload: MfaCodeRequest, request: Request, username: str = Depends(require_session)
) -> dict:
    _enforce_rate_limit(request)
    account = admin_store.load()
    assert account is not None
    if not account.pending_totp_secret:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=_NO_PENDING_ENROLL_MSG)

    if not totp.verify_totp(account.pending_totp_secret, payload.code):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Código inválido.")

    account.totp_secret = account.pending_totp_secret
    account.pending_totp_secret = None
    account.mfa_enabled = True
    admin_store.save(account)
    return {"ok": True}


@router.post("/mfa/disable")
async def mfa_disable(
    payload: DisableMfaRequest, request: Request, username: str = Depends(require_session)
) -> dict:
    _enforce_rate_limit(request)
    account = admin_store.load()
    assert account is not None
    if not verify_password(payload.password, account.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Senha inválida.")

    account.mfa_enabled = False
    account.totp_secret = ""
    account.pending_totp_secret = None
    admin_store.save(account)
    return {"ok": True}
