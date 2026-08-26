"""Rotas de SSO via SAML 2.0 — ver app/auth/saml.py pro fluxo completo.

Três rotas públicas (sem `require_session`, óbvio — servem justamente pra
autenticar): `/metadata` (o IdP importa por aqui, ou os campos são
digitados manualmente), `/login` (redireciona pro IdP) e `/acs`
(recebe a resposta assinada de volta). `/status` também é pública — a
tela de login precisa saber se deve mostrar o botão de SSO antes de
qualquer sessão existir. `/config` é a única admin-only (só depois de
autenticado com uma conta local — não dá pra configurar SSO via SSO)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

from app.audit.log import audit_log
from app.auth import saml
from app.auth.dependencies import SESSION_COOKIE_NAME, cookie_should_be_secure, require_admin
from app.auth.sessions import session_store
from app.auth.store import SamlIdpConfig, user_store
from app.core.config import settings

router = APIRouter(prefix="/api/auth/saml")


class SamlConfigRequest(BaseModel):
    entity_id: str = Field(..., min_length=1, max_length=500)
    sso_url: str = Field(..., min_length=1, max_length=500)
    x509_cert: str = Field(..., min_length=1, max_length=10_000)


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


@router.get("/status")
async def saml_status() -> dict:
    config = user_store.load_saml_config()
    return {
        "configured": config is not None,
        "login_url": "/api/auth/saml/login" if config else None,
        # Sempre a URL fixa configurada (CERTDISC_PUBLIC_BASE_URL), nunca a
        # origin da requisição atual — precisa bater com o que fica
        # cadastrado no IdP mesmo que o admin esteja acessando pela LAN.
        "sp_entity_id": saml.sp_entity_id(settings.public_base_url),
        "acs_url": saml.acs_url(settings.public_base_url),
    }


@router.post("/config")
async def save_saml_config(
    payload: SamlConfigRequest, username: str = Depends(require_admin)
) -> dict:
    config = SamlIdpConfig(
        entity_id=payload.entity_id.strip(),
        sso_url=payload.sso_url.strip(),
        x509_cert=payload.x509_cert.strip(),
    )
    user_store.save_saml_config(config)
    audit_log.record(username=username, action="saml_config_saved", detail=config.entity_id)
    return {
        "ok": True,
        "sp_entity_id": saml.sp_entity_id(settings.public_base_url),
        "acs_url": saml.acs_url(settings.public_base_url),
    }


@router.get("/metadata")
async def saml_metadata():
    config = user_store.load_saml_config()
    if config is None:
        raise HTTPException(status_code=404, detail="SSO SAML não configurado.")
    xml, errors = saml.sp_metadata_xml(config, settings.public_base_url)
    if errors:
        raise HTTPException(status_code=500, detail=f"Metadata inválida: {errors}")
    return Response(content=xml, media_type="application/xml")


@router.get("/login")
async def saml_login(request: Request):
    config = user_store.load_saml_config()
    if config is None:
        raise HTTPException(status_code=400, detail="SSO SAML não configurado.")
    auth = await saml.build_auth(request, config, settings.public_base_url)
    return RedirectResponse(auth.login())


@router.post("/acs")
async def saml_acs(request: Request):
    config = user_store.load_saml_config()
    if config is None:
        raise HTTPException(status_code=400, detail="SSO SAML não configurado.")

    auth = await saml.build_auth(request, config, settings.public_base_url)
    try:
        auth.process_response()
    except Exception as err:
        # python3-saml faz parsing de XML já no construtor da Response,
        # antes do próprio try/except interno de is_valid() entrar em
        # ação — um POST malformado (bot varrendo endpoints, IdP mal
        # configurado, etc.) nesse endpoint público e sem autenticação
        # lançava XMLSyntaxError direto pra fora como 500 em vez de
        # falhar como qualquer outra tentativa de login inválida.
        raise HTTPException(
            status_code=401, detail=f"Falha ao processar a resposta SAML: {err}"
        ) from err
    errors = auth.get_errors()
    if errors:
        raise HTTPException(
            status_code=401, detail=f"Falha na validação da resposta SAML: {'; '.join(errors)}"
        )
    if not auth.is_authenticated():
        raise HTTPException(status_code=401, detail="IdP não confirmou a autenticação.")

    email = saml.extract_email(auth)
    if not email:
        raise HTTPException(
            status_code=401, detail="A resposta do IdP não trouxe um e-mail identificável."
        )

    display_name = saml.extract_display_name(auth, fallback=email)
    account = saml.provision_or_get_user(user_store, email, display_name)
    if account.auth_source != "saml":
        # E-mail já existe como conta local (usuário/senha) — não deixa o
        # SSO sequestrar uma conta que a pessoa não provisionou por SSO.
        raise HTTPException(
            status_code=401,
            detail="Já existe uma conta local com esse e-mail — faça login com usuário/senha.",
        )

    audit_log.record(username=account.username, action="saml_login", detail=email)
    token = session_store.issue(account.username)
    response = RedirectResponse(url="/", status_code=303)
    _set_session_cookie(response, token, request)
    return response
