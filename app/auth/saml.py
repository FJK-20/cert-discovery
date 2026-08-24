"""SSO via SAML 2.0 — autenticação alternativa à senha/MFA local, pra
integrar com um IdP corporativo (Entra ID / Azure AD, ou qualquer outro
que fale SAML 2.0 padrão — não é específico da Microsoft). Usa
`python3-saml` (lib de referência da OneLogin) pra assinatura/validação de
XML — segurança crítica o bastante pra não reimplementar na mão, mesmo
raciocínio já aplicado à lib `acme` pro protocolo ACME.

Fluxo mínimo, sem certificado próprio do SP: o AuthnRequest sai sem
assinatura (padrão aceito pela maioria dos IdPs, inclusive Entra ID no
modo "Basic SAML") — só a Response do IdP precisa vir assinada, validada
contra o `x509_cert` público configurado (app/auth/store.py). Não exige
gerar/trocar certificado do lado do app pra funcionar; pode ser reforçado
depois se for preciso.

Provisionamento automático: no primeiro login bem-sucedido via SSO, se não
existir uma conta local com aquele e-mail, uma é criada com o papel
`leitor` (least privilege, mesmo princípio já usado em `routes_auth.py`
pra criação manual de usuário) — um admin promove depois se for o caso.
"""

from __future__ import annotations

import re
import secrets

from fastapi import Request
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings

from app.auth.passwords import hash_password
from app.auth.store import ROLE_LEITOR, SamlIdpConfig, UserAccount, UserStore

_NAMEID_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
_EMAIL_CLAIM = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
_DISPLAYNAME_CLAIM = "http://schemas.microsoft.com/identity/claims/displayname"
_GIVENNAME_CLAIM = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"
_SURNAME_CLAIM = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"
_NAME_CLAIM = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"


def sp_entity_id(base_url: str) -> str:
    return f"{base_url}/api/auth/saml/metadata"


def acs_url(base_url: str) -> str:
    return f"{base_url}/api/auth/saml/acs"


def _settings_dict(idp: SamlIdpConfig, base_url: str) -> dict:
    return {
        "strict": True,
        "sp": {
            "entityId": sp_entity_id(base_url),
            "assertionConsumerService": {
                "url": acs_url(base_url),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "NameIDFormat": _NAMEID_FORMAT,
        },
        "idp": {
            "entityId": idp.entity_id,
            "singleSignOnService": {
                "url": idp.sso_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": idp.x509_cert,
        },
        "security": {
            "authnRequestsSigned": False,
            "wantAssertionsSigned": True,
            "wantMessagesSigned": False,
        },
    }


async def _request_data(request: Request, base_url: str) -> dict:
    """Adapta um Request do FastAPI pro formato que python3-saml espera
    (o mesmo shape que a lib usa pra WSGI/Flask/Django — não é específico
    de nenhum framework, só um dict com as partes relevantes da requisição)."""
    form: dict = {}
    if request.method == "POST":
        parsed = await request.form()
        form = dict(parsed)
    from urllib.parse import urlsplit

    parsed_base = urlsplit(base_url)
    return {
        "https": "on" if parsed_base.scheme == "https" else "off",
        "http_host": parsed_base.netloc,
        "server_port": str(parsed_base.port or (443 if parsed_base.scheme == "https" else 80)),
        "script_name": request.url.path,
        "get_data": dict(request.query_params),
        "post_data": form,
    }


async def build_auth(request: Request, idp: SamlIdpConfig, base_url: str) -> OneLogin_Saml2_Auth:
    data = await _request_data(request, base_url)
    return OneLogin_Saml2_Auth(data, old_settings=_settings_dict(idp, base_url))


def sp_metadata_xml(idp: SamlIdpConfig, base_url: str) -> tuple[str, list[str]]:
    """Devolve (metadata_xml, erros_de_validação) — pra servir em
    GET /api/auth/saml/metadata, o jeito mais simples de configurar o
    lado da Entra ID (importar por URL em vez de digitar campo por
    campo)."""
    settings = OneLogin_Saml2_Settings(
        settings=_settings_dict(idp, base_url), sp_validation_only=True
    )
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)
    return metadata.decode() if isinstance(metadata, bytes) else metadata, list(errors)


def extract_email(auth: OneLogin_Saml2_Auth) -> str | None:
    """O NameID já é configurado pra vir como e-mail (NameIDFormat acima)
    — mas alguns IdPs mandam o e-mail só como atributo (claim), não como
    NameID, então tenta os dois."""
    name_id = auth.get_nameid()
    if name_id and "@" in name_id:
        return name_id
    attributes = auth.get_attributes()
    values = attributes.get(_EMAIL_CLAIM) or []
    return values[0] if values else None


def extract_display_name(auth: OneLogin_Saml2_Auth, fallback: str) -> str:
    """Nome amigável pra mostrar na UI — o NameID/e-mail de convidado B2B
    do Entra ID vem como `usuario_dominio.com#EXT#@tenant.onmicrosoft.com`
    (identificador técnico, não algo que se mostra numa badge). Tenta os
    claims na ordem em que o Entra ID costuma mandá-los: displayname
    (nem sempre presente) → givenname+surname (default do Entra ID pra
    qualquer usuário, inclusive convidado) → claim "name" (só se não
    parecer um UPN/e-mail) → por último, limpa o próprio identificador."""
    attributes = auth.get_attributes()

    display = attributes.get(_DISPLAYNAME_CLAIM) or []
    if display and display[0].strip():
        return display[0].strip()

    given = (attributes.get(_GIVENNAME_CLAIM) or [""])[0].strip()
    surname = (attributes.get(_SURNAME_CLAIM) or [""])[0].strip()
    full = " ".join(part for part in (given, surname) if part)
    if full:
        return full

    name = attributes.get(_NAME_CLAIM) or []
    if name and name[0].strip() and "@" not in name[0] and "#" not in name[0]:
        return name[0].strip()

    return _clean_identifier(fallback)


def _clean_identifier(identifier: str) -> str:
    # Corta em "@" (domínio) e "#" (sufixo "#EXT#" de UPN de convidado B2B
    # do Entra ID) antes de virar título. UPN de convidado tem outra
    # armadilha: é "<local>_<domínio-original>" (o "@" do e-mail original
    # vira "_" nessa mangling) — sem tratar isso, "luanvitorfaustino_gmail.com"
    # viraria "Luanvitorfaustino Gmail Com" em vez de só "Luanvitorfaustino".
    local_part = identifier.split("@")[0].split("#")[0]
    if "_" in local_part:
        head, _, tail = local_part.partition("_")
        if "." in tail:  # o que sobra depois do "_" parece um domínio — descarta
            local_part = head
    words = [w for w in re.split(r"[.\-]+", local_part) if w]
    return " ".join(w.capitalize() for w in words) if words else identifier


def provision_or_get_user(store: UserStore, email: str, display_name: str = "") -> UserAccount:
    """Acha a conta local pelo e-mail (usado como username pras contas
    SSO) ou provisiona uma nova, sempre como `leitor` — nunca cria um
    admin sem intervenção humana. Atualiza o nome de exibição a cada
    login (não só na primeira vez) — se a pessoa mudar de nome no IdP, a
    UI acompanha sem precisar recriar a conta."""
    existing = store.load(email)
    if existing is not None:
        if display_name and existing.display_name != display_name:
            existing.display_name = display_name
            store.save(existing)
        return existing

    account = UserAccount(
        username=email,
        password_hash=hash_password(secrets.token_urlsafe(32)),
        role=ROLE_LEITOR,
        auth_source="saml",
        display_name=display_name,
    )
    store.save(account)
    return account
