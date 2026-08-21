"""Cliente REST mínimo pro Azure DNS (API do Resource Manager) — segundo
provedor de DNS automático, ao lado da Cloudflare (app/acme/cloudflare.py),
provando que a interface `set_dns_challenge`/`clear_dns_challenge` (ver
app/acme/issuance.py) é plugável de verdade, não só na teoria.

Só REST via `httpx` (já é dependência do projeto), sem o SDK oficial
(`azure-identity`/`azure-mgmt-dns`) — mesma filosofia de dependência
mínima do resto do projeto. O que esse módulo precisa (autenticação
OAuth2 client-credentials + CRUD de um registro TXT) é simples o
bastante pra não justificar um SDK inteiro.

Síncrono de propósito, mesmo motivo do cliente da Cloudflare: o fluxo de
emissão ACME inteiro roda numa thread separada.
"""

from __future__ import annotations

import httpx

from app.acme.store import AzureDnsCredentials

_TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
_ARM_BASE = "https://management.azure.com"
_API_VERSION = "2018-05-01"
_TIMEOUT = 15.0


class AzureDnsError(Exception):
    """Erro de comunicação, autenticação ou permissão com o Azure DNS —
    mensagem já segura pra mostrar ao usuário (nunca inclui o
    client_secret)."""


def _request(method: str, url: str, **kwargs) -> httpx.Response:
    try:
        return httpx.request(method, url, timeout=_TIMEOUT, **kwargs)
    except httpx.HTTPError as exc:
        raise AzureDnsError(f"falha de rede ao chamar o Azure: {exc}") from exc


def _get_access_token(creds: AzureDnsCredentials) -> str:
    response = _request(
        "POST",
        _TOKEN_URL.format(tenant=creds.tenant_id),
        data={
            "grant_type": "client_credentials",
            "client_id": creds.client_id,
            "client_secret": creds.client_secret,
            "scope": f"{_ARM_BASE}/.default",
        },
    )
    if response.status_code != 200:
        raise AzureDnsError(
            f"Falha ao autenticar no Azure (tenant/client/secret corretos?): "
            f"HTTP {response.status_code}"
        )
    return response.json()["access_token"]


def _zone_url(creds: AzureDnsCredentials) -> str:
    return (
        f"{_ARM_BASE}/subscriptions/{creds.subscription_id}/resourceGroups/"
        f"{creds.resource_group}/providers/Microsoft.Network/dnsZones/{creds.zone_name}"
    )


def _record_url(creds: AzureDnsCredentials, relative_name: str) -> str:
    return f"{_zone_url(creds)}/TXT/{relative_name}"


def _relative_name(record_name: str, zone_name: str) -> str:
    """Azure quer só a parte do nome relativa à zona (ex: `_acme-challenge`
    numa zona `example.com`, não o FQDN completo `_acme-challenge.example.com`
    que o resto do app usa)."""
    record_name = record_name.rstrip(".")
    zone_name = zone_name.rstrip(".")
    if record_name == zone_name:
        return "@"
    suffix = f".{zone_name}"
    if record_name.endswith(suffix):
        return record_name[: -len(suffix)]
    raise AzureDnsError(f"'{record_name}' não pertence à zona configurada '{zone_name}'.")


def verify_credentials(creds: AzureDnsCredentials) -> bool:
    """Confirma que as credenciais autenticam e enxergam a zona
    configurada — só leitura, não modifica nada."""
    try:
        token = _get_access_token(creds)
        response = _request(
            "GET",
            _zone_url(creds),
            params={"api-version": _API_VERSION},
            headers={"Authorization": f"Bearer {token}"},
        )
        return response.status_code == 200
    except AzureDnsError:
        return False


def create_txt_record(creds: AzureDnsCredentials, record_name: str, value: str) -> str:
    """Cria (ou substitui) o registro TXT — devolve o nome relativo usado,
    que `delete_txt_record` precisa pra limpar depois (o "handle" opaco
    que app/acme/renewal.py já usa pro par create/delete da Cloudflare)."""
    token = _get_access_token(creds)
    relative_name = _relative_name(record_name, creds.zone_name)
    response = _request(
        "PUT",
        _record_url(creds, relative_name),
        params={"api-version": _API_VERSION},
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={"properties": {"TTL": 60, "TXTRecords": [{"value": [value]}]}},
    )
    if response.status_code not in (200, 201):
        raise AzureDnsError(
            f"Falha ao criar registro TXT no Azure DNS: HTTP {response.status_code}"
        )
    return relative_name


def delete_txt_record(creds: AzureDnsCredentials, relative_name: str) -> None:
    token = _get_access_token(creds)
    response = _request(
        "DELETE",
        _record_url(creds, relative_name),
        params={"api-version": _API_VERSION},
        headers={"Authorization": f"Bearer {token}"},
    )
    # Azure devolve 200 (removeu) ou 204 (já não existia) pra DELETE —
    # os dois são sucesso aqui, é limpeza best-effort.
    if response.status_code not in (200, 204):
        raise AzureDnsError(
            f"Falha ao remover registro TXT do Azure DNS: HTTP {response.status_code}"
        )
