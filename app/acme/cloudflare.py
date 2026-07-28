"""Cliente mínimo da API v4 da Cloudflare, só o necessário para o desafio
ACME DNS-01: achar a zona do domínio, criar e depois remover o registro
TXT `_acme-challenge.<domínio>`.

Síncrono de propósito (`httpx.Client`, não `AsyncClient`): todo o fluxo de
emissão ACME roda numa thread separada (a lib `acme` é síncrona por baixo),
então não há necessidade de misturar chamadas assíncronas aqui — ver
app/acme/issuance.py.
"""

from __future__ import annotations

import httpx

from app.core.config import settings


class CloudflareError(Exception):
    """Erro de comunicação ou de permissão com a API da Cloudflare."""


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _request(method: str, path: str, token: str, **kwargs) -> dict:
    url = f"{settings.cloudflare_api_base}{path}"
    try:
        response = httpx.request(method, url, headers=_headers(token), timeout=15.0, **kwargs)
    except httpx.HTTPError as exc:
        raise CloudflareError(f"falha de rede ao chamar a Cloudflare: {exc}") from exc

    try:
        payload = response.json()
    except ValueError as exc:
        raise CloudflareError(
            f"resposta inesperada da Cloudflare (status {response.status_code})"
        ) from exc

    if not payload.get("success"):
        errors = payload.get("errors") or [{"message": f"HTTP {response.status_code}"}]
        message = "; ".join(e.get("message", str(e)) for e in errors)
        raise CloudflareError(f"Cloudflare recusou a requisição: {message}")
    return payload


def verify_token(token: str) -> bool:
    """True se o token for válido e ativo. Não garante escopo de DNS:Edit
    — isso só se confirma na prática ao tentar criar o registro."""
    try:
        payload = _request("GET", "/user/tokens/verify", token)
    except CloudflareError:
        return False
    return payload.get("result", {}).get("status") == "active"


def find_zone_id(domain: str, token: str) -> str:
    """Acha a zona Cloudflare responsável por `domain`, tentando o nome
    completo e depois removendo labels da esquerda (mesma heurística usada
    por certbot-dns-cloudflare/lego) até achar uma zona cadastrada."""
    labels = domain.strip(".").split(".")
    for start in range(len(labels) - 1):
        candidate = ".".join(labels[start:])
        payload = _request("GET", "/zones", token, params={"name": candidate})
        results = payload.get("result") or []
        if results:
            return results[0]["id"]
    raise CloudflareError(
        f"nenhuma zona Cloudflare encontrada para '{domain}' (o token tem acesso à zona certa?)"
    )


def create_txt_record(zone_id: str, name: str, content: str, token: str) -> str:
    payload = _request(
        "POST",
        f"/zones/{zone_id}/dns_records",
        token,
        json={"type": "TXT", "name": name, "content": content, "ttl": 120},
    )
    return payload["result"]["id"]


def delete_txt_record(zone_id: str, record_id: str, token: str) -> None:
    _request("DELETE", f"/zones/{zone_id}/dns_records/{record_id}", token)
