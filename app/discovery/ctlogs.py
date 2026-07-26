"""Cliente para a API pública JSON do crt.sh (Certificate Transparency).

O crt.sh é um serviço público mantido sobre um único Postgres e é conhecido
por ser lento e instável sob carga — o design aqui assume isso como normal,
não como exceção: timeout curto, poucas retries com backoff, e tratamento
explícito para respostas que "funcionam" (HTTP 200) mas não são JSON válido
(o serviço às vezes devolve uma página HTML de erro mesmo com status 200).

Importante: o crt.sh só devolve METADADOS (emissor, common_name, SANs,
validade, serial) — não devolve os bytes do certificado nem um fingerprint.
Por isso os hostnames aqui descobertos são só um ponto de partida; a
identidade real (fingerprint) só existe depois do handshake TLS ao vivo.
"""

from __future__ import annotations

import asyncio
import logging

import httpx

logger = logging.getLogger(__name__)

CRTSH_URL = "https://crt.sh/"
MAX_RESPONSE_BYTES = 20 * 1024 * 1024  # corta respostas gigantes antes de processar
_RETRIES = 2
_RETRY_BACKOFF_SECONDS = 1.5


class CtLogUnavailable(Exception):
    """crt.sh não respondeu ou respondeu de forma inesperada."""


async def fetch_hostnames(domain: str, *, client: httpx.AsyncClient, timeout: float) -> set[str]:
    """Consulta `%.{domain}` no crt.sh e retorna o conjunto normalizado de
    hostnames encontrados nos campos common_name/name_value.

    Levanta CtLogUnavailable se o serviço não responder de forma utilizável
    — o chamador decide se quer seguir só com hosts colados manualmente.
    """
    last_error: Exception | None = None
    for attempt in range(_RETRIES + 1):
        try:
            response = await client.get(
                CRTSH_URL,
                params={"q": f"%.{domain}", "output": "json"},
                timeout=timeout,
            )
        except httpx.HTTPError as exc:
            last_error = exc
        else:
            if response.status_code == 200 and _looks_like_json(response):
                if len(response.content) > MAX_RESPONSE_BYTES:
                    logger.warning("resposta do crt.sh truncada por tamanho para %s", domain)
                try:
                    payload = response.json()
                except ValueError as exc:
                    last_error = exc
                else:
                    return _extract_hostnames(payload)
            else:
                last_error = CtLogUnavailable(
                    f"resposta inesperada do crt.sh (status={response.status_code})"
                )
        if attempt < _RETRIES:
            await asyncio.sleep(_RETRY_BACKOFF_SECONDS * (attempt + 1))

    raise CtLogUnavailable(f"crt.sh indisponível para '{domain}': {last_error}")


def _looks_like_json(response: httpx.Response) -> bool:
    content_type = response.headers.get("content-type", "")
    return "json" in content_type or response.text.lstrip().startswith(("[", "{"))


def _extract_hostnames(payload: object) -> set[str]:
    hostnames: set[str] = set()
    if not isinstance(payload, list):
        return hostnames
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        for field_name in ("common_name", "name_value"):
            raw = entry.get(field_name)
            if not raw:
                continue
            # name_value costuma vir multilinha: várias SANs por registro.
            for line in str(raw).splitlines():
                normalized = normalize_hostname(line)
                if normalized:
                    hostnames.add(normalized)
    return hostnames


def normalize_hostname(raw: str) -> str | None:
    value = raw.strip().lower().rstrip(".")
    if not value or " " in value:
        return None
    return value
