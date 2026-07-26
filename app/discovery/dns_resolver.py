"""Resolução DNS assíncrona via dnspython.

Não usamos `asyncio.loop.getaddrinfo`: seu wrapper roda a chamada bloqueante
numa thread do ThreadPoolExecutor padrão e, se cancelada por timeout, a
thread continua presa até a libc retornar sozinha — com muitos hosts com DNS
lento/blackhole (comum ao resolver SANs históricos de CT log) isso pode
esgotar o pool e serializar o que deveria ser concorrente. dns.asyncresolver
usa sockets assíncronos nativos, então o cancelamento por timeout é limpo.
"""

from __future__ import annotations

import dns.asyncresolver
import dns.exception


async def resolve_ips(hostname: str, *, timeout: float) -> list[str]:
    """Resolve A e AAAA. Hostname que não resolve retorna lista vazia
    (é tratado como UNRESOLVED pelo chamador, não como erro fatal do scan)."""
    ips: list[str] = []
    for record_type in ("A", "AAAA"):
        try:
            answer = await dns.asyncresolver.resolve(
                hostname, record_type, lifetime=timeout
            )
        except (dns.exception.DNSException, OSError):
            continue
        ips.extend(str(item) for item in answer)
    return ips


def to_idna(hostname: str) -> str | None:
    """Normaliza hostnames com caracteres não-ASCII para punycode antes de
    usar em DNS/SNI. Hostnames que falham a codificação são descartados
    individualmente (não derrubam o scan inteiro)."""
    try:
        return hostname.encode("idna").decode("ascii")
    except UnicodeError:
        return None
