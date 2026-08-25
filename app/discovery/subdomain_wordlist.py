"""Enumeração ativa de subdomínios comuns via DNS — opcional, desligada por
padrão (checkbox "Também testar subdomínios comuns" na tela de Inventário).

Diferente do resto da descoberta (consulta a um serviço público de CT log +
handshake TLS padrão, o que qualquer navegador faz), isto é reconhecimento
ATIVO: tenta resolver `<palavra>.<domínio>` pra uma lista curta de prefixos
comuns, mesmo pra nomes que nunca tiveram certificado nenhum (por isso nunca
apareceriam via CT log). Only ativa com o mesmo checkbox de autorização que
já existe pro resto do scan — e só entra no pipeline principal quem
efetivamente resolveu (tentativa que não resolveu é descartada aqui mesmo,
não vira "não resolvido" no inventário — seria só ruído, diferente de um
host que apareceu no CT log e parou de responder, que é informação real).

Lista curta de propósito (não é um wordlist de milhares de entradas de
ferramenta dedicada de enumeração) — cobre os prefixos mais comuns o
bastante pra ser útil sem virar um scanner agressivo por padrão.
"""

from __future__ import annotations

import asyncio

from app.discovery.dns_resolver import resolve_ips

COMMON_SUBDOMAINS: tuple[str, ...] = (
    "www", "mail", "webmail", "smtp", "pop", "imap", "ftp", "sftp",
    "api", "api-v1", "api-v2", "app", "apps", "portal", "gateway", "proxy",
    "admin", "administrator", "cpanel", "whm", "webdisk", "direct",
    "vpn", "remote", "sso", "auth", "login", "secure", "secure2",
    "dev", "staging", "test", "qa", "uat", "sandbox", "preview", "beta",
    "alpha", "demo", "prod", "production",
    "blog", "shop", "store", "m", "mobile",
    "cdn", "static", "assets", "img", "images", "video", "media",
    "docs", "help", "support", "status", "wiki", "chat",
    "git", "gitlab", "github", "jenkins", "ci",
    "monitor", "grafana", "kibana", "prometheus", "metrics", "logs",
    "jira", "confluence",
    "db", "database", "sql", "redis", "cache", "backup",
    "old", "new", "internal", "intranet", "extranet",
    "ns1", "ns2", "ns3", "mx", "mx1", "mx2", "autodiscover",
)


async def discover_hosts(domain: str, *, timeout: float, max_concurrency: int) -> set[str]:
    """Tenta `<palavra>.<domínio>` pra cada prefixo comum, em paralelo
    (limitado por `max_concurrency`, mesma disciplina do resto do scan).
    Devolve só os que resolveram — silencioso pros que não resolveram, de
    propósito (não é achado, é ruído)."""
    semaphore = asyncio.Semaphore(max_concurrency)
    found: set[str] = set()

    async def _try_one(prefix: str) -> None:
        hostname = f"{prefix}.{domain}"
        async with semaphore:
            ips = await resolve_ips(hostname, timeout=timeout)
        if ips:
            found.add(hostname)

    await asyncio.gather(*(_try_one(prefix) for prefix in COMMON_SUBDOMAINS))
    return found
