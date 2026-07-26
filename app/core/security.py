"""Validação de IP para evitar SSRF: só permite conectar em endereços públicos.

O app recebe hostnames de fontes não confiáveis (SANs históricos de CT logs,
ou colados manualmente pelo usuário) e abre conexões TCP/TLS reais para os
IPs resolvidos. Sem esta validação, alguém poderia usar o serviço para
sondar redes internas (RFC1918, endpoint de metadata de cloud, etc.) através
de um domínio que resolve para um IP privado — inclusive via serviços como
nip.io/sslip.io que resolvem qualquer string de IP sob demanda.

A validação é sempre feita no IP já resolvido, nunca no texto do hostname.
"""

from __future__ import annotations

import ipaddress

# Ranges adicionais que as properties padrão do ipaddress não cobrem
# integralmente entre versões do Python (CGNAT, benchmarking, etc.) — mantidos
# explícitos para não depender de nuances de versão do stdlib.
_EXTRA_BLOCKED_V4 = [
    ipaddress.ip_network("0.0.0.0/8"),        # "this network"
    ipaddress.ip_network("100.64.0.0/10"),     # CGNAT / shared address space
    ipaddress.ip_network("192.0.0.0/24"),      # IETF protocol assignments
    ipaddress.ip_network("192.0.2.0/24"),      # TEST-NET-1
    ipaddress.ip_network("198.18.0.0/15"),     # benchmarking
    ipaddress.ip_network("198.51.100.0/24"),   # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),    # TEST-NET-3
]

_EXTRA_BLOCKED_V6 = [
    ipaddress.ip_network("100::/64"),    # discard-only
    ipaddress.ip_network("2001:db8::/32"),  # documentação
]

# Bem conhecido: endpoint de metadata usado por AWS/GCP/Azure/DigitalOcean/etc.
# Já coberto por 169.254.0.0/16 (link-local), mas mantido nomeado para que
# exista um teste explícito e legível sobre este caso específico.
CLOUD_METADATA_IP = ipaddress.ip_address("169.254.169.254")


def _unwrap_ipv4_mapped(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """Extrai o IPv4 embutido em endereços IPv6 mapeados ou NAT64.

    Um atacante pode codificar um IPv4 privado dentro de um IPv6
    "::ffff:10.0.0.1" ou "64:ff9b::10.0.0.1" para escapar de um filtro que só
    olhe as properties do IPv6 "puro" — por isso o desembrulho é obrigatório.
    """
    mapped = ip.ipv4_mapped
    if mapped is not None:
        return mapped
    nat64_prefix = ipaddress.ip_network("64:ff9b::/96")
    if ip in nat64_prefix:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def is_public_ip(ip_str: str) -> bool:
    """True somente se `ip_str` for um endereço público, roteável e seguro
    para o serviço conectar. Qualquer caso duvidoso retorna False.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    if isinstance(ip, ipaddress.IPv6Address):
        embedded_v4 = _unwrap_ipv4_mapped(ip)
        if embedded_v4 is not None:
            return is_public_ip(str(embedded_v4))

    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return False

    extra = _EXTRA_BLOCKED_V4 if isinstance(ip, ipaddress.IPv4Address) else _EXTRA_BLOCKED_V6
    if any(ip in net for net in extra):
        return False

    return True
