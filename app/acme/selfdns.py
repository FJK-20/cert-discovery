"""Servidor DNS autoritativo mínimo — responde só a consultas TXT para
`<hash>.<selfdns_zone>`, a zona que este processo opera diretamente pra
`DnsMode.SELF_HOSTED_DNS` (ver app/acme/renewal.py). Qualquer outra
consulta recebe REFUSED: este servidor nunca deve virar um resolvedor
de propósito geral, só responde pela própria zona.

Por que isso existe, e por que não é só mais um "provedor de DNS" como
Cloudflare/Azure: os outros modos automáticos SEMPRE exigem uma
credencial de terceiro em algum lugar — mesmo `CNAME_DELEGATION` precisa
de um token Cloudflare pra zona de delegação. Este modo elimina essa
exigência por completo: o único requisito é uma delegação NS de verdade
no registrador (feita uma vez, fora do app, pelo operador desta
instância) apontando pra onde este processo escuta. Depois disso, cada
domínio certificado só precisa de UM CNAME manual, criado uma vez, e a
resposta ao desafio ACME é publicada e removida por este servidor —
processo local, sem chamada de rede nem segredo nenhum.

`dnspython` já é dependência do projeto (resolução client-side em
app/discovery/dns_resolver.py e app/acme/dns_check.py) — reaproveitado
aqui pra parsear/montar mensagens DNS em vez de outra lib só pra isso.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging

import dns.flags
import dns.message
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from app.core.config import settings

logger = logging.getLogger(__name__)

# hash -> valor TXT atualmente esperado. Só existe enquanto uma emissão/
# renovação está com o desafio pendente (set_challenge no início,
# clear_challenge no finally de issue_certificate) — mesma disciplina de
# "handle opaco" que os outros modos usam, só que em memória local em vez
# de numa API externa. Escrita/leitura de dict é atômica sob o GIL, mesmo
# raciocínio já documentado em renewal.py.
_challenges: dict[str, str] = {}

_TTL_SECONDS = 60


def target_hostname(domain: str) -> str:
    """Nome estável dentro da zona própria — o mesmo domínio emitido
    sempre mapeia pro mesmo alvo, então o CNAME que a pessoa configura
    uma vez continua válido em toda renovação futura (mesma ideia de
    `_delegation_target` em renewal.py, mas resolvida por este servidor
    em vez de por uma API de terceiro)."""
    digest = hashlib.sha256(domain.encode()).hexdigest()[:16]
    zone = settings.selfdns_zone.strip(".")
    return f"{digest}.{zone}"


def set_challenge(domain: str, value: str) -> None:
    _challenges[target_hostname(domain)] = value


def clear_challenge(domain: str) -> None:
    _challenges.pop(target_hostname(domain), None)


def _build_response(data: bytes) -> bytes | None:
    try:
        query = dns.message.from_wire(data)
    except Exception:
        return None  # lixo/não é uma query DNS válida — não responde nada

    response = dns.message.make_response(query)
    response.flags |= dns.flags.AA  # autoritativo — só pra própria zona, nunca pra outra

    if len(query.question) != 1:
        response.set_rcode(dns.rcode.REFUSED)
        return response.to_wire()

    question = query.question[0]
    qname = question.name.to_text(omit_final_dot=True).lower()
    zone = settings.selfdns_zone.strip(".").lower()

    if not zone or not (qname == zone or qname.endswith(f".{zone}")):
        # Fora da nossa zona — nunca responde por um domínio de terceiro,
        # pra este servidor jamais virar um open resolver por acidente.
        response.set_rcode(dns.rcode.REFUSED)
        return response.to_wire()

    if question.rdtype != dns.rdatatype.TXT:
        # Zona é nossa, mas não é o tipo que este servidor sabe responder
        # (NOERROR sem answer = NODATA, resposta correta pro protocolo).
        return response.to_wire()

    value = _challenges.get(qname)
    if value is None:
        response.set_rcode(dns.rcode.NXDOMAIN)
        return response.to_wire()

    rrset = dns.rrset.from_text(
        question.name, _TTL_SECONDS, dns.rdataclass.IN, dns.rdatatype.TXT, f'"{value}"'
    )
    response.answer.append(rrset)
    return response.to_wire()


class _DnsProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        try:
            response = _build_response(data)
        except Exception:
            logger.exception("Falha inesperada processando consulta DNS de %s", addr)
            return
        if response is not None:
            self.transport.sendto(response, addr)


async def _handle_tcp_connection(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    # DNS sobre TCP tem o mesmo wire format do UDP, só com um prefixo de 2
    # bytes (big-endian) com o tamanho da mensagem antes dela — é só isso
    # que muda (RFC 1035 §4.2.2). A maioria dos resolvedores só usa TCP
    # quando a resposta UDP não coube ou veio truncada; nossas respostas
    # são minúsculas (um TXT curto), então isso raramente é exercitado na
    # prática, mas um servidor autoritativo de verdade precisa suportar —
    # alguns resolvedores/validadores sempre preferem TCP.
    try:
        length_prefix = await reader.readexactly(2)
        length = int.from_bytes(length_prefix, "big")
        data = await reader.readexactly(length)
        response = _build_response(data)
        if response is not None:
            writer.write(len(response).to_bytes(2, "big") + response)
            await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionError):
        pass
    except Exception:
        logger.exception("Falha inesperada processando consulta DNS via TCP")
    finally:
        writer.close()


_udp_transport: asyncio.DatagramTransport | None = None
_tcp_server: asyncio.base_events.Server | None = None


async def start() -> None:
    """Sobe os listeners UDP e TCP na porta configurada — chamado no
    lifespan do FastAPI (app/main.py), só quando `selfdns_enabled` está
    ligado. Silenciosamente não faz nada se já estiver rodando (evita
    listener duplicado num hot-reload de teste, por exemplo)."""
    global _udp_transport, _tcp_server
    if not settings.selfdns_enabled or _udp_transport is not None:
        return
    if not settings.selfdns_zone:
        logger.warning(
            "CERTDISC_SELFDNS_ENABLED=1 mas CERTDISC_SELFDNS_ZONE não foi configurada — "
            "servidor DNS próprio não vai subir."
        )
        return
    loop = asyncio.get_running_loop()
    _udp_transport, _ = await loop.create_datagram_endpoint(
        _DnsProtocol, local_addr=("0.0.0.0", settings.selfdns_port)
    )
    _tcp_server = await asyncio.start_server(
        _handle_tcp_connection, host="0.0.0.0", port=settings.selfdns_port
    )
    logger.info(
        "Servidor DNS próprio escutando em udp+tcp/%s pra zona %s",
        settings.selfdns_port,
        settings.selfdns_zone,
    )


def stop() -> None:
    global _udp_transport, _tcp_server
    if _udp_transport is not None:
        _udp_transport.close()
        _udp_transport = None
    if _tcp_server is not None:
        _tcp_server.close()
        _tcp_server = None
