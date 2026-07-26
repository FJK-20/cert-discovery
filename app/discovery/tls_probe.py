"""Handshake TLS ao vivo: conecta no host, captura o certificado servido.

Decisões importantes:
- Conecta sempre pelo IP literal já resolvido e validado (nunca deixa a
  camada de socket/TLS re-resolver o hostname) — evita DNS rebinding.
  `server_hostname` continua sendo o hostname original, só para o SNI.
- SSLContext propositalmente permissivo (`CERT_NONE`, sem checar hostname):
  o objetivo é CAPTURAR o certificado mesmo se expirado/self-signed/com
  hostname divergente — a validade é avaliada depois por nós via
  `cryptography`, não pela confiança do TLS stack.
- Timeouts separados para connect TCP e handshake TLS (um host lento numa
  fase não deve consumir o orçamento inteiro do outro).
- `ip_validator` é injetável para permitir testes contra 127.0.0.1 com um
  servidor local, sem criar nenhum bypass global em produção.
"""

from __future__ import annotations

import asyncio
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from app.core.security import is_public_ip


class ProbeError(Exception):
    """Falha ao conectar/handshake — o host é tratado como indisponível,
    não como erro fatal do scan inteiro."""


@dataclass
class ProbeResult:
    subject_cn: str | None
    issuer: str | None
    not_before: datetime
    not_after: datetime
    serial_number: str
    sha256_fingerprint: str
    sans: list[str]


def _build_ssl_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _extract_der_chain(ssl_object: ssl.SSLObject | None) -> list[bytes]:
    if ssl_object is None:
        return []
    get_chain = getattr(ssl_object, "get_unverified_chain", None)
    if get_chain is not None:
        try:
            chain = get_chain()  # Python 3.13+: list[bytes] já em DER
        except Exception:
            chain = None
        if chain:
            return list(chain)
    leaf_der = ssl_object.getpeercert(binary_form=True)
    return [leaf_der] if leaf_der else []


def _to_probe_result(leaf: x509.Certificate) -> ProbeResult:
    try:
        subject_cn = leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except IndexError:
        subject_cn = None
    try:
        issuer = leaf.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except IndexError:
        issuer = leaf.issuer.rfc4514_string()

    try:
        san_ext = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []

    not_before = _as_utc(leaf.not_valid_before_utc)
    not_after = _as_utc(leaf.not_valid_after_utc)

    return ProbeResult(
        subject_cn=subject_cn,
        issuer=issuer,
        not_before=not_before,
        not_after=not_after,
        serial_number=format(leaf.serial_number, "x"),
        sha256_fingerprint=leaf.fingerprint(hashes.SHA256()).hex(),
        sans=list(sans),
    )


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


async def probe_host(
    hostname: str,
    ip: str,
    *,
    port: int = 443,
    connect_timeout: float,
    handshake_timeout: float,
    ip_validator=is_public_ip,
) -> ProbeResult:
    if not ip_validator(ip):
        raise ProbeError(f"IP {ip} bloqueado (não é um endereço público válido)")

    loop = asyncio.get_running_loop()

    try:
        transport, protocol = await asyncio.wait_for(
            loop.create_connection(asyncio.Protocol, host=ip, port=port),
            timeout=connect_timeout,
        )
    except (TimeoutError, OSError) as exc:
        raise ProbeError(f"falha ao conectar em {hostname} ({ip}:{port}): {exc}") from exc

    ctx = _build_ssl_context()
    try:
        tls_transport = await asyncio.wait_for(
            loop.start_tls(transport, protocol, ctx, server_hostname=hostname),
            timeout=handshake_timeout,
        )
    except (TimeoutError, OSError, ssl.SSLError) as exc:
        transport.close()
        raise ProbeError(f"falha no handshake TLS em {hostname} ({ip}:{port}): {exc}") from exc

    try:
        ssl_object = tls_transport.get_extra_info("ssl_object")
        der_chain = _extract_der_chain(ssl_object)
    finally:
        tls_transport.close()

    if not der_chain:
        raise ProbeError(f"nenhum certificado obtido de {hostname} ({ip}:{port})")

    leaf = x509.load_der_x509_certificate(der_chain[0])
    return _to_probe_result(leaf)
