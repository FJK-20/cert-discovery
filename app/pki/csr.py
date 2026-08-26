"""CSR (Certificate Signing Request) e validação do certificado que volta
de uma CA externa — o fluxo manual pra qualquer CA que não fale ACME (CA
interna da empresa, certificado comprado manualmente). A chave privada é
gerada aqui e nunca sai do servidor; só o CSR (dado público) é baixado
pelo usuário pra submeter à CA escolhida."""

from __future__ import annotations

from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def build_csr(domains: list[str], key: rsa.RSAPrivateKey) -> bytes:
    """`domains[0]` vira o Common Name; todos os domínios (incluindo o
    primeiro) entram como Subject Alternative Name — é o que qualquer CA
    moderna espera pra validar múltiplos hosts num certificado só."""
    if not domains:
        raise ValueError("build_csr precisa de ao menos um domínio")
    san = x509.SubjectAlternativeName([x509.DNSName(d) for d in domains])
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domains[0])]))
        .add_extension(san, critical=False)
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM)


def certificate_matches_key(cert_pem: str, private_key_pem: str) -> bool:
    """True se a chave pública do certificado bater com a chave privada
    gerada pro CSR — prova que esse certificado específico é resposta
    daquele pedido, não de outro (ou de um key pair completamente
    diferente colado por engano)."""
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    cert_public_numbers = cert.public_key().public_numbers()
    key_public_numbers = key.public_key().public_numbers()
    return cert_public_numbers == key_public_numbers


def certificate_info(cert_pem: str) -> tuple[list[str], str | None]:
    """Domínios (SANs, ou CN se não houver SAN) e data de expiração ISO do
    certificado — pra comparar com o que foi pedido e popular o registro
    salvo, igual ao que a emissão ACME já faz."""
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        domains = san.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        domains = []
    if not domains:
        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        domains = [str(cn_attrs[0].value)] if cn_attrs else []

    not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else None
    if not_after and not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=UTC)
    return domains, not_after.isoformat() if not_after else None


def validate_completed_certificate(cert_pem: str, requested_domains: list[str]) -> None:
    """Levanta `ValueError` (mensagem pronta pra virar 400 na rota) se o
    certificado colado não é uma resposta válida ao CSR original — achado
    numa auditoria de robustez: a única checagem antes disso era a chave
    pública bater com a privada gerada, o que não garante nem validade
    nem que o certificado cobre o domínio pedido. Não valida a cadeia
    contra um trust store de propósito: a CA pode ser interna/privada,
    sem raiz pública nenhuma (é o caso de uso central deste fluxo) — só o
    que dá pra checar sem isso: não expirado, não autoassinado (não é
    resposta de CA nenhuma), e as SANs cobrindo todo domínio pedido."""
    cert = x509.load_pem_x509_certificate(cert_pem.encode())

    not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else None
    if not_after and not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=UTC)
    if not_after and not_after < datetime.now(UTC):
        raise ValueError(f"certificado já expirado em {not_after.isoformat()}")

    if cert.issuer == cert.subject:
        raise ValueError(
            "certificado autoassinado não é uma resposta válida de uma CA — "
            "confirme que colou o certificado assinado pela CA, não um rascunho"
        )

    domains, _ = certificate_info(cert_pem)
    requested = {d.lower() for d in requested_domains}
    actual = {d.lower() for d in domains}
    if not requested.issubset(actual):
        faltando = ", ".join(sorted(requested - actual))
        raise ValueError(
            f"o certificado não cobre todos os domínios pedidos no CSR (faltando: {faltando})"
        )
