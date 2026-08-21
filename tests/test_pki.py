"""Testes das funções puras de app/pki/{keys,csr}.py — geração/serialização
de chave, CSR (single e multi-domínio), e a checagem que garante que um
certificado enviado de volta pra um CSR manual é resposta daquele pedido
específico. Nada aqui toca rede — é usado tanto pela emissão ACME quanto
pelo fluxo manual de CSR."""

from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from app.pki import csr as pki_csr
from app.pki import keys as pki_keys


def test_serialize_and_deserialize_private_key_round_trip():
    key = pki_keys.generate_private_key()
    pem = pki_keys.serialize_private_key(key)
    assert "PRIVATE KEY" in pem

    restored = pki_keys.deserialize_private_key(pem)
    assert restored.private_numbers() == key.private_numbers()


def test_build_csr_single_domain_has_correct_cn_and_san():
    key = pki_keys.generate_private_key()
    csr_pem = pki_csr.build_csr(["app.example.com"], key)
    csr = x509.load_pem_x509_csr(csr_pem)

    cn = csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    assert cn == "app.example.com"

    san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    assert san.value.get_values_for_type(x509.DNSName) == ["app.example.com"]
    assert csr.is_signature_valid


def test_build_csr_multi_domain_cn_is_first_all_are_san():
    key = pki_keys.generate_private_key()
    domains = ["example.com", "www.example.com", "app.example.com"]
    csr_pem = pki_csr.build_csr(domains, key)
    csr = x509.load_pem_x509_csr(csr_pem)

    cn = csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    assert cn == "example.com"

    san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    assert san.value.get_values_for_type(x509.DNSName) == domains


def test_build_csr_rejects_empty_domain_list():
    key = pki_keys.generate_private_key()
    try:
        pki_csr.build_csr([], key)
        raised = False
    except ValueError:
        raised = True
    assert raised


def _self_signed_cert(domains: list[str], key: rsa.RSAPrivateKey) -> str:
    """Simula "a CA respondeu" — não é o fluxo real (nenhuma CA assina CSR
    self-signed), só um jeito offline de gerar um certificado com uma
    chave pública conhecida pra testar a checagem de correspondência."""
    from datetime import UTC, datetime, timedelta

    from cryptography.hazmat.primitives import hashes, serialization

    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, domains[0])])
    san = x509.SubjectAlternativeName([x509.DNSName(d) for d in domains])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=90))
        .add_extension(san, critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def test_certificate_matches_key_true_for_the_right_key():
    key = pki_keys.generate_private_key()
    cert_pem = _self_signed_cert(["app.example.com"], key)
    key_pem = pki_keys.serialize_private_key(key)
    assert pki_csr.certificate_matches_key(cert_pem, key_pem) is True


def test_certificate_matches_key_false_for_a_different_key():
    key = pki_keys.generate_private_key()
    other_key = pki_keys.generate_private_key()
    cert_pem = _self_signed_cert(["app.example.com"], key)
    other_key_pem = pki_keys.serialize_private_key(other_key)
    assert pki_csr.certificate_matches_key(cert_pem, other_key_pem) is False


def test_certificate_info_returns_sans_and_expiry():
    key = pki_keys.generate_private_key()
    domains = ["example.com", "www.example.com"]
    cert_pem = _self_signed_cert(domains, key)
    found_domains, not_after = pki_csr.certificate_info(cert_pem)
    assert found_domains == domains
    assert not_after is not None
