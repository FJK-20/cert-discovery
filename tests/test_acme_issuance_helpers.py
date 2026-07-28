"""Testes das funções puras de app/acme/issuance.py (serialização de
chave, geração de CSR) — sem tocar em rede/ACME real."""

from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from app.acme.issuance import (
    _build_csr,
    _deserialize_private_key,
    _serialize_private_key,
)


def test_serialize_and_deserialize_private_key_round_trip():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = _serialize_private_key(key)
    assert "PRIVATE KEY" in pem

    restored = _deserialize_private_key(pem)
    assert restored.private_numbers() == key.private_numbers()


def test_build_csr_has_correct_cn_and_san():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr_pem = _build_csr("app.example.com", key)
    csr = x509.load_pem_x509_csr(csr_pem)

    cn = csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    assert cn == "app.example.com"

    san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    assert san.value.get_values_for_type(x509.DNSName) == ["app.example.com"]

    assert csr.is_signature_valid
