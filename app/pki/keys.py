"""Geração e (de)serialização de chave privada — compartilhado entre a
emissão ACME (app/acme/issuance.py) e o fluxo manual de CSR
(app/pki/csr.py). RSA 2048 em todo lugar, por consistência; nunca sai do
processo em texto puro fora de um download explícito pedido pelo usuário."""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

KEY_SIZE = 2048


def generate_private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE)


def serialize_private_key(key: rsa.RSAPrivateKey) -> str:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


def deserialize_private_key(pem: str) -> rsa.RSAPrivateKey:
    key = serialization.load_pem_private_key(pem.encode(), password=None)
    assert isinstance(key, rsa.RSAPrivateKey)
    return key
