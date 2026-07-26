"""Hash de senha via scrypt (stdlib `hashlib`, sem dependência extra).

Parâmetros (n=2**14, r=8, p=1) seguem a recomendação mínima do OWASP para
scrypt em login interativo — memory-hard, resistente a força bruta em GPU,
com custo de CPU aceitável para um único admin logando ocasionalmente.
"""

from __future__ import annotations

import hashlib
import hmac
import os

_N = 2**14
_R = 8
_P = 1
_DKLEN = 64
_SALT_BYTES = 16


def hash_password(password: str) -> str:
    salt = os.urandom(_SALT_BYTES)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=_N, r=_R, p=_P, dklen=_DKLEN)
    return f"{salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split("$", 1)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except (ValueError, IndexError):
        return False
    candidate = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=_N, r=_R, p=_P, dklen=len(expected)
    )
    return hmac.compare_digest(candidate, expected)
