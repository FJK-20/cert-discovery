"""Hash de senha via scrypt (stdlib `hashlib`, sem dependência extra).

Parâmetros (n=2**17, r=8, p=1) seguem a recomendação ATUAL do OWASP
Password Storage Cheat Sheet pra scrypt (128 MiB por hash) — achado numa
auditoria de robustez: o valor anterior (n=2**14, 16 MiB) era o mínimo de
uma versão antiga da mesma recomendação, 8x mais fraco que o atual.

Formato do hash embute o `n` usado (`"{n}$salt$digest"`) — sem isso, subir
`_N` no código quebraria a verificação de toda senha já salva com o valor
antigo (scrypt exige os MESMOS parâmetros pra bater o hash), forçando
reset de senha de quem já tinha conta. `verify_password` ainda aceita o
formato legado de 2 campos (`salt$digest`, sem `n` — assume `_LEGACY_N`,
o único valor que este código já usou antes deste fix) pelas contas
existentes; `needs_rehash` sinaliza pro chamador (routes_auth.py)
recalcular com os parâmetros atuais no próximo login bem-sucedido —
migração transparente, mesmo espírito do `_maybe_decrypt` em
app/core/crypto.py pra segredo cifrado."""

from __future__ import annotations

import hashlib
import hmac
import os

_N = 2**17
_LEGACY_N = 2**14
_R = 8
_P = 1
_DKLEN = 64
_SALT_BYTES = 16


def _maxmem_for(n: int) -> int:
    # hashlib.scrypt's default maxmem (0 -> limite padrão do OpenSSL) é
    # baixo demais pro N atual — 128 MiB reais (n=2**17, r=8) já estoura
    # esse teto com "memory limit exceeded". Fórmula padrão de memória do
    # scrypt é ~128*N*r bytes; folga de ~1.25x pra margem de segurança.
    return 130 * n * _R


def hash_password(password: str) -> str:
    salt = os.urandom(_SALT_BYTES)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=_N, r=_R, p=_P, maxmem=_maxmem_for(_N), dklen=_DKLEN
    )
    return f"{_N}${salt.hex()}${digest.hex()}"


def _parse_stored(stored: str) -> tuple[int, bytes, bytes] | None:
    parts = stored.split("$")
    try:
        if len(parts) == 3:
            n = int(parts[0])
            salt, expected = bytes.fromhex(parts[1]), bytes.fromhex(parts[2])
        elif len(parts) == 2:
            n = _LEGACY_N
            salt, expected = bytes.fromhex(parts[0]), bytes.fromhex(parts[1])
        else:
            return None
    except (ValueError, IndexError):
        return None
    return n, salt, expected


def verify_password(password: str, stored: str) -> bool:
    parsed = _parse_stored(stored)
    if parsed is None:
        return False
    n, salt, expected = parsed
    candidate = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=n,
        r=_R,
        p=_P,
        maxmem=_maxmem_for(n),
        dklen=len(expected),
    )
    return hmac.compare_digest(candidate, expected)


def needs_rehash(stored: str) -> bool:
    """True se o hash foi calculado com um `n` mais fraco que o atual
    (inclusive o formato legado, sempre `_LEGACY_N`) — chamador decide
    recalcular com `hash_password()` depois de uma verificação bem-
    sucedida, sem exigir reset de senha."""
    parsed = _parse_stored(stored)
    return parsed is None or parsed[0] < _N
