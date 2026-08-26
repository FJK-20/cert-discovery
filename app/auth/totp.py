"""TOTP (RFC 6238) implementado com a stdlib — sem dependência extra.

Compatível com apps autenticadores padrão (Google Authenticator, Authy,
1Password, etc.): SHA-1, 6 dígitos, período de 30s, conforme o default que
esses apps esperam.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
import time
import urllib.parse

DIGITS = 6
PERIOD_SECONDS = 30
VALID_WINDOW = 1  # tolera +/- 1 período (relógio do usuário levemente dessincronizado)


def generate_secret(length: int = 20) -> str:
    """Segredo aleatório em Base32 (formato esperado pelos apps autenticadores)."""
    return base64.b32encode(os.urandom(length)).decode("ascii").rstrip("=")


def _pad_base32(value: str) -> str:
    return value + "=" * ((8 - len(value) % 8) % 8)


def _hotp(secret: str, counter: int) -> str:
    key = base64.b32decode(_pad_base32(secret), casefold=True)
    counter_bytes = struct.pack(">Q", counter)
    digest = hmac.new(key, counter_bytes, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % (10**DIGITS)).zfill(DIGITS)


def totp_now(secret: str, *, timestamp: float | None = None) -> str:
    now = timestamp if timestamp is not None else time.time()
    counter = int(now // PERIOD_SECONDS)
    return _hotp(secret, counter)


def verify_totp(
    secret: str,
    code: str,
    *,
    last_counter: int | None = None,
    timestamp: float | None = None,
) -> int | None:
    """Retorna o counter do código usado se válido e ainda não consumido,
    ou `None` se inválido. Achado numa auditoria de robustez: sem
    rastrear consumo, um código observado (rede, ombro, log de acesso)
    valia de novo por toda a janela de tolerância (~90s) — TOTP é
    projetado pra ser de uso único, não só "válido por um tempo".

    `last_counter=None` (default) não aplica proteção de replay —
    comportamento original, usado na confirmação de enrollment (segredo
    acabou de nascer, não tem nada anterior pra reproduzir ainda).
    Passar o último counter já consumido da conta fecha o replay: um
    candidato `<= last_counter` é ignorado mesmo que o código bata."""
    if not code or not code.isdigit() or len(code) != DIGITS:
        return None
    now = timestamp if timestamp is not None else time.time()
    counter = int(now // PERIOD_SECONDS)
    for offset in range(-VALID_WINDOW, VALID_WINDOW + 1):
        candidate = counter + offset
        if last_counter is not None and candidate <= last_counter:
            continue
        if hmac.compare_digest(_hotp(secret, candidate), code):
            return candidate
    return None


def provisioning_uri(secret: str, *, account_name: str, issuer: str) -> str:
    label = urllib.parse.quote(f"{issuer}:{account_name}")
    query = {
        "secret": secret,
        "issuer": issuer,
        "algorithm": "SHA1",
        "digits": DIGITS,
        "period": PERIOD_SECONDS,
    }
    return f"otpauth://totp/{label}?{urllib.parse.urlencode(query)}"
