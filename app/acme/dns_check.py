"""Verifica se um registro TXT específico já está visível publicamente —
usado no modo manual do DNS-01 pra confirmar que a pessoa criou o registro
certo antes de avisar a CA (evita gastar uma tentativa de validação, que
tem rate limit, num registro que ainda não propagou)."""

from __future__ import annotations

import dns.asyncresolver
import dns.exception


async def txt_record_contains(hostname: str, expected_value: str, *, timeout: float) -> bool:
    try:
        answer = await dns.asyncresolver.resolve(hostname, "TXT", lifetime=timeout)
    except (dns.exception.DNSException, OSError):
        return False
    for rdata in answer:
        value = b"".join(rdata.strings).decode("utf-8", errors="replace")
        if value == expected_value:
            return True
    return False


async def cname_matches(hostname: str, expected_target: str, *, timeout: float) -> bool:
    """True se `hostname` for um CNAME apontando pro `expected_target`
    (usado no modo de delegação: a pessoa configura o CNAME uma vez, e
    daí em diante toda renovação usa esse mesmo registro sem precisar de
    mais nenhuma ação manual)."""
    try:
        answer = await dns.asyncresolver.resolve(hostname, "CNAME", lifetime=timeout)
    except (dns.exception.DNSException, OSError):
        return False
    expected = expected_target.strip(".").lower()
    return any(str(rdata.target).strip(".").lower() == expected for rdata in answer)
