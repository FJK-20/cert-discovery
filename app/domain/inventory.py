"""Consolidação do inventário: dedupe e ordenação para a fila de renovação."""

from __future__ import annotations

from app.domain.models import CertificateRecord, Origin
from app.domain.urgency import renewal_priority


def dedupe_live_records(records: list[CertificateRecord]) -> list[CertificateRecord]:
    """Dedupe por fingerprint SHA-256, único espaço de identidade confiável
    (o mesmo certificado pode estar servido em vários hosts/IPs).
    """
    seen: dict[str, CertificateRecord] = {}
    others: list[CertificateRecord] = []
    for record in records:
        if record.origin is Origin.LIVE and record.sha256_fingerprint:
            existing = seen.get(record.sha256_fingerprint)
            if existing is None:
                seen[record.sha256_fingerprint] = record
            else:
                # Mesmo certificado servido em outro host: mantém o primeiro
                # registro e anota o host adicional para não perder a informação.
                base_note = existing.note or f"Também servido em: {existing.host}"
                existing.note = f"{base_note}, {record.host}"
        else:
            others.append(record)
    return list(seen.values()) + others


def build_inventory(records: list[CertificateRecord]) -> list[CertificateRecord]:
    """Consolida, deduplica e ordena por urgência (a fila de renovação é
    simplesmente este inventário ordenado — os itens mais urgentes primeiro)."""
    deduped = dedupe_live_records(records)
    return sorted(deduped, key=lambda r: (renewal_priority(r.status), r.days_until_expiry or 0))


def renewal_queue(records: list[CertificateRecord]) -> list[CertificateRecord]:
    """Subconjunto da fila que realmente precisa de atenção (exclui OK e achados
    apenas de CT log/wildcard/não resolvidos, que não são acionáveis)."""
    from app.domain.models import Status

    actionable = {Status.EXPIRED, Status.CRITICAL, Status.WARNING}
    return [r for r in build_inventory(records) if r.status in actionable]
