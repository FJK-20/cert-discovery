"""Classificação de urgência — função pura, sem I/O, fácil de testar.

Só se aplica a certificados confirmados por handshake ao vivo: é sobre eles
que faz sentido falar em "está servido agora e vai expirar em X dias".
"""

from __future__ import annotations

from datetime import UTC, datetime

from app.domain.models import Status

CRITICAL_THRESHOLD_DAYS = 7
WARNING_THRESHOLD_DAYS = 30


def days_until(not_after: datetime, *, now: datetime | None = None) -> int:
    reference = now or datetime.now(UTC)
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=UTC)
    delta = not_after - reference
    return delta.days


def classify(not_after: datetime, *, now: datetime | None = None) -> tuple[Status, int]:
    """Retorna (status, dias_restantes) para um certificado confirmado ao vivo."""
    days_left = days_until(not_after, now=now)
    if days_left < 0:
        return Status.EXPIRED, days_left
    if days_left < CRITICAL_THRESHOLD_DAYS:
        return Status.CRITICAL, days_left
    if days_left < WARNING_THRESHOLD_DAYS:
        return Status.WARNING, days_left
    return Status.OK, days_left


def renewal_priority(status: Status) -> int:
    """Menor número = mais urgente. Usado para ordenar a fila de renovação."""
    order = {
        Status.EXPIRED: 0,
        Status.CRITICAL: 1,
        Status.WARNING: 2,
        Status.OK: 3,
        Status.CT_ONLY: 4,
        Status.WILDCARD: 5,
        Status.UNRESOLVED: 6,
    }
    return order.get(status, 99)
