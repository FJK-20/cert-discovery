"""Configuração via variáveis de ambiente, com defaults seguros para demo pública."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    max_hosts_per_scan: int = _int_env("CERTDISC_MAX_HOSTS", 400)
    max_concurrent_probes: int = _int_env("CERTDISC_MAX_CONCURRENCY", 30)

    ctlogs_timeout_seconds: float = 20.0
    dns_timeout_seconds: float = 4.0
    tcp_connect_timeout_seconds: float = 4.0
    tls_handshake_timeout_seconds: float = 5.0

    job_total_budget_seconds: float = 90.0
    job_ttl_seconds: float = 15 * 60

    rate_limit_requests_per_minute: int = _int_env("CERTDISC_RATE_LIMIT_RPM", 6)


settings = Settings()
