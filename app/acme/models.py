from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum


class AcmeEnvironment(StrEnum):
    STAGING = "staging"
    PRODUCTION = "production"


class DnsMode(StrEnum):
    """Como o desafio DNS-01 é resolvido. `MANUAL` é o padrão genérico —
    funciona com qualquer provedor de DNS, sem credencial nenhuma.
    `CLOUDFLARE` é um plugin opcional pra quem quer automação total."""

    MANUAL = "manual"
    CLOUDFLARE = "cloudflare"


class AcmeJobState(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    AWAITING_DNS = "awaiting_dns"
    DONE = "done"
    FAILED = "failed"


@dataclass
class AcmeJob:
    domain: str
    environment: AcmeEnvironment
    dns_mode: DnsMode = DnsMode.MANUAL
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    state: AcmeJobState = AcmeJobState.PENDING
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    progress_message: str = ""
    error: str | None = None
    certificate_id: str | None = None
    # Preenchidos quando dns_mode=manual e o job entra em AWAITING_DNS —
    # é o que a tela de Emissão mostra pro usuário criar no DNS dele.
    dns_record_name: str | None = None
    dns_record_value: str | None = None
