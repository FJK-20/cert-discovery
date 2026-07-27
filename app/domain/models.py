from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum


class Origin(StrEnum):
    """De onde veio o achado: só do CT log, ou confirmado por handshake ao vivo."""

    CT_LOG = "ct_log"
    LIVE = "live"


class Status(StrEnum):
    # Classificações reais, só aplicáveis a certificados confirmados ao vivo.
    EXPIRED = "expired"
    CRITICAL = "critical"  # expira em < 7 dias
    WARNING = "warning"    # expira em < 30 dias
    OK = "ok"
    # Achados apenas de CT log, sem confirmação por handshake — nunca
    # recebem uma das classificações acima, para não sugerir uma certeza
    # que os dados não sustentam.
    WILDCARD = "wildcard"
    UNRESOLVED = "unresolved"
    CT_ONLY = "ct_only"


@dataclass
class CertificateRecord:
    host: str
    origin: Origin
    status: Status
    subject_cn: str | None = None
    issuer: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    days_until_expiry: int | None = None
    serial_number: str | None = None
    sha256_fingerprint: str | None = None
    sans: list[str] = field(default_factory=list)
    resolved_ip: str | None = None
    note: str | None = None


class JobState(StrEnum):
    PENDING = "pending"
    DISCOVERING_HOSTS = "discovering_hosts"
    RESOLVING_DNS = "resolving_dns"
    PROBING_TLS = "probing_tls"
    DONE = "done"
    PARTIAL_TIMEOUT = "partial_timeout"
    FAILED = "failed"


@dataclass
class ScanJob:
    domain: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    state: JobState = JobState.PENDING
    # datetime.utcnow() é naive e faz `.timestamp()` assumir fuso local — em
    # servidor fora de UTC isso desalinha o cálculo de TTL em _evict_expired.
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    progress_message: str = ""
    hosts_total: int = 0
    hosts_done: int = 0
    records: list[CertificateRecord] = field(default_factory=list)
    error: str | None = None
