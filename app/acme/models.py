from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum


class AcmeEnvironment(StrEnum):
    STAGING = "staging"
    PRODUCTION = "production"


class AcmeJobState(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


@dataclass
class AcmeJob:
    domain: str
    environment: AcmeEnvironment
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    state: AcmeJobState = AcmeJobState.PENDING
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    progress_message: str = ""
    error: str | None = None
    certificate_id: str | None = None
