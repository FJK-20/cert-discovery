"""Configuração de notificação — webhook genérico e/ou SMTP simples.
Mesmo padrão dos outros stores: JSON em `data/`, permissão 0600 (a senha
SMTP é sensível)."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path

from app.core.config import settings


@dataclass
class NotificationConfig:
    webhook_url: str | None = None
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_use_tls: bool = True
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from: str | None = None
    smtp_to: str | None = None


class NotificationStore:
    def __init__(self, data_dir: Path) -> None:
        self._path = data_dir / "notification_config.json"

    def load(self) -> NotificationConfig | None:
        if not self._path.exists():
            return None
        return NotificationConfig(**json.loads(self._path.read_text()))

    def save(self, config: NotificationConfig) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(asdict(config)))
        os.chmod(self._path, 0o600)


notification_store = NotificationStore(Path(settings.data_dir))
