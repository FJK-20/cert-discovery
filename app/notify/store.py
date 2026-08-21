"""Configuração de notificação — webhook genérico e/ou SMTP simples.
Mesmo padrão dos outros stores: JSON em `data/`, permissão 0600, e a senha
SMTP (o campo sensível daqui) criptografada em repouso (app/core/crypto.py)
— mesma migração transparente de dado legado que app/acme/store.py."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path

from app.core.config import settings
from app.core.crypto import DecryptionError, SecretBox


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
        self._box = SecretBox(data_dir)

    def load(self) -> NotificationConfig | None:
        if not self._path.exists():
            return None
        raw = json.loads(self._path.read_text())
        password = raw.get("smtp_password")
        if password:
            try:
                raw["smtp_password"] = self._box.decrypt(password)
            except DecryptionError:
                pass  # dado legado em texto plano — recriptografado no próximo save()
        return NotificationConfig(**raw)

    def save(self, config: NotificationConfig) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        entry = asdict(config)
        entry["smtp_password"] = self._box.encrypt(entry["smtp_password"])
        self._path.write_text(json.dumps(entry))
        os.chmod(self._path, 0o600)


notification_store = NotificationStore(Path(settings.data_dir))
