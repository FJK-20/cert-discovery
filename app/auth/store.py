"""Persistência do admin único em um arquivo JSON local.

Só existe um admin (não é um sistema multiusuário — foge do escopo deste
MVP). O arquivo sobrevive a reinícios do container via volume Docker (ver
docker-compose.yml) e é criado com permissão 0600 (contém hash de senha e
segredo TOTP, ambos sensíveis).

`mfa_enabled=False` indica um cadastro iniciado mas não confirmado: o admin
só é considerado "pronto para uso" depois de validar um código do
autenticador — é assim que o MFA é obrigatório, sem opção de pular.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path

from app.core.config import settings


@dataclass
class AdminAccount:
    username: str
    password_hash: str
    totp_secret: str
    mfa_enabled: bool = False


class AdminStore:
    def __init__(self, data_dir: Path) -> None:
        self._path = data_dir / "admin.json"

    def load(self) -> AdminAccount | None:
        if not self._path.exists():
            return None
        data = json.loads(self._path.read_text())
        return AdminAccount(**data)

    def save(self, account: AdminAccount) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(asdict(account)))
        os.chmod(self._path, 0o600)


admin_store = AdminStore(Path(settings.data_dir))
