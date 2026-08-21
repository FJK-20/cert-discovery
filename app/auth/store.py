"""Persistência de usuários (multiusuário, dois papéis simples: `admin` e
`leitor`) em um arquivo JSON local.

O arquivo sobrevive a reinícios do container via volume Docker (ver
docker-compose.yml) e é criado com permissão 0600 (contém hash de senha e
segredo TOTP de cada usuário, ambos sensíveis).

Migração automática e silenciosa do formato antigo (Fase 0-3: um admin só,
objeto plano no topo do arquivo) pro novo (dict por username) — o arquivo
real já em produção (`data/admin.json`) tem esse formato antigo, e a
primeira leitura depois do deploy precisa continuar autenticando o mesmo
admin sem exigir um cadastro novo. Detecção: formato antigo tem `username`
na raiz; novo tem usernames como chaves.

MFA é opcional, desligado por padrão, por usuário (`mfa_enabled=False`).
Cada usuário ativa o próprio quando quiser, já autenticado, via
`/api/auth/mfa/enroll` — nunca fica habilitado sem antes confirmar um
código válido (`pending_totp_secret` -> `totp_secret` só depois de
`verify_totp` passar).
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path

from app.core.config import settings

ROLE_ADMIN = "admin"
ROLE_LEITOR = "leitor"
ROLES = (ROLE_ADMIN, ROLE_LEITOR)


@dataclass
class UserAccount:
    username: str
    password_hash: str
    role: str = ROLE_ADMIN
    totp_secret: str = ""
    mfa_enabled: bool = False
    pending_totp_secret: str | None = None


class UserStore:
    def __init__(self, data_dir: Path) -> None:
        self._path = data_dir / "admin.json"

    def _load_all(self) -> dict[str, dict]:
        if not self._path.exists():
            return {}
        raw = json.loads(self._path.read_text())
        if "username" in raw:
            # Formato antigo (Fase 0-3): um único admin, objeto plano.
            raw = {raw["username"]: raw}
        for entry in raw.values():
            # Usuário migrado do formato antigo não tinha `role` — todo
            # usuário pré-existente era, por definição, o admin único.
            entry.setdefault("role", ROLE_ADMIN)
        return raw

    def _save_all(self, users: dict[str, dict]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(users))
        os.chmod(self._path, 0o600)

    def load(self, username: str) -> UserAccount | None:
        entry = self._load_all().get(username)
        return UserAccount(**entry) if entry else None

    def save(self, account: UserAccount) -> None:
        users = self._load_all()
        users[account.username] = asdict(account)
        self._save_all(users)

    def delete(self, username: str) -> None:
        users = self._load_all()
        users.pop(username, None)
        self._save_all(users)

    def list_all(self) -> list[UserAccount]:
        return sorted(
            (UserAccount(**entry) for entry in self._load_all().values()),
            key=lambda u: u.username,
        )

    def count(self) -> int:
        return len(self._load_all())

    def count_admins(self) -> int:
        return sum(1 for u in self.list_all() if u.role == ROLE_ADMIN)


user_store = UserStore(Path(settings.data_dir))
