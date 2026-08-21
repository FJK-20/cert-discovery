"""Persistência de usuários (multiusuário, quatro papéis: `admin`,
`operador`, `auditor` e `leitor`) em um arquivo JSON local.

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

O segredo TOTP (ativo ou pendente) fica criptografado em repouso
(app/core/crypto.py) — quem tiver o segredo em texto plano consegue gerar
códigos MFA válidos pra sempre, então é tão sensível quanto uma senha. O
hash de senha em si não precisa dessa camada (já é irreversível por
natureza — scrypt).
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path

from app.core.config import settings
from app.core.crypto import DecryptionError, SecretBox

ROLE_ADMIN = "admin"
ROLE_OPERADOR = "operador"
ROLE_AUDITOR = "auditor"
ROLE_LEITOR = "leitor"
# Segregação de funções deliberada (mesmo espírito do "quem aprova não
# instala"): admin controla contas/config do sistema; operador roda o
# ciclo de vida de certificados no dia a dia mas nunca vê o log de
# auditoria nem gerencia usuários; auditor enxerga tudo pra fins de
# compliance mas não consegue agir; leitor só vê o inventário/certificados.
# Não são hierárquicos entre si (operador e auditor são papéis paralelos,
# não um "acima" do outro) — só admin tem acesso a tudo.
ROLES = (ROLE_ADMIN, ROLE_OPERADOR, ROLE_AUDITOR, ROLE_LEITOR)


@dataclass
class UserAccount:
    username: str
    password_hash: str
    role: str = ROLE_ADMIN
    totp_secret: str = ""
    mfa_enabled: bool = False
    pending_totp_secret: str | None = None
    # "local" (usuário/senha, o padrão) ou "saml" (provisionado
    # automaticamente no primeiro login SSO — ver app/auth/saml.py). Conta
    # "saml" nunca tem senha utilizável (password_hash é lixo aleatório
    # gerado na criação, nunca combina com nada) — login por senha pra
    # essas contas é sempre rejeitado, mesmo que alguém tente string vazia.
    auth_source: str = "local"


@dataclass
class SamlIdpConfig:
    """Config do IdP (Entra ID ou qualquer IdP SAML 2.0 padrão) — nada
    aqui é segredo: `x509_cert` é a chave PÚBLICA de assinatura do IdP,
    existe justamente pra ser compartilhada (é o que prova que uma
    resposta SAML veio mesmo do IdP configurado)."""

    entity_id: str
    sso_url: str
    x509_cert: str


class UserStore:
    def __init__(self, data_dir: Path) -> None:
        self._path = data_dir / "admin.json"
        self._saml_path = data_dir / "saml_idp_config.json"
        self._box = SecretBox(data_dir)

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
            entry.setdefault("auth_source", "local")
        return raw

    def _save_all(self, users: dict[str, dict]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(users))
        os.chmod(self._path, 0o600)

    def _decrypt_secret(self, value: str | None) -> str | None:
        if not value:
            return value
        try:
            return self._box.decrypt(value)
        except DecryptionError:
            return value  # dado legado em texto plano — recriptografado no próximo save()

    def _to_account(self, entry: dict) -> UserAccount:
        entry = dict(entry)
        entry["totp_secret"] = self._decrypt_secret(entry.get("totp_secret")) or ""
        entry["pending_totp_secret"] = self._decrypt_secret(entry.get("pending_totp_secret"))
        return UserAccount(**entry)

    def load(self, username: str) -> UserAccount | None:
        entry = self._load_all().get(username)
        return self._to_account(entry) if entry else None

    def save(self, account: UserAccount) -> None:
        users = self._load_all()
        entry = asdict(account)
        entry["totp_secret"] = self._box.encrypt(entry["totp_secret"])
        entry["pending_totp_secret"] = self._box.encrypt(entry["pending_totp_secret"])
        users[account.username] = entry
        self._save_all(users)

    def delete(self, username: str) -> None:
        users = self._load_all()
        users.pop(username, None)
        self._save_all(users)

    def list_all(self) -> list[UserAccount]:
        return sorted(
            (self._to_account(entry) for entry in self._load_all().values()),
            key=lambda u: u.username,
        )

    def count(self) -> int:
        return len(self._load_all())

    def count_admins(self) -> int:
        return sum(1 for u in self.list_all() if u.role == ROLE_ADMIN)

    def load_saml_config(self) -> SamlIdpConfig | None:
        if not self._saml_path.exists():
            return None
        return SamlIdpConfig(**json.loads(self._saml_path.read_text()))

    def save_saml_config(self, config: SamlIdpConfig) -> None:
        self._saml_path.parent.mkdir(parents=True, exist_ok=True)
        self._saml_path.write_text(json.dumps(asdict(config)))
        os.chmod(self._saml_path, 0o600)


user_store = UserStore(Path(settings.data_dir))
