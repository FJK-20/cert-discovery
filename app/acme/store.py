"""Persistência do módulo ACME: conta por ambiente (staging/produção),
credenciais do provedor DNS e certificados emitidos.

Mesmo padrão de app/auth/store.py: arquivos JSON em `data/`, permissão
0600 — tudo aqui é sensível (chave de conta ACME, token de API do
provedor DNS, e as próprias chaves privadas dos certificados emitidos).
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path

from app.core.config import settings


@dataclass
class AcmeAccount:
    environment: str
    account_key_pem: str
    account_uri: str


@dataclass
class DnsCredentials:
    provider: str
    api_token: str
    # Domínio (zona) que o token controla, usado como alvo da delegação
    # CNAME — ver DnsMode.CNAME_DELEGATION em app/acme/renewal.py. Opcional:
    # sem isso, o token só serve pro modo "cloudflare" direto (zona igual
    # ao domínio emitido).
    delegation_zone: str | None = None


@dataclass
class IssuedCertificate:
    id: str
    domain: str
    environment: str
    issued_at: str
    not_after: str | None
    fullchain_pem: str
    private_key_pem: str


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))
    os.chmod(path, 0o600)


class AcmeStore:
    def __init__(self, data_dir: Path) -> None:
        self._accounts_path = data_dir / "acme_accounts.json"
        self._dns_path = data_dir / "dns_credentials.json"
        self._certs_dir = data_dir / "acme_certificates"

    def load_account(self, environment: str) -> AcmeAccount | None:
        if not self._accounts_path.exists():
            return None
        raw = json.loads(self._accounts_path.read_text())
        entry = raw.get(environment)
        return AcmeAccount(**entry) if entry else None

    def save_account(self, account: AcmeAccount) -> None:
        raw = {}
        if self._accounts_path.exists():
            raw = json.loads(self._accounts_path.read_text())
        raw[account.environment] = asdict(account)
        _write_json(self._accounts_path, raw)

    def load_dns_credentials(self) -> DnsCredentials | None:
        if not self._dns_path.exists():
            return None
        return DnsCredentials(**json.loads(self._dns_path.read_text()))

    def save_dns_credentials(self, creds: DnsCredentials) -> None:
        _write_json(self._dns_path, asdict(creds))

    def save_certificate(self, cert: IssuedCertificate) -> None:
        path = self._certs_dir / f"{cert.id}.json"
        _write_json(path, asdict(cert))

    def load_certificate(self, cert_id: str) -> IssuedCertificate | None:
        path = self._certs_dir / f"{cert_id}.json"
        if not path.exists():
            return None
        return IssuedCertificate(**json.loads(path.read_text()))

    def list_certificates(self) -> list[IssuedCertificate]:
        if not self._certs_dir.exists():
            return []
        certs = [
            IssuedCertificate(**json.loads(path.read_text()))
            for path in sorted(self._certs_dir.glob("*.json"))
        ]
        return sorted(certs, key=lambda c: c.issued_at, reverse=True)


acme_store = AcmeStore(Path(settings.data_dir))
