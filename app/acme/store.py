"""Persistência do módulo ACME: conta por ambiente (staging/produção),
credenciais do provedor DNS e certificados emitidos.

Mesmo padrão de app/auth/store.py: arquivos JSON em `data/`, permissão
0600 — tudo aqui é sensível (chave de conta ACME, token de API do
provedor DNS, e as próprias chaves privadas dos certificados emitidos).

Os campos mais sensíveis (`account_key_pem`, `api_token`,
`private_key_pem`) ficam criptografados em repouso (app/core/crypto.py) —
só o texto plano em memória, nunca no arquivo. Dado gravado antes dessa
camada existir (Fase 0-3) ainda é texto plano no disco: `_maybe_decrypt`
detecta que não é um token Fernet válido e devolve como está, sem quebrar
— e o próximo `save()` já grava criptografado, migração transparente sem
precisar de um passo manual.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path

from app.core.config import settings
from app.core.crypto import DecryptionError, SecretBox


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
class CaCredentials:
    ca: str
    # kid é um identificador, não segredo por si só — mas hmac_key é a
    # chave de assinatura da External Account Binding, tão sensível quanto
    # o token de um provedor de DNS.
    eab_kid: str
    eab_hmac_key: str


@dataclass
class IssuedCertificate:
    id: str
    domain: str
    environment: str
    issued_at: str
    not_after: str | None
    fullchain_pem: str
    private_key_pem: str
    # None pros certificados manuais via CSR (não tem como renovar sozinho
    # — precisa de uma pessoa levando um CSR novo pra CA de novo). Pros
    # emitidos via ACME, guarda o dns_mode usado (ver app.acme.models) —
    # é o que o agendador de renovação (app/acme/scheduler.py) consulta
    # pra saber se pode tentar renovar sem intervenção humana.
    dns_mode: str | None = None
    # Mesma ideia do dns_mode acima, mas pra CA: None pros manuais via
    # CSR, "letsencrypt" ou "zerossl" pros emitidos via ACME. Só
    # bookkeeping/exibição — qualquer CA funciona com qualquer dns_mode,
    # não afeta a lógica de renovação.
    ca: str | None = None


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))
    os.chmod(path, 0o600)


def _maybe_decrypt(box: SecretBox, value: str | None) -> str | None:
    if not value:
        return value
    try:
        return box.decrypt(value)
    except DecryptionError:
        return value  # dado legado ainda em texto plano — recriptografado no próximo save()


class AcmeStore:
    def __init__(self, data_dir: Path) -> None:
        self._accounts_path = data_dir / "acme_accounts.json"
        self._dns_path = data_dir / "dns_credentials.json"
        self._ca_credentials_path = data_dir / "ca_credentials.json"
        self._certs_dir = data_dir / "acme_certificates"
        self._box = SecretBox(data_dir)

    def load_account(self, environment: str) -> AcmeAccount | None:
        if not self._accounts_path.exists():
            return None
        raw = json.loads(self._accounts_path.read_text())
        entry = raw.get(environment)
        if not entry:
            return None
        entry["account_key_pem"] = _maybe_decrypt(self._box, entry["account_key_pem"])
        return AcmeAccount(**entry)

    def save_account(self, account: AcmeAccount) -> None:
        raw = {}
        if self._accounts_path.exists():
            raw = json.loads(self._accounts_path.read_text())
        entry = asdict(account)
        entry["account_key_pem"] = self._box.encrypt(entry["account_key_pem"])
        raw[account.environment] = entry
        _write_json(self._accounts_path, raw)

    def load_dns_credentials(self) -> DnsCredentials | None:
        if not self._dns_path.exists():
            return None
        raw = json.loads(self._dns_path.read_text())
        raw["api_token"] = _maybe_decrypt(self._box, raw["api_token"])
        return DnsCredentials(**raw)

    def save_dns_credentials(self, creds: DnsCredentials) -> None:
        entry = asdict(creds)
        entry["api_token"] = self._box.encrypt(entry["api_token"])
        _write_json(self._dns_path, entry)

    def load_ca_credentials(self, ca: str) -> CaCredentials | None:
        if not self._ca_credentials_path.exists():
            return None
        raw = json.loads(self._ca_credentials_path.read_text())
        entry = raw.get(ca)
        if not entry:
            return None
        entry["eab_hmac_key"] = _maybe_decrypt(self._box, entry["eab_hmac_key"])
        return CaCredentials(**entry)

    def save_ca_credentials(self, creds: CaCredentials) -> None:
        raw = {}
        if self._ca_credentials_path.exists():
            raw = json.loads(self._ca_credentials_path.read_text())
        entry = asdict(creds)
        entry["eab_hmac_key"] = self._box.encrypt(entry["eab_hmac_key"])
        raw[creds.ca] = entry
        _write_json(self._ca_credentials_path, raw)

    def save_certificate(self, cert: IssuedCertificate) -> None:
        path = self._certs_dir / f"{cert.id}.json"
        entry = asdict(cert)
        entry["private_key_pem"] = self._box.encrypt(entry["private_key_pem"])
        _write_json(path, entry)

    def load_certificate(self, cert_id: str) -> IssuedCertificate | None:
        path = self._certs_dir / f"{cert_id}.json"
        if not path.exists():
            return None
        raw = json.loads(path.read_text())
        raw["private_key_pem"] = _maybe_decrypt(self._box, raw["private_key_pem"])
        return IssuedCertificate(**raw)

    def list_certificates(self) -> list[IssuedCertificate]:
        if not self._certs_dir.exists():
            return []
        certs = []
        for path in sorted(self._certs_dir.glob("*.json")):
            raw = json.loads(path.read_text())
            raw["private_key_pem"] = _maybe_decrypt(self._box, raw["private_key_pem"])
            certs.append(IssuedCertificate(**raw))
        return sorted(certs, key=lambda c: c.issued_at, reverse=True)


acme_store = AcmeStore(Path(settings.data_dir))
