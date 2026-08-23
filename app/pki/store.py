"""Persistência dos CSRs pendentes — gerados aqui, esperando o
certificado assinado voltar de uma CA externa. Diferente dos jobs ACME
(que resolvem em minutos), esse fluxo pode levar dias (alguém preenchendo
um formulário de CA comercial, ou esperando o time de PKI interno
assinar), então fica em disco, não em memória — o app pode reiniciar no
meio da espera sem perder o CSR nem a chave gerada. Mesmo padrão de
app/acme/store.py: JSON em `data/`, permissão 0600, chave privada
criptografada em repouso (app/core/crypto.py) — o CSR em si (`csr_pem`)
não é sensível (só a chave pública), fica em texto plano."""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from app.core.config import settings
from app.core.crypto import DecryptionError, SecretBox


@dataclass
class PendingCsr:
    domains: list[str]
    private_key_pem: str
    csr_pem: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    # Contexto opcional (Fase 8) — capturado na criação do CSR (quando a
    # pessoa sabe pra que é), carregado até a conclusão em IssuedCertificate.
    organization_id: str | None = None
    system_id: str | None = None
    project_id: str | None = None


class PendingCsrStore:
    def __init__(self, data_dir: Path) -> None:
        self._dir = data_dir / "pending_csrs"
        self._box = SecretBox(data_dir)

    def _decrypt(self, raw: dict) -> dict:
        try:
            raw["private_key_pem"] = self._box.decrypt(raw["private_key_pem"])
        except DecryptionError:
            pass  # dado legado em texto plano — recriptografado no próximo save()
        return raw

    def save(self, pending: PendingCsr) -> None:
        self._dir.mkdir(parents=True, exist_ok=True)
        path = self._dir / f"{pending.id}.json"
        entry = asdict(pending)
        entry["private_key_pem"] = self._box.encrypt(entry["private_key_pem"])
        path.write_text(json.dumps(entry))
        os.chmod(path, 0o600)

    def load(self, csr_id: str) -> PendingCsr | None:
        path = self._dir / f"{csr_id}.json"
        if not path.exists():
            return None
        return PendingCsr(**self._decrypt(json.loads(path.read_text())))

    def delete(self, csr_id: str) -> None:
        path = self._dir / f"{csr_id}.json"
        path.unlink(missing_ok=True)

    def list(self) -> list[PendingCsr]:
        if not self._dir.exists():
            return []
        paths = sorted(self._dir.glob("*.json"))
        pending = [PendingCsr(**self._decrypt(json.loads(p.read_text()))) for p in paths]
        return sorted(pending, key=lambda p: p.created_at, reverse=True)


pending_csr_store = PendingCsrStore(Path(settings.data_dir))
