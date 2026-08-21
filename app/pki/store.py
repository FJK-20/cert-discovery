"""Persistência dos CSRs pendentes — gerados aqui, esperando o
certificado assinado voltar de uma CA externa. Diferente dos jobs ACME
(que resolvem em minutos), esse fluxo pode levar dias (alguém preenchendo
um formulário de CA comercial, ou esperando o time de PKI interno
assinar), então fica em disco, não em memória — o app pode reiniciar no
meio da espera sem perder o CSR nem a chave gerada. Mesmo padrão de
app/acme/store.py: JSON em `data/`, permissão 0600."""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from app.core.config import settings


@dataclass
class PendingCsr:
    domains: list[str]
    private_key_pem: str
    csr_pem: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


class PendingCsrStore:
    def __init__(self, data_dir: Path) -> None:
        self._dir = data_dir / "pending_csrs"

    def save(self, pending: PendingCsr) -> None:
        self._dir.mkdir(parents=True, exist_ok=True)
        path = self._dir / f"{pending.id}.json"
        path.write_text(json.dumps(asdict(pending)))
        os.chmod(path, 0o600)

    def load(self, csr_id: str) -> PendingCsr | None:
        path = self._dir / f"{csr_id}.json"
        if not path.exists():
            return None
        return PendingCsr(**json.loads(path.read_text()))

    def delete(self, csr_id: str) -> None:
        path = self._dir / f"{csr_id}.json"
        path.unlink(missing_ok=True)

    def list(self) -> list[PendingCsr]:
        if not self._dir.exists():
            return []
        paths = sorted(self._dir.glob("*.json"))
        pending = [PendingCsr(**json.loads(p.read_text())) for p in paths]
        return sorted(pending, key=lambda p: p.created_at, reverse=True)


pending_csr_store = PendingCsrStore(Path(settings.data_dir))
