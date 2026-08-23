"""Cadastros de contexto (Fase 8): Organizações, Sistemas e Projetos —
dimensões que a emissão/importação de certificado pode referenciar (quem
é o dono organizacional, qual sistema/projeto usa aquele certificado).

Sistema e Projeto são estruturalmente idênticos (nome + descrição +
status) — uma única classe genérica (`CatalogStore`, parametrizada pelo
nome da tabela) cobre os dois, em vez de duas classes coladas com a
mesma lógica. Organização tem campos próprios (endereço/contato
resumidos, sem virar um assistente de várias etapas) — `OrganizationStore`
não reaproveita `CatalogStore` porque o formato realmente é outro, não só
"mais alguns campos"."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from app.core.config import settings
from app.core.db import get_connection


@dataclass
class CatalogEntry:
    name: str
    description: str = ""
    status: str = "active"
    created_by: str | None = None
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


class CatalogStore:
    """Reaproveitada pra `systems` e `projects` — mesmo esquema de
    tabela nos dois, só o nome muda (ver app/core/db.py)."""

    def __init__(self, data_dir: Path, table_name: str) -> None:
        self._data_dir = data_dir
        self._table = table_name

    def create(self, entry: CatalogEntry) -> CatalogEntry:
        conn = get_connection(self._data_dir)
        try:
            conn.execute(
                f"""
                INSERT INTO {self._table}
                    (id, name, description, status, created_by, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.id,
                    entry.name,
                    entry.description,
                    entry.status,
                    entry.created_by,
                    entry.created_at,
                    entry.updated_at,
                ),
            )
            conn.commit()
        finally:
            conn.close()
        return entry

    def list_all(self) -> list[CatalogEntry]:
        conn = get_connection(self._data_dir)
        try:
            rows = conn.execute(f"SELECT * FROM {self._table} ORDER BY name ASC").fetchall()
        finally:
            conn.close()
        return [CatalogEntry(**dict(row)) for row in rows]

    def load(self, entry_id: str) -> CatalogEntry | None:
        conn = get_connection(self._data_dir)
        try:
            row = conn.execute(
                f"SELECT * FROM {self._table} WHERE id = ?", (entry_id,)
            ).fetchone()
        finally:
            conn.close()
        return CatalogEntry(**dict(row)) if row else None

    def update(self, entry_id: str, *, name: str, description: str, status: str) -> bool:
        conn = get_connection(self._data_dir)
        try:
            cursor = conn.execute(
                f"""
                UPDATE {self._table}
                SET name = ?, description = ?, status = ?, updated_at = ?
                WHERE id = ?
                """,
                (name, description, status, datetime.now(UTC).isoformat(), entry_id),
            )
            conn.commit()
        finally:
            conn.close()
        return cursor.rowcount > 0

    def delete(self, entry_id: str) -> bool:
        conn = get_connection(self._data_dir)
        try:
            cursor = conn.execute(f"DELETE FROM {self._table} WHERE id = ?", (entry_id,))
            conn.commit()
        finally:
            conn.close()
        return cursor.rowcount > 0


@dataclass
class Organization:
    name: str
    unit: str = ""
    city: str = ""
    state: str = ""
    country: str = ""
    phone: str = ""
    category: str = ""
    status: str = "active"
    created_by: str | None = None
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


class OrganizationStore:
    def __init__(self, data_dir: Path) -> None:
        self._data_dir = data_dir

    def create(self, org: Organization) -> Organization:
        conn = get_connection(self._data_dir)
        try:
            conn.execute(
                """
                INSERT INTO organizations
                    (id, name, unit, city, state, country, phone, category, status,
                     created_by, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    org.id, org.name, org.unit, org.city, org.state, org.country,
                    org.phone, org.category, org.status, org.created_by,
                    org.created_at, org.updated_at,
                ),
            )
            conn.commit()
        finally:
            conn.close()
        return org

    def list_all(self) -> list[Organization]:
        conn = get_connection(self._data_dir)
        try:
            rows = conn.execute("SELECT * FROM organizations ORDER BY name ASC").fetchall()
        finally:
            conn.close()
        return [Organization(**dict(row)) for row in rows]

    def load(self, org_id: str) -> Organization | None:
        conn = get_connection(self._data_dir)
        try:
            row = conn.execute(
                "SELECT * FROM organizations WHERE id = ?", (org_id,)
            ).fetchone()
        finally:
            conn.close()
        return Organization(**dict(row)) if row else None

    def update(self, org_id: str, **fields_to_update) -> bool:
        allowed = {"name", "unit", "city", "state", "country", "phone", "category", "status"}
        updates = {k: v for k, v in fields_to_update.items() if k in allowed}
        if not updates:
            return False
        updates["updated_at"] = datetime.now(UTC).isoformat()
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        conn = get_connection(self._data_dir)
        try:
            cursor = conn.execute(
                f"UPDATE organizations SET {set_clause} WHERE id = ?",
                (*updates.values(), org_id),
            )
            conn.commit()
        finally:
            conn.close()
        return cursor.rowcount > 0

    def delete(self, org_id: str) -> bool:
        conn = get_connection(self._data_dir)
        try:
            cursor = conn.execute("DELETE FROM organizations WHERE id = ?", (org_id,))
            conn.commit()
        finally:
            conn.close()
        return cursor.rowcount > 0


organization_store = OrganizationStore(Path(settings.data_dir))
system_store = CatalogStore(Path(settings.data_dir), "systems")
project_store = CatalogStore(Path(settings.data_dir), "projects")
