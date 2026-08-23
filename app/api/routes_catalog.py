"""CRUD de Organizações, Sistemas e Projetos (Fase 8) — cadastros de
contexto que a emissão/importação de certificado pode referenciar.
Leitura liberada pra qualquer sessão autenticada (populam dropdowns em
Emissão/Importação/CSR); escrita (criar/editar/remover) é admin-only,
mesmo padrão de qualquer outra configuração do sistema (credencial de
DNS/CA, usuários)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.audit.log import audit_log
from app.auth.dependencies import require_admin, require_session
from app.catalog.store import (
    CatalogEntry,
    CatalogStore,
    Organization,
    organization_store,
    project_store,
    system_store,
)

router = APIRouter(dependencies=[Depends(require_session)])

_VALID_STATUS = {"active", "inactive"}


class CatalogEntryRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str = Field("", max_length=1000)
    status: str = Field("active")


def _catalog_snapshot(entry: CatalogEntry) -> dict:
    return {
        "id": entry.id,
        "name": entry.name,
        "description": entry.description,
        "status": entry.status,
        "created_by": entry.created_by,
        "created_at": entry.created_at,
        "updated_at": entry.updated_at,
    }


def _build_catalog_router(store: CatalogStore, prefix: str, label: str) -> APIRouter:
    sub = APIRouter(prefix=prefix)

    @sub.get("")
    async def list_entries() -> list[dict]:
        return [_catalog_snapshot(e) for e in store.list_all()]

    @sub.post("", status_code=201)
    async def create_entry(
        payload: CatalogEntryRequest, username: str = Depends(require_admin)
    ) -> dict:
        if payload.status not in _VALID_STATUS:
            raise HTTPException(status_code=400, detail="Status inválido.")
        entry = CatalogEntry(
            name=payload.name.strip(),
            description=payload.description.strip(),
            status=payload.status,
            created_by=username,
        )
        store.create(entry)
        audit_log.record(username=username, action=f"{label}_created", detail=entry.name)
        return _catalog_snapshot(entry)

    @sub.put("/{entry_id}")
    async def update_entry(
        entry_id: str, payload: CatalogEntryRequest, username: str = Depends(require_admin)
    ) -> dict:
        if payload.status not in _VALID_STATUS:
            raise HTTPException(status_code=400, detail="Status inválido.")
        if store.load(entry_id) is None:
            raise HTTPException(status_code=404, detail=f"{label.capitalize()} não encontrado.")
        store.update(
            entry_id,
            name=payload.name.strip(),
            description=payload.description.strip(),
            status=payload.status,
        )
        audit_log.record(username=username, action=f"{label}_updated", detail=payload.name)
        return _catalog_snapshot(store.load(entry_id))

    @sub.delete("/{entry_id}")
    async def delete_entry(entry_id: str, username: str = Depends(require_admin)) -> dict:
        entry = store.load(entry_id)
        if entry is None:
            raise HTTPException(status_code=404, detail=f"{label.capitalize()} não encontrado.")
        store.delete(entry_id)
        audit_log.record(username=username, action=f"{label}_deleted", detail=entry.name)
        return {"ok": True}

    return sub


router.include_router(_build_catalog_router(system_store, "/api/systems", "system"))
router.include_router(_build_catalog_router(project_store, "/api/projects", "project"))


class OrganizationRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    unit: str = Field("", max_length=200)
    city: str = Field("", max_length=120)
    state: str = Field("", max_length=120)
    country: str = Field("", max_length=120)
    phone: str = Field("", max_length=60)
    category: str = Field("", max_length=120)
    status: str = Field("active")


def _org_snapshot(org: Organization) -> dict:
    return {
        "id": org.id,
        "name": org.name,
        "unit": org.unit,
        "city": org.city,
        "state": org.state,
        "country": org.country,
        "phone": org.phone,
        "category": org.category,
        "status": org.status,
        "created_by": org.created_by,
        "created_at": org.created_at,
        "updated_at": org.updated_at,
    }


@router.get("/api/organizations")
async def list_organizations() -> list[dict]:
    return [_org_snapshot(o) for o in organization_store.list_all()]


@router.post("/api/organizations", status_code=201)
async def create_organization(
    payload: OrganizationRequest, username: str = Depends(require_admin)
) -> dict:
    if payload.status not in _VALID_STATUS:
        raise HTTPException(status_code=400, detail="Status inválido.")
    org = Organization(
        name=payload.name.strip(),
        unit=payload.unit.strip(),
        city=payload.city.strip(),
        state=payload.state.strip(),
        country=payload.country.strip(),
        phone=payload.phone.strip(),
        category=payload.category.strip(),
        status=payload.status,
        created_by=username,
    )
    organization_store.create(org)
    audit_log.record(username=username, action="organization_created", detail=org.name)
    return _org_snapshot(org)


@router.put("/api/organizations/{org_id}")
async def update_organization(
    org_id: str, payload: OrganizationRequest, username: str = Depends(require_admin)
) -> dict:
    if payload.status not in _VALID_STATUS:
        raise HTTPException(status_code=400, detail="Status inválido.")
    if organization_store.load(org_id) is None:
        raise HTTPException(status_code=404, detail="Organização não encontrada.")
    organization_store.update(
        org_id,
        name=payload.name.strip(),
        unit=payload.unit.strip(),
        city=payload.city.strip(),
        state=payload.state.strip(),
        country=payload.country.strip(),
        phone=payload.phone.strip(),
        category=payload.category.strip(),
        status=payload.status,
    )
    audit_log.record(username=username, action="organization_updated", detail=payload.name)
    return _org_snapshot(organization_store.load(org_id))


@router.delete("/api/organizations/{org_id}")
async def delete_organization(org_id: str, username: str = Depends(require_admin)) -> dict:
    org = organization_store.load(org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organização não encontrada.")
    organization_store.delete(org_id)
    audit_log.record(username=username, action="organization_deleted", detail=org.name)
    return {"ok": True}
