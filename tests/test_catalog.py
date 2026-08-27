"""CRUD de Organizações/Sistemas/Projetos (Fase 8) — leitura liberada pra
qualquer sessão autenticada, escrita admin-only."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.audit.log import audit_log
from app.auth.sessions import TokenStore
from app.auth.store import UserStore
from app.catalog.store import CatalogStore, OrganizationStore
from app.core.ratelimit import SlidingWindowRateLimiter
from app.main import app

ADMIN = {"username": "admin", "password": "supersecretpw"}


def _client(tmp_path, monkeypatch) -> TestClient:
    session_store = TokenStore(ttl_seconds=3600)
    unlimited = SlidingWindowRateLimiter(max_requests=1000, window_seconds=300)
    monkeypatch.setattr("app.auth.routes_auth.user_store", UserStore(tmp_path))
    monkeypatch.setattr("app.auth.dependencies.user_store", UserStore(tmp_path))
    monkeypatch.setattr("app.auth.routes_saml.user_store", UserStore(tmp_path))
    monkeypatch.setattr("app.auth.routes_auth.session_store", session_store)
    monkeypatch.setattr("app.auth.routes_auth.pending_login_store", TokenStore(ttl_seconds=300))
    monkeypatch.setattr("app.auth.dependencies.session_store", session_store)
    monkeypatch.setattr("app.auth.routes_auth._rate_limiter", unlimited)
    monkeypatch.setattr("app.auth.routes_auth._account_rate_limiter", unlimited)
    monkeypatch.setattr("app.api.routes_catalog.organization_store", OrganizationStore(tmp_path))
    monkeypatch.setattr(
        "app.api.routes_catalog.system_store", CatalogStore(tmp_path, "systems")
    )
    monkeypatch.setattr(
        "app.api.routes_catalog.project_store", CatalogStore(tmp_path, "projects")
    )
    monkeypatch.setattr(audit_log, "_data_dir", tmp_path)
    client = TestClient(app)
    client.post("/api/auth/setup", json=ADMIN)
    return client


def test_admin_can_create_list_update_delete_organization(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    created = client.post(
        "/api/organizations",
        json={"name": "Acme Corp", "unit": "TI", "city": "Blumenau", "state": "SC"},
    )
    assert created.status_code == 201
    org_id = created.json()["id"]

    listed = client.get("/api/organizations").json()
    assert any(o["id"] == org_id and o["name"] == "Acme Corp" for o in listed)

    updated = client.put(
        f"/api/organizations/{org_id}",
        json={"name": "Acme Corp Ltda", "city": "Blumenau", "state": "SC"},
    )
    assert updated.status_code == 200
    assert updated.json()["name"] == "Acme Corp Ltda"

    deleted = client.delete(f"/api/organizations/{org_id}")
    assert deleted.status_code == 200
    assert not any(o["id"] == org_id for o in client.get("/api/organizations").json())


def test_update_and_delete_unknown_organization_is_404(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    assert client.put("/api/organizations/ghost", json={"name": "x"}).status_code == 404
    assert client.delete("/api/organizations/ghost").status_code == 404


def test_systems_and_projects_crud(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    for prefix, label in [("/api/systems", "Ansible"), ("/api/projects", "Migração PIX")]:
        created = client.post(prefix, json={"name": label, "description": "desc"})
        assert created.status_code == 201
        entry_id = created.json()["id"]

        listed = client.get(prefix).json()
        assert any(e["id"] == entry_id for e in listed)

        updated = client.put(
            f"{prefix}/{entry_id}", json={"name": label, "description": "nova desc"}
        )
        assert updated.status_code == 200
        assert updated.json()["description"] == "nova desc"

        assert client.delete(f"{prefix}/{entry_id}").status_code == 200


def test_invalid_status_is_rejected(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    response = client.post("/api/systems", json={"name": "x", "status": "quebrado"})
    assert response.status_code == 400


def test_leitor_can_list_but_not_write(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.post(
        "/api/auth/users",
        json={"username": "viewer", "password": "readonlypw", "role": "leitor"},
    )
    client.post("/api/auth/logout")
    client.post("/api/auth/login", json={"username": "viewer", "password": "readonlypw"})

    assert client.get("/api/organizations").status_code == 200
    assert client.get("/api/systems").status_code == 200
    assert client.get("/api/projects").status_code == 200

    forbidden = client.post("/api/organizations", json={"name": "x"})
    assert forbidden.status_code == 403


def test_unauthenticated_request_is_rejected(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/logout")
    assert client.get("/api/organizations").status_code == 401


def test_organization_and_catalog_actions_are_audit_logged(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.post("/api/organizations", json={"name": "Acme"})
    client.post("/api/systems", json={"name": "CRM"})

    entries = client.get("/api/audit-log").json()
    actions = {e["action"] for e in entries}
    assert "organization_created" in actions
    assert "system_created" in actions
