"""/healthz (liveness) e /readyz (readiness) — achado numa auditoria de
robustez: só existia liveness, que responde "ok" mesmo se o data_dir
estiver inacessível (volume montado errado, permissão faltando). Sem
readiness, um orquestrador (Kubernetes, etc.) mandaria tráfego pra uma
réplica que nunca vai conseguir gravar nada."""

from __future__ import annotations

import dataclasses

from fastapi.testclient import TestClient

from app.core.config import settings as real_settings
from app.main import app


def test_healthz_always_ok():
    client = TestClient(app)
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readyz_ok_when_data_dir_accessible(tmp_path, monkeypatch):
    fake_settings = dataclasses.replace(real_settings, data_dir=str(tmp_path))
    monkeypatch.setattr("app.main.settings", fake_settings)
    client = TestClient(app)
    response = client.get("/readyz")
    assert response.status_code == 200
    assert response.json() == {"status": "ready"}


def test_readyz_503_when_data_dir_inaccessible(monkeypatch):
    def _boom(_data_dir):
        raise OSError("simulated: volume não montado")

    monkeypatch.setattr("app.main.get_connection", _boom)
    client = TestClient(app)
    response = client.get("/readyz")
    assert response.status_code == 503
    assert response.json()["status"] == "not ready"
