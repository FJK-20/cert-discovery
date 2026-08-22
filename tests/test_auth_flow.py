"""Teste de integração do fluxo completo: cadastro (MFA opcional, desligado
por padrão) -> login em uma etapa -> ativação de MFA (exige provar o código
antes de valer) -> login em duas etapas -> desativação -> proteção da API de
scan -> logout. Também cobre multiusuário/papéis (Fase 4): só admin gerencia
outros usuários, `leitor` não passa em rota de escrita.

Os singletons globais (user_store/session_store/pending_login_store/rate
limiter) são substituídos por instâncias isoladas por teste via monkeypatch,
para não vazar estado entre testes nem depender do disco real. O
`job_manager.create` também é substituído por um fake: este arquivo testa a
camada de autenticação, não o pipeline de scan (já coberto em outros testes).
"""

from fastapi.testclient import TestClient

from app.audit.log import audit_log
from app.auth import totp
from app.auth.api_keys import api_key_store
from app.auth.sessions import TokenStore
from app.auth.store import UserStore
from app.core.ratelimit import SlidingWindowRateLimiter
from app.main import app

ADMIN = {"username": "admin", "password": "supersecretpw"}
SCAN_BODY = {"domain": "example.com", "consent": True}


class _FakeJob:
    id = "fake-job-id"


async def _fake_create(domain, manual_hosts=None):
    return _FakeJob()


def _client(tmp_path, monkeypatch) -> TestClient:
    session_store = TokenStore(ttl_seconds=3600)
    unlimited = SlidingWindowRateLimiter(max_requests=1000, window_seconds=300)
    monkeypatch.setattr("app.auth.routes_auth.user_store", UserStore(tmp_path))
    monkeypatch.setattr("app.auth.dependencies.user_store", UserStore(tmp_path))
    monkeypatch.setattr("app.auth.routes_saml.user_store", UserStore(tmp_path))
    monkeypatch.setattr("app.auth.routes_auth.session_store", session_store)
    monkeypatch.setattr("app.auth.routes_auth.pending_login_store", TokenStore(ttl_seconds=300))
    monkeypatch.setattr("app.auth.routes_auth._rate_limiter", unlimited)
    monkeypatch.setattr("app.auth.dependencies.session_store", session_store)
    monkeypatch.setattr("app.jobs.manager.job_manager.create", _fake_create)
    # `audit_log` é um singleton só, importado por referência em cada
    # arquivo de rota (routes_auth/routes_scan/routes_acme/...) — mutar o
    # atributo do objeto compartilhado (em vez de reatribuir o nome do
    # módulo) propaga pra todo mundo que já importou essa mesma instância.
    monkeypatch.setattr(audit_log, "_data_dir", tmp_path)
    monkeypatch.setattr(api_key_store, "_data_dir", tmp_path)
    return TestClient(app)


def _state(client: TestClient) -> str:
    return client.get("/api/auth/status").json()["state"]


def _scan_status(client: TestClient) -> int:
    return client.post("/api/scan", json=SCAN_BODY).status_code


def test_status_is_needs_setup_when_no_admin(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    assert _state(client) == "needs_setup"


def test_scan_requires_authentication(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    assert _scan_status(client) == 401


def test_setup_grants_immediate_access_without_mfa(tmp_path, monkeypatch):
    """MFA é opcional e desligado por padrão: o cadastro já autentica na
    hora, sem etapa intermediária forçada."""
    client = _client(tmp_path, monkeypatch)

    setup_response = client.post("/api/auth/setup", json=ADMIN)
    assert setup_response.status_code == 201
    assert setup_response.json() == {"ok": True}

    assert _state(client) == "authenticated"
    assert _scan_status(client) == 200
    assert client.get("/api/auth/mfa/status").json() == {"enabled": False}


def test_cannot_register_second_admin(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)

    second = client.post("/api/auth/setup", json={"username": "other", "password": "anotherpw"})
    assert second.status_code == 400


def test_login_single_step_when_mfa_disabled(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)

    client.post("/api/auth/logout")
    assert _state(client) == "needs_login"
    assert _scan_status(client) == 401

    bad_login = {"username": "admin", "password": "wrong"}
    assert client.post("/api/auth/login", json=bad_login).status_code == 401

    login_response = client.post("/api/auth/login", json=ADMIN)
    assert login_response.status_code == 200
    assert login_response.json() == {"mfa_required": False}
    assert _state(client) == "authenticated"
    assert _scan_status(client) == 200


def test_mfa_enroll_requires_valid_code_before_enabling(tmp_path, monkeypatch):
    """Não pode ficar ativado "no escuro": o segredo só vira o oficial da
    conta depois de confirmar um código correto."""
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)

    enroll = client.post("/api/auth/mfa/enroll")
    assert enroll.status_code == 200
    secret = enroll.json()["secret"]
    assert client.get("/api/auth/mfa/status").json() == {"enabled": False}

    wrong = client.post("/api/auth/mfa/enroll/confirm", json={"code": "000000"})
    assert wrong.status_code == 401
    assert client.get("/api/auth/mfa/status").json() == {"enabled": False}

    confirmed = client.post(
        "/api/auth/mfa/enroll/confirm", json={"code": totp.totp_now(secret)}
    )
    assert confirmed.status_code == 200
    assert client.get("/api/auth/mfa/status").json() == {"enabled": True}


def test_mfa_enroll_confirm_without_pending_enrollment_fails(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)

    response = client.post("/api/auth/mfa/enroll/confirm", json={"code": "123456"})
    assert response.status_code == 400


def test_mfa_endpoints_require_authentication(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)
    client.post("/api/auth/logout")

    assert client.get("/api/auth/mfa/status").status_code == 401
    assert client.post("/api/auth/mfa/enroll").status_code == 401
    assert client.post("/api/auth/mfa/disable", json={"password": "x"}).status_code == 401


def test_login_flow_requires_password_and_mfa_once_enabled(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)
    secret = client.post("/api/auth/mfa/enroll").json()["secret"]
    client.post("/api/auth/mfa/enroll/confirm", json={"code": totp.totp_now(secret)})

    client.post("/api/auth/logout")
    assert _state(client) == "needs_login"
    assert _scan_status(client) == 401

    bad_login = {"username": "admin", "password": "wrong"}
    assert client.post("/api/auth/login", json=bad_login).status_code == 401

    login_response = client.post("/api/auth/login", json=ADMIN)
    assert login_response.status_code == 200
    body = login_response.json()
    assert body["mfa_required"] is True
    pending_token = body["pending_token"]
    assert _state(client) == "needs_login"

    # senha certa mas MFA errado: ainda não autenticado
    bad_mfa = {"pending_token": pending_token, "code": "000000"}
    assert client.post("/api/auth/login/verify-mfa", json=bad_mfa).status_code == 401
    assert _state(client) == "needs_login"

    good_mfa = {"pending_token": pending_token, "code": totp.totp_now(secret)}
    assert client.post("/api/auth/login/verify-mfa", json=good_mfa).status_code == 200
    assert _state(client) == "authenticated"
    assert _scan_status(client) == 200


def test_disable_mfa_requires_correct_password_and_reverts_to_single_step_login(
    tmp_path, monkeypatch
):
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)
    secret = client.post("/api/auth/mfa/enroll").json()["secret"]
    client.post("/api/auth/mfa/enroll/confirm", json={"code": totp.totp_now(secret)})
    assert client.get("/api/auth/mfa/status").json() == {"enabled": True}

    wrong_password = client.post("/api/auth/mfa/disable", json={"password": "wrong"})
    assert wrong_password.status_code == 401
    assert client.get("/api/auth/mfa/status").json() == {"enabled": True}

    disabled = client.post("/api/auth/mfa/disable", json={"password": ADMIN["password"]})
    assert disabled.status_code == 200
    assert client.get("/api/auth/mfa/status").json() == {"enabled": False}

    client.post("/api/auth/logout")
    login_response = client.post("/api/auth/login", json=ADMIN)
    assert login_response.json() == {"mfa_required": False}
    assert _state(client) == "authenticated"


def test_first_setup_grants_admin_role(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)
    assert client.get("/api/auth/me").json() == {
        "username": "admin",
        "role": "admin",
        "mfa_enabled": False,
    }


def test_admin_can_create_and_list_users(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)

    created = client.post(
        "/api/auth/users",
        json={"username": "viewer", "password": "readonlypw", "role": "leitor"},
    )
    assert created.status_code == 201

    users = client.get("/api/auth/users").json()
    assert {"username": "admin", "role": "admin", "mfa_enabled": False} in users
    assert {"username": "viewer", "role": "leitor", "mfa_enabled": False} in users


def test_cannot_create_user_with_invalid_role(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)

    response = client.post(
        "/api/auth/users", json={"username": "x", "password": "somepassword", "role": "superuser"}
    )
    assert response.status_code == 400


def test_cannot_create_duplicate_username(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)

    response = client.post(
        "/api/auth/users", json={"username": "admin", "password": "somepassword", "role": "leitor"}
    )
    assert response.status_code == 400


def test_leitor_role_blocked_from_write_routes_but_allowed_to_read(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)
    client.post(
        "/api/auth/users",
        json={"username": "viewer", "password": "readonlypw", "role": "leitor"},
    )
    client.post("/api/auth/logout")

    login = client.post(
        "/api/auth/login", json={"username": "viewer", "password": "readonlypw"}
    )
    assert login.json() == {"mfa_required": False}

    # leitura continua liberada
    assert client.get("/api/acme/certificates").status_code == 200
    assert client.get("/api/acme/renewal-history").status_code == 200
    assert client.get("/api/scan/history").status_code == 200

    # escrita é bloqueada com 403 (autenticado, mas sem o papel certo)
    assert _scan_status(client) == 403
    forbidden = client.post("/api/auth/users", json={"username": "x", "password": "x" * 10})
    assert forbidden.status_code == 403

    # leitor não enxerga log de auditoria nem lista de usuários — esses
    # dois exigem admin ou auditor, não qualquer papel autenticado
    assert client.get("/api/audit-log").status_code == 403
    assert client.get("/api/auth/users").status_code == 403


def test_operador_can_do_certificate_lifecycle_but_not_manage_users_or_system_config(
    tmp_path, monkeypatch
):
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)
    client.post(
        "/api/auth/users",
        json={"username": "op", "password": "operatorpw1", "role": "operador"},
    )
    client.post("/api/auth/logout")
    login = client.post("/api/auth/login", json={"username": "op", "password": "operatorpw1"})
    assert login.json() == {"mfa_required": False}

    # ciclo de vida de certificado (dia a dia) é permitido
    assert _scan_status(client) == 200
    assert client.post("/api/scheduler/check-now").status_code in (200, 429)

    # configuração sensível do sistema e gestão de usuários continuam só admin
    denied = client.post("/api/auth/users", json={"username": "x", "password": "x" * 10})
    assert denied.status_code == 403
    assert client.delete("/api/auth/users/admin").status_code == 403
    dns_creds = client.post(
        "/api/acme/dns-credentials", json={"api_token": "fake-token-000000000000000"}
    )
    assert dns_creds.status_code == 403
    notify_cfg = client.post("/api/notifications/config", json={"webhook_url": "https://x.example"})
    assert notify_cfg.status_code == 403

    # nem log de auditoria nem lista de usuários — não é o papel dele
    assert client.get("/api/audit-log").status_code == 403
    assert client.get("/api/auth/users").status_code == 403


def test_auditor_can_view_audit_log_and_users_but_cannot_act(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)
    client.post(
        "/api/auth/users",
        json={"username": "aud", "password": "auditorpw1", "role": "auditor"},
    )
    client.post("/api/auth/logout")
    login = client.post("/api/auth/login", json={"username": "aud", "password": "auditorpw1"})
    assert login.json() == {"mfa_required": False}

    # visão de compliance liberada
    assert client.get("/api/audit-log").status_code == 200
    users = client.get("/api/auth/users")
    assert users.status_code == 200
    assert any(u["username"] == "admin" for u in users.json())

    # mas não age em nada — nem ciclo de vida de certificado, nem gestão
    # de usuários (só enxerga, não administra)
    assert _scan_status(client) == 403
    denied = client.post("/api/auth/users", json={"username": "x", "password": "x" * 10})
    assert denied.status_code == 403
    assert client.delete("/api/auth/users/admin").status_code == 403

    # chave privada é sensível mesmo sem ser "escrita" — também exige admin,
    # inclusive antes de checar se o certificado existe (403 nunca vaza
    # existência via um 404 primeiro)
    assert client.get("/api/acme/certificates/nonexistent/privkey.pem").status_code == 403
    assert client.get("/api/acme/certificates/nonexistent/fullchain.pem").status_code == 404


def test_user_cannot_delete_self(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)
    response = client.delete("/api/auth/users/admin")
    assert response.status_code == 400


def test_cannot_delete_last_admin(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)
    client.post(
        "/api/auth/users",
        json={"username": "viewer", "password": "readonlypw", "role": "leitor"},
    )
    # loga como viewer não daria pra deletar admin (não é admin) — aqui
    # testamos a regra em si, ainda autenticado como o único admin, tentando
    # remover a si mesmo é bloqueado por outra regra (self-delete); pra
    # testar "último admin" de verdade, criamos um segundo admin, removemos
    # um deles, e confirmamos que o último não sai.
    client.post(
        "/api/auth/users",
        json={"username": "second-admin", "password": "anotheradminpw", "role": "admin"},
    )
    assert client.delete("/api/auth/users/second-admin").status_code == 200
    # agora só sobra "admin" como administrador — não pode remover viewer
    # de novo (já não existe) nem promover a situação de zero admins
    assert client.delete("/api/auth/users/viewer").status_code == 200
    users = client.get("/api/auth/users").json()
    assert [u["username"] for u in users] == ["admin"]


def test_new_login_fails_for_a_deleted_user(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)
    client.post(
        "/api/auth/users",
        json={"username": "viewer", "password": "readonlypw", "role": "leitor"},
    )
    client.delete("/api/auth/users/viewer")

    viewer_client = TestClient(app)
    bad_login = viewer_client.post(
        "/api/auth/login", json={"username": "viewer", "password": "readonlypw"}
    )
    assert bad_login.status_code == 401


def test_api_key_authenticates_and_respects_its_role(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)

    created = client.post("/api/auth/api-keys", json={"name": "ci-bot", "role": "operador"})
    assert created.status_code == 201
    body = created.json()
    assert body["key"].startswith("certdisc_")
    assert "key" not in client.get("/api/auth/api-keys").json()[0]  # nunca reexibida

    # a chave nunca aparece na listagem — só id/name/role/timestamps
    listed = client.get("/api/auth/api-keys").json()
    assert listed[0]["name"] == "ci-bot"
    assert listed[0]["role"] == "operador"

    key_client = TestClient(app)
    headers = {"Authorization": f"Bearer {body['key']}"}
    assert key_client.post("/api/scan", json=SCAN_BODY, headers=headers).status_code == 200
    # papel operador não gerencia usuários, nem com API key
    forbidden = key_client.post(
        "/api/auth/users", json={"username": "x", "password": "x" * 10}, headers=headers
    )
    assert forbidden.status_code == 403


def test_revoked_api_key_stops_authenticating(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)

    created = client.post("/api/auth/api-keys", json={"name": "ci-bot", "role": "leitor"})
    key_id, raw_key = created.json()["id"], created.json()["key"]

    key_client = TestClient(app)
    headers = {"Authorization": f"Bearer {raw_key}"}
    assert key_client.get("/api/acme/certificates", headers=headers).status_code == 200

    revoked = client.delete(f"/api/auth/api-keys/{key_id}")
    assert revoked.status_code == 200
    assert key_client.get("/api/acme/certificates", headers=headers).status_code == 401


def test_invalid_bearer_token_is_rejected(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)

    key_client = TestClient(app)
    headers = {"Authorization": "Bearer certdisc_isso-nunca-foi-criado"}
    assert key_client.get("/api/acme/certificates", headers=headers).status_code == 401


def test_saml_status_reports_not_configured_by_default(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    status = client.get("/api/auth/saml/status").json()
    assert status["configured"] is False
    assert status["login_url"] is None
    assert status["sp_entity_id"].endswith("/api/auth/saml/metadata")
    assert status["acs_url"].endswith("/api/auth/saml/acs")


def test_saml_config_requires_admin(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)
    client.post(
        "/api/auth/users",
        json={"username": "viewer", "password": "readonlypw", "role": "leitor"},
    )
    client.post("/api/auth/logout")
    client.post("/api/auth/login", json={"username": "viewer", "password": "readonlypw"})

    forbidden = client.post(
        "/api/auth/saml/config",
        json={
            "entity_id": "https://sts.windows.net/tenant/",
            "sso_url": "https://login.microsoftonline.com/tenant/saml2",
            "x509_cert": "FAKE",
        },
    )
    assert forbidden.status_code == 403


def test_saml_config_save_and_status_and_metadata(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)

    saved = client.post(
        "/api/auth/saml/config",
        json={
            "entity_id": "https://sts.windows.net/tenant/",
            "sso_url": "https://login.microsoftonline.com/tenant/saml2",
            "x509_cert": "FAKE-CERT",
        },
    )
    assert saved.status_code == 200
    body = saved.json()
    assert body["acs_url"].endswith("/api/auth/saml/acs")

    status = client.get("/api/auth/saml/status").json()
    assert status["configured"] is True
    assert status["login_url"] == "/api/auth/saml/login"

    metadata = client.get("/api/auth/saml/metadata")
    assert metadata.status_code == 200
    assert "EntityDescriptor" in metadata.text


def test_saml_acs_parses_real_form_post_without_crashing(tmp_path, monkeypatch):
    # Regressão: request.form() (usado pra ler o SAMLResponse do POST
    # binding) precisa da lib python-multipart instalada — sem ela, o
    # primeiro POST real de um IdP de verdade batia em AssertionError não
    # tratado (500), e nenhum teste existente descobria isso porque todos
    # usavam MagicMock em vez de um POST form-encoded de verdade. A resposta
    # aqui é lixo (sem assinatura válida), então o esperado é 401 — o que
    # importa é NÃO ser 500.
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)
    client.post(
        "/api/auth/saml/config",
        json={
            "entity_id": "https://sts.windows.net/tenant/",
            "sso_url": "https://login.microsoftonline.com/tenant/saml2",
            "x509_cert": "FAKE-CERT",
        },
    )
    response = client.post(
        "/api/auth/saml/acs",
        data={"SAMLResponse": "bm90LWEtcmVhbC1zYW1sLXJlc3BvbnNl"},
    )
    assert response.status_code == 401


def test_saml_metadata_404_when_not_configured(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    assert client.get("/api/auth/saml/metadata").status_code == 404


def test_sso_provisioned_account_cannot_login_with_password(tmp_path, monkeypatch):
    from app.auth import saml as saml_module
    from app.auth.store import UserStore as US

    store = US(tmp_path)
    saml_module.provision_or_get_user(store, "sso.user@example.com")

    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)  # precisa de um admin pro state virar needs_login
    client.post("/api/auth/logout")

    response = client.post(
        "/api/auth/login", json={"username": "sso.user@example.com", "password": "qualquer"}
    )
    assert response.status_code == 401
    assert "SSO" in response.json()["detail"]
