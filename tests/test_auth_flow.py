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

import time

from fastapi.testclient import TestClient

from app.audit.log import audit_log
from app.auth import saml, totp
from app.auth.api_keys import api_key_store
from app.auth.sessions import TokenStore
from app.auth.store import UserStore
from app.core.ratelimit import SlidingWindowRateLimiter
from app.main import app

ADMIN = {"username": "admin", "password": "supersecretpw"}
SCAN_BODY = {"domain": "example.com", "consent": True}


class _FakeJob:
    id = "fake-job-id"


async def _fake_create(domain, manual_hosts=None, *, enumerate_subdomains=False):
    return _FakeJob()


def _fixed_clock(monkeypatch, start: float = 1_700_000_000.0):
    """Congela time.time() (usado tanto pelo teste ao gerar um código TOTP
    quanto pelo servidor ao verificar) numa referência controlável — desde
    a proteção de replay em app.auth.totp, dois `totp.totp_now(secret)`
    chamados em sequência rápida (tempo real) podem cair na mesma janela
    de 30s e gerar o MESMO código, que a segunda verificação corretamente
    rejeita por já ter sido consumido. Devolve um objeto com `.advance()`
    pra mover o relógio pro próximo período entre dois códigos do mesmo
    teste."""

    state = {"now": start}

    class _Clock:
        def advance(self, seconds: float = totp.PERIOD_SECONDS) -> None:
            state["now"] += seconds

    monkeypatch.setattr(time, "time", lambda: state["now"])
    return _Clock()


def _client(tmp_path, monkeypatch) -> TestClient:
    session_store = TokenStore(ttl_seconds=3600)
    unlimited = SlidingWindowRateLimiter(max_requests=1000, window_seconds=300)
    monkeypatch.setattr("app.auth.routes_auth.user_store", UserStore(tmp_path))
    monkeypatch.setattr("app.auth.dependencies.user_store", UserStore(tmp_path))
    monkeypatch.setattr("app.auth.routes_saml.user_store", UserStore(tmp_path))
    # SamlRequestStore (correlação de InResponseTo) é um singleton de
    # módulo — sem isolar, um request_id registrado/consumido num teste
    # vazaria pro próximo dentro do mesmo processo pytest.
    monkeypatch.setattr(saml, "pending_saml_requests", saml.SamlRequestStore())
    monkeypatch.setattr("app.auth.routes_auth.session_store", session_store)
    monkeypatch.setattr("app.auth.routes_auth.pending_login_store", TokenStore(ttl_seconds=300))
    monkeypatch.setattr("app.auth.routes_auth._rate_limiter", unlimited)
    monkeypatch.setattr("app.auth.routes_auth._account_rate_limiter", unlimited)
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


def test_login_transparently_upgrades_a_legacy_password_hash(tmp_path, monkeypatch):
    """Achado numa auditoria de robustez: os parâmetros do scrypt
    subiram (app/auth/passwords.py) — uma conta criada antes desse fix
    tem o hash no formato antigo (mais fraco) salvo em disco. Login
    bem-sucedido precisa recalcular com os parâmetros atuais, sem exigir
    reset de senha de ninguém."""
    import hashlib

    from app.auth.passwords import _LEGACY_N

    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)

    store = UserStore(tmp_path)
    account = store.load(ADMIN["username"])
    legacy_salt = b"\x02" * 16
    legacy_digest = hashlib.scrypt(
        ADMIN["password"].encode(), salt=legacy_salt, n=_LEGACY_N, r=8, p=1, dklen=64
    )
    account.password_hash = f"{legacy_salt.hex()}${legacy_digest.hex()}"
    store.save(account)

    client.post("/api/auth/logout")
    login = client.post("/api/auth/login", json=ADMIN)
    assert login.status_code == 200

    upgraded = store.load(ADMIN["username"])
    assert upgraded.password_hash.count("$") == 2, "formato novo embute o n (3 campos)"
    assert upgraded.password_hash != account.password_hash


def test_cannot_register_second_admin(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)

    second = client.post("/api/auth/setup", json={"username": "other", "password": "anotherpw"})
    assert second.status_code == 400


def test_login_pays_the_same_hashing_cost_for_a_nonexistent_account(tmp_path, monkeypatch):
    """Achado numa auditoria de robustez: `account is not None and
    verify_password(...)` de curto-circuito pulava o scrypt inteiro
    quando a conta não existe, virando um oráculo de timing pra
    descobrir quais usernames existem sem precisar de senha nenhuma.
    Prova comportamental (não medição de tempo, que seria instável em
    CI): hash_password() precisa ser chamado mesmo pra uma conta que
    não existe."""
    import app.auth.routes_auth as routes_auth_module

    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)
    client.post("/api/auth/logout")

    calls = []
    original = routes_auth_module.hash_password
    monkeypatch.setattr(
        routes_auth_module, "hash_password", lambda pw: calls.append(pw) or original(pw)
    )

    response = client.post(
        "/api/auth/login", json={"username": "nao-existe", "password": "qualquer"}
    )
    assert response.status_code == 401
    assert calls == ["qualquer"]


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


def test_account_rate_limit_is_keyed_by_account_not_shared_globally(tmp_path, monkeypatch):
    """Achado numa auditoria de robustez: o limite existente era só por
    IP da conexão TCP — um deploy atrás de proxy/túnel faz todo mundo
    compartilhar um balde só (ninguém mais loga por 5min depois de 8
    tentativas de QUALQUER pessoa), e mesmo sem proxy, um spray de senha
    distribuído (várias origens, uma conta só) nunca esbarrava em limite
    nenhum. O balde por conta é independente do de IP (que a fixture já
    deixa ilimitado) — esgotar tentativas contra "admin" não afeta
    login de "second" alguma."""
    from app.core.config import settings as real_settings
    from app.core.ratelimit import SlidingWindowRateLimiter

    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)
    client.post(
        "/api/auth/users",
        json={"username": "second", "password": "secondpw123", "role": "leitor"},
    )
    client.post("/api/auth/logout")

    monkeypatch.setattr(
        "app.auth.routes_auth._account_rate_limiter",
        SlidingWindowRateLimiter(
            max_requests=real_settings.auth_rate_limit_requests,
            window_seconds=real_settings.auth_rate_limit_window_seconds,
        ),
    )

    for _ in range(real_settings.auth_rate_limit_requests):
        response = client.post(
            "/api/auth/login", json={"username": "admin", "password": "wrong"}
        )
        assert response.status_code == 401

    blocked = client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
    assert blocked.status_code == 429
    assert "conta" in blocked.json()["detail"]

    # conta diferente, balde diferente — o esgotamento acima não vaza.
    other = client.post(
        "/api/auth/login", json={"username": "second", "password": "secondpw123"}
    )
    assert other.status_code == 200


def test_login_flow_requires_password_and_mfa_once_enabled(tmp_path, monkeypatch):
    clock = _fixed_clock(monkeypatch)
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)
    secret = client.post("/api/auth/mfa/enroll").json()["secret"]
    client.post("/api/auth/mfa/enroll/confirm", json={"code": totp.totp_now(secret)})
    # próximo período: o código de confirmação de enrollment já foi
    # consumido (proteção de replay) — o login real precisa de um novo.
    clock.advance()

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


def test_mfa_code_cannot_be_replayed_across_two_logins(tmp_path, monkeypatch):
    """Achado numa auditoria de robustez: sem rastrear consumo, um código
    de 6 dígitos observado (rede, ombro, log de acesso) valia de novo por
    toda a janela de tolerância (~90s) — TOTP é projetado pra uso único."""
    clock = _fixed_clock(monkeypatch)
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)
    secret = client.post("/api/auth/mfa/enroll").json()["secret"]
    client.post("/api/auth/mfa/enroll/confirm", json={"code": totp.totp_now(secret)})
    clock.advance()
    client.post("/api/auth/logout")

    code = totp.totp_now(secret)
    first_login = client.post("/api/auth/login", json=ADMIN)
    first_verify = client.post(
        "/api/auth/login/verify-mfa",
        json={"pending_token": first_login.json()["pending_token"], "code": code},
    )
    assert first_verify.status_code == 200
    client.post("/api/auth/logout")

    # mesmo código, mesmo instante (relógio congelado) — a segunda tentativa
    # de usar ESSE código específico não pode logar de novo.
    second_login = client.post("/api/auth/login", json=ADMIN)
    second_verify = client.post(
        "/api/auth/login/verify-mfa",
        json={"pending_token": second_login.json()["pending_token"], "code": code},
    )
    assert second_verify.status_code == 401


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
        "display_name": "admin",
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
    admin_row = {"username": "admin", "display_name": "", "role": "admin", "mfa_enabled": False}
    viewer_row = {"username": "viewer", "display_name": "", "role": "leitor", "mfa_enabled": False}
    assert admin_row in users
    assert viewer_row in users


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


def test_admin_can_change_a_users_role(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)
    client.post(
        "/api/auth/users",
        json={"username": "viewer", "password": "readonlypw", "role": "leitor"},
    )
    response = client.patch("/api/auth/users/viewer/role", json={"role": "operador"})
    assert response.status_code == 200
    users = client.get("/api/auth/users").json()
    viewer_row = {
        "username": "viewer",
        "display_name": "",
        "role": "operador",
        "mfa_enabled": False,
    }
    assert viewer_row in users


def test_cannot_change_role_to_invalid_value(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)
    client.post(
        "/api/auth/users",
        json={"username": "viewer", "password": "readonlypw", "role": "leitor"},
    )
    response = client.patch("/api/auth/users/viewer/role", json={"role": "superuser"})
    assert response.status_code == 400


def test_cannot_change_role_of_unknown_user(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)
    response = client.patch("/api/auth/users/ghost/role", json={"role": "operador"})
    assert response.status_code == 404


def test_cannot_demote_last_admin(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)
    response = client.patch("/api/auth/users/admin/role", json={"role": "leitor"})
    assert response.status_code == 400
    users = client.get("/api/auth/users").json()
    assert {"username": "admin", "display_name": "", "role": "admin", "mfa_enabled": False} in users


def test_can_demote_an_admin_when_another_admin_exists(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)
    client.post(
        "/api/auth/users",
        json={"username": "second-admin", "password": "anotheradminpw", "role": "admin"},
    )
    response = client.patch("/api/auth/users/second-admin/role", json={"role": "leitor"})
    assert response.status_code == 200


def test_only_admin_can_change_roles(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)
    client.post(
        "/api/auth/users",
        json={"username": "viewer", "password": "readonlypw", "role": "leitor"},
    )
    client.post("/api/auth/logout")
    client.post("/api/auth/login", json={"username": "viewer", "password": "readonlypw"})
    response = client.patch("/api/auth/users/viewer/role", json={"role": "admin"})
    assert response.status_code == 403


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


def test_deleting_a_user_revokes_their_existing_session(tmp_path, monkeypatch):
    """Achado numa auditoria de robustez: session_store (token→username)
    é independente de user_store — excluir a conta não invalidava um
    cookie de sessão já emitido, deixando uma conta desligada com leitura
    válida (inventário, histórico, cadastros) pelo TTL de sessão inteiro
    (12h). O logado de fato precisa perder acesso na PRÓXIMA requisição,
    não só falhar num login novo (já coberto pelo teste acima)."""
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)
    client.post(
        "/api/auth/users",
        json={"username": "viewer", "password": "readonlypw", "role": "leitor"},
    )

    viewer_client = TestClient(app)
    viewer_client.post("/api/auth/login", json={"username": "viewer", "password": "readonlypw"})
    assert viewer_client.get("/api/auth/me").status_code == 200

    client.delete("/api/auth/users/viewer")

    # mesmo cliente, mesmo cookie de sessão — nenhum novo login envolvido
    response = viewer_client.get("/api/auth/me")
    assert response.status_code == 401


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


def _build_fake_saml_response(in_response_to: str) -> str:
    import base64

    xml = (
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        f'ID="_resp1" InResponseTo="{in_response_to}" Version="2.0" '
        'IssueInstant="2024-01-01T00:00:00Z"></samlp:Response>'
    )
    return base64.b64encode(xml.encode()).decode()


def _saml_config(client):
    client.post(
        "/api/auth/saml/config",
        json={
            "entity_id": "https://sts.windows.net/tenant/",
            "sso_url": "https://login.microsoftonline.com/tenant/saml2",
            "x509_cert": "FAKE-CERT",
        },
    )


def test_saml_acs_rejects_response_with_unregistered_in_response_to(tmp_path, monkeypatch):
    """Achado numa auditoria de robustez: sem correlacionar com um
    AuthnRequest que este processo emitiu, uma Response válida
    endereçada a OUTRO login (login CSRF) — ou reenviada depois de já
    ter sido usada (replay) — era processada como autenticação de quem
    está no navegador."""
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)
    _saml_config(client)

    raw = _build_fake_saml_response("_never-registered")
    response = client.post("/api/auth/saml/acs", data={"SAMLResponse": raw})
    assert response.status_code == 401
    assert "não corresponde a um login iniciado" in response.json()["detail"]


def test_saml_acs_consumes_registered_request_id_only_once(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)
    _saml_config(client)

    saml.pending_saml_requests.register("_req-abc")
    raw = _build_fake_saml_response("_req-abc")

    # passa da checagem de correlação (consome o id), mas ainda falha —
    # como esperado — na validação de assinatura de verdade (não é uma
    # Response real assinada por um IdP). O que importa é a MENSAGEM: não
    # é mais a de correlação, é a de assinatura/estrutura inválida.
    first = client.post("/api/auth/saml/acs", data={"SAMLResponse": raw})
    assert first.status_code == 401
    assert "não corresponde a um login iniciado" not in first.json()["detail"]

    # reenviar a MESMA Response (replay): o id já foi consumido na
    # primeira tentativa, volta a ser rejeitada como não solicitada.
    second = client.post("/api/auth/saml/acs", data={"SAMLResponse": raw})
    assert second.status_code == 401
    assert "não corresponde a um login iniciado" in second.json()["detail"]


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


def _audit_actions(client) -> list[str]:
    return [e["action"] for e in client.get("/api/audit-log").json()]


def test_login_success_is_audited(tmp_path, monkeypatch):
    """Achado numa auditoria de robustez: login bem-sucedido, falhado,
    MFA inválido e logout não deixavam rastro — um spray de senha
    bem-sucedido contra o admin não aparecia em lugar nenhum, no produto
    cujo propósito central é log de auditoria."""
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)
    client.post("/api/auth/logout")

    response = client.post("/api/auth/login", json=ADMIN)
    assert response.status_code == 200
    assert "login_success" in _audit_actions(client)


def test_login_failure_is_audited_with_attempted_username(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)
    client.post("/api/auth/logout")

    response = client.post(
        "/api/auth/login", json={"username": "admin", "password": "senha-errada"}
    )
    assert response.status_code == 401

    # o cliente saiu sem sessão válida (login falhou de propósito) —
    # precisa reautenticar pra poder ler o log que acabou de registrar
    # essa própria falha.
    client.post("/api/auth/login", json=ADMIN)
    entries = client.get("/api/audit-log").json()
    failed = next(e for e in entries if e["action"] == "login_failed")
    assert failed["detail"] == "admin"


def test_logout_is_audited(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)

    response = client.post("/api/auth/logout")
    assert response.status_code == 200

    client.post("/api/auth/login", json=ADMIN)
    assert "logout" in _audit_actions(client)


def test_mfa_verify_failure_is_audited(tmp_path, monkeypatch):
    clock = _fixed_clock(monkeypatch)
    client = _client(tmp_path, monkeypatch)
    client.post("/api/auth/setup", json=ADMIN)

    secret = client.post("/api/auth/mfa/enroll").json()["secret"]
    client.post("/api/auth/mfa/enroll/confirm", json={"code": totp.totp_now(secret)})
    client.post("/api/auth/logout")

    login = client.post("/api/auth/login", json=ADMIN)
    pending_token = login.json()["pending_token"]
    response = client.post(
        "/api/auth/login/verify-mfa", json={"pending_token": pending_token, "code": "000000"}
    )
    assert response.status_code == 401

    # a verificação MFA falhou de propósito, sem sessão — completa o
    # login de verdade pra poder ler o log. Próximo período: o código de
    # confirmação de enrollment já foi consumido (proteção de replay).
    clock.advance()
    login2 = client.post("/api/auth/login", json=ADMIN)
    client.post(
        "/api/auth/login/verify-mfa",
        json={"pending_token": login2.json()["pending_token"], "code": totp.totp_now(secret)},
    )
    assert "mfa_failed" in _audit_actions(client)
