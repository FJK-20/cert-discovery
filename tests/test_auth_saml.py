"""Testa app/auth/saml.py: provisionamento de usuário, extração de e-mail
da resposta SAML, geração de metadata do SP. Não testa a validação de
assinatura XML em si — isso é responsabilidade da lib python3-saml
(bem estabelecida, mesmo raciocínio de confiar na lib `acme` pro
protocolo ACME em vez de reimplementar)."""

from __future__ import annotations

from unittest.mock import MagicMock

from app.auth import saml
from app.auth.passwords import verify_password
from app.auth.store import ROLE_ADMIN, ROLE_LEITOR, SamlIdpConfig, UserAccount, UserStore

_IDP_CONFIG = SamlIdpConfig(
    entity_id="https://sts.windows.net/tenant-id/",
    sso_url="https://login.microsoftonline.com/tenant-id/saml2",
    x509_cert="FAKE-CERT-BASE64",
)


def test_provision_or_get_user_creates_leitor_by_default(tmp_path):
    store = UserStore(tmp_path)
    account = saml.provision_or_get_user(store, "new.person@example.com")

    assert account.username == "new.person@example.com"
    assert account.role == ROLE_LEITOR
    assert account.auth_source == "saml"
    assert store.load("new.person@example.com") == account


def test_provision_or_get_user_is_idempotent(tmp_path):
    store = UserStore(tmp_path)
    first = saml.provision_or_get_user(store, "person@example.com")
    second = saml.provision_or_get_user(store, "person@example.com")
    assert first == second
    assert store.count() == 1


def test_provision_or_get_user_returns_existing_local_account_unchanged(tmp_path):
    store = UserStore(tmp_path)
    store.save(
        UserAccount(
            username="admin@example.com",
            password_hash="realhash",
            role=ROLE_ADMIN,
            auth_source="local",
        )
    )
    account = saml.provision_or_get_user(store, "admin@example.com")
    # devolve a conta local existente como está — quem chama (routes_saml)
    # é responsável por recusar login SSO nela, não essa função
    assert account.auth_source == "local"
    assert account.role == ROLE_ADMIN
    assert store.count() == 1  # não duplicou nem criou outra


def test_provisioned_user_has_unusable_password(tmp_path):
    store = UserStore(tmp_path)
    account = saml.provision_or_get_user(store, "person@example.com")
    assert verify_password("", account.password_hash) is False
    assert verify_password("password123", account.password_hash) is False


def test_extract_email_prefers_nameid_when_it_looks_like_email():
    auth = MagicMock()
    auth.get_nameid.return_value = "person@example.com"
    auth.get_attributes.return_value = {}
    assert saml.extract_email(auth) == "person@example.com"


def test_extract_email_falls_back_to_claim_when_nameid_is_not_email():
    auth = MagicMock()
    auth.get_nameid.return_value = "some-opaque-id"
    auth.get_attributes.return_value = {saml._EMAIL_CLAIM: ["claimed@example.com"]}
    assert saml.extract_email(auth) == "claimed@example.com"


def test_extract_email_returns_none_when_nothing_available():
    auth = MagicMock()
    auth.get_nameid.return_value = None
    auth.get_attributes.return_value = {}
    assert saml.extract_email(auth) is None


def test_extract_display_name_prefers_displayname_claim():
    auth = MagicMock()
    auth.get_attributes.return_value = {saml._DISPLAYNAME_CLAIM: ["Luan Faustino"]}
    assert saml.extract_display_name(auth, fallback="irrelevant@example.com") == "Luan Faustino"


def test_extract_display_name_falls_back_to_given_and_surname():
    auth = MagicMock()
    auth.get_attributes.return_value = {
        saml._GIVENNAME_CLAIM: ["Luan"],
        saml._SURNAME_CLAIM: ["Faustino"],
    }
    assert saml.extract_display_name(auth, fallback="irrelevant@example.com") == "Luan Faustino"


def test_extract_display_name_ignores_name_claim_that_looks_like_upn():
    auth = MagicMock()
    auth.get_attributes.return_value = {
        saml._NAME_CLAIM: ["person_gmail.com#EXT#@tenant.onmicrosoft.com"]
    }
    # claim "name" descartado por parecer UPN — cai pro fallback limpo
    assert (
        saml.extract_display_name(auth, fallback="person_gmail.com#EXT#@tenant.onmicrosoft.com")
        == "Person"
    )


def test_extract_display_name_cleans_up_guest_upn_fallback_when_no_claims_available():
    # Reproduz o caso real: convidado B2B do Entra ID sem nenhum claim de
    # nome configurado — só sobra o NameID/e-mail mangled de convidado.
    auth = MagicMock()
    auth.get_attributes.return_value = {}
    fallback = "luanvitorfaustino_gmail.com#EXT#@luanvitorfaustinogmail.onmicrosoft.com"
    assert saml.extract_display_name(auth, fallback=fallback) == "Luanvitorfaustino"


def test_provision_or_get_user_saves_display_name(tmp_path):
    store = UserStore(tmp_path)
    account = saml.provision_or_get_user(store, "new.person@example.com", "New Person")
    assert account.display_name == "New Person"
    assert store.load("new.person@example.com").display_name == "New Person"


def test_provision_or_get_user_updates_display_name_on_repeat_login(tmp_path):
    store = UserStore(tmp_path)
    saml.provision_or_get_user(store, "person@example.com", "Old Name")
    updated = saml.provision_or_get_user(store, "person@example.com", "New Name")
    assert updated.display_name == "New Name"
    assert store.load("person@example.com").display_name == "New Name"


def test_sp_entity_id_and_acs_url_are_derived_from_base_url():
    base = "https://certmanager.example.com"
    assert saml.sp_entity_id(base) == "https://certmanager.example.com/api/auth/saml/metadata"
    assert saml.acs_url(base) == "https://certmanager.example.com/api/auth/saml/acs"


def test_sp_metadata_xml_generates_valid_metadata_without_errors():
    xml, errors = saml.sp_metadata_xml(_IDP_CONFIG, "https://certmanager.example.com")
    assert errors == []
    assert "EntityDescriptor" in xml
    assert "https://certmanager.example.com/api/auth/saml/acs" in xml


def test_saml_idp_config_round_trip(tmp_path):
    store = UserStore(tmp_path)
    assert store.load_saml_config() is None

    store.save_saml_config(_IDP_CONFIG)
    assert store.load_saml_config() == _IDP_CONFIG


# --- SamlRequestStore: fecha login CSRF e replay via correlação de
# InResponseTo (achado numa auditoria de robustez) ---


def test_saml_request_store_consume_removes_pending_id():
    store = saml.SamlRequestStore()
    store.register("req-1")
    assert store.consume("req-1") is True
    # já consumido — reenviar a mesma Response não encontra mais o id
    # pendente, rejeitada como se fosse não solicitada (fecha replay).
    assert store.consume("req-1") is False


def test_saml_request_store_rejects_unknown_or_missing_id():
    store = saml.SamlRequestStore()
    assert store.consume("nunca-registrado") is False
    assert store.consume(None) is False
    assert store.consume("") is False


def test_saml_request_store_expires_after_ttl(monkeypatch):
    store = saml.SamlRequestStore(ttl_seconds=10)
    fake_now = [1_000_000.0]
    monkeypatch.setattr(saml.time, "time", lambda: fake_now[0])
    store.register("req-1")
    fake_now[0] += 11
    assert store.consume("req-1") is False


def test_peek_in_response_to_reads_attribute_before_any_validation():
    """get_in_response_to() lê direto do envelope XML, sem checar
    assinatura/certificado — por isso dá pra correlacionar ANTES de
    chamar process_response(), inclusive pra uma Response que nunca vai
    passar na validação de verdade (é exatamente o caso de um ataque)."""
    import base64

    from onelogin.saml2.settings import OneLogin_Saml2_Settings

    settings_dict = saml._settings_dict(_IDP_CONFIG, "https://certmanager.example.com")
    ol_settings = OneLogin_Saml2_Settings(settings=settings_dict, sp_validation_only=True)
    xml = (
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        'ID="_resp1" InResponseTo="_req123" Version="2.0" '
        'IssueInstant="2024-01-01T00:00:00Z"></samlp:Response>'
    )
    raw = base64.b64encode(xml.encode()).decode()

    class _FakeAuth:
        def get_settings(self):
            return ol_settings

    assert saml.peek_in_response_to(_FakeAuth(), raw) == "_req123"
