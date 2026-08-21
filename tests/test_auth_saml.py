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
