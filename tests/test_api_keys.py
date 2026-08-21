"""Testa app/auth/api_keys.py: criação/autenticação/revogação de API keys,
e que a chave em texto puro nunca fica recuperável depois de criada."""

from __future__ import annotations

from app.auth.api_keys import ApiKeyStore


def test_create_returns_id_and_a_usable_key(tmp_path):
    store = ApiKeyStore(tmp_path)
    key_id, raw_key = store.create(name="ci-bot", role="operador", created_by="admin")

    assert key_id
    assert raw_key.startswith("certdisc_")

    info = store.authenticate(raw_key)
    assert info is not None
    assert info.id == key_id
    assert info.name == "ci-bot"
    assert info.role == "operador"
    assert info.created_by == "admin"


def test_authenticate_rejects_wrong_key(tmp_path):
    store = ApiKeyStore(tmp_path)
    store.create(name="ci-bot", role="operador", created_by="admin")
    assert store.authenticate("certdisc_totalmente-inventada") is None


def test_authenticate_rejects_malformed_key(tmp_path):
    store = ApiKeyStore(tmp_path)
    assert store.authenticate("nem-comeca-com-o-prefixo-certo") is None


def test_authenticate_updates_last_used_at(tmp_path):
    store = ApiKeyStore(tmp_path)
    _, raw_key = store.create(name="ci-bot", role="leitor", created_by="admin")
    before = store.list_all()[0]
    assert before.last_used_at is None

    store.authenticate(raw_key)
    after = store.list_all()[0]
    assert after.last_used_at is not None


def test_revoke_makes_key_stop_authenticating(tmp_path):
    store = ApiKeyStore(tmp_path)
    key_id, raw_key = store.create(name="ci-bot", role="operador", created_by="admin")
    assert store.authenticate(raw_key) is not None

    store.revoke(key_id)
    assert store.authenticate(raw_key) is None
    assert store.get(key_id) is None


def test_raw_key_never_persisted_on_disk(tmp_path):
    store = ApiKeyStore(tmp_path)
    _, raw_key = store.create(name="ci-bot", role="operador", created_by="admin")

    db_path = tmp_path / "cert_discovery.sqlite3"
    assert raw_key.encode() not in db_path.read_bytes()


def test_list_all_orders_newest_first(tmp_path):
    store = ApiKeyStore(tmp_path)
    store.create(name="first", role="leitor", created_by="admin")
    store.create(name="second", role="leitor", created_by="admin")

    names = [k.name for k in store.list_all()]
    assert names == ["second", "first"]
