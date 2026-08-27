"""Testa app/core/crypto.py (criptografia em repouso) e a migração
transparente de dado legado em texto plano nos stores que passaram a usar
essa camada (Fase 5)."""

from __future__ import annotations

import json

import pytest

from app.acme.store import AcmeStore, DecryptionError, DnsCredentials, IssuedCertificate
from app.auth.store import UserAccount, UserStore
from app.core.crypto import SecretBox, looks_like_fernet_token
from app.notify.store import NotificationConfig, NotificationStore
from app.pki.store import PendingCsr, PendingCsrStore


def test_encrypt_decrypt_round_trips(tmp_path):
    box = SecretBox(tmp_path)
    ciphertext = box.encrypt("segredo-de-verdade")
    assert ciphertext != "segredo-de-verdade"
    assert box.decrypt(ciphertext) == "segredo-de-verdade"


def test_encrypt_none_and_empty_pass_through_unchanged(tmp_path):
    box = SecretBox(tmp_path)
    assert box.encrypt(None) is None
    assert box.encrypt("") == ""


def test_two_boxes_same_data_dir_share_master_key(tmp_path):
    box1 = SecretBox(tmp_path)
    box2 = SecretBox(tmp_path)
    ciphertext = box1.encrypt("segredo")
    assert box2.decrypt(ciphertext) == "segredo"


def test_master_key_file_created_with_restrictive_permissions(tmp_path):
    box = SecretBox(tmp_path)
    box.encrypt("aciona a criação da chave")
    key_path = tmp_path / "master.key"
    assert key_path.exists()
    assert oct(key_path.stat().st_mode)[-3:] == "600"


def test_acme_certificate_private_key_is_encrypted_on_disk(tmp_path):
    store = AcmeStore(tmp_path)
    store.save_certificate(
        IssuedCertificate(
            id="c1", domain="example.com", environment="staging", issued_at="2026-01-01",
            not_after=None, fullchain_pem="CERT", private_key_pem="MINHA CHAVE PRIVADA",
        )
    )
    raw = json.loads((tmp_path / "acme_certificates" / "c1.json").read_text())
    assert raw["private_key_pem"] != "MINHA CHAVE PRIVADA"

    loaded = store.load_certificate("c1")
    assert loaded.private_key_pem == "MINHA CHAVE PRIVADA"


def test_acme_store_reads_legacy_plaintext_certificate(tmp_path):
    certs_dir = tmp_path / "acme_certificates"
    certs_dir.mkdir(parents=True)
    (certs_dir / "legacy.json").write_text(
        json.dumps(
            {
                "id": "legacy", "domain": "old.example.com", "environment": "staging",
                "issued_at": "2026-01-01", "not_after": None, "fullchain_pem": "CERT",
                "private_key_pem": "CHAVE ANTIGA EM TEXTO PLANO", "dns_mode": None,
            }
        )
    )
    store = AcmeStore(tmp_path)
    loaded = store.load_certificate("legacy")
    assert loaded.private_key_pem == "CHAVE ANTIGA EM TEXTO PLANO"


def test_acme_dns_credentials_token_is_encrypted_on_disk(tmp_path):
    store = AcmeStore(tmp_path)
    creds = DnsCredentials(provider="cloudflare", api_token="cfat_super_secreto")
    store.save_dns_credentials(creds)
    raw = json.loads((tmp_path / "dns_credentials.json").read_text())
    assert raw["api_token"] != "cfat_super_secreto"
    assert store.load_dns_credentials().api_token == "cfat_super_secreto"


def test_notification_smtp_password_is_encrypted_on_disk(tmp_path):
    store = NotificationStore(tmp_path)
    store.save(NotificationConfig(smtp_host="smtp.example.com", smtp_password="senha-smtp"))
    raw = json.loads((tmp_path / "notification_config.json").read_text())
    assert raw["smtp_password"] != "senha-smtp"
    assert store.load().smtp_password == "senha-smtp"


def test_user_totp_secret_is_encrypted_on_disk(tmp_path):
    store = UserStore(tmp_path)
    store.save(UserAccount(username="admin", password_hash="hash", totp_secret="JBSWY3DPEHPK3PXP"))
    raw = json.loads((tmp_path / "admin.json").read_text())
    assert raw["admin"]["totp_secret"] != "JBSWY3DPEHPK3PXP"
    assert store.load("admin").totp_secret == "JBSWY3DPEHPK3PXP"


def test_user_store_reads_legacy_plaintext_admin(tmp_path):
    # Formato antigo (Fase 0-3): objeto plano, sem role, totp_secret em
    # texto puro — o arquivo real já em produção tinha exatamente essa cara.
    (tmp_path / "admin.json").write_text(
        json.dumps(
            {
                "username": "admin", "password_hash": "hash",
                "totp_secret": "SEGREDOTOTPANTIGO", "mfa_enabled": True,
                "pending_totp_secret": None,
            }
        )
    )
    store = UserStore(tmp_path)
    account = store.load("admin")
    assert account.role == "admin"
    assert account.totp_secret == "SEGREDOTOTPANTIGO"


def test_user_store_handles_a_user_literally_named_username(tmp_path):
    """Achado numa auditoria de robustez: a detecção de formato antigo
    checava só `"username" in raw` — um usuário real chamado literalmente
    "username" faz essa mesma condição bater no formato ATUAL (multi-
    usuário), onde `raw["username"]` é um dict de conta, não a string do
    admin único. Sem distinguir os dois, isso explodia com TypeError
    (dict não é hasheável) tentando usar o dict como chave — travando
    load/save pra TODO MUNDO no store, não só essa conta."""
    store = UserStore(tmp_path)
    store.save(UserAccount(username="username", password_hash="hash1", role="leitor"))
    store.save(UserAccount(username="admin", password_hash="hash2", role="admin"))

    loaded = store.load("username")
    assert loaded is not None
    assert loaded.role == "leitor"
    assert store.load("admin").role == "admin"
    assert {u.username for u in store.list_all()} == {"username", "admin"}


def test_looks_like_fernet_token_recognizes_real_tokens(tmp_path):
    box = SecretBox(tmp_path)
    token = box.encrypt("qualquer segredo")
    assert looks_like_fernet_token(token) is True


def test_looks_like_fernet_token_rejects_plain_text():
    assert looks_like_fernet_token("cfat_um_token_de_api_qualquer") is False
    assert looks_like_fernet_token("-----BEGIN PRIVATE KEY-----") is False
    assert looks_like_fernet_token("JBSWY3DPEHPK3PXP") is False
    assert looks_like_fernet_token("") is False


def test_acme_store_raises_instead_of_leaking_ciphertext_after_key_rotation(tmp_path):
    """Achado numa auditoria de robustez: antes deste fix, decriptografar
    com a master key ERRADA (rotação de CERTDISC_MASTER_KEY, ou
    data/master.key perdido/substituído) devolvia o CIPHERTEXT cru como
    se fosse o token de API em texto plano — silencioso, sem nenhuma
    indicação da causa real. Um token de API real (não-Fernet) legado
    continua sendo aceito como texto plano normalmente (teste
    test_acme_store_reads_legacy_plaintext_certificate acima)."""
    store = AcmeStore(tmp_path)
    store.save_dns_credentials(DnsCredentials(provider="cloudflare", api_token="token-real"))

    # simula rotação de master key: um SecretBox novo, com uma chave
    # Fernet válida mas DIFERENTE da original, no mesmo diretório de dados.
    import os

    from cryptography.fernet import Fernet

    (tmp_path / "master.key").unlink()
    os.environ["CERTDISC_MASTER_KEY"] = Fernet.generate_key().decode()
    try:
        rotated_store = AcmeStore(tmp_path)
        with pytest.raises(DecryptionError, match="master key"):
            rotated_store.load_dns_credentials()
    finally:
        os.environ.pop("CERTDISC_MASTER_KEY", None)


def test_pki_csr_private_key_is_encrypted_on_disk(tmp_path):
    store = PendingCsrStore(tmp_path)
    pending = PendingCsr(domains=["example.com"], private_key_pem="CHAVE CSR", csr_pem="CSR PEM")
    store.save(pending)
    raw = json.loads((tmp_path / "pending_csrs" / f"{pending.id}.json").read_text())
    assert raw["private_key_pem"] != "CHAVE CSR"
    assert store.load(pending.id).private_key_pem == "CHAVE CSR"
    assert store.load(pending.id).csr_pem == "CSR PEM"  # não criptografado, não é sensível
