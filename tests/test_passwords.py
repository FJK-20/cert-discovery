import hashlib

from app.auth.passwords import _LEGACY_N, _N, hash_password, needs_rehash, verify_password


def test_verify_password_accepts_correct_password():
    stored = hash_password("correct horse battery staple")
    assert verify_password("correct horse battery staple", stored) is True


def test_verify_password_rejects_wrong_password():
    stored = hash_password("correct horse battery staple")
    assert verify_password("wrong password", stored) is False


def test_hash_password_uses_random_salt():
    first = hash_password("same password")
    second = hash_password("same password")
    assert first != second


def test_verify_password_rejects_malformed_stored_value():
    assert verify_password("anything", "not-a-valid-hash") is False


def test_hash_password_uses_current_owasp_n_and_embeds_it():
    """Achado numa auditoria de robustez: n=2**14 era o mínimo de uma
    versão antiga da recomendação OWASP — atual pede 2**17 (8x mais
    memória). O hash embute o n usado, senão subir esse valor no código
    quebraria a verificação de toda senha já salva com o valor antigo."""
    stored = hash_password("qualquer coisa")
    n_field = stored.split("$", 1)[0]
    assert int(n_field) == _N == 2**17


def _legacy_hash(password: str) -> str:
    """Reproduz o formato de ANTES deste fix (`salt$digest`, sem `n`) —
    é exatamente o que uma conta real criada antes desta mudança tem
    salvo em disco."""
    salt = b"\x01" * 16
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_LEGACY_N, r=8, p=1, dklen=64)
    return f"{salt.hex()}${digest.hex()}"


def test_verify_password_still_accepts_legacy_two_field_format():
    """Uma conta criada antes deste fix não pode ficar sem conseguir
    logar — verify_password precisa continuar aceitando o formato antigo
    (sem campo de n, sempre _LEGACY_N)."""
    stored = _legacy_hash("senha-antiga")
    assert verify_password("senha-antiga", stored) is True
    assert verify_password("senha-errada", stored) is False


def test_needs_rehash_true_for_legacy_format_and_false_for_current():
    legacy = _legacy_hash("senha-antiga")
    current = hash_password("senha-nova")
    assert needs_rehash(legacy) is True
    assert needs_rehash(current) is False


def test_needs_rehash_true_for_malformed_value():
    assert needs_rehash("garbage") is True
