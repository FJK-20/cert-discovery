from app.auth.passwords import hash_password, verify_password


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
