from app.auth import totp

SECRET = totp.generate_secret()


def test_totp_now_and_verify_round_trip():
    code = totp.totp_now(SECRET, timestamp=1_700_000_000)
    assert totp.verify_totp(SECRET, code, timestamp=1_700_000_000) is True


def test_verify_totp_rejects_wrong_code():
    assert totp.verify_totp(SECRET, "000000", timestamp=1_700_000_000) is False


def test_verify_totp_tolerates_one_period_of_clock_drift():
    code = totp.totp_now(SECRET, timestamp=1_700_000_000)
    # Um período (30s) à frente ainda deve validar (VALID_WINDOW = 1).
    assert totp.verify_totp(SECRET, code, timestamp=1_700_000_000 + totp.PERIOD_SECONDS) is True


def test_verify_totp_rejects_beyond_valid_window():
    code = totp.totp_now(SECRET, timestamp=1_700_000_000)
    far_future = 1_700_000_000 + totp.PERIOD_SECONDS * 5
    assert totp.verify_totp(SECRET, code, timestamp=far_future) is False


def test_verify_totp_rejects_malformed_code():
    assert totp.verify_totp(SECRET, "abcdef", timestamp=1_700_000_000) is False
    assert totp.verify_totp(SECRET, "123", timestamp=1_700_000_000) is False
    assert totp.verify_totp(SECRET, "", timestamp=1_700_000_000) is False


def test_provisioning_uri_contains_issuer_and_secret():
    uri = totp.provisioning_uri(SECRET, account_name="admin", issuer="Cert Discovery")
    assert uri.startswith("otpauth://totp/")
    assert "secret=" in uri
    assert "issuer=" in uri
