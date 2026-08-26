from app.auth import totp

SECRET = totp.generate_secret()


def test_totp_now_and_verify_round_trip():
    code = totp.totp_now(SECRET, timestamp=1_700_000_000)
    assert totp.verify_totp(SECRET, code, timestamp=1_700_000_000) is not None


def test_verify_totp_rejects_wrong_code():
    assert totp.verify_totp(SECRET, "000000", timestamp=1_700_000_000) is None


def test_verify_totp_tolerates_one_period_of_clock_drift():
    code = totp.totp_now(SECRET, timestamp=1_700_000_000)
    # Um período (30s) à frente ainda deve validar (VALID_WINDOW = 1).
    assert (
        totp.verify_totp(SECRET, code, timestamp=1_700_000_000 + totp.PERIOD_SECONDS) is not None
    )


def test_verify_totp_rejects_beyond_valid_window():
    code = totp.totp_now(SECRET, timestamp=1_700_000_000)
    far_future = 1_700_000_000 + totp.PERIOD_SECONDS * 5
    assert totp.verify_totp(SECRET, code, timestamp=far_future) is None


def test_verify_totp_rejects_malformed_code():
    assert totp.verify_totp(SECRET, "abcdef", timestamp=1_700_000_000) is None
    assert totp.verify_totp(SECRET, "123", timestamp=1_700_000_000) is None
    assert totp.verify_totp(SECRET, "", timestamp=1_700_000_000) is None


def test_verify_totp_returns_the_matched_counter():
    code = totp.totp_now(SECRET, timestamp=1_700_000_000)
    expected_counter = int(1_700_000_000 // totp.PERIOD_SECONDS)
    assert totp.verify_totp(SECRET, code, timestamp=1_700_000_000) == expected_counter


def test_verify_totp_rejects_replay_of_an_already_consumed_counter():
    """Achado numa auditoria de robustez: sem rastrear consumo, um
    código de 6 dígitos observado (rede, ombro, log) valia de novo por
    toda a janela de tolerância (~90s) — TOTP é de uso único."""
    code = totp.totp_now(SECRET, timestamp=1_700_000_000)
    used_counter = totp.verify_totp(SECRET, code, timestamp=1_700_000_000)
    assert used_counter is not None

    # o mesmo código, no mesmo instante, não vale mais uma vez.
    replayed = totp.verify_totp(
        SECRET, code, last_counter=used_counter, timestamp=1_700_000_000
    )
    assert replayed is None


def test_verify_totp_without_last_counter_does_not_enforce_replay_protection():
    # Comportamento explícito pra confirmação de enrollment: segredo
    # acabou de nascer, não tem consumo anterior pra proteger contra.
    code = totp.totp_now(SECRET, timestamp=1_700_000_000)
    assert totp.verify_totp(SECRET, code, timestamp=1_700_000_000) is not None
    assert totp.verify_totp(SECRET, code, timestamp=1_700_000_000) is not None


def test_provisioning_uri_contains_issuer_and_secret():
    uri = totp.provisioning_uri(SECRET, account_name="admin", issuer="Cert Discovery")
    assert uri.startswith("otpauth://totp/")
    assert "secret=" in uri
    assert "issuer=" in uri
