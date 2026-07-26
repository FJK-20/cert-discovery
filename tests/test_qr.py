from app.auth.qr import to_svg_data_uri


def test_to_svg_data_uri_returns_embeddable_data_uri():
    result = to_svg_data_uri("otpauth://totp/Test:admin?secret=ABC")
    assert result.startswith("data:image/svg+xml;base64,")
    assert len(result) > 100
