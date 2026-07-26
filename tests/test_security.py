from app.core.security import is_public_ip


def test_public_ipv4_allowed():
    assert is_public_ip("8.8.8.8") is True
    assert is_public_ip("1.1.1.1") is True


def test_public_ipv6_allowed():
    assert is_public_ip("2606:4700:4700::1111") is True


def test_rfc1918_blocked():
    assert is_public_ip("10.0.0.1") is False
    assert is_public_ip("172.16.5.4") is False
    assert is_public_ip("192.168.1.1") is False


def test_loopback_blocked():
    assert is_public_ip("127.0.0.1") is False
    assert is_public_ip("::1") is False


def test_cloud_metadata_ip_blocked():
    assert is_public_ip("169.254.169.254") is False


def test_link_local_blocked():
    assert is_public_ip("169.254.1.5") is False
    assert is_public_ip("fe80::1") is False


def test_cgnat_blocked():
    assert is_public_ip("100.64.0.1") is False


def test_multicast_and_broadcast_blocked():
    assert is_public_ip("224.0.0.1") is False
    assert is_public_ip("255.255.255.255") is False


def test_test_net_ranges_blocked():
    assert is_public_ip("192.0.2.1") is False
    assert is_public_ip("198.51.100.1") is False
    assert is_public_ip("203.0.113.1") is False


def test_ipv4_mapped_ipv6_unwraps_and_blocks_private():
    # ::ffff:10.0.0.1 -> 10.0.0.1 é privado, deve ser bloqueado mesmo
    # olhando "só" pra forma IPv6.
    assert is_public_ip("::ffff:10.0.0.1") is False


def test_ipv4_mapped_ipv6_unwraps_and_allows_public():
    assert is_public_ip("::ffff:8.8.8.8") is True


def test_nat64_mapped_private_blocked():
    # 64:ff9b::/96 + 169.254.169.254 embutido
    assert is_public_ip("64:ff9b::a9fe:a9fe") is False


def test_invalid_ip_string_blocked():
    assert is_public_ip("not-an-ip") is False
    assert is_public_ip("") is False
