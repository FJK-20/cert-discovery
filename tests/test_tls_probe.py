import asyncio
import datetime
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.discovery.tls_probe import probe_host


def _generate_self_signed_cert(common_name: str):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return cert, cert_pem, key_pem


def test_probe_host_captures_live_self_signed_certificate(tmp_path):
    common_name = "probe.test.local"
    cert, cert_pem, key_pem = _generate_self_signed_cert(common_name)
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(cert_pem)
    key_path.write_bytes(key_pem)

    async def run():
        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(str(cert_path), str(key_path))

        server = await asyncio.start_server(
            lambda reader, writer: None, host="127.0.0.1", port=0, ssl=server_ctx
        )
        port = server.sockets[0].getsockname()[1]

        async with server:
            result = await probe_host(
                common_name,
                "127.0.0.1",
                port=port,
                connect_timeout=2,
                handshake_timeout=2,
                # 127.0.0.1 é bloqueado por padrão (proteção anti-SSRF) — em
                # produção isso é sempre `is_public_ip`; aqui, e só aqui,
                # injetamos um validador permissivo para testar contra um
                # servidor local.
                ip_validator=lambda ip: True,
            )

        assert result.subject_cn == common_name
        assert result.sha256_fingerprint == cert.fingerprint(hashes.SHA256()).hex()
        assert common_name in result.sans
        assert result.serial_number == format(cert.serial_number, "x")

    asyncio.run(run())


def test_probe_host_rejects_blocked_ip_without_connecting():
    from app.discovery.tls_probe import ProbeError

    async def run():
        try:
            await probe_host(
                "internal.example.com",
                "127.0.0.1",
                connect_timeout=1,
                handshake_timeout=1,
            )
        except ProbeError as exc:
            assert "bloqueado" in str(exc)
        else:
            raise AssertionError("esperava ProbeError para IP privado")

    asyncio.run(run())
