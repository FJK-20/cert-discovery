"""Fluxo de emissão/renovação via ACME DNS-01, usando a lib `acme` oficial
do projeto Certbot/EFF (protocolo ACME é criptograficamente sensível o
bastante para não reimplementar na mão).

Síncrono de propósito — a lib `acme` é construída sobre `requests`, não
`asyncio`. O orquestrador (app/acme/renewal.py) roda `issue_certificate`
inteiro numa thread via `asyncio.to_thread`.

Validado manualmente contra o ambiente staging real do Let's Encrypt
(directory fetch, registro de conta, criação de ordem e extração do
desafio DNS-01 — os 4 primeiros passos do fluxo abaixo) antes de integrar.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import josepy as jose
from acme import challenges, messages
from acme import client as acme_client
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.acme.store import AcmeAccount, AcmeStore

USER_AGENT = "cert-discovery-platform/1.0"
_KEY_SIZE = 2048


class IssuanceError(Exception):
    """Erro em qualquer etapa do fluxo ACME — sempre com uma mensagem
    segura para mostrar ao usuário (não vaza segredos)."""


@dataclass
class IssuedResult:
    fullchain_pem: str
    private_key_pem: str
    not_after: datetime | None


def _serialize_private_key(key: rsa.RSAPrivateKey) -> str:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


def _deserialize_private_key(pem: str) -> rsa.RSAPrivateKey:
    key = serialization.load_pem_private_key(pem.encode(), password=None)
    assert isinstance(key, rsa.RSAPrivateKey)
    return key


def _build_csr(domain: str, key: rsa.RSAPrivateKey) -> bytes:
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM)


def _get_or_create_account(
    store: AcmeStore, environment: str, directory_url: str
) -> tuple[acme_client.ClientV2, jose.JWKRSA]:
    saved = store.load_account(environment)
    if saved is not None:
        account_key = jose.JWKRSA(key=_deserialize_private_key(saved.account_key_pem))
        net = acme_client.ClientNetwork(account_key, user_agent=USER_AGENT)
        directory = acme_client.ClientV2.get_directory(directory_url, net)
        acme = acme_client.ClientV2(directory, net)
        # Reidrata a conta já registrada para o net.account (necessário pro
        # header `kid` das próximas requisições).
        regr = messages.RegistrationResource(body=messages.Registration(), uri=saved.account_uri)
        acme.net.account = acme.query_registration(regr)
        return acme, account_key

    raw_key = rsa.generate_private_key(public_exponent=65537, key_size=_KEY_SIZE)
    account_key = jose.JWKRSA(key=raw_key)
    net = acme_client.ClientNetwork(account_key, user_agent=USER_AGENT)
    directory = acme_client.ClientV2.get_directory(directory_url, net)
    acme = acme_client.ClientV2(directory, net)
    try:
        regr = acme.new_account(messages.NewRegistration.from_data(terms_of_service_agreed=True))
    except messages.Error as exc:
        raise IssuanceError(f"Falha ao registrar conta ACME: {exc}") from exc

    store.save_account(
        AcmeAccount(
            environment=environment,
            account_key_pem=_serialize_private_key(raw_key),
            account_uri=regr.uri,
        )
    )
    return acme, account_key


def issue_certificate(
    *,
    domain: str,
    environment: str,
    directory_url: str,
    store: AcmeStore,
    set_dns_challenge: Callable[[str, str], object],
    clear_dns_challenge: Callable[[object], None],
    wait_for_dns_ready: Callable[[], None],
    total_budget_seconds: float,
    on_progress: Callable[[str], None] = lambda _msg: None,
) -> IssuedResult:
    """Executa o fluxo completo. `set_dns_challenge(record_name, value)`
    deve criar o TXT e devolver um "handle" opaco que `clear_dns_challenge`
    usa pra remover — desacopla este módulo do provedor DNS específico.
    `wait_for_dns_ready()` bloqueia até o desafio estar pronto pra validar:
    no modo automático (Cloudflare) é só um `time.sleep` de propagação; no
    modo manual, bloqueia até a pessoa confirmar (ver
    app/acme/renewal.py) — a interface não sabe nem precisa saber qual dos
    dois é."""
    on_progress("Preparando conta ACME...")
    acme, account_key = _get_or_create_account(store, environment, directory_url)

    on_progress("Gerando chave e CSR do certificado...")
    cert_key = rsa.generate_private_key(public_exponent=65537, key_size=_KEY_SIZE)
    csr_pem = _build_csr(domain, cert_key)

    on_progress("Criando pedido de certificado (order)...")
    try:
        orderr = acme.new_order(csr_pem)
    except messages.Error as exc:
        raise IssuanceError(f"Falha ao criar pedido ACME: {exc}") from exc

    dns_handles = []
    try:
        on_progress("Configurando desafio DNS-01 no provedor de DNS...")
        for authz in orderr.authorizations:
            dns_challs = [c for c in authz.body.challenges if isinstance(c.chall, challenges.DNS01)]
            if not dns_challs:
                raise IssuanceError(f"Servidor ACME não ofereceu desafio DNS-01 para {domain}.")
            chall = dns_challs[0]
            validation = chall.chall.validation(account_key)
            record_name = chall.chall.validation_domain_name(authz.body.identifier.value)
            handle = set_dns_challenge(record_name, validation)
            dns_handles.append(handle)

        on_progress("Aguardando o desafio DNS ficar pronto...")
        wait_for_dns_ready()

        on_progress("Avisando a CA que o desafio está pronto...")
        for authz in orderr.authorizations:
            dns_challs = [c for c in authz.body.challenges if isinstance(c.chall, challenges.DNS01)]
            chall = dns_challs[0]
            response = chall.response(account_key)
            acme.answer_challenge(chall, response)

        on_progress("Aguardando validação e emissão pela CA...")
        deadline = datetime.now() + timedelta(seconds=total_budget_seconds)
        try:
            finalized = acme.poll_and_finalize(orderr, deadline)
        except messages.Error as exc:
            raise IssuanceError(f"CA recusou o pedido: {exc}") from exc
    finally:
        on_progress("Limpando registro DNS temporário...")
        for handle in dns_handles:
            try:
                clear_dns_challenge(handle)
            except Exception:  # nunca deixa a limpeza derrubar o resultado
                pass

    if not finalized.fullchain_pem:
        raise IssuanceError("CA não retornou o certificado emitido.")

    leaf = x509.load_pem_x509_certificate(finalized.fullchain_pem.encode())
    not_after = leaf.not_valid_after_utc if hasattr(leaf, "not_valid_after_utc") else None
    if not_after and not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=UTC)

    return IssuedResult(
        fullchain_pem=finalized.fullchain_pem,
        private_key_pem=_serialize_private_key(cert_key),
        not_after=not_after,
    )
