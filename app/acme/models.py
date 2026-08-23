from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum


class AcmeEnvironment(StrEnum):
    STAGING = "staging"
    PRODUCTION = "production"


class CertificateAuthority(StrEnum):
    """Qual CA emite o certificado — eixo independente do modo de
    validação DNS (`DnsMode` abaixo): qualquer CA funciona com qualquer
    modo, porque o desafio DNS-01 é o mesmo protocolo nos dois casos.
    `LETS_ENCRYPT` não precisa de credencial nenhuma (conta ACME comum).
    `ZEROSSL` exige External Account Binding (EAB) — um par kid/hmac_key
    de uma conta ZeroSSL, sem o qual `new_account()` é rejeitado pela CA."""

    LETS_ENCRYPT = "letsencrypt"
    ZEROSSL = "zerossl"


class DnsMode(StrEnum):
    """Como o desafio DNS-01 é resolvido. `MANUAL` é o padrão genérico —
    funciona com qualquer provedor de DNS, sem credencial nenhuma.
    `CLOUDFLARE` e `AZURE_DNS` são plugins opcionais pra quem quer
    automação total, cada um com sua própria credencial — dois provedores
    reais provando que a interface de plugin é plugável de verdade, não só
    na teoria. `CNAME_DELEGATION` fica no meio: uma configuração manual
    única (um CNAME) e, depois disso, toda renovação futura daquele
    domínio é automática — sem token nenhum do lado do domínio emitido
    (usa a credencial Cloudflare salva como zona de delegação)."""

    MANUAL = "manual"
    CLOUDFLARE = "cloudflare"
    AZURE_DNS = "azure_dns"
    CNAME_DELEGATION = "cname_delegation"


class AcmeJobState(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    AWAITING_DNS = "awaiting_dns"
    DONE = "done"
    FAILED = "failed"


@dataclass
class AcmeJob:
    domain: str
    environment: AcmeEnvironment
    dns_mode: DnsMode = DnsMode.MANUAL
    ca: CertificateAuthority = CertificateAuthority.LETS_ENCRYPT
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    state: AcmeJobState = AcmeJobState.PENDING
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    progress_message: str = ""
    error: str | None = None
    certificate_id: str | None = None
    # Preenchidos quando o job entra em AWAITING_DNS — é o que a tela de
    # Emissão mostra pro usuário criar no DNS dele. dns_record_type indica
    # se é TXT (modo manual) ou CNAME (configuração única da delegação).
    dns_record_type: str = "TXT"
    dns_record_name: str | None = None
    dns_record_value: str | None = None
    # Contexto opcional (Fase 8) — ver app/acme/store.py, mesmo campo em
    # IssuedCertificate; só carregado até lá quando o job termina.
    organization_id: str | None = None
    system_id: str | None = None
    project_id: str | None = None
