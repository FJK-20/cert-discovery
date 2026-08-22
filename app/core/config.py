"""Configuração via variáveis de ambiente, com defaults seguros para demo pública."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _bool_env(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    max_hosts_per_scan: int = _int_env("CERTDISC_MAX_HOSTS", 400)
    max_concurrent_probes: int = _int_env("CERTDISC_MAX_CONCURRENCY", 30)

    ctlogs_timeout_seconds: float = 20.0
    dns_timeout_seconds: float = 4.0
    tcp_connect_timeout_seconds: float = 4.0
    tls_handshake_timeout_seconds: float = 5.0

    job_total_budget_seconds: float = 90.0
    job_ttl_seconds: float = 15 * 60

    rate_limit_requests_per_minute: int = _int_env("CERTDISC_RATE_LIMIT_RPM", 6)

    # Autenticação / MFA
    data_dir: str = os.environ.get("CERTDISC_DATA_DIR", "data")
    session_ttl_seconds: float = 12 * 3600
    pending_login_ttl_seconds: float = 5 * 60
    cookie_secure: bool = _bool_env("CERTDISC_COOKIE_SECURE", False)
    totp_issuer: str = "Certificate Manager"
    auth_rate_limit_requests: int = _int_env("CERTDISC_AUTH_RATE_LIMIT", 8)
    auth_rate_limit_window_seconds: float = 300.0

    # ACME / renovação DNS-01
    # Staging por padrão de propósito: produção tem rate limit real (Let's
    # Encrypt) e emite certificado confiável de verdade — trocar exige ação
    # explícita do usuário, nunca é o default.
    acme_directory_staging: str = "https://acme-staging-v02.api.letsencrypt.org/directory"
    acme_directory_production: str = "https://acme-v02.api.letsencrypt.org/directory"
    # ZeroSSL não publica um diretório de staging separado — toda emissão
    # via ZeroSSL sai direto num certificado de produção real.
    zerossl_directory_url: str = "https://acme.zerossl.com/v2/DV90"
    acme_job_budget_seconds: float = 180.0
    # Modo manual espera uma pessoa ir criar o registro TXT — minutos, não
    # segundos. Budget bem maior que o do modo automático (Cloudflare).
    acme_manual_dns_budget_seconds: float = 20 * 60
    acme_job_ttl_seconds: float = 30 * 60
    acme_dns_propagation_wait_seconds: float = 15.0
    cloudflare_api_base: str = "https://api.cloudflare.com/client/v4"

    # Agendador de renovação — verifica periodicamente certificados
    # entrando na janela de renovação (1/3 da validade restante).
    scheduler_check_interval_seconds: float = float(
        _int_env("CERTDISC_SCHEDULER_INTERVAL_SECONDS", 6 * 60 * 60)
    )

    # SSO via SAML — o Entity ID e a Assertion Consumer Service URL do SP
    # precisam ser fixos e coincidir com o que foi cadastrado no IdP (ver
    # app/auth/saml.py), então não podem ser derivados da URL de cada
    # requisição (o app responde tanto pela LAN quanto pelo domínio
    # público, mas só o domínio público é alcançável pelo navegador
    # redirecionado pelo IdP).
    public_base_url: str = os.environ.get("CERTDISC_PUBLIC_BASE_URL", "http://localhost:8000")


settings = Settings()
