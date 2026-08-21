"""Verifica periodicamente os certificados emitidos por este app e
dispara renovação automática pros que suportam (`cloudflare` ou
`cname_delegation`) — notifica em vez de tentar pros que exigem
confirmação manual (dns_mode `manual`, ou emitidos via CSR manual, que
nem tem dns_mode).

Regra de negócio: a janela de renovação começa a 1/3 da validade
restante (ex.: certificado de 90 dias — padrão Let's Encrypt — entra na
fila a partir de 30 dias antes de expirar, mesma prática recomendada pela
própria CA).

Só o certificado mais recente de cada domínio entra na checagem: depois
de uma renovação bem-sucedida, o certificado antigo (agora superado) tem
um `not_after` mais cedo mas deixa de ser "o atual" — fica de fora sem
precisar apagar nada nem manter estado extra de "já renovado".

Cada tentativa de renovação automática é registrada em
`app/acme/history.py` (SQLite, sobrevive a restart). É de lá que vem a
contagem de tentativas desde o último sucesso — a base do retry com
backoff exponencial (regra de negócio 05): falha notifica sempre, tenta
de novo depois de um tempo crescente, e depois de `_MAX_AUTO_RETRIES`
tentativas desiste de tentar sozinho e só continua notificando.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime

from app.acme.history import RenewalHistoryStore, renewal_history
from app.acme.models import AcmeEnvironment, AcmeJobState, CertificateAuthority, DnsMode
from app.acme.renewal import AcmeRenewalManager, renewal_manager
from app.acme.store import AcmeStore, IssuedCertificate, acme_store
from app.core.config import settings
from app.notify import notifier
from app.notify.store import NotificationStore
from app.notify.store import notification_store as default_notification_store

_AUTO_RENEWABLE_MODES = {DnsMode.CLOUDFLARE.value, DnsMode.CNAME_DELEGATION.value}
_TERMINAL_STATES = {AcmeJobState.DONE.value, AcmeJobState.FAILED.value}

# Regra de negócio 05: retry com backoff, depois de esgotar as tentativas
# avisa em vez de desistir silenciosamente. Backoff exponencial (10min,
# 20min, 40min, ...) travado no próprio intervalo de checagem — não faz
# sentido esperar mais que isso, o próximo ciclo natural já tentaria de
# novo de qualquer forma.
_MAX_AUTO_RETRIES = 5
_BACKOFF_BASE_SECONDS = 600.0


def renewal_threshold(cert: IssuedCertificate) -> datetime | None:
    if not cert.not_after:
        return None
    issued_at = datetime.fromisoformat(cert.issued_at)
    not_after = datetime.fromisoformat(cert.not_after)
    total_validity = not_after - issued_at
    return not_after - (total_validity / 3)


def latest_per_domain(certs: list[IssuedCertificate]) -> list[IssuedCertificate]:
    latest: dict[str, IssuedCertificate] = {}
    for cert in certs:
        current = latest.get(cert.domain)
        if current is None or cert.issued_at > current.issued_at:
            latest[cert.domain] = cert
    return list(latest.values())


class RenewalScheduler:
    def __init__(
        self,
        *,
        store: AcmeStore = acme_store,
        manager: AcmeRenewalManager = renewal_manager,
        notify_store: NotificationStore = default_notification_store,
        history: RenewalHistoryStore = renewal_history,
        check_interval_seconds: float | None = None,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._store = store
        self._manager = manager
        self._notify_store = notify_store
        self._history = history
        self._check_interval_seconds = (
            check_interval_seconds
            if check_interval_seconds is not None
            else settings.scheduler_check_interval_seconds
        )
        self._now = now
        self._last_check_at: datetime | None = None
        self._task: asyncio.Task | None = None

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._run_forever())

    @property
    def last_check_at(self) -> datetime | None:
        return self._last_check_at

    @property
    def check_interval_seconds(self) -> float:
        return self._check_interval_seconds

    async def _run_forever(self) -> None:
        while True:
            try:
                await self.check_once()
            except Exception:
                pass  # uma falha na checagem não pode matar o loop pra sempre
            await asyncio.sleep(self._check_interval_seconds)

    async def check_once(self) -> list[dict]:
        """Uma passada de verificação — separada de `_run_forever` pra dar
        pra chamar sob demanda (testes, e o botão "verificar agora" da
        tela de Renovação)."""
        self._last_check_at = self._now()
        results = []
        for cert in latest_per_domain(self._store.list_certificates()):
            threshold = renewal_threshold(cert)
            if threshold is None or self._now() < threshold:
                continue
            results.append(await self._handle_due_certificate(cert))
        return results

    async def _handle_due_certificate(self, cert: IssuedCertificate) -> dict:
        if cert.dns_mode in _AUTO_RENEWABLE_MODES:
            return await self._attempt_auto_renewal(cert)
        return self._notify_manual_renewal_needed(cert)

    async def _attempt_auto_renewal(self, cert: IssuedCertificate) -> dict:
        attempts = self._history.attempts_since_last_success(cert.domain)
        last = attempts[-1] if attempts else None

        if last is not None and last["state"] == "failed" and last["finished_at"]:
            backoff = min(
                _BACKOFF_BASE_SECONDS * (2 ** (len(attempts) - 1)), self._check_interval_seconds
            )
            elapsed = (self._now() - datetime.fromisoformat(last["finished_at"])).total_seconds()
            if elapsed < backoff:
                return {
                    "domain": cert.domain,
                    "action": "renewal_backoff",
                    "retry_in_seconds": round(backoff - elapsed),
                }

        if len(attempts) >= _MAX_AUTO_RETRIES:
            message = (
                f"Renovação automática de {cert.domain} esgotou {len(attempts)} tentativas "
                f"e precisa de renovação manual. Último erro: "
                f"{last['error'] if last else 'desconhecido'}."
            )
            notifier.notify(
                f"{cert.domain}: renovação automática esgotada", message, self._notify_store.load()
            )
            return {"domain": cert.domain, "action": "renewal_exhausted", "attempts": len(attempts)}

        job = await self._manager.create(
            cert.domain,
            AcmeEnvironment(cert.environment),
            DnsMode(cert.dns_mode),
            # Certificados emitidos antes do campo `ca` existir não têm
            # esse dado gravado — assume Let's Encrypt (era a única CA
            # disponível na época), nunca troca de CA silenciosamente numa
            # renovação automática.
            CertificateAuthority(cert.ca) if cert.ca else CertificateAuthority.LETS_ENCRYPT,
            trigger="scheduler",
        )
        # Espera o job terminar. O teto usa o budget do modo manual (bem
        # maior) porque, no pior caso de cname_delegation (alguém apagou o
        # CNAME depois de configurado), o job entra em AWAITING_DNS e só
        # desiste sozinho depois desse tempo — ninguém está olhando a tela
        # pra confirmar, então precisa dar tempo dele desistir por conta
        # própria em vez de eu desistir de esperar primeiro e mandar uma
        # notificação de "falhou" enquanto ele ainda estava rodando.
        deadline = self._now().timestamp() + settings.acme_manual_dns_budget_seconds + 10
        while job.state.value not in _TERMINAL_STATES and self._now().timestamp() < deadline:
            await asyncio.sleep(0.5)

        if job.state.value == AcmeJobState.DONE.value:
            return {"domain": cert.domain, "action": "renewed", "job_id": job.id}

        attempt_number = len(attempts) + 1
        error = job.error or "tempo esgotado aguardando a renovação"
        if attempt_number >= _MAX_AUTO_RETRIES:
            message = (
                f"Tentativa {attempt_number}/{_MAX_AUTO_RETRIES} de renovação de {cert.domain} "
                f"falhou: {error}. Tentativas automáticas esgotadas — precisa de ação manual."
            )
            subject = f"{cert.domain}: renovação automática esgotada"
        else:
            message = (
                f"Tentativa {attempt_number}/{_MAX_AUTO_RETRIES} de renovação de {cert.domain} "
                f"falhou: {error}. Nova tentativa automática em breve."
            )
            subject = f"Falha ao renovar {cert.domain}"
        notifier.notify(subject, message, self._notify_store.load())
        return {
            "domain": cert.domain,
            "action": "renewal_failed",
            "error": error,
            "attempt_number": attempt_number,
        }

    def _notify_manual_renewal_needed(self, cert: IssuedCertificate) -> dict:
        message = (
            f"O certificado de {cert.domain} expira em {cert.not_after} e precisa de "
            "renovação manual (emitido num modo que exige confirmação humana)."
        )
        notifier.notify(
            f"{cert.domain} precisa de renovação manual", message, self._notify_store.load()
        )
        return {"domain": cert.domain, "action": "manual_renewal_notified"}


scheduler = RenewalScheduler()
