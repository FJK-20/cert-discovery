"""Orquestra um job de emissão/renovação ACME, mesmo padrão do
ScanJobManager (app/jobs/manager.py): job store em memória, progresso
consultável via polling/SSE, timeout de orçamento total.

Diferença chave: o fluxo ACME em si (app/acme/issuance.py) é síncrono
(lib `acme` roda sobre `requests`), então roda inteiro numa thread via
`asyncio.to_thread` — as atualizações de progresso feitas de dentro da
thread em `job.progress_message`/`job.state` são seguras porque cada
atribuição é uma operação atômica sob o GIL; não há seção crítica maior
que precise de lock aqui.

Quatro modos de resolver o desafio DNS-01 (`job.dns_mode`):
- `manual` (padrão, genérico): a thread de emissão cria o pedido na CA,
  publica o nome/valor do TXT esperado em `job.dns_record_*` e
  **bloqueia** num `threading.Event` até alguém chamar `confirm_dns()` —
  isso é o que a pessoa faz manualmente em qualquer provedor de DNS, sem
  credencial nenhuma. Repete a cada emissão/renovação.
- `cloudflare`/`azure_dns`: automático, mesmo fluxo de sempre (credencial
  da API cria e remove o TXT sozinha, só uma espera fixa de propagação).
- `cname_delegation`: híbrido. Na primeira vez pra um domínio, pede uma
  configuração manual única (um CNAME de `_acme-challenge.<domínio>` pra
  uma zona que o app controla) — mesmo bloqueio via evento que o modo
  manual usa, só que verificando CNAME em vez de TXT. Depois de
  configurado, toda emissão futura daquele domínio detecta o CNAME já
  existente e segue automática, sem token nenhum do lado do domínio
  emitido (o TXT de cada desafio é publicado na zona de delegação, que o
  app já controla via as credenciais Cloudflare salvas).
- `self_hosted_dns`: mesma ideia híbrida do `cname_delegation` (CNAME
  configurado uma vez, automático depois), mas SEM nenhuma credencial de
  terceiro em lugar nenhum — a zona de delegação é respondida pelo
  próprio processo (app/acme/selfdns.py), não por uma API externa. O
  único pré-requisito é uma delegação NS de verdade no registrador,
  feita uma vez pelo operador da instância, fora do app.
"""

from __future__ import annotations

import asyncio
import hashlib
import threading
import time
import uuid
from datetime import UTC, datetime

from app.acme import azure_dns, cloudflare, dns_check, selfdns
from app.acme.history import RenewalHistoryStore, renewal_history
from app.acme.issuance import IssuanceError, issue_certificate
from app.acme.models import AcmeEnvironment, AcmeJob, AcmeJobState, CertificateAuthority, DnsMode
from app.acme.store import AcmeStore, IssuedCertificate, acme_store
from app.core.config import settings

_EVENT_BASED_MODES = (DnsMode.MANUAL, DnsMode.CNAME_DELEGATION, DnsMode.SELF_HOSTED_DNS)


def _delegation_target(domain: str, delegation_zone: str) -> str:
    """Nome estável e determinístico dentro da zona de delegação — mesmo
    domínio emitido sempre mapeia pro mesmo alvo, então o CNAME que a
    pessoa configura uma vez continua válido em toda renovação futura."""
    digest = hashlib.sha256(domain.encode()).hexdigest()[:12]
    return f"{digest}.acme-delegate.{delegation_zone.strip('.')}"


class AcmeRenewalManager:
    def __init__(
        self, store: AcmeStore = acme_store, history: RenewalHistoryStore = renewal_history
    ) -> None:
        self._jobs: dict[str, AcmeJob] = {}
        self._confirm_events: dict[str, threading.Event] = {}
        self._store = store
        self._history = history

    async def create(
        self,
        domain: str,
        environment: AcmeEnvironment,
        dns_mode: DnsMode = DnsMode.MANUAL,
        ca: CertificateAuthority = CertificateAuthority.LETS_ENCRYPT,
        *,
        trigger: str = "manual",
        organization_id: str | None = None,
        system_id: str | None = None,
        project_id: str | None = None,
    ) -> AcmeJob:
        self._evict_expired()
        job = AcmeJob(
            domain=domain,
            environment=environment,
            dns_mode=dns_mode,
            ca=ca,
            organization_id=organization_id,
            system_id=system_id,
            project_id=project_id,
        )
        self._jobs[job.id] = job
        if dns_mode in _EVENT_BASED_MODES:
            self._confirm_events[job.id] = threading.Event()
        attempt_number = len(self._history.attempts_since_last_success(domain)) + 1
        self._history.start(
            attempt_id=job.id,
            domain=domain,
            environment=environment.value,
            dns_mode=dns_mode.value,
            trigger=trigger,
            attempt_number=attempt_number,
        )
        asyncio.create_task(self._run(job))
        return job

    def get(self, job_id: str) -> AcmeJob | None:
        return self._jobs.get(job_id)

    async def confirm_dns(self, job_id: str) -> tuple[bool, str]:
        """Chamado pela rota quando a pessoa clica "Verificar propagação e
        continuar" (modo manual) ou "Verificar CNAME e continuar" (primeira
        configuração da delegação). Só destrava a thread de emissão se o
        registro esperado já estiver visível publicamente — evita gastar
        uma tentativa de validação (rate limit da CA) num registro que
        ainda não propagou."""
        job = self._jobs.get(job_id)
        if job is None:
            return False, "Job não encontrado (pode ter expirado)."
        if job.state != AcmeJobState.AWAITING_DNS:
            return False, "Esse job não está esperando confirmação de DNS."
        if job.dns_record_name is None or job.dns_record_value is None:
            return False, "Estado interno inválido — tente emitir novamente."

        if job.dns_record_type == "CNAME":
            found = await dns_check.cname_matches(
                job.dns_record_name, job.dns_record_value, timeout=10.0
            )
            not_found_message = "CNAME ainda não encontrado — aguarde a propagação e tente de novo."
        else:
            found = await dns_check.txt_record_contains(
                job.dns_record_name, job.dns_record_value, timeout=10.0
            )
            not_found_message = (
                "Registro TXT ainda não encontrado — aguarde a propagação e tente de novo."
            )

        if not found:
            return False, not_found_message

        job.state = AcmeJobState.RUNNING
        job.progress_message = "DNS confirmado — continuando..."
        event = self._confirm_events.get(job_id)
        if event is not None:
            event.set()
        return True, "DNS confirmado."

    def _evict_expired(self) -> None:
        cutoff = time.time() - settings.acme_job_ttl_seconds
        expired = [jid for jid, job in self._jobs.items() if job.created_at.timestamp() < cutoff]
        for jid in expired:
            self._jobs.pop(jid, None)
            self._confirm_events.pop(jid, None)

    async def _run(self, job: AcmeJob) -> None:
        job.state = AcmeJobState.RUNNING
        budget = (
            settings.acme_manual_dns_budget_seconds
            if job.dns_mode in _EVENT_BASED_MODES
            else settings.acme_job_budget_seconds
        )
        try:
            await asyncio.wait_for(asyncio.to_thread(self._issue_sync, job), timeout=budget)
            job.state = AcmeJobState.DONE
            job.progress_message = "Certificado emitido com sucesso."
        except TimeoutError:
            job.state = AcmeJobState.FAILED
            job.error = "Tempo esgotado aguardando a emissão do certificado."
        except IssuanceError as exc:
            job.state = AcmeJobState.FAILED
            job.error = str(exc)
        except Exception as exc:  # nunca deixa o job travado em progresso
            job.state = AcmeJobState.FAILED
            job.error = f"Erro inesperado: {exc}"
        finally:
            self._confirm_events.pop(job.id, None)
            self._history.finish(
                job.id,
                state=job.state.value,
                error=job.error,
                certificate_id=job.certificate_id,
            )

    def _issue_sync(self, job: AcmeJob) -> None:
        if job.dns_mode == DnsMode.CLOUDFLARE:
            result = self._issue_via_cloudflare(job)
        elif job.dns_mode == DnsMode.AZURE_DNS:
            result = self._issue_via_azure_dns(job)
        elif job.dns_mode == DnsMode.CNAME_DELEGATION:
            result = self._issue_via_cname_delegation(job)
        elif job.dns_mode == DnsMode.SELF_HOSTED_DNS:
            result = self._issue_via_self_hosted_dns(job)
        else:
            result = self._issue_via_manual_dns(job)

        cert = IssuedCertificate(
            id=str(uuid.uuid4()),
            domain=job.domain,
            environment=job.environment.value,
            issued_at=datetime.now(UTC).isoformat(),
            not_after=result.not_after.isoformat() if result.not_after else None,
            fullchain_pem=result.fullchain_pem,
            private_key_pem=result.private_key_pem,
            dns_mode=job.dns_mode.value,
            ca=job.ca.value,
            organization_id=job.organization_id,
            system_id=job.system_id,
            project_id=job.project_id,
        )
        self._store.save_certificate(cert)
        job.certificate_id = cert.id

    def _directory_url(self, job: AcmeJob) -> str:
        if job.ca == CertificateAuthority.ZEROSSL:
            return settings.zerossl_directory_url
        return (
            settings.acme_directory_production
            if job.environment == AcmeEnvironment.PRODUCTION
            else settings.acme_directory_staging
        )

    def _account_storage_key(self, job: AcmeJob) -> str:
        """Chave de armazenamento da conta ACME (app/acme/store.py) — não
        é simplesmente `job.environment.value` porque a ZeroSSL não tem
        staging separado: usar "production" pra ela colidiria com a conta
        de produção da Let's Encrypt, cada uma pisando na conta salva da
        outra."""
        if job.ca == CertificateAuthority.ZEROSSL:
            return "zerossl"
        return job.environment.value

    def _eab_credentials(self, job: AcmeJob) -> tuple[str | None, str | None]:
        if job.ca != CertificateAuthority.ZEROSSL:
            return None, None
        creds = self._store.load_ca_credentials(CertificateAuthority.ZEROSSL.value)
        if creds is None:
            raise IssuanceError(
                "Nenhuma credencial EAB da ZeroSSL configurada. Configure o "
                "kid e a chave HMAC (em Emissão → Configurar ZeroSSL) antes "
                "de emitir um certificado por essa CA."
            )
        return creds.eab_kid, creds.eab_hmac_key

    def _issue_via_cloudflare(self, job: AcmeJob):
        creds = self._store.load_dns_credentials()
        if creds is None:
            raise IssuanceError(
                "Nenhuma credencial de provedor de DNS configurada. "
                "Configure o token da Cloudflare antes de emitir um certificado."
            )
        eab_kid, eab_hmac_key = self._eab_credentials(job)

        def set_dns_challenge(record_name: str, value: str) -> tuple[str, str]:
            job.progress_message = f"Criando registro TXT {record_name}..."
            try:
                zone_id = cloudflare.find_zone_id(job.domain, creds.api_token)
                record_id = cloudflare.create_txt_record(
                    zone_id, record_name, value, creds.api_token
                )
            except cloudflare.CloudflareError as exc:
                raise IssuanceError(f"Falha ao configurar o DNS na Cloudflare: {exc}") from exc
            return (zone_id, record_id)

        def clear_dns_challenge(handle: tuple[str, str]) -> None:
            zone_id, record_id = handle
            # Erro na limpeza não deve mascarar o resultado da emissão —
            # já é tratado como best-effort por quem chama (issue_certificate).
            cloudflare.delete_txt_record(zone_id, record_id, creds.api_token)

        def wait_for_dns_ready() -> None:
            time.sleep(settings.acme_dns_propagation_wait_seconds)

        # Deixa uma margem dentro do orçamento total do job para a limpeza
        # do DNS e a gravação do certificado depois que a lib retorna.
        issuance_budget = max(30.0, settings.acme_job_budget_seconds - 20.0)

        return issue_certificate(
            domain=job.domain,
            environment=self._account_storage_key(job),
            directory_url=self._directory_url(job),
            store=self._store,
            set_dns_challenge=set_dns_challenge,
            clear_dns_challenge=clear_dns_challenge,
            wait_for_dns_ready=wait_for_dns_ready,
            eab_kid=eab_kid,
            eab_hmac_key=eab_hmac_key,
            total_budget_seconds=issuance_budget,
            on_progress=lambda message: setattr(job, "progress_message", message),
        )

    def _issue_via_azure_dns(self, job: AcmeJob):
        creds = self._store.load_azure_dns_credentials()
        if creds is None:
            raise IssuanceError(
                "Nenhuma credencial do Azure DNS configurada. Configure o "
                "service principal antes de emitir um certificado por esse modo."
            )
        eab_kid, eab_hmac_key = self._eab_credentials(job)

        def set_dns_challenge(record_name: str, value: str) -> str:
            job.progress_message = f"Criando registro TXT {record_name} no Azure DNS..."
            try:
                return azure_dns.create_txt_record(creds, record_name, value)
            except azure_dns.AzureDnsError as exc:
                raise IssuanceError(f"Falha ao configurar o DNS no Azure: {exc}") from exc

        def clear_dns_challenge(relative_name: str) -> None:
            # Erro na limpeza não deve mascarar o resultado da emissão —
            # já é tratado como best-effort por quem chama (issue_certificate).
            azure_dns.delete_txt_record(creds, relative_name)

        def wait_for_dns_ready() -> None:
            time.sleep(settings.acme_dns_propagation_wait_seconds)

        issuance_budget = max(30.0, settings.acme_job_budget_seconds - 20.0)

        return issue_certificate(
            domain=job.domain,
            environment=self._account_storage_key(job),
            directory_url=self._directory_url(job),
            store=self._store,
            set_dns_challenge=set_dns_challenge,
            clear_dns_challenge=clear_dns_challenge,
            wait_for_dns_ready=wait_for_dns_ready,
            eab_kid=eab_kid,
            eab_hmac_key=eab_hmac_key,
            total_budget_seconds=issuance_budget,
            on_progress=lambda message: setattr(job, "progress_message", message),
        )

    def _issue_via_manual_dns(self, job: AcmeJob):
        eab_kid, eab_hmac_key = self._eab_credentials(job)

        def set_dns_challenge(record_name: str, value: str) -> None:
            job.dns_record_type = "TXT"
            job.dns_record_name = record_name
            job.dns_record_value = value
            job.state = AcmeJobState.AWAITING_DNS
            job.progress_message = "Aguardando você criar o registro TXT no seu DNS..."
            return None

        def clear_dns_challenge(_handle: None) -> None:
            job.progress_message = "Emitido — pode remover o registro TXT do seu DNS (opcional)."

        def wait_for_dns_ready() -> None:
            self._block_on_confirmation(job)

        return issue_certificate(
            domain=job.domain,
            environment=self._account_storage_key(job),
            directory_url=self._directory_url(job),
            store=self._store,
            set_dns_challenge=set_dns_challenge,
            clear_dns_challenge=clear_dns_challenge,
            wait_for_dns_ready=wait_for_dns_ready,
            eab_kid=eab_kid,
            eab_hmac_key=eab_hmac_key,
            total_budget_seconds=settings.acme_manual_dns_budget_seconds,
            on_progress=lambda message: setattr(job, "progress_message", message),
        )

    def _issue_via_cname_delegation(self, job: AcmeJob):
        creds = self._store.load_dns_credentials()
        if creds is None or not creds.delegation_zone:
            raise IssuanceError(
                "Nenhuma zona de delegação configurada. Configure o token e o "
                "domínio de delegação da Cloudflare (em Emissão → Configurar "
                "token) antes de usar este modo."
            )
        eab_kid, eab_hmac_key = self._eab_credentials(job)

        challenge_hostname = f"_acme-challenge.{job.domain}"
        delegation_target = _delegation_target(job.domain, creds.delegation_zone)

        already_delegated = asyncio.run(
            dns_check.cname_matches(challenge_hostname, delegation_target, timeout=10.0)
        )
        if not already_delegated:
            job.dns_record_type = "CNAME"
            job.dns_record_name = challenge_hostname
            job.dns_record_value = delegation_target
            job.state = AcmeJobState.AWAITING_DNS
            job.progress_message = "Aguardando você configurar o CNAME de delegação (uma vez só)..."
            self._block_on_confirmation(job)
            job.progress_message = "CNAME confirmado — prosseguindo com a emissão automática..."

        def set_dns_challenge(_record_name: str, value: str) -> tuple[str, str]:
            # O desafio de verdade é publicado no ALVO do CNAME (a zona de
            # delegação que o app controla), não no nome original do
            # domínio emitido — é isso que faz a validação seguir o CNAME.
            job.progress_message = f"Criando registro TXT em {delegation_target}..."
            try:
                zone_id = cloudflare.find_zone_id(creds.delegation_zone, creds.api_token)
                record_id = cloudflare.create_txt_record(
                    zone_id, delegation_target, value, creds.api_token
                )
            except cloudflare.CloudflareError as exc:
                raise IssuanceError(f"Falha ao configurar o DNS de delegação: {exc}") from exc
            return (zone_id, record_id)

        def clear_dns_challenge(handle: tuple[str, str]) -> None:
            zone_id, record_id = handle
            cloudflare.delete_txt_record(zone_id, record_id, creds.api_token)

        def wait_for_dns_ready() -> None:
            time.sleep(settings.acme_dns_propagation_wait_seconds)

        issuance_budget = max(30.0, settings.acme_job_budget_seconds - 20.0)

        return issue_certificate(
            domain=job.domain,
            environment=self._account_storage_key(job),
            directory_url=self._directory_url(job),
            store=self._store,
            set_dns_challenge=set_dns_challenge,
            clear_dns_challenge=clear_dns_challenge,
            wait_for_dns_ready=wait_for_dns_ready,
            eab_kid=eab_kid,
            eab_hmac_key=eab_hmac_key,
            total_budget_seconds=issuance_budget,
            on_progress=lambda message: setattr(job, "progress_message", message),
        )

    def _issue_via_self_hosted_dns(self, job: AcmeJob):
        # Sem credencial nenhuma — mesmo espírito do modo manual, só que
        # em vez de exigir uma pessoa recriando o TXT a cada renovação, um
        # CNAME configurado uma vez basta pra sempre (a resposta de
        # verdade sai deste próprio processo, ver app/acme/selfdns.py).
        if not settings.selfdns_enabled or not settings.selfdns_zone:
            raise IssuanceError(
                "Servidor DNS próprio não está ligado nesta instância "
                "(CERTDISC_SELFDNS_ENABLED/CERTDISC_SELFDNS_ZONE) — configure no "
                "deploy antes de usar este modo."
            )
        eab_kid, eab_hmac_key = self._eab_credentials(job)

        challenge_hostname = f"_acme-challenge.{job.domain}"
        delegation_target = selfdns.target_hostname(job.domain)

        already_delegated = asyncio.run(
            dns_check.cname_matches(challenge_hostname, delegation_target, timeout=10.0)
        )
        if not already_delegated:
            job.dns_record_type = "CNAME"
            job.dns_record_name = challenge_hostname
            job.dns_record_value = delegation_target
            job.state = AcmeJobState.AWAITING_DNS
            job.progress_message = (
                "Aguardando você configurar o CNAME (uma vez só, sem credencial)..."
            )
            self._block_on_confirmation(job)
            job.progress_message = "CNAME confirmado — prosseguindo com a emissão automática..."

        def set_dns_challenge(_record_name: str, value: str) -> None:
            job.progress_message = f"Publicando resposta do desafio em {delegation_target}..."
            selfdns.set_challenge(job.domain, value)
            return None

        def clear_dns_challenge(_handle: None) -> None:
            selfdns.clear_challenge(job.domain)

        def wait_for_dns_ready() -> None:
            # Mesma margem de propagação dos outros modos automáticos —
            # dá tempo do resolvedor da CA enxergar a resposta recém-
            # publicada antes de a CA consultar de verdade.
            time.sleep(settings.acme_dns_propagation_wait_seconds)

        issuance_budget = max(30.0, settings.acme_job_budget_seconds - 20.0)

        return issue_certificate(
            domain=job.domain,
            environment=self._account_storage_key(job),
            directory_url=self._directory_url(job),
            store=self._store,
            set_dns_challenge=set_dns_challenge,
            clear_dns_challenge=clear_dns_challenge,
            wait_for_dns_ready=wait_for_dns_ready,
            eab_kid=eab_kid,
            eab_hmac_key=eab_hmac_key,
            total_budget_seconds=issuance_budget,
            on_progress=lambda message: setattr(job, "progress_message", message),
        )

    def _block_on_confirmation(self, job: AcmeJob) -> None:
        event = self._confirm_events.get(job.id)
        if event is None:
            raise IssuanceError("Estado interno inválido — tente emitir novamente.")
        confirmed = event.wait(timeout=settings.acme_manual_dns_budget_seconds)
        if not confirmed:
            raise IssuanceError("Tempo esgotado aguardando confirmação do registro DNS.")


renewal_manager = AcmeRenewalManager()
