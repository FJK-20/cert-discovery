"""Orquestra um job de emissão/renovação ACME, mesmo padrão do
ScanJobManager (app/jobs/manager.py): job store em memória, progresso
consultável via polling/SSE, timeout de orçamento total.

Diferença chave: o fluxo ACME em si (app/acme/issuance.py) é síncrono
(lib `acme` roda sobre `requests`), então roda inteiro numa thread via
`asyncio.to_thread` — as atualizações de progresso feitas de dentro da
thread em `job.progress_message`/`job.state` são seguras porque cada
atribuição é uma operação atômica sob o GIL; não há seção crítica maior
que precise de lock aqui.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from datetime import UTC, datetime

from app.acme import cloudflare
from app.acme.issuance import IssuanceError, issue_certificate
from app.acme.models import AcmeEnvironment, AcmeJob, AcmeJobState
from app.acme.store import AcmeStore, IssuedCertificate, acme_store
from app.core.config import settings


class AcmeRenewalManager:
    def __init__(self, store: AcmeStore = acme_store) -> None:
        self._jobs: dict[str, AcmeJob] = {}
        self._store = store

    async def create(self, domain: str, environment: AcmeEnvironment) -> AcmeJob:
        self._evict_expired()
        job = AcmeJob(domain=domain, environment=environment)
        self._jobs[job.id] = job
        asyncio.create_task(self._run(job))
        return job

    def get(self, job_id: str) -> AcmeJob | None:
        return self._jobs.get(job_id)

    def _evict_expired(self) -> None:
        cutoff = time.time() - settings.acme_job_ttl_seconds
        expired = [jid for jid, job in self._jobs.items() if job.created_at.timestamp() < cutoff]
        for jid in expired:
            self._jobs.pop(jid, None)

    async def _run(self, job: AcmeJob) -> None:
        job.state = AcmeJobState.RUNNING
        try:
            await asyncio.wait_for(
                asyncio.to_thread(self._issue_sync, job),
                timeout=settings.acme_job_budget_seconds,
            )
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

    def _issue_sync(self, job: AcmeJob) -> None:
        creds = self._store.load_dns_credentials()
        if creds is None:
            raise IssuanceError(
                "Nenhuma credencial de provedor de DNS configurada. "
                "Configure o token da Cloudflare antes de emitir um certificado."
            )

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

        def on_progress(message: str) -> None:
            job.progress_message = message

        directory_url = (
            settings.acme_directory_production
            if job.environment == AcmeEnvironment.PRODUCTION
            else settings.acme_directory_staging
        )

        # Deixa uma margem dentro do orçamento total do job para a limpeza
        # do DNS e a gravação do certificado depois que a lib retorna.
        issuance_budget = max(30.0, settings.acme_job_budget_seconds - 20.0)

        result = issue_certificate(
            domain=job.domain,
            environment=job.environment.value,
            directory_url=directory_url,
            store=self._store,
            set_dns_challenge=set_dns_challenge,
            clear_dns_challenge=clear_dns_challenge,
            dns_propagation_wait_seconds=settings.acme_dns_propagation_wait_seconds,
            total_budget_seconds=issuance_budget,
            on_progress=on_progress,
        )

        cert = IssuedCertificate(
            id=str(uuid.uuid4()),
            domain=job.domain,
            environment=job.environment.value,
            issued_at=datetime.now(UTC).isoformat(),
            not_after=result.not_after.isoformat() if result.not_after else None,
            fullchain_pem=result.fullchain_pem,
            private_key_pem=result.private_key_pem,
        )
        self._store.save_certificate(cert)
        job.certificate_id = cert.id


renewal_manager = AcmeRenewalManager()
