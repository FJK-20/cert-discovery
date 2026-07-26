"""Orquestra o pipeline de um scan: CT logs -> DNS -> TLS -> inventário.

Job store em memória, de propósito: é um MVP de portfólio sem banco de
dados. Por isso a aplicação precisa rodar com um único worker Uvicorn — ver
README/docker-compose. Jobs antigos são removidos após `job_ttl_seconds`
para não crescer indefinidamente num processo de longa duração.
"""

from __future__ import annotations

import asyncio
import time

import httpx

from app.core.config import settings
from app.discovery import ctlogs
from app.discovery.dns_resolver import resolve_ips, to_idna
from app.discovery.tls_probe import ProbeError, probe_host
from app.domain.inventory import build_inventory
from app.domain.models import CertificateRecord, JobState, Origin, ScanJob, Status
from app.domain.urgency import classify

_TLS_PORT = 443


class ScanJobManager:
    def __init__(self) -> None:
        self._jobs: dict[str, ScanJob] = {}

    async def create(self, domain: str, manual_hosts: list[str] | None = None) -> ScanJob:
        self._evict_expired()
        job = ScanJob(domain=domain)
        self._jobs[job.id] = job
        asyncio.create_task(self._run(job, manual_hosts or []))
        return job

    def get(self, job_id: str) -> ScanJob | None:
        return self._jobs.get(job_id)

    def _evict_expired(self) -> None:
        cutoff = time.time() - settings.job_ttl_seconds
        expired = [jid for jid, job in self._jobs.items() if job.created_at.timestamp() < cutoff]
        for jid in expired:
            self._jobs.pop(jid, None)

    async def _run(self, job: ScanJob, manual_hosts: list[str]) -> None:
        try:
            await asyncio.wait_for(
                self._pipeline(job, manual_hosts), timeout=settings.job_total_budget_seconds
            )
            if job.state is not JobState.FAILED:
                job.state = JobState.DONE
                job.progress_message = "Concluído"
        except TimeoutError:
            job.records = build_inventory(job.records)
            job.state = JobState.PARTIAL_TIMEOUT
            job.progress_message = "Tempo esgotado — exibindo resultados parciais"
        except Exception as exc:  # nunca deixa o job travado em progresso
            job.state = JobState.FAILED
            job.error = str(exc)

    async def _pipeline(self, job: ScanJob, manual_hosts: list[str]) -> None:
        job.state = JobState.DISCOVERING_HOSTS
        job.progress_message = "Consultando Certificate Transparency logs..."

        hostnames: set[str] = {h for h in (ctlogs.normalize_hostname(h) for h in manual_hosts) if h}
        async with httpx.AsyncClient() as client:
            try:
                ct_hosts = await ctlogs.fetch_hostnames(
                    job.domain, client=client, timeout=settings.ctlogs_timeout_seconds
                )
                hostnames |= ct_hosts
            except ctlogs.CtLogUnavailable as exc:
                job.progress_message = (
                    f"CT logs indisponíveis ({exc}); usando apenas hosts informados manualmente"
                )

        apex = ctlogs.normalize_hostname(job.domain)
        if apex:
            hostnames.add(apex)

        wildcard_hosts = {h for h in hostnames if h.startswith("*.")}
        candidate_hosts = sorted(hostnames - wildcard_hosts)[: settings.max_hosts_per_scan]

        for host in wildcard_hosts:
            job.records.append(
                CertificateRecord(
                    host=host,
                    origin=Origin.CT_LOG,
                    status=Status.WILDCARD,
                    note="Wildcard descoberto via CT log — não é diretamente resolvível",
                )
            )

        job.hosts_total = len(candidate_hosts)
        job.state = JobState.PROBING_TLS
        job.progress_message = f"Resolvendo DNS e testando TLS em {job.hosts_total} hosts..."

        semaphore = asyncio.Semaphore(settings.max_concurrent_probes)
        await asyncio.gather(
            *(self._process_host(job, host, semaphore) for host in candidate_hosts)
        )

        job.records = build_inventory(job.records)

    async def _process_host(self, job: ScanJob, host: str, semaphore: asyncio.Semaphore) -> None:
        async with semaphore:
            try:
                idna_host = to_idna(host)
                if idna_host is None:
                    job.records.append(
                        CertificateRecord(
                            host=host,
                            origin=Origin.CT_LOG,
                            status=Status.UNRESOLVED,
                            note="Hostname inválido (falha na codificação IDNA)",
                        )
                    )
                    return

                ips = await resolve_ips(idna_host, timeout=settings.dns_timeout_seconds)
                if not ips:
                    job.records.append(
                        CertificateRecord(
                            host=host,
                            origin=Origin.CT_LOG,
                            status=Status.UNRESOLVED,
                            note="Não resolveu DNS (A/AAAA)",
                        )
                    )
                    return

                try:
                    result = await probe_host(
                        idna_host,
                        ips[0],
                        port=_TLS_PORT,
                        connect_timeout=settings.tcp_connect_timeout_seconds,
                        handshake_timeout=settings.tls_handshake_timeout_seconds,
                    )
                except ProbeError as exc:
                    job.records.append(
                        CertificateRecord(
                            host=host,
                            origin=Origin.CT_LOG,
                            status=Status.CT_ONLY,
                            resolved_ip=ips[0],
                            note=str(exc),
                        )
                    )
                    return

                status, days_left = classify(result.not_after)
                job.records.append(
                    CertificateRecord(
                        host=host,
                        origin=Origin.LIVE,
                        status=status,
                        subject_cn=result.subject_cn,
                        issuer=result.issuer,
                        not_before=result.not_before,
                        not_after=result.not_after,
                        days_until_expiry=days_left,
                        serial_number=result.serial_number,
                        sha256_fingerprint=result.sha256_fingerprint,
                        sans=result.sans,
                        resolved_ip=ips[0],
                    )
                )
            finally:
                job.hosts_done += 1


job_manager = ScanJobManager()
