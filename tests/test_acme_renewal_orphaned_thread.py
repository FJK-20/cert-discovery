"""Achado numa auditoria de robustez (app/acme/renewal.py:_run): asyncio.
wait_for() cancela a ESPERA, não a thread por trás de asyncio.to_thread()
— Python não tem como interromper uma thread à força. Depois de um
timeout, a thread continua rodando sozinha (órfã) e pode concluir a
emissão minutos depois, batendo save_certificate() já com o job marcado
"failed" e o histórico já gravado — desperdiçando o rate limit de
"duplicate certificate" da CA (5/semana na Let's Encrypt) numa emissão
que já tinha sido bem-sucedida.

Testa que, quando isso acontece, o certificado emitido pela thread órfã
é reconhecido (nunca descartado — já custou o rate limit) e o histórico é
corrigido de "failed" pra "done" em vez de ficar com um registro
permanentemente errado."""

from __future__ import annotations

import asyncio
import dataclasses
import time

from app.acme import renewal as renewal_module
from app.acme.history import RenewalHistoryStore
from app.acme.issuance import IssuedResult
from app.acme.models import AcmeEnvironment, AcmeJobState, DnsMode
from app.acme.store import AcmeStore


async def _wait_until(condition, *, timeout=5.0, step=0.02):
    elapsed = 0.0
    while elapsed < timeout:
        if condition():
            return True
        await asyncio.sleep(step)
        elapsed += step
    return False


def test_orphaned_thread_completing_after_timeout_corrects_history_to_done(tmp_path, monkeypatch):
    fast_settings = dataclasses.replace(renewal_module.settings, acme_job_budget_seconds=0.1)
    monkeypatch.setattr(renewal_module, "settings", fast_settings)

    def _slow_issue_via_cloudflare(self, job):
        # Bem mais que o budget de 0.1s acima — o wrapper asyncio desiste
        # de esperar bem antes desta chamada (que roda numa thread real)
        # terminar, simulando a chamada de rede lenta que o achado descreve.
        time.sleep(0.3)
        return IssuedResult(fullchain_pem="FAKE CERT", private_key_pem="FAKE KEY", not_after=None)

    monkeypatch.setattr(
        renewal_module.AcmeRenewalManager, "_issue_via_cloudflare", _slow_issue_via_cloudflare
    )

    history = RenewalHistoryStore(tmp_path)
    manager = renewal_module.AcmeRenewalManager(store=AcmeStore(tmp_path), history=history)

    async def scenario():
        job = await manager.create("app.example.com", AcmeEnvironment.STAGING, DnsMode.CLOUDFLARE)

        # o wrapper assíncrono desiste primeiro...
        assert await _wait_until(lambda: job.state == AcmeJobState.FAILED)
        assert "esgotado" in job.error
        failed_entries = history.recent(limit=10)
        failed_entry = next(e for e in failed_entries if e["domain"] == "app.example.com")
        assert failed_entry["state"] == "failed"

        # ...mas a thread órfã (dormindo 0.3s) termina de verdade depois,
        # e precisa corrigir o job E o histórico pra "done". Espera pelo
        # HISTÓRICO em disco (não só job.state em memória, que a própria
        # thread seta um instante antes de gravar) — é a fonte da verdade
        # que o scheduler realmente consulta.
        def _history_corrected():
            entries = history.recent(limit=10)
            entry = next((e for e in entries if e["domain"] == "app.example.com"), None)
            return entry is not None and entry["state"] == "done"

        assert await _wait_until(_history_corrected, timeout=2.0)
        assert job.state == AcmeJobState.DONE
        assert job.certificate_id is not None

        corrected_entries = history.recent(limit=10)
        corrected_entry = next(e for e in corrected_entries if e["domain"] == "app.example.com")
        assert corrected_entry["state"] == "done"
        assert corrected_entry["certificate_id"] == job.certificate_id
        assert corrected_entry["id"] == failed_entry["id"], (
            "precisa corrigir a MESMA linha de tentativa, não criar uma nova"
        )

    asyncio.run(scenario())


def test_normal_completion_within_budget_is_unaffected(tmp_path, monkeypatch):
    """Garante que o fix não muda nada no caminho feliz (sem timeout)."""

    def _fast_issue_via_cloudflare(self, job):
        return IssuedResult(fullchain_pem="FAKE CERT", private_key_pem="FAKE KEY", not_after=None)

    monkeypatch.setattr(
        renewal_module.AcmeRenewalManager, "_issue_via_cloudflare", _fast_issue_via_cloudflare
    )

    manager = renewal_module.AcmeRenewalManager(
        store=AcmeStore(tmp_path), history=RenewalHistoryStore(tmp_path)
    )

    async def scenario():
        job = await manager.create("app.example.com", AcmeEnvironment.STAGING, DnsMode.CLOUDFLARE)
        assert await _wait_until(lambda: job.state == AcmeJobState.DONE)
        assert job.certificate_id is not None
        assert job.error is None

    asyncio.run(scenario())
