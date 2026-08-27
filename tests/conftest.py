"""Reduz o custo do scrypt (app/auth/passwords.py) durante a suíte —
achado numa auditoria de robustez subiu o parâmetro n de 2**14 pra 2**17
(recomendação atual do OWASP), apropriado pro login humano ocasional que
o app realmente atende, mas caro demais (~150-300ms por chamada) pra
rodar em toda chamada incidental de hash_password()/verify_password()
espalhada pela suíte inteira — dezenas de arquivos de teste completamente
alheios a senha chamam `/api/auth/setup`/`login` só pra montar um cliente
autenticado, e cada um pagaria o custo real sem testar nada que
tests/test_passwords.py já não cubra diretamente com o valor real.

`tests/test_passwords.py` fica de fora de propósito: é ele quem verifica
o parâmetro de produção de verdade."""

from __future__ import annotations

import pytest

from app.auth import passwords


@pytest.fixture(autouse=True)
def _cheap_password_hashing(request, monkeypatch):
    if request.module.__name__ == "tests.test_passwords":
        return
    # Precisa continuar maior que _LEGACY_N (2**14): testes de migração
    # (test_auth_flow.py) constroem um hash "legado" com o n real antigo
    # e esperam que o n "atual" (mesmo reduzido aqui) seja reconhecido
    # como mais forte, disparando o re-hash transparente.
    monkeypatch.setattr(passwords, "_N", 2**15)
