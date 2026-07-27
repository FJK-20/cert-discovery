# Certificate Discovery Platform

Descoberta e inventário de certificados TLS: consulta CT logs (crt.sh),
resolve DNS, faz handshake TLS ao vivo, deduplica por fingerprint, classifica
por urgência de expiração e monta fila de renovação. Projeto de portfólio
open source (MIT) — não é código de cliente.

## Stack
Python 3.13, FastAPI, `httpx`, `cryptography`, `dnspython`, stdlib TOTP/scrypt
(sem pyotp/passlib). Frontend: HTML/CSS/JS vanilla, sem framework. Docker
Compose para rodar (`--workers 1`, obrigatório — job store é em memória).

## Arquivos principais
- `app/main.py` — FastAPI app, decide index.html vs auth.html
- `app/jobs/manager.py` — orquestra o pipeline de scan (CT → DNS → TLS)
- `app/discovery/{ctlogs,dns_resolver,tls_probe}.py` — cada etapa do pipeline
- `app/core/security.py` — validação anti-SSRF (crítico, não afrouxar)
- `app/auth/` — cadastro de admin + MFA obrigatório + login em 2 etapas
- `static/{index,auth}.html` + `app.js`/`auth.js` — frontend

## Regras importantes
- MFA é **obrigatório**, sem opção de pular — não adicionar bypass.
- `tls_probe.py` sempre conecta pelo IP já resolvido e validado (nunca
  deixa a camada TLS re-resolver o hostname) — evita DNS rebinding.
- Testes são 100% offline/mockados (`httpx.MockTransport`, TLS local
  self-signed). Rodar com `. .venv/bin/activate && pytest -q && ruff check .`
- `data/admin.json` é sensível (hash de senha + segredo TOTP) — nunca ler
  nem versionar.
- Ao mexer em Docker: rebuildar com `docker compose up -d --build` (static/
  não é volume, precisa build para refletir mudanças).
- Para logs: sempre `docker compose logs --tail=N`, nunca sem `--tail`.
