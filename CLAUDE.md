# Certificate Manager

Gerenciador de certificados TLS de ciclo completo: descoberta (CT logs +
handshake TLS ao vivo, dedupe por fingerprint), emissão/renovação via ACME
(Let's Encrypt e ZeroSSL, DNS-01 manual/Cloudflare/Azure DNS/delegação
CNAME) ou CSR manual, renovação agendada com notificação, multiusuário com
4 papéis + SSO SAML, log de auditoria tamper-evident, criptografia em
repouso. Ferramenta open source (MIT) de uso real, não só peça de
portfólio — o objetivo é funcionar de verdade, genérica o bastante pra
rodar em ambientes diferentes (o usuário pretende usar a própria, a
começar pelo ambiente onde trabalha). Isso não muda a regra de sempre:
nenhum dado real de um ambiente específico (nome de organização, CNPJ,
domínio interno, credencial, print de tela de produção de terceiro) vai
pro código/commits/docs — cada deploy configura o que é seu via variável
de ambiente ou pela própria UI, o repo fica genérico. O diretório/repo
continua se chamando `cert-discovery` (não renomear — quebraria o path
da imagem `ghcr.io/fjk-20/cert-discovery`), mas a identidade voltada pro
usuário é "Certificate Manager", não mais "discovery" — descoberta é uma
etapa do ciclo de vida, não o produto inteiro.

## Stack
Python 3.13, FastAPI, `httpx`, `cryptography`, `dnspython`, stdlib TOTP/scrypt
(sem pyotp/passlib). Frontend: HTML/CSS/JS vanilla, sem framework. Docker
Compose para rodar (`--workers 1`, obrigatório — job store é em memória).

## Arquivos principais
- `app/main.py` — FastAPI app, decide index.html vs auth.html
- `app/jobs/manager.py` — orquestra o pipeline de scan (CT → DNS → TLS)
- `app/discovery/{ctlogs,dns_resolver,tls_probe}.py` — cada etapa do pipeline
- `app/core/security.py` — validação anti-SSRF (crítico, não afrouxar)
- `app/auth/` — cadastro de admin + MFA opcional (ativável pelo próprio
  admin já logado) + login em 1 ou 2 etapas conforme o MFA estar ligado
- `static/{index,auth}.html` + `app.js`/`auth.js` — frontend

## Regras importantes
- MFA é **opcional**, desligado por padrão, ativado pelo admin em
  "🔒 Segurança" (`/api/auth/mfa/*`, tudo atrás de `require_session`). A
  ativação só vira efetiva depois de confirmar um código TOTP válido
  (`pending_totp_secret` → `totp_secret` só após `verify_totp` passar) —
  nunca marcar `mfa_enabled=True` sem essa prova.
- `tls_probe.py` sempre conecta pelo IP já resolvido e validado (nunca
  deixa a camada TLS re-resolver o hostname) — evita DNS rebinding.
- Testes são 100% offline/mockados (`httpx.MockTransport`, TLS local
  self-signed). Rodar com `. .venv/bin/activate && pytest -q && ruff check .`
- `data/admin.json` é sensível (hash de senha + segredo TOTP) — nunca ler
  nem versionar.
- Ao mexer em Docker: rebuildar com `docker compose up -d --build` (static/
  não é volume, precisa build para refletir mudanças).
- Para logs: sempre `docker compose logs --tail=N`, nunca sem `--tail`.
- **Deploy público**: além de rodar em `http://192.168.1.50:8000` (LAN), o
  app também é servido publicamente em `https://certmanager.fausto.app.br`
  via Cloudflare Tunnel (`cert-discovery-tunnel.service`, systemd, config
  em `/etc/cloudflared/cert-discovery-config.yml`). Esse hostname é
  **proxied pela Cloudflare** — depois de qualquer `docker compose up -d
  --build` que mude `static/`, o público continua vendo a versão antiga
  (cache de borda, `cache-control: max-age=14400`) até rodar um purge:
  `POST /zones/{zone_id}/purge_cache` com um token escopado à permissão
  "Cache Purge" da zona `fausto.app.br` (zone id
  `bb3fab970841a23ea6593074a8045bb0`). Confirmar com
  `curl -sD - .../static/style.css | grep cf-cache-status` (deve virar
  `HIT` com `age` baixo depois do purge, não ficar em `MISS`/`age` alto).
