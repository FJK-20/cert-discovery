# Certificate Discovery Platform

![CI](https://github.com/FJK-20/cert-discovery/actions/workflows/ci.yml/badge.svg)

Plataforma open source para descoberta e inventário de certificados TLS.

A aplicação recebe um domínio autorizado, consulta fontes públicas de
Certificate Transparency, identifica hosts relacionados, realiza resolução
DNS e handshake TLS e consolida os certificados encontrados em um inventário.

> **Nota:** este projeto foi desenvolvido com auxílio de IA (Claude), como
> peça de portfólio pessoal. O código foi revisado, mas pode conter bugs
> pontuais, casos de borda não cobertos ou comportamento inesperado em
> ambientes fora dos testados aqui. Use por sua conta e risco, revise antes
> de qualquer uso além de estudo/demonstração, e sinta-se à vontade para
> abrir uma issue se encontrar algo estranho.

<p align="center">
  <img src="docs/screenshots/app-empty.png" alt="Tela inicial da Certificate Discovery Platform" width="49%" />
  <img src="docs/screenshots/app-results.png" alt="Inventário de certificados com cards de resumo e tabela de resultados" width="49%" />
</p>

## Problema

Organizações frequentemente possuem certificados distribuídos entre
servidores, aplicações e provedores diferentes. Isso aumenta o risco de
certificados expirarem sem acompanhamento.

## Solução

A plataforma automatiza:

- descoberta de certificados públicos (via Certificate Transparency logs);
- identificação de hosts ativos;
- coleta de certificados via handshake TLS ao vivo;
- deduplicação por fingerprint SHA-256;
- classificação por urgência de expiração;
- montagem automática de uma fila priorizada de renovação;
- geração de inventário exportável (CSV/JSON);
- dashboard visual: cards de resumo clicáveis, gráficos de distribuição por emissor/prazo de expiração, e painel de detalhes completo (SANs, serial, fingerprint) ao clicar em qualquer linha da tabela.

## Como funciona

```mermaid
flowchart LR
    A[Domínio informado] --> B[Consulta crt.sh<br/>Certificate Transparency]
    B --> C[Lista de hostnames candidatos]
    C --> D[Resolução DNS]
    D --> E[Handshake TLS ao vivo]
    E --> F[Inventário consolidado<br/>dedupe por fingerprint]
    F --> G[Classificação de urgência<br/>+ fila de renovação]
    G --> H[Export CSV / JSON]
```

Importante: o crt.sh só devolve **metadados** (emissor, validade, SANs), não
os bytes do certificado. Por isso o inventário distingue dois tipos de
achado:

- **Confirmado ao vivo** (`live`): o handshake TLS teve sucesso, o
  certificado real foi capturado e tem fingerprint SHA-256 verificável — só
  esses entram nas classificações `expired`/`critical`/`warning`/`ok` e na
  fila de renovação.
- **Só CT log** (`ct_only`/`wildcard`/`unresolved`): hostname histórico sem
  confirmação ao vivo (por exemplo, um wildcard `*.sub.dominio.com`, ou um
  host que não resolveu DNS, ou que recusou o handshake). Aparece no
  inventário para visibilidade, mas não é tratado como certeza.

## ⚠️ Uso responsável

Use apenas em domínios que você possui ou está explicitamente autorizado a
testar. A ferramenta só consulta dados públicos (Certificate Transparency) e
realiza handshakes TLS padrão — o mesmo que qualquer navegador faz ao abrir
um site — mas ainda assim é um scanner, e como tal deve ser usado com
autorização e bom senso. O formulário exige uma confirmação explícita de
autorização antes de iniciar um scan.

## Instalação e execução

### Opção 1 — Docker (recomendada, mais simples)

Pré-requisito: [Docker](https://docs.docker.com/get-docker/) com Docker Compose.

```bash
git clone https://github.com/FJK-20/cert-discovery.git
cd cert-discovery
docker compose up --build
```

Abra `http://localhost:8000` no navegador. Pronto — nenhuma instalação de
Python, pip ou dependências no seu sistema. No primeiro acesso, a aplicação
pede para cadastrar o admin (veja [Acesso e autenticação](#acesso-e-autenticação)).

### Opção 2 — Python direto (sem Docker)

Pré-requisito: Python 3.13+ (para captura completa da cadeia de
certificados — em 3.12 ou anterior, a aplicação roda normalmente mas captura
só o certificado-folha, sem a cadeia).

```bash
git clone https://github.com/FJK-20/cert-discovery.git
cd cert-discovery
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 1
```

Abra `http://localhost:8000`.

## Acesso e autenticação

A aplicação exige uma conta de administrador (usuário + senha). A
autenticação em dois fatores (**MFA/TOTP**) é **opcional**, desligada por
padrão — o próprio admin ativa quando quiser, já logado, na seção
"🔒 Segurança".

1. **Primeiro acesso**: nenhum admin cadastrado ainda → tela de cadastro
   (usuário + senha, mínimo 8 caracteres). Ao concluir, já entra
   autenticado — sem etapa extra forçada.
2. **Ativar o MFA (opcional)**: em "🔒 Segurança", um QR code é exibido para
   escanear com um app autenticador (Google Authenticator, Authy, 1Password,
   etc. — qualquer app compatível com TOTP/RFC 6238). O MFA só passa a
   `ativado` depois de confirmar um código válido de 6 dígitos gerado pelo
   app — isso garante que o autenticador está configurado corretamente antes
   de depender dele num login futuro. Também é possível desativar a
   qualquer momento (confirmando a senha atual).
3. **Acessos seguintes**: login com usuário/senha; se o MFA estiver
   ativado, uma segunda etapa pede o código do autenticador. A sessão fica
   em um cookie `httpOnly`.
4. Toda a API de scan (`/api/scan/*`) exige sessão autenticada — sem login
   válido, retorna 401.

A conta (usuário, hash da senha, segredo TOTP quando o MFA está ativo) fica
em `data/admin.json` (permissão `0600`), persistida via volume Docker entre
reinícios — só os *jobs* de scan em si são efêmeros (ver
[Limitações conhecidas](#limitações-conhecidas)).

**Perdeu a senha (ou o acesso ao MFA, se estiver ativado)?** Pare o serviço,
apague `data/admin.json` e refaça o cadastro. Não há fluxo de recuperação
de conta na v1 (single-admin, MVP de portfólio) — é um trade-off
deliberado, não um recurso faltando por descuido.

## Renovação automática (ACME DNS-01)

Além do inventário, a aplicação emite/renova certificados **reais** via
[Let's Encrypt](https://letsencrypt.org/) usando o protocolo ACME v2 com
desafio **DNS-01**, resolvido automaticamente através da API da
[Cloudflare](https://developers.cloudflare.com/api/).

DNS-01 foi escolhido (em vez de HTTP-01) porque não depende de expor a porta
80 do host que vai receber o certificado — o desafio é resolvido inteiramente
via API, criando e removendo um registro TXT temporário na zona DNS.

### Como usar

1. Na seção "Renovação automática" da interface, abra "Configurar / atualizar
   token da Cloudflare" e informe um
   [API Token](https://dash.cloudflare.com/profile/api-tokens) (não a Global
   API Key) com permissão **Zone → DNS → Edit**, restrito à(s) zona(s) que
   você pretende usar. O token é validado contra a API da Cloudflare antes de
   ser salvo (`data/dns_credentials.json`, permissão `0600`) e nunca é
   reexibido pela interface.
2. Informe o domínio e escolha o ambiente:
   - **Staging** (padrão): certificado de teste, **não confiável** no
     navegador, mas sem limite de taxa relevante — use para validar o fluxo.
   - **Produção**: certificado real, confiável, mas sujeito ao
     [rate limit do Let's Encrypt](https://letsencrypt.org/docs/rate-limits/)
     (ex.: certificados por domínio registrável por semana).
3. Confirme a autorização e acompanhe o progresso em tempo real (criação da
   conta ACME, criação do registro DNS, aguardando propagação, validação,
   finalização). Ao concluir, baixe `fullchain.pem` e `privkey.pem`.

### O que acontece nos bastidores

```mermaid
flowchart LR
    A[Cria/reutiliza conta ACME<br/>por ambiente] --> B[Cria pedido de<br/>certificado no Let's Encrypt]
    B --> C[Cria TXT de validação<br/>via API Cloudflare]
    C --> D[Aguarda propagação DNS]
    D --> E[Let's Encrypt valida<br/>o desafio DNS-01]
    E --> F[Emite o certificado]
    F --> G[Remove o TXT<br/>best-effort]
```

A conta ACME (chave privada da conta, não do certificado) é criada uma vez
por ambiente (staging/produção) e reaproveitada nas emissões seguintes,
como o protocolo ACME espera. A chave privada de cada certificado emitido é
gerada localmente e nunca sai do seu servidor, exceto no download que você
mesmo solicita.

### Segurança e limites

- Cada emissão é uma ação sensível: rate limit dedicado (5 emissões a cada 5
  minutos, por IP) além do rate limit geral de scans.
- O token da Cloudflare, a chave da conta ACME e as chaves privadas dos
  certificados emitidos ficam em `data/` com permissão `0600` — mesma
  disciplina do restante do projeto (veja [Segurança](#segurança)).
- Só a Cloudflare é suportada como provedor DNS na v1 — é um trade-off
  deliberado de escopo, não uma limitação técnica do desenho.
- Assim como o cadastro de admin, isso é uma feature de portfólio: não há
  renovação automática agendada (cron) nem alerta de expiração — a emissão é
  sempre disparada manualmente pela interface.

## Variáveis de ambiente

| Variável                     | Padrão | Descrição                                            |
|-------------------------------|--------|-------------------------------------------------------|
| `CERTDISC_MAX_HOSTS`          | `400`  | Máximo de hosts investigados por scan                 |
| `CERTDISC_MAX_CONCURRENCY`    | `30`   | Handshakes TLS simultâneos                            |
| `CERTDISC_RATE_LIMIT_RPM`     | `6`    | Limite de scans por minuto, por IP do requisitante    |
| `CERTDISC_DATA_DIR`           | `data` | Diretório onde `admin.json` é persistido              |
| `CERTDISC_COOKIE_SECURE`      | `false`| Marca o cookie de sessão como `Secure` (ative atrás de HTTPS) |
| `CERTDISC_AUTH_RATE_LIMIT`    | `8`    | Limite de tentativas de login/MFA a cada 5 min, por IP |

## Segurança

Como a aplicação conecta a hosts derivados de um domínio informado pelo
usuário (via CT logs, que podem conter qualquer SAN histórico), ela inclui
proteção deliberada contra SSRF:

- validação do **IP já resolvido** (nunca do texto do hostname) antes de
  conectar, bloqueando redes privadas, loopback, link-local (incluindo o
  endpoint de metadata de nuvem `169.254.169.254`), CGNAT, multicast e
  variantes IPv6 (incluindo IPv4-mapped e NAT64, que podem esconder um IP
  privado dentro de um endereço IPv6);
- conexão sempre pelo **IP literal** resolvido uma única vez, nunca deixando
  a camada de socket/TLS re-resolver o hostname (evita DNS rebinding);
- rate limiting por IP do requisitante e checkbox de consentimento
  obrigatório no formulário.

Veja `app/core/security.py` e `tests/test_security.py` para a lista completa
de ranges bloqueados e os casos de teste.

Sobre a autenticação:

- senha com hash **scrypt** (`hashlib.scrypt` da stdlib, sem dependência
  extra), nunca armazenada em texto puro;
- **MFA (TOTP/RFC 6238)** implementado com a stdlib (`hmac`/`hashlib`),
  opcional e ativável a qualquer momento — a ativação só é confirmada
  depois de validar um código real gerado pelo autenticador, nunca fica
  "ligado" sem essa prova;
- login em duas etapas (senha, depois código) via tokens de curta duração
  em memória — a senha nunca autentica sozinha;
- rate limiting dedicado nas rotas de login/MFA (`CERTDISC_AUTH_RATE_LIMIT`),
  já que um código de 6 dígitos é força-bruteável sem esse limite;
- cookie de sessão `httpOnly` + `SameSite=Lax`; sem CORS liberado para
  outras origens (mitiga CSRF sem precisar de token dedicado).

## Limitações conhecidas

- **Jobs de scan são efêmeros**: vivem em memória de um único processo (por
  isso `--workers 1` é obrigatório). Reiniciar o serviço descarta scans em
  andamento — escolha deliberada de escopo, não uma limitação a corrigir. A
  conta de admin **não** é afetada por isso (fica persistida em disco).
- **Single-admin**: não é um sistema multiusuário — está fora do escopo
  deste MVP.
- **Dependência do crt.sh**: é um serviço público mantido por terceiros,
  conhecido por ser lento/instável sob carga. A aplicação já lida com isso
  (timeout, retry com backoff, detecção de resposta HTML de erro), mas se o
  serviço estiver fora do ar, use o campo "Avançado" da interface para colar
  subdomínios manualmente.
- **Wildcards** (`*.sub.dominio.com`) descobertos via CT log não são
  expandidos automaticamente — aparecem no inventário sinalizados como tal.

## Testes

```bash
pip install -r requirements-dev.txt
pytest
ruff check .
```

Todos os testes são offline/determinísticos: consultas ao crt.sh são
mockadas (`httpx.MockTransport`), e o handshake TLS é testado contra um
servidor local com certificado self-signed gerado no próprio teste — nenhum
teste depende de rede externa.

## Roadmap / ideias futuras

- Expansão opcional de wildcards por labels comuns.
- Suporte a outras fontes de CT log além do crt.sh (redundância).
- Histórico de scans (com persistência opcional).
- Notificação (e-mail/webhook) quando um certificado entra na fila crítica.

## Licença

MIT — veja [LICENSE](LICENSE).
