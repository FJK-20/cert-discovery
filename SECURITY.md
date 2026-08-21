# Política de Segurança

## Reportando uma vulnerabilidade

Encontrou um problema de segurança? Não abra uma issue pública.

Reporte de forma privada por uma das duas vias:

- [GitHub Security Advisories](https://github.com/FJK-20/cert-discovery/security/advisories/new)
  do repositório (recomendado — permite acompanhar o status e coordenar
  divulgação).
- E-mail direto pro mantenedor, listado no perfil do GitHub
  ([@FJK-20](https://github.com/FJK-20)).

Inclua o máximo de detalhe possível: passos pra reproduzir, versão/commit
afetado, e o impacto que você identificou. Uma prova de conceito ajuda,
mas não é obrigatória pra abrir o report.

Este é um projeto de portfólio mantido por uma pessoa só, sem orçamento
formal — não há programa de recompensa (bug bounty) nem SLA contratual de
resposta. Na prática: reports de segurança são a prioridade mais alta
acima de qualquer feature nova, e a expectativa razoável é resposta inicial
em poucos dias.

## Escopo

Está dentro do escopo qualquer vulnerabilidade no código deste
repositório: autenticação/autorização, injeção, SSRF, exposição de dado
sensível, falha de criptografia, bypass de RBAC, quebra da cadeia de
auditoria, etc.

Fora do escopo: vulnerabilidades em dependências de terceiros sem exploit
demonstrável específico desta aplicação (reporte direto ao projeto afetado
— e sinta-se à vontade para também nos avisar, já rodamos
[`pip-audit`](https://github.com/FJK-20/cert-discovery/blob/master/.github/workflows/ci.yml)
no CI), e infraestrutura de deploy que não é deste repositório (seu
servidor, seu provedor de nuvem).

## O que já está endereçado

Documentado com mais detalhe no [README](README.md#segurança) — resumo:

- Senha com hash `scrypt` (stdlib), nunca texto puro.
- MFA (TOTP/RFC 6238) opcional, com prova de configuração antes de ativar.
- RBAC de quatro papéis com segregação de funções (`admin`/`operador`/
  `auditor`/`leitor`) — toda rota de escrita exige o papel certo, checado
  no backend a cada request, não só escondido na interface.
- Log de auditoria append-only com cadeia de hashes (tamper-evident).
- Segredos sensíveis (chave privada de certificado, token de API, senha de
  SMTP, segredo TOTP) criptografados em repouso, nunca em texto puro no
  disco.
- Proteção contra SSRF (`app/core/security.py`) — resolve o IP uma vez,
  conecta pelo IP literal, bloqueia ranges privados/link-local/CGNAT/
  variantes IPv6.
- Cabeçalhos de segurança HTTP (CSP restritiva sem `unsafe-inline`,
  X-Frame-Options, X-Content-Type-Options, HSTS quando atrás de TLS).
- Rate limiting em toda rota sensível (login, MFA, scan, emissão de
  certificado).
- Cookie de sessão `httpOnly` + `SameSite=Lax`, sem CORS liberado pra
  outras origens.
- Dependências verificadas por vulnerabilidade conhecida a cada push
  (`pip-audit` no CI).

## O que não está no escopo deste projeto

Portfólio de MVP, não produto enterprise com equipe de segurança dedicada.
Não existe (e não faz sentido fingir que existe): HSM físico, integração
com PKI corporativo real, certificação formal de compliance regulatório,
SIEM próprio, ou auditoria de segurança externa contratada. Ver
[README — Roadmap](README.md#roadmap--ideias-futuras) pro que está
genuinamente planejado.
