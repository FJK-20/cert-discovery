# Python 3.13: usa ssl.SSLSocket.get_unverified_chain() (stdlib) para
# capturar a cadeia completa de certificados no handshake, sem dependência
# extra. Ver app/discovery/tls_probe.py.
FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY static ./static

# Achado numa auditoria de robustez: o processo rodava como root (uid 0)
# por padrão — um RCE em qualquer dependência exfiltraria a master key de
# criptografia junto com os dados que ela protege (chave privada de todo
# certificado gerenciado), colapsando a criptografia em repouso inteira.
# UID/GID fixos (não um `adduser` sem número) pra o dono do volume
# ./data no host poder ser ajustado de forma previsível entre rebuilds
# (`chown -R 1000:1000 data/` no host, uma vez, antes do primeiro deploy
# com esta imagem).
RUN groupadd --gid 1000 certdisc \
    && useradd --uid 1000 --gid certdisc --shell /usr/sbin/nologin --no-create-home certdisc \
    && chown -R certdisc:certdisc /app
USER certdisc

EXPOSE 8000

# --workers 1: o job store do scan vive em memória de processo único (sem
# banco de dados, de propósito, para um MVP de portfólio). Múltiplos workers
# quebrariam o polling/SSE (job criado num worker, consultado em outro).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
