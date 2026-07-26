# Python 3.13: usa ssl.SSLSocket.get_unverified_chain() (stdlib) para
# capturar a cadeia completa de certificados no handshake, sem dependência
# extra. Ver app/discovery/tls_probe.py.
FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY static ./static

EXPOSE 8000

# --workers 1: o job store do scan vive em memória de processo único (sem
# banco de dados, de propósito, para um MVP de portfólio). Múltiplos workers
# quebrariam o polling/SSE (job criado num worker, consultado em outro).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
