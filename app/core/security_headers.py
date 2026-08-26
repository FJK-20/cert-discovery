"""Cabeçalhos de segurança HTTP (OWASP Secure Headers) aplicados em toda
resposta — mitigação em camada extra, independente da validação de entrada
já feita em cada rota.

CSP sem `unsafe-inline` em nenhuma diretiva: todo `<script>`/CSS do
frontend já vive em arquivo externo (`static/app.js`/`style.css`), sem
handler inline nem `<style>` embutido — então uma política restritiva não
quebra nada (verificado manualmente, sem nenhum `onclick=`/`style=`
dinâmico sobrando no HTML gerado por JS). `img-src` precisa de `data:`
pelo QR code do MFA, que é servido como SVG embutido (app/auth/qr.py)."""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "font-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)


def _request_is_https(request: Request) -> bool:
    # Mesma lógica de cookie_should_be_secure() em app/auth/dependencies.py
    # (não compartilhada por módulo pra não inverter a camada — core
    # importando de auth) — decisão por requisição, não só por variável
    # global: uma instância que serve LAN por HTTP puro e domínio público
    # por HTTPS ao mesmo tempo (via proxy/túnel) nunca poderia ligar HSTS
    # globalmente sem quebrar a LAN, mesmo already tendo TLS de verdade no
    # domínio público.
    if request.url.scheme == "https":
        return True
    return request.headers.get("x-forwarded-proto", "").lower() == "https"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, *, hsts_enabled: bool) -> None:
        super().__init__(app)
        # Override de deploy: força HSTS em toda resposta, pra quem roda
        # uma instância só-HTTPS e não quer depender de X-Forwarded-Proto.
        self._hsts_enabled = hsts_enabled

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = _CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), camera=(), microphone=(), payment=()"
        )
        # Só faz sentido anunciar HTTPS obrigatório quando ESTA requisição
        # chegou por HTTPS (direto, ou via X-Forwarded-Proto de um proxy/
        # túnel) — senão um acesso local por HTTP simples (LAN/demo sem
        # certificado) ficaria preso numa promessa que o próprio servidor
        # não cumpre.
        if self._hsts_enabled or _request_is_https(request):
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        return response
