"""Renderiza o QR code de enrollment do TOTP como SVG embutido (data URI).

Usa `qrcode` só para o desenho (sem Pillow/lxml — a factory SVG é pura
stdlib por baixo dos panos). O segredo continua disponível como texto puro
na tela de cadastro, para quem preferir digitar manualmente no app.
"""

from __future__ import annotations

import base64
import io

import qrcode
import qrcode.image.svg


def to_svg_data_uri(data: str) -> str:
    image = qrcode.make(data, image_factory=qrcode.image.svg.SvgPathImage)
    buffer = io.BytesIO()
    image.save(buffer)
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/svg+xml;base64,{encoded}"
