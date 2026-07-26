"""Rate limit simples por IP do requisitante (janela deslizante em memória).

Sem isso, uma instância pública deste serviço vira, na prática, um proxy de
reconhecimento contra terceiros usando o IP do próprio servidor — mesmo com
a proteção de SSRF (item separado) bem aplicada.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque


class SlidingWindowRateLimiter:
    def __init__(self, max_requests: int, window_seconds: float = 60.0) -> None:
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        hits = self._hits[key]
        while hits and now - hits[0] > self._window_seconds:
            hits.popleft()
        if len(hits) >= self._max_requests:
            return False
        hits.append(now)
        return True
