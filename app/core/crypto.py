"""Criptografia em repouso pros segredos que a aplicação guarda em disco
(chave privada de certificado, chave de conta ACME, token de API, senha de
SMTP, segredo TOTP) — o "HSM virtual" realista pra um projeto sem hardware
dedicado: uma master key separada dos dados que ela protege, nunca
versionada, nunca exposta por nenhuma rota da API.

A master key vem de `CERTDISC_MASTER_KEY` (recomendado em produção — a
variável pode ser injetada por um secret manager externo, separado do disco
da aplicação, e sobrevive a um redeploy sem depender do volume de dados).
Se não estiver definida, uma chave é gerada e persistida em
`data/master.key` (0600) na primeira vez — funciona sem configuração extra
pra rodar localmente/demo, mas nesse caso a chave mora no mesmo disco que
os dados que protege, o que não é segregação de verdade. Documentado como
trade-off explícito, não escondido — ver README.

Criptografia acontece só na borda de serialização (o que vai pro disco);
o resto da aplicação sempre trabalha com o texto plano em memória, igual
antes — não muda nenhuma lógica de negócio, só o que fica gravado."""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

DecryptionError = InvalidToken


def _load_or_create_key(data_dir: Path) -> bytes:
    env_key = os.environ.get("CERTDISC_MASTER_KEY")
    if env_key:
        return env_key.encode()

    key_path = data_dir / "master.key"
    if key_path.exists():
        return key_path.read_bytes().strip()

    data_dir.mkdir(parents=True, exist_ok=True)
    key = Fernet.generate_key()
    key_path.write_bytes(key)
    os.chmod(key_path, 0o600)
    return key


class SecretBox:
    def __init__(self, data_dir: Path) -> None:
        self._data_dir = data_dir
        self._fernet: Fernet | None = None

    def _get_fernet(self) -> Fernet:
        # Preguiçoso (não na criação do singleton) — evita gerar/gravar
        # data/master.key só por importar o módulo (ex: em testes que nem
        # tocam segredo nenhum).
        if self._fernet is None:
            self._fernet = Fernet(_load_or_create_key(self._data_dir))
        return self._fernet

    def encrypt(self, plaintext: str | None) -> str | None:
        if plaintext is None or plaintext == "":
            return plaintext
        return self._get_fernet().encrypt(plaintext.encode()).decode()

    def decrypt(self, ciphertext: str | None) -> str | None:
        if ciphertext is None or ciphertext == "":
            return ciphertext
        return self._get_fernet().decrypt(ciphertext.encode()).decode()
