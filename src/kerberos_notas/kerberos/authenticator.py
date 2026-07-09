import uuid

from kerberos_notas.crypto.crypto_utils import (
    base64_para_bytes,
    criptografar_json,
    descriptografar_json,
)
from kerberos_notas.kerberos.tickets import timestamp_atual


def criar_autenticador(
        usuario: str,
        chave_sessao_base64: str,
        nonce: str | None = None,
        timestamp: int | None = None,
) -> dict:
    chave_sessao = base64_para_bytes(chave_sessao_base64)

    dados = {
        "usuario": usuario,
        "timestamp": timestamp if timestamp is not None else timestamp_atual(),
        "nonce": nonce or uuid.uuid4().hex,
    }

    return criptografar_json(chave_sessao, dados)


def abrir_autenticador(chave_sessao_base64: str, autenticador_criptografado: dict) -> dict:
    chave_sessao = base64_para_bytes(chave_sessao_base64)
    return descriptografar_json(chave_sessao, autenticador_criptografado)