import os
import json
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TAMANHO_NONCE = 12
TAMANHO_CHAVE_AES = 32

def gerar_chave_simetrica() -> bytes:
    """
    Gera uma chave simétrica aleatória de 256 bits
    """

    return os.urandom(TAMANHO_CHAVE_AES)



def bytes_para_base64(dados: bytes) -> str:
    return base64.b64encode(dados).decode("utf-8")


def base64_para_bytes(dados_base64: str) -> bytes:
    return base64.b64decode(dados_base64)


def criptografar_json(chave: bytes, dados: dict) -> dict:
    """
    Cifra um dicinario usando AES-GCM.

    Retorna nonce e ciphertex em base64
    """

    aesgcm = AESGCM(chave)
    nonce = os.urandom(TAMANHO_NONCE)

    dados_json = json.dumps(dados).encode("utf-8")

    ciphertext = aesgcm.encrypt(
        nonce,
        dados_json,
        None
    )

    return {
        "nonce": bytes_para_base64(nonce),
        "ciphertext": bytes_para_base64(ciphertext)
    }


def descriptografar_json(chave: bytes, pacote: dict) -> dict:
    """
    Descriptografa um pacote gerado pela função criptografar_json
    """

    aesgcm = AESGCM(chave)
    nonce = base64_para_bytes(pacote["nonce"])
    ciphertext = base64_para_bytes(pacote["ciphertext"])

    dados_json = aesgcm.decrypt(
        nonce,
        ciphertext,
        None
    )

    return json.loads(dados_json.decode("utf-8"))