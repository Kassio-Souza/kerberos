import json
from pathlib import Path

from kerberos_notas.crypto.kdf import derivar_chave_senha, gerar_verificador_chave
from kerberos_notas.crypto.crypto_utils import (
    gerar_chave_simetrica,
    bytes_para_base64,
    criptografar_json,
)
from kerberos_notas.kerberos.tickets import criar_tgt
from kerberos_notas.config import CHAVE_SECRETA_TGS


CAMINHO_USUARIOS = Path(__file__).resolve().parents[3] / "data" / "usuarios.json"


def carregar_usuarios() -> dict:
    with open(CAMINHO_USUARIOS, "r", encoding="utf-8") as arquivo:
        return json.load(arquivo)


def autenticar_no_as(nome_usuario: str, senha: str) -> dict:
    """
    Simula o Servidor de Autenticação do Kerberos.

    O AS recebe usuário e senha, valida o usuário e devolve:
    - chave de sessão Cliente-TGS;
    - TGT criptografado com a chave secreta do TGS.

    A resposta ao cliente é criptografada com a chave derivada da senha do usuário.
    """
    dados_usuarios = carregar_usuarios()
    usuarios = dados_usuarios.get("usuarios", {})

    if nome_usuario not in usuarios:
        raise ValueError("Usuário não encontrado.")

    dados_usuario = usuarios[nome_usuario]

    salt = dados_usuario["salt"]
    verificador_salvo = dados_usuario["verificador"]

    chave_cliente = derivar_chave_senha(senha, salt)
    verificador_calculado = gerar_verificador_chave(chave_cliente)

    if verificador_calculado != verificador_salvo:
        raise ValueError("Senha inválida.")

    chave_sessao_cliente_tgs = gerar_chave_simetrica()
    chave_sessao_cliente_tgs_base64 = bytes_para_base64(chave_sessao_cliente_tgs)

    tgt = criar_tgt(
        id_cliente=nome_usuario,
        chave_sessao_cliente_tgs_base64=chave_sessao_cliente_tgs_base64,
        id_tgs="tgs"
    )

    tgt_criptografado = criptografar_json(
        CHAVE_SECRETA_TGS,
        tgt
    )

    resposta_para_cliente = {
        "id_tgs": "tgs",
        "chave_sessao_cliente_tgs": chave_sessao_cliente_tgs_base64,
        "tgt": tgt_criptografado
    }

    resposta_criptografada = criptografar_json(
        chave_cliente,
        resposta_para_cliente
    )

    return resposta_criptografada


