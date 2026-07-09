"""
@file as_server.py
@brief Lógica do Servidor de Autenticação do Kerberos Notas.

@details
Valida usuário e senha, deriva a chave do cliente, emite chave de sessão
Cliente-TGS e cria o TGT criptografado para o Ticket Granting Server.

Componentes principais:
- carregar_usuarios
- autenticar_no_as

Papel na arquitetura:
Representa o AS do protocolo Kerberos, primeira etapa do fluxo de autenticação.
"""

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
    """
    ***************************************************************************
    Função: carregar_usuarios

    @brief Carrega o cadastro de usuários usado pelo AS.

    Descrição:
    Abre o arquivo JSON de usuários e retorna seu conteúdo para validação de
    identidade, salt e verificador de senha.

    Parâmetros:
    Não recebe parâmetros explícitos.

    Valor retornado:
    @return Retorna dict com os dados lidos de usuarios.json.

    Assertiva de entrada:
    @pre CAMINHO_USUARIOS deve apontar para um arquivo JSON existente e válido.

    Assertiva de saída:
    @post Retorna estrutura contendo, quando cadastrados, usuários com salt e verificador.

    Exceções:
    @throws Exception Pode propagar FileNotFoundError, PermissionError ou JSONDecodeError.

    Observações:
    O arquivo representa o armazenamento simples usado no projeto acadêmico.
    ***************************************************************************
    """
    with open(CAMINHO_USUARIOS, "r", encoding="utf-8") as arquivo:
        return json.load(arquivo)


def autenticar_no_as(nome_usuario: str, senha: str) -> dict:
    """
    ***************************************************************************
    Função: autenticar_no_as

    @brief Executa a autenticação inicial do cliente no AS.

    Descrição:
    Busca o usuário cadastrado, deriva a chave a partir da senha e do salt,
    compara o verificador calculado com o salvo, gera chave Cliente-TGS, cria o
    TGT e criptografa a resposta destinada ao cliente.

    Parâmetros:
    @param nome_usuario Nome do usuário que solicita autenticação.
    @param senha Senha textual informada pelo usuário.

    Valor retornado:
    @return Retorna dict criptografado com a chave derivada do cliente.

    Assertiva de entrada:
    @pre nome_usuario != None
    @pre senha != None
    @pre O usuário deve existir no cadastro para autenticação bem-sucedida.

    Assertiva de saída:
    @post Retorna resposta com id_tgs, chave Cliente-TGS e TGT, todos protegidos para
    @post o cliente; lança exceção se usuário ou senha não forem válidos.

    Exceções:
    @throws ValueError quando o usuário não existe ou a senha é inválida.

    Observações:
    O TGT é criptografado com CHAVE_SECRETA_TGS; o cliente o transporta sem
    conseguir abrir seu conteúdo.
    ***************************************************************************
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


