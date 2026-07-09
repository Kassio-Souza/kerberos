"""
@file authenticator.py
@brief Criação e abertura de autenticadores Kerberos.

@details
Implementa o autenticador enviado pelo cliente ao TGS ou ao serviço protegido,
contendo usuário, timestamp e nonce criptografados com a chave de sessão.

Componentes principais:
- criar_autenticador
- abrir_autenticador

Papel na arquitetura:
Permite provar posse da chave de sessão sem enviar a chave pela rede.
"""

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
    """
    ***************************************************************************
    Função: criar_autenticador

    @brief Cria um autenticador criptografado com a chave de sessão.

    Descrição:
    Monta um dicionário com usuário, timestamp e nonce, converte a chave de
    sessão de Base64 para bytes e cifra os dados com AES-GCM.

    Parâmetros:
    @param usuario Nome do cliente que solicita acesso.
    @param chave_sessao_base64 Chave de sessão compartilhada em Base64.
    @param nonce Valor opcional usado para evitar replay.
    @param timestamp Timestamp opcional; se ausente, usa o instante atual.

    Valor retornado:
    @return Retorna dict criptografado com nonce e ciphertext.

    Assertiva de entrada:
    @pre usuario != None
    @pre chave_sessao_base64 deve ser Base64 de uma chave AES válida.

    Assertiva de saída:
    @post Retorna autenticador que pode ser aberto com a mesma chave de sessão.

    Exceções:
    @throws Exception Pode propagar erros de Base64 ou AES-GCM para chave inválida.

    Observações:
    O autenticador diferencia requisições recentes e ajuda a reduzir replay no
    TGS e no serviço de notas.
    ***************************************************************************
    """
    chave_sessao = base64_para_bytes(chave_sessao_base64)

    dados = {
        "usuario": usuario,
        "timestamp": timestamp if timestamp is not None else timestamp_atual(),
        "nonce": nonce or uuid.uuid4().hex,
    }

    return criptografar_json(chave_sessao, dados)


def abrir_autenticador(chave_sessao_base64: str, autenticador_criptografado: dict) -> dict:
    """
    ***************************************************************************
    Função: abrir_autenticador

    @brief Descriptografa um autenticador Kerberos.

    Descrição:
    Converte a chave de sessão de Base64 para bytes e usa descriptografar_json
    para recuperar usuário, timestamp e nonce.

    Parâmetros:
    @param chave_sessao_base64 Chave de sessão compartilhada em Base64.
    @param autenticador_criptografado Pacote criptografado enviado pelo cliente.

    Valor retornado:
    @return Retorna dict com os dados internos do autenticador.

    Assertiva de entrada:
    @pre chave_sessao_base64 deve corresponder à chave usada na criação.
    @pre autenticador_criptografado deve conter nonce e ciphertext.

    Assertiva de saída:
    @post Retorna autenticador em claro quando a chave é correta.

    Exceções:
    @throws Exception Pode propagar exceções de descriptografia quando chave ou pacote forem inválidos.

    Observações:
    A validação semântica de usuário, timestamp e nonce ocorre nos servidores.
    ***************************************************************************
    """
    chave_sessao = base64_para_bytes(chave_sessao_base64)
    return descriptografar_json(chave_sessao, autenticador_criptografado)
