"""
@file crypto_utils.py
@brief Utilitários de criptografia simétrica e codificação Base64.

@details
Reúne funções usadas para gerar chaves AES, converter bytes para Base64 e
criptografar ou descriptografar dicionários JSON com AES-GCM.

Componentes principais:
- gerar_chave_simetrica
- criptografar_json
- descriptografar_json

Papel na arquitetura:
Fornece a camada criptográfica comum para AS, TGS, cliente e serviço de notas
no fluxo Kerberos Notas.
"""

import os
import json
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TAMANHO_NONCE = 12
TAMANHO_CHAVE_AES = 32

def gerar_chave_simetrica() -> bytes:
    """
    ***************************************************************************
    Função: gerar_chave_simetrica

    @brief Gera uma chave simétrica aleatória de 256 bits.

    Descrição:
    Cria uma sequência de bytes aleatórios com tamanho adequado para AES-256.
    No Kerberos Notas, essa chave é usada como chave de sessão Cliente-TGS ou
    Cliente-Serviço.

    Parâmetros:
    Não recebe parâmetros explícitos.

    Valor retornado:
    @return Retorna bytes aleatórios com TAMANHO_CHAVE_AES bytes.

    Assertiva de entrada:
    @pre O gerador de aleatoriedade do sistema operacional deve estar disponível.

    Assertiva de saída:
    @post Retorna uma chave de 32 bytes adequada para AES-GCM.

    Exceções:
    @throws Exception Pode propagar exceções de os.urandom caso a fonte de aleatoriedade falhe.

    Observações:
    A função centraliza a criação de chaves de sessão usadas nos tickets.
    ***************************************************************************
    """

    return os.urandom(TAMANHO_CHAVE_AES)



def bytes_para_base64(dados: bytes) -> str:
    """
    ***************************************************************************
    Função: bytes_para_base64

    @brief Codifica bytes em texto Base64.

    Descrição:
    Converte dados binários para uma representação textual em UTF-8, adequada
    para armazenamento em JSON e transporte por socket.

    Parâmetros:
    @param dados Sequência de bytes que será codificada.

    Valor retornado:
    @return Retorna uma string Base64.

    Assertiva de entrada:
    @pre dados != None
    @pre dados deve ser um objeto bytes.

    Assertiva de saída:
    @post Retorna texto decodificável por base64_para_bytes.

    Exceções:
    @throws Exception Pode propagar TypeError se o valor recebido não for bytes-like.

    Observações:
    A conversão permite incluir chaves, nonces e ciphertexts em mensagens JSON.
    ***************************************************************************
    """
    return base64.b64encode(dados).decode("utf-8")


def base64_para_bytes(dados_base64: str) -> bytes:
    """
    ***************************************************************************
    Função: base64_para_bytes

    @brief Decodifica texto Base64 para bytes.

    Descrição:
    Recupera os dados binários originais a partir de uma string Base64 usada no
    armazenamento ou transporte de mensagens do protocolo.

    Parâmetros:
    @param dados_base64 String contendo dados codificados em Base64.

    Valor retornado:
    @return Retorna os bytes decodificados.

    Assertiva de entrada:
    @pre dados_base64 != None
    @pre dados_base64 deve conter uma representação Base64 válida.

    Assertiva de saída:
    @post Retorna os bytes correspondentes à entrada textual.

    Exceções:
    @throws Exception Pode propagar erros de decodificação Base64 para entradas inválidas.

    Observações:
    É usada para abrir chaves de sessão e campos criptográficos recebidos em JSON.
    ***************************************************************************
    """
    return base64.b64decode(dados_base64)


def criptografar_json(chave: bytes, dados: dict) -> dict:
    """
    ***************************************************************************
    Função: criptografar_json

    @brief Cifra um dicionário JSON usando AES-GCM.

    Descrição:
    Serializa o dicionário recebido para JSON, gera um nonce aleatório e cifra
    o conteúdo com AES-GCM. O retorno contém nonce e ciphertext em Base64.

    Parâmetros:
    @param chave Chave simétrica em bytes, com tamanho compatível com AESGCM.
    @param dados Dicionário serializável em JSON que será protegido.

    Valor retornado:
    @return Retorna dict com os campos "nonce" e "ciphertext" em Base64.

    Assertiva de entrada:
    @pre chave != None
    @pre dados != None
    @pre dados deve ser serializável por json.dumps.

    Assertiva de saída:
    @post Retorna um pacote criptografado que pode ser aberto por descriptografar_json
    @post com a mesma chave.

    Exceções:
    @throws Exception Pode propagar exceções de AESGCM para chave inválida.
    @throws Exception Pode propagar TypeError se dados não puder ser serializado em JSON.

    Observações:
    AES-GCM fornece confidencialidade e autenticação do conteúdo usado em tickets,
    autenticadores e respostas Kerberos do projeto.
    ***************************************************************************
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
    ***************************************************************************
    Função: descriptografar_json

    @brief Abre um pacote JSON cifrado por criptografar_json.

    Descrição:
    Decodifica nonce e ciphertext em Base64, aplica AES-GCM com a chave recebida
    e desserializa o JSON descriptografado para um dicionário Python.

    Parâmetros:
    @param chave Chave simétrica em bytes usada para descriptografia.
    @param pacote Dicionário contendo os campos "nonce" e "ciphertext".

    Valor retornado:
    @return Retorna o dicionário originalmente criptografado.

    Assertiva de entrada:
    @pre chave != None
    @pre pacote deve conter nonce e ciphertext em Base64.

    Assertiva de saída:
    @post Retorna o conteúdo em claro quando a chave e o pacote são válidos.

    Exceções:
    @throws KeyError se os campos esperados não existirem.
    @throws Exception se a autenticação AES-GCM falhar ou a chave estiver errada.

    Observações:
    Falhas de descriptografia indicam chave incorreta, pacote alterado ou dados
    incompatíveis com o fluxo Kerberos esperado.
    ***************************************************************************
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
