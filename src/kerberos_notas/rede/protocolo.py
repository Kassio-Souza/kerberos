"""
@file protocolo.py
@brief Protocolo simples de mensagens JSON sobre sockets TCP.

@details
Envia e recebe dicionários JSON delimitados por quebra de linha, além de
fornecer chamada cliente síncrona para os servidores.

Componentes principais:
- enviar_json
- receber_json
- chamar_servidor

Papel na arquitetura:
Transporta mensagens entre cliente web, AS, TGS e Serviço de Notas.
"""

import json
import socket


TAMANHO_BUFFER = 65536
ENCODING = "utf-8"


def enviar_json(conexao: socket.socket, dados: dict) -> None:
    """
    ***************************************************************************
    Função: enviar_json

    @brief Envia um dicionário JSON por socket.

    Descrição:
    Serializa dados em JSON, acrescenta quebra de linha como delimitador e envia
    todos os bytes pela conexão.

    Parâmetros:
    @param conexao Socket conectado.
    @param dados Dicionário serializável em JSON.

    Valor retornado:
    @return Não retorna valor.

    Assertiva de entrada:
    @pre conexao deve estar aberta e dados deve ser serializável.

    Assertiva de saída:
    @post A mensagem JSON delimitada por newline é enviada ao par remoto.

    Exceções:
    @throws Exception Pode propagar erros de socket ou serialização JSON.

    Observações:
    O delimitador simplifica a leitura de uma mensagem por conexão.
    ***************************************************************************
    """
    mensagem = json.dumps(dados, ensure_ascii=False)
    conexao.sendall((mensagem + "\n").encode(ENCODING))


def receber_json(conexao: socket.socket) -> dict:
    """
    ***************************************************************************
    Função: receber_json

    @brief Recebe uma mensagem JSON de um socket.

    Descrição:
    Lê blocos até encontrar quebra de linha ou fim de conexão, decodifica em
    UTF-8 e desserializa o JSON para dicionário.

    Parâmetros:
    @param conexao Socket conectado de onde os dados serão lidos.

    Valor retornado:
    @return Retorna dict recebido.

    Assertiva de entrada:
    @pre conexao deve estar aberta para leitura.

    Assertiva de saída:
    @post Retorna mensagem JSON parseada.

    Exceções:
    @throws ConnectionError se nenhum dado for recebido.

    Observações:
    O protocolo é didático e não implementa framing binário complexo.
    ***************************************************************************
    """
    partes = []

    while True:
        bloco = conexao.recv(TAMANHO_BUFFER)

        if not bloco:
            break

        partes.append(bloco)

        if b"\n" in bloco:
            break

    if not partes:
        raise ConnectionError("Nenhum dado recebido pelo socket.")

    dados = b"".join(partes).decode(ENCODING).strip()

    return json.loads(dados)


def chamar_servidor(host: str, porta: int, requisicao: dict, timeout: int = 10) -> dict:
    """
    ***************************************************************************
    Função: chamar_servidor

    @brief Envia uma requisição JSON e recebe resposta de um servidor TCP.

    Descrição:
    Abre conexão TCP, envia a requisição com enviar_json e retorna o dicionário
    lido por receber_json.

    Parâmetros:
    @param host Endereço do servidor.
    @param porta Porta TCP do servidor.
    @param requisicao Dicionário da requisição.
    @param timeout Tempo máximo de conexão em segundos.

    Valor retornado:
    @return Retorna dict de resposta do servidor.

    Assertiva de entrada:
    @pre host e porta devem apontar para servidor ativo.

    Assertiva de saída:
    @post Fecha a conexão ao sair do bloco with e retorna a resposta recebida.

    Exceções:
    @throws Exception Pode propagar TimeoutError, OSError, ConnectionError ou JSONDecodeError.

    Observações:
    Usada pela camada cliente para chamar AS, TGS e serviço de notas.
    ***************************************************************************
    """
    with socket.create_connection((host, porta), timeout=timeout) as conexao:
        enviar_json(conexao, requisicao)
        return receber_json(conexao)
