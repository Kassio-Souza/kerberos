import json
import socket


TAMANHO_BUFFER = 65536
ENCODING = "utf-8"


def enviar_json(conexao: socket.socket, dados: dict) -> None:
    """
    Envia um dicionário JSON pelo socket.

    A quebra de linha funciona como delimitador da mensagem.
    """
    mensagem = json.dumps(dados, ensure_ascii=False)
    conexao.sendall((mensagem + "\n").encode(ENCODING))


def receber_json(conexao: socket.socket) -> dict:
    """
    Recebe uma mensagem JSON enviada pelo socket.
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
    Abre conexão com um servidor, envia uma requisição JSON e recebe uma resposta JSON.
    """
    with socket.create_connection((host, porta), timeout=timeout) as conexao:
        enviar_json(conexao, requisicao)
        return receber_json(conexao)