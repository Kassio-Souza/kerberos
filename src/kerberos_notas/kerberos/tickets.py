import time
import uuid

TEMPO_VALIDADE_TICKET = 60 * 10
TEMPO_VALIDADE_TICKET_SERVICO = 60 * 10

def timestamp_atual() -> int:
    return int(time.time())


def ticket_expirou(timestamp_emissao: int, validade_segundos: int) -> bool:
    agora = timestamp_atual()

    return agora > timestamp_emissao + validade_segundos


def ticket_expirou_por_timestamp(timestamp_expiracao: int) -> bool:
    return timestamp_atual() > timestamp_expiracao

def criar_tgt(
        id_cliente: str,
        chave_sessao_cliente_tgs_base64: str,
        id_tgs: str = "tgs"
) -> dict:
    """
    Cria o ticket granting ticket.

    Esse ticket será criptografado com a chave secreta do TGS.
    O cliente não consegue abrir esse ticket.
    """

    return {
        "id_cliente": id_cliente,
        "id_tgs": id_tgs,
        "chave_sessao_cliente_tgs": chave_sessao_cliente_tgs_base64,
        "timestamp_emissao": timestamp_atual(),
        "validade_segundos": TEMPO_VALIDADE_TICKET
    }


def criar_ticket_servico(
        usuario: str,
        servico: str,
        chave_sessao_cliente_servico_base64: str,
        validade_segundos: int = TEMPO_VALIDADE_TICKET_SERVICO
) -> dict:
    timestamp_emissao = timestamp_atual()

    return {
        "usuario": usuario,
        "servico": servico,
        "chave_sessao_cliente_servico": chave_sessao_cliente_servico_base64,
        "timestamp_emissao": timestamp_emissao,
        "timestamp_expiracao": timestamp_emissao + validade_segundos,
        "nonce": uuid.uuid4().hex
    }
