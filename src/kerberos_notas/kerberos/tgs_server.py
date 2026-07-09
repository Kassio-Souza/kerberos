from kerberos_notas.config import CHAVE_SECRETA_SERVICO_NOTAS, CHAVE_SECRETA_TGS
from kerberos_notas.crypto.crypto_utils import (
    base64_para_bytes,
    bytes_para_base64,
    criptografar_json,
    descriptografar_json,
    gerar_chave_simetrica,
)
from kerberos_notas.kerberos.authenticator import abrir_autenticador
from kerberos_notas.kerberos.tickets import (
    criar_ticket_servico,
    ticket_expirou,
    ticket_expirou_por_timestamp,
    timestamp_atual,
)


TEMPO_MAXIMO_AUTENTICADOR = 60 * 5

CHAVES_SERVICOS = {
    "notas": CHAVE_SECRETA_SERVICO_NOTAS
}


def obter_chave_servico(servico: str) -> bytes:
    if servico not in CHAVES_SERVICOS:
        raise ValueError("Servico desconhecido.")

    return CHAVES_SERVICOS[servico]


def validar_tgt(usuario: str, tgt_criptografado: dict) -> dict:
    if not tgt_criptografado:
        raise ValueError("TGT nao informado.")

    try:
        tgt = descriptografar_json(CHAVE_SECRETA_TGS, tgt_criptografado)
    except Exception as erro:
        raise ValueError("TGT invalido ou nao pode ser descriptografado.") from erro

    if tgt.get("id_cliente") != usuario:
        raise ValueError("TGT pertence a outro usuario.")

    chave_sessao = tgt.get("chave_sessao_cliente_tgs")
    if not chave_sessao:
        raise ValueError("TGT nao contem chave de sessao Cliente-TGS.")

    if ticket_expirou(tgt["timestamp_emissao"], tgt["validade_segundos"]):
        raise ValueError("TGT expirado.")

    return tgt


def validar_autenticador(usuario: str, tgt: dict, autenticador_criptografado: dict) -> dict:
    if not autenticador_criptografado:
        raise ValueError("Autenticador nao informado.")

    chave_sessao = tgt["chave_sessao_cliente_tgs"]

    try:
        autenticador = abrir_autenticador(chave_sessao, autenticador_criptografado)
    except Exception as erro:
        raise ValueError("Autenticador invalido ou nao pode ser descriptografado.") from erro

    if autenticador.get("usuario") != usuario:
        raise ValueError("Usuario do autenticador diferente do usuario do TGT.")

    timestamp = autenticador.get("timestamp")
    if timestamp is None:
        raise ValueError("Autenticador sem timestamp.")

    if ticket_expirou(timestamp, TEMPO_MAXIMO_AUTENTICADOR):
        raise ValueError("Autenticador expirado.")

    if timestamp > timestamp_atual() + TEMPO_MAXIMO_AUTENTICADOR:
        raise ValueError("Autenticador com timestamp invalido.")

    return autenticador


def emitir_ticket_servico(
        usuario: str,
        servico: str,
        tgt_criptografado: dict,
        autenticador_criptografado: dict
) -> dict:
    chave_servico = obter_chave_servico(servico)
    tgt = validar_tgt(usuario, tgt_criptografado)
    validar_autenticador(usuario, tgt, autenticador_criptografado)

    chave_sessao_cliente_servico = gerar_chave_simetrica()
    chave_sessao_cliente_servico_base64 = bytes_para_base64(chave_sessao_cliente_servico)

    ticket_servico = criar_ticket_servico(
        usuario=usuario,
        servico=servico,
        chave_sessao_cliente_servico_base64=chave_sessao_cliente_servico_base64
    )

    ticket_servico_criptografado = criptografar_json(chave_servico, ticket_servico)
    chave_cliente_tgs = base64_para_bytes(tgt["chave_sessao_cliente_tgs"])

    resposta_cliente = criptografar_json(
        chave_cliente_tgs,
        {
            "usuario": usuario,
            "servico": servico,
            "chave_sessao_cliente_servico": chave_sessao_cliente_servico_base64,
            "timestamp_emissao": ticket_servico["timestamp_emissao"],
            "timestamp_expiracao": ticket_servico["timestamp_expiracao"],
            "nonce_ticket": ticket_servico["nonce"]
        }
    )

    return {
        "servico": servico,
        "ticket_servico": ticket_servico_criptografado,
        "resposta_cliente": resposta_cliente
    }


def abrir_ticket_servico(servico: str, ticket_servico_criptografado: dict) -> dict:
    chave_servico = obter_chave_servico(servico)

    try:
        ticket_servico = descriptografar_json(chave_servico, ticket_servico_criptografado)
    except Exception as erro:
        raise ValueError("Ticket de servico invalido ou nao pode ser descriptografado.") from erro

    if ticket_servico.get("servico") != servico:
        raise ValueError("Ticket foi emitido para outro servico.")

    if ticket_expirou_por_timestamp(ticket_servico["timestamp_expiracao"]):
        raise ValueError("Ticket de servico expirado.")

    return ticket_servico
