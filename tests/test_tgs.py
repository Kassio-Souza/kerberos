import pytest

from kerberos_notas.config import CHAVE_SECRETA_SERVICO_NOTAS, CHAVE_SECRETA_TGS
from kerberos_notas.crypto.crypto_utils import (
    base64_para_bytes,
    bytes_para_base64,
    criptografar_json,
    descriptografar_json,
    gerar_chave_simetrica,
)
from kerberos_notas.kerberos.authenticator import criar_autenticador
from kerberos_notas.kerberos.tgs_server import (
    abrir_ticket_servico,
    emitir_ticket_servico,
)
from kerberos_notas.kerberos.tickets import (
    criar_tgt,
    criar_ticket_servico,
    timestamp_atual,
)


def montar_tgt(usuario="ana", validade_segundos=600, timestamp_emissao=None):
    chave_sessao = gerar_chave_simetrica()
    chave_sessao_base64 = bytes_para_base64(chave_sessao)

    tgt = criar_tgt(
        id_cliente=usuario,
        chave_sessao_cliente_tgs_base64=chave_sessao_base64
    )
    tgt["validade_segundos"] = validade_segundos

    if timestamp_emissao is not None:
        tgt["timestamp_emissao"] = timestamp_emissao

    return chave_sessao_base64, criptografar_json(CHAVE_SECRETA_TGS, tgt)


def test_tgs_emite_ticket_servico_com_tgt_valido():
    chave_sessao_tgs, tgt = montar_tgt()
    autenticador = criar_autenticador("ana", chave_sessao_tgs)

    resposta = emitir_ticket_servico(
        usuario="ana",
        servico="notas",
        tgt_criptografado=tgt,
        autenticador_criptografado=autenticador
    )

    dados_cliente = descriptografar_json(
        chave=base64_para_bytes(chave_sessao_tgs),
        pacote=resposta["resposta_cliente"]
    )

    assert resposta["servico"] == "notas"
    assert "ticket_servico" in resposta
    assert dados_cliente["usuario"] == "ana"
    assert dados_cliente["servico"] == "notas"
    assert dados_cliente["chave_sessao_cliente_servico"]


def test_tgs_rejeita_tgt_expirado():
    chave_sessao_tgs, tgt = montar_tgt(
        validade_segundos=1,
        timestamp_emissao=timestamp_atual() - 10
    )
    autenticador = criar_autenticador("ana", chave_sessao_tgs)

    with pytest.raises(ValueError, match="TGT expirado"):
        emitir_ticket_servico("ana", "notas", tgt, autenticador)


def test_tgs_rejeita_autenticador_invalido():
    _, tgt = montar_tgt()
    chave_errada = bytes_para_base64(gerar_chave_simetrica())
    autenticador = criar_autenticador("ana", chave_errada)

    with pytest.raises(ValueError, match="Autenticador invalido"):
        emitir_ticket_servico("ana", "notas", tgt, autenticador)


def test_tgs_rejeita_usuario_diferente_no_autenticador():
    chave_sessao_tgs, tgt = montar_tgt(usuario="ana")
    autenticador = criar_autenticador("bia", chave_sessao_tgs)

    with pytest.raises(ValueError, match="Usuario do autenticador diferente"):
        emitir_ticket_servico("ana", "notas", tgt, autenticador)


def test_ticket_servico_tem_dados_necessarios():
    chave_sessao_tgs, tgt = montar_tgt()
    autenticador = criar_autenticador("ana", chave_sessao_tgs)

    resposta = emitir_ticket_servico("ana", "notas", tgt, autenticador)
    ticket = abrir_ticket_servico("notas", resposta["ticket_servico"])

    assert ticket["usuario"] == "ana"
    assert ticket["servico"] == "notas"
    assert ticket["chave_sessao_cliente_servico"]
    assert ticket["timestamp_expiracao"] > ticket["timestamp_emissao"]
    assert ticket["nonce"]


def test_ticket_servico_nao_fica_legivel_sem_chave_correta():
    chave_sessao_tgs, tgt = montar_tgt()
    autenticador = criar_autenticador("ana", chave_sessao_tgs)

    resposta = emitir_ticket_servico("ana", "notas", tgt, autenticador)
    ticket_criptografado = resposta["ticket_servico"]
    texto_ticket = str(ticket_criptografado)

    assert "ana" not in texto_ticket
    assert "chave_sessao_cliente_servico" not in texto_ticket

    with pytest.raises(Exception):
        descriptografar_json(gerar_chave_simetrica(), ticket_criptografado)

    ticket_aberto = descriptografar_json(CHAVE_SECRETA_SERVICO_NOTAS, ticket_criptografado)
    assert ticket_aberto["usuario"] == "ana"


def test_ticket_servico_expirado_nao_e_aceito():
    ticket = criar_ticket_servico(
        usuario="ana",
        servico="notas",
        chave_sessao_cliente_servico_base64=bytes_para_base64(gerar_chave_simetrica()),
        validade_segundos=-1
    )
    ticket_criptografado = criptografar_json(CHAVE_SECRETA_SERVICO_NOTAS, ticket)

    with pytest.raises(ValueError, match="Ticket de servico expirado"):
        abrir_ticket_servico("notas", ticket_criptografado)
