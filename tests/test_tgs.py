"""
---
* Arquivo: test_tgs.py
* @file test_tgs.py
* @brief Testes do Ticket Granting Server.
*
* Descrição
* Exercita emissão, abertura e rejeição de tickets no TGS, incluindo expiração,
* autenticador inválido e confidencialidade do ticket de serviço.
*
* Componentes principais
* * montar_tgt
* * test_tgs_emite_ticket_servico_com_tgt_valido
* * test_ticket_servico_expirado_nao_e_aceito
*
* Papel na arquitetura
* Valida a etapa intermediária entre AS e Serviço de Notas.
---
"""

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
    """
    ---
    * Função: montar_tgt
    * @brief Monta um TGT criptografado para testes do TGS.
    *
    * Descrição
    * Gera chave Cliente-TGS, cria TGT em claro, ajusta validade e timestamp quando
    * solicitado e criptografa com a chave secreta do TGS.
    *
    * Parâmetros
    * @param usuario Usuário que constará no TGT.
    * @param validade_segundos Validade configurada para o TGT.
    * @param timestamp_emissao Timestamp opcional para simular emissão passada.
    *
    * Valor retornado
    * @return Retorna tupla com chave Cliente-TGS em Base64 e TGT criptografado.
    *
    * Assertiva de entrada
    * usuario deve ser compatível com os testes.
    *
    * Assertiva de saída
    * Retorna TGT que o TGS consegue abrir com CHAVE_SECRETA_TGS.
    *
    * Exceções
    * Pode propagar erros de geração de chave ou criptografia.
    *
    * Observações
    * É helper de teste, não função de produção.
    ---
    """
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
    """
    ---
    * Função: test_tgs_emite_ticket_servico_com_tgt_valido
    * @brief Verifica emissão de ticket com TGT válido.
    *
    * Descrição
    * Usa TGT válido e autenticador correto para solicitar ticket de serviço e abre
    * a resposta destinada ao cliente.
    *
    * Parâmetros
    * Nenhum parâmetro é recebido.
    *
    * Valor retornado
    * @return Não retorna valor.
    *
    * Assertiva de entrada
    * TGT e autenticador são consistentes para o usuário ana.
    *
    * Assertiva de saída
    * Resposta contém serviço notas, ticket de serviço e chave Cliente-Serviço.
    *
    * Exceções
    * AssertionError se a emissão não produzir dados esperados.
    *
    * Observações
    * Cobre o caminho feliz do TGS-REQ/TGS-REP.
    ---
    """
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
    """
    ---
    * Função: test_tgs_rejeita_tgt_expirado
    * @brief Verifica rejeição de TGT expirado.
    *
    * Descrição
    * Cria TGT com emissão no passado e validade curta, depois confirma que o TGS
    * rejeita a emissão de ticket de serviço.
    *
    * Parâmetros
    * Nenhum parâmetro é recebido.
    *
    * Valor retornado
    * @return Não retorna valor.
    *
    * Assertiva de entrada
    * O TGT usado no teste já está fora da validade.
    *
    * Assertiva de saída
    * emitir_ticket_servico lança ValueError com mensagem de TGT expirado.
    *
    * Exceções
    * O teste espera ValueError.
    *
    * Observações
    * Garante a checagem temporal de tickets Kerberos.
    ---
    """
    chave_sessao_tgs, tgt = montar_tgt(
        validade_segundos=1,
        timestamp_emissao=timestamp_atual() - 10
    )
    autenticador = criar_autenticador("ana", chave_sessao_tgs)

    with pytest.raises(ValueError, match="TGT expirado"):
        emitir_ticket_servico("ana", "notas", tgt, autenticador)


def test_tgs_rejeita_autenticador_invalido():
    """
    ---
    * Função: test_tgs_rejeita_autenticador_invalido
    * @brief Verifica rejeição de autenticador com chave errada.
    *
    * Descrição
    * Monta TGT válido, mas cria autenticador com outra chave de sessão, esperando
    * falha de descriptografia no TGS.
    *
    * Parâmetros
    * Nenhum parâmetro é recebido.
    *
    * Valor retornado
    * @return Não retorna valor.
    *
    * Assertiva de entrada
    * Autenticador não corresponde à chave Cliente-TGS do TGT.
    *
    * Assertiva de saída
    * O TGS lança ValueError indicando autenticador inválido.
    *
    * Exceções
    * O teste espera ValueError.
    *
    * Observações
    * Demonstra a prova de posse da chave Cliente-TGS.
    ---
    """
    _, tgt = montar_tgt()
    chave_errada = bytes_para_base64(gerar_chave_simetrica())
    autenticador = criar_autenticador("ana", chave_errada)

    with pytest.raises(ValueError, match="Autenticador invalido"):
        emitir_ticket_servico("ana", "notas", tgt, autenticador)


def test_tgs_rejeita_usuario_diferente_no_autenticador():
    """
    ---
    * Função: test_tgs_rejeita_usuario_diferente_no_autenticador
    * @brief Verifica rejeição por usuário divergente no autenticador.
    *
    * Descrição
    * Usa TGT de ana e autenticador cifrado corretamente, mas com usuário bia.
    *
    * Parâmetros
    * Nenhum parâmetro é recebido.
    *
    * Valor retornado
    * @return Não retorna valor.
    *
    * Assertiva de entrada
    * TGT e autenticador têm usuários diferentes.
    *
    * Assertiva de saída
    * O TGS lança ValueError sobre divergência de usuário.
    *
    * Exceções
    * O teste espera ValueError.
    *
    * Observações
    * Impede uso combinado de credenciais de usuários distintos.
    ---
    """
    chave_sessao_tgs, tgt = montar_tgt(usuario="ana")
    autenticador = criar_autenticador("bia", chave_sessao_tgs)

    with pytest.raises(ValueError, match="Usuario do autenticador diferente"):
        emitir_ticket_servico("ana", "notas", tgt, autenticador)


def test_ticket_servico_tem_dados_necessarios():
    """
    ---
    * Função: test_ticket_servico_tem_dados_necessarios
    * @brief Confirma campos essenciais do ticket de serviço.
    *
    * Descrição
    * Emite ticket, abre com a chave do serviço e verifica usuário, serviço, chave
    * de sessão, timestamps e nonce.
    *
    * Parâmetros
    * Nenhum parâmetro é recebido.
    *
    * Valor retornado
    * @return Não retorna valor.
    *
    * Assertiva de entrada
    * TGT e autenticador são válidos.
    *
    * Assertiva de saída
    * Ticket contém os dados necessários para o serviço protegido.
    *
    * Exceções
    * AssertionError se algum campo obrigatório faltar.
    *
    * Observações
    * Valida a estrutura esperada pelo Serviço de Notas.
    ---
    """
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
    """
    ---
    * Função: test_ticket_servico_nao_fica_legivel_sem_chave_correta
    * @brief Verifica confidencialidade do ticket de serviço.
    *
    * Descrição
    * Confirma que o ticket criptografado não expõe dados em texto e não pode ser
    * aberto com chave aleatória.
    *
    * Parâmetros
    * Nenhum parâmetro é recebido.
    *
    * Valor retornado
    * @return Não retorna valor.
    *
    * Assertiva de entrada
    * Ticket foi criptografado com CHAVE_SECRETA_SERVICO_NOTAS.
    *
    * Assertiva de saída
    * Somente a chave correta abre o ticket.
    *
    * Exceções
    * O teste espera exceção ao usar chave incorreta.
    *
    * Observações
    * Demonstra a proteção do ticket contra leitura pelo cliente.
    ---
    """
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
    """
    ---
    * Função: test_ticket_servico_expirado_nao_e_aceito
    * @brief Verifica rejeição de ticket de serviço expirado.
    *
    * Descrição
    * Cria ticket de serviço com validade negativa, criptografa e confirma que a
    * abertura pelo serviço é recusada.
    *
    * Parâmetros
    * Nenhum parâmetro é recebido.
    *
    * Valor retornado
    * @return Não retorna valor.
    *
    * Assertiva de entrada
    * Ticket possui timestamp de expiração já ultrapassado.
    *
    * Assertiva de saída
    * abrir_ticket_servico lança ValueError.
    *
    * Exceções
    * O teste espera ValueError.
    *
    * Observações
    * Cobre a validade temporal no acesso ao serviço protegido.
    ---
    """
    ticket = criar_ticket_servico(
        usuario="ana",
        servico="notas",
        chave_sessao_cliente_servico_base64=bytes_para_base64(gerar_chave_simetrica()),
        validade_segundos=-1
    )
    ticket_criptografado = criptografar_json(CHAVE_SECRETA_SERVICO_NOTAS, ticket)

    with pytest.raises(ValueError, match="Ticket de servico expirado"):
        abrir_ticket_servico("notas", ticket_criptografado)
