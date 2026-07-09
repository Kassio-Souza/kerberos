"""
@file tgs_server.py
@brief Lógica do Ticket Granting Server do Kerberos Notas.

@details
Valida TGT e autenticador Cliente-TGS, identifica a chave do serviço e emite
ticket de serviço com chave de sessão Cliente-Serviço.

Componentes principais:
- validar_tgt
- validar_autenticador
- emitir_ticket_servico
- abrir_ticket_servico

Papel na arquitetura:
Representa o TGS, etapa intermediária entre autenticação inicial e acesso ao
serviço protegido.
"""

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
    """
    ***************************************************************************
    Função: obter_chave_servico

    @brief Retorna a chave secreta do serviço solicitado.

    Descrição:
    Consulta o mapa local de serviços conhecidos e obtém a chave usada para
    criptografar ou abrir tickets daquele serviço.

    Parâmetros:
    @param servico Nome lógico do serviço, como "notas".

    Valor retornado:
    @return Retorna bytes da chave secreta do serviço.

    Assertiva de entrada:
    @pre servico != None
    @pre servico deve estar cadastrado em CHAVES_SERVICOS.

    Assertiva de saída:
    @post Retorna a chave correspondente ou lança exceção para serviço desconhecido.

    Exceções:
    @throws ValueError quando o serviço não está registrado.

    Observações:
    No projeto há apenas o serviço de notas, protegido por chave compartilhada.
    ***************************************************************************
    """
    if servico not in CHAVES_SERVICOS:
        raise ValueError("Servico desconhecido.")

    return CHAVES_SERVICOS[servico]


def validar_tgt(usuario: str, tgt_criptografado: dict) -> dict:
    """
    ***************************************************************************
    Função: validar_tgt

    @brief Descriptografa e valida um TGT recebido pelo TGS.

    Descrição:
    Verifica presença do TGT, abre o ticket com a chave secreta do TGS, confirma
    usuário, chave Cliente-TGS e validade temporal.

    Parâmetros:
    @param usuario Usuário declarado na requisição ao TGS.
    @param tgt_criptografado TGT criptografado emitido pelo AS.

    Valor retornado:
    @return Retorna dict do TGT em claro após validação.

    Assertiva de entrada:
    @pre usuario != None
    @pre tgt_criptografado deve ter sido criptografado com CHAVE_SECRETA_TGS.

    Assertiva de saída:
    @post Retorna TGT válido ou lança ValueError com a causa da rejeição.

    Exceções:
    @throws ValueError para TGT ausente, inválido, de outro usuário, sem chave ou expirado.

    Observações:
    Esta validação impede que um cliente use TGT de outro usuário ou ticket expirado.
    ***************************************************************************
    """
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
    """
    ***************************************************************************
    Função: validar_autenticador

    @brief Valida o autenticador Cliente-TGS.

    Descrição:
    Abre o autenticador com a chave Cliente-TGS contida no TGT e verifica usuário,
    presença de timestamp, expiração e timestamp futuro fora da janela permitida.

    Parâmetros:
    @param usuario Usuário declarado na requisição ao TGS.
    @param tgt TGT já validado e em claro.
    @param autenticador_criptografado Autenticador enviado pelo cliente.

    Valor retornado:
    @return Retorna dict do autenticador em claro.

    Assertiva de entrada:
    @pre usuario deve ser o mesmo usuário do TGT.
    @pre tgt deve conter chave_sessao_cliente_tgs.
    @pre autenticador_criptografado deve estar cifrado com a chave Cliente-TGS.

    Assertiva de saída:
    @post Retorna autenticador válido ou lança ValueError.

    Exceções:
    @throws ValueError para autenticador ausente, inválido, expirado ou incompatível.

    Observações:
    O autenticador prova posse da chave de sessão Cliente-TGS sem expor a chave.
    ***************************************************************************
    """
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
    """
    ***************************************************************************
    Função: emitir_ticket_servico

    @brief Emite ticket de serviço e chave Cliente-Serviço.

    Descrição:
    Valida o TGT e o autenticador Cliente-TGS, gera uma nova chave de sessão para
    o serviço solicitado, cria o ticket de serviço e monta a resposta ao cliente.

    Parâmetros:
    @param usuario Usuário que solicita acesso ao serviço.
    @param servico Nome do serviço alvo.
    @param tgt_criptografado TGT emitido pelo AS.
    @param autenticador_criptografado Autenticador Cliente-TGS.

    Valor retornado:
    @return Retorna dict com servico, ticket_servico e resposta_cliente.

    Assertiva de entrada:
    @pre servico deve ser conhecido pelo TGS.
    @pre tgt_criptografado e autenticador_criptografado devem ser válidos.

    Assertiva de saída:
    @post Retorna ticket de serviço criptografado para o serviço e resposta criptografada
    @post para o cliente com a chave Cliente-TGS.

    Exceções:
    @throws Exception Propaga ValueError de obter_chave_servico, validar_tgt e validar_autenticador.

    Observações:
    Essa função representa a emissão de credencial de serviço no Kerberos.
    ***************************************************************************
    """
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
    """
    ***************************************************************************
    Função: abrir_ticket_servico

    @brief Abre e valida um ticket de serviço.

    Descrição:
    Obtém a chave secreta do serviço, descriptografa o ticket, confirma que ele
    foi emitido para o serviço correto e verifica sua expiração.

    Parâmetros:
    @param servico Nome do serviço que recebeu o ticket.
    @param ticket_servico_criptografado Ticket emitido pelo TGS.

    Valor retornado:
    @return Retorna dict do ticket de serviço em claro.

    Assertiva de entrada:
    @pre servico deve estar cadastrado em CHAVES_SERVICOS.
    @pre ticket_servico_criptografado deve ter sido cifrado com a chave do serviço.

    Assertiva de saída:
    @post Retorna ticket válido ou lança ValueError.

    Exceções:
    @throws ValueError para serviço desconhecido, ticket inválido, outro serviço ou expiração.

    Observações:
    Usada pelo serviço protegido antes de aceitar qualquer operação do cliente.
    ***************************************************************************
    """
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
