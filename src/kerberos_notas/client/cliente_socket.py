"""
@file cliente_socket.py
@brief Cliente de rede para comunicação com AS, TGS e Serviço de Notas.

@details
Monta requisições JSON, envia via socket para os servidores Kerberos Notas e
transforma respostas de erro em exceções Python.

Componentes principais:
- chamar_as_autenticacao
- chamar_tgs_emitir_ticket
- chamar_servico_notas_listar
- chamar_servico_notas_criar

Papel na arquitetura:
Faz a ponte entre a aplicação web cliente e os processos TCP que simulam AS,
TGS e serviço protegido.
"""

from kerberos_notas.config import (
    HOST_AS,
    HOST_TGS,
    HOST_SERVICO_NOTAS,
    PORTA_AS,
    PORTA_TGS,
    PORTA_SERVICO_NOTAS,
)
from kerberos_notas.rede.protocolo import chamar_servidor
from kerberos_notas.rede.logs import log_passo, log_ok, log_erro, log_dados


def chamar_as_autenticacao(usuario: str, senha: str) -> dict:
    """
    ***************************************************************************
    Função: chamar_as_autenticacao

    @brief Solicita autenticação ao AS por socket.

    Descrição:
    Envia usuário e senha ao Servidor de Autenticação com ação "autenticar" e
    retorna os dados criptografados recebidos em caso de sucesso.

    Parâmetros:
    @param usuario Nome de usuário informado no login.
    @param senha Senha textual usada pelo AS para validação.

    Valor retornado:
    @return Retorna dict com dados emitidos pelo AS.

    Assertiva de entrada:
    @pre usuario != None
    @pre senha != None
    @pre O AS deve estar acessível em HOST_AS:PORTA_AS.

    Assertiva de saída:
    @post Retorna resposta do AS ou lança ValueError se a resposta indicar erro.

    Exceções:
    @throws ValueError quando o AS retorna ok falso.

    Observações:
    Esta chamada inicia o fluxo Kerberos completo do cliente web.
    ***************************************************************************
    """
    log_passo(
        "CLIENTE WEB",
        1,
        "Chamando o AS via socket",
        f"Usuário tentando autenticação: {usuario}"
    )

    requisicao = {
        "acao": "autenticar",
        "usuario": usuario,
        "senha": senha,
    }

    log_dados("CLIENTE WEB", "Requisição enviada ao AS", requisicao)

    resposta = chamar_servidor(
        HOST_AS,
        PORTA_AS,
        requisicao
    )

    log_dados("CLIENTE WEB", "Resposta recebida do AS", resposta)

    if not resposta.get("ok"):
        log_erro("CLIENTE WEB", resposta.get("erro", "Erro ao autenticar no AS."))
        raise ValueError(resposta.get("erro", "Erro ao autenticar no AS."))

    log_ok("CLIENTE WEB", "AS respondeu com sucesso.")

    return resposta["dados"]


def chamar_tgs_emitir_ticket(
        usuario: str,
        tgt: dict,
        servico: str,
        autenticador: dict,
) -> dict:
    """
    ***************************************************************************
    Função: chamar_tgs_emitir_ticket

    @brief Solicita ao TGS a emissão de ticket de serviço.

    Descrição:
    Envia usuário, TGT, nome do serviço e autenticador Cliente-TGS ao TGS e
    retorna o ticket de serviço e a resposta criptografada para o cliente.

    Parâmetros:
    @param usuario Usuário autenticado.
    @param tgt TGT criptografado recebido do AS.
    @param servico Nome do serviço desejado.
    @param autenticador Autenticador Cliente-TGS.

    Valor retornado:
    @return Retorna dict com resposta do TGS.

    Assertiva de entrada:
    @pre O TGS deve estar ativo e os dados Kerberos devem ser válidos.

    Assertiva de saída:
    @post Retorna ticket de serviço ou lança ValueError se o TGS rejeitar a solicitação.

    Exceções:
    @throws ValueError quando o TGS retorna ok falso.

    Observações:
    A função não abre o TGT; apenas transporta credenciais entre cliente e TGS.
    ***************************************************************************
    """
    log_passo(
        "CLIENTE WEB",
        2,
        "Chamando o TGS via socket",
        f"Solicitando ticket para o serviço: {servico}"
    )

    requisicao = {
        "acao": "emitir_ticket",
        "usuario": usuario,
        "tgt": tgt,
        "servico": servico,
        "autenticador": autenticador,
    }

    log_dados("CLIENTE WEB", "Requisição enviada ao TGS", requisicao)

    resposta = chamar_servidor(
        HOST_TGS,
        PORTA_TGS,
        requisicao
    )

    log_dados("CLIENTE WEB", "Resposta recebida do TGS", resposta)

    if not resposta.get("ok"):
        log_erro("CLIENTE WEB", resposta.get("erro", "Erro ao obter ticket no TGS."))
        raise ValueError(resposta.get("erro", "Erro ao obter ticket no TGS."))

    log_ok("CLIENTE WEB", "TGS emitiu o ticket de serviço com sucesso.")

    return resposta["dados"]


def chamar_servico_notas_listar(
        usuario: str,
        ticket_servico: dict,
        autenticador: dict,
) -> dict:
    """
    ***************************************************************************
    Função: chamar_servico_notas_listar

    @brief Solicita listagem de notas ao serviço protegido.

    Descrição:
    Envia ação "listar_notas" com usuário, ticket de serviço e autenticador
    Cliente-Serviço para o Serviço de Notas.

    Parâmetros:
    @param usuario Usuário que solicita a listagem.
    @param ticket_servico Ticket de serviço emitido pelo TGS.
    @param autenticador Autenticador Cliente-Serviço.

    Valor retornado:
    @return Retorna dict com notas e AP-REP.

    Assertiva de entrada:
    @pre O serviço de notas deve estar acessível e as credenciais devem ser válidas.

    Assertiva de saída:
    @post Retorna dados do serviço ou lança ValueError se a operação for rejeitada.

    Exceções:
    @throws ValueError quando o serviço retorna ok falso.

    Observações:
    O AP-REP retornado ainda precisa ser validado pelo cliente.
    ***************************************************************************
    """
    log_passo(
        "CLIENTE WEB",
        3,
        "Chamando o Serviço de Notas via socket",
        "Operação solicitada: listar notas."
    )

    requisicao = {
        "acao": "listar_notas",
        "usuario": usuario,
        "ticket_servico": ticket_servico,
        "autenticador": autenticador,
    }

    log_dados("CLIENTE WEB", "Requisição enviada ao Serviço de Notas", requisicao)

    resposta = chamar_servidor(
        HOST_SERVICO_NOTAS,
        PORTA_SERVICO_NOTAS,
        requisicao
    )

    log_dados("CLIENTE WEB", "Resposta recebida do Serviço de Notas", resposta)

    if not resposta.get("ok"):
        log_erro("CLIENTE WEB", resposta.get("erro", "Erro ao listar notas."))
        raise ValueError(resposta.get("erro", "Erro ao listar notas."))

    log_ok("CLIENTE WEB", "Serviço de Notas respondeu com sucesso.")

    return resposta["dados"]


def chamar_servico_notas_criar(
        usuario: str,
        aluno: str,
        disciplina: str,
        valor: str,
        ticket_servico: dict,
        autenticador: dict,
) -> dict:
    """
    ***************************************************************************
    Função: chamar_servico_notas_criar

    @brief Solicita criação de nota ao serviço protegido.

    Descrição:
    Envia ação "criar_nota" com dados acadêmicos, ticket de serviço e
    autenticador Cliente-Serviço.

    Parâmetros:
    @param usuario Professor autenticado que cria a nota.
    @param aluno Aluno que receberá a nota.
    @param disciplina Disciplina da nota.
    @param valor Valor textual da nota.
    @param ticket_servico Ticket de serviço emitido pelo TGS.
    @param autenticador Autenticador Cliente-Serviço.

    Valor retornado:
    @return Retorna dict com nota criada e AP-REP.

    Assertiva de entrada:
    @pre Credenciais Kerberos devem ser válidas e o serviço deve estar ativo.

    Assertiva de saída:
    @post Retorna resposta do serviço ou lança ValueError em rejeição.

    Exceções:
    @throws ValueError quando o serviço retorna ok falso.

    Observações:
    A autorização de professor é aplicada no serviço de notas, não nesta função.
    ***************************************************************************
    """
    log_passo(
        "CLIENTE WEB",
        3,
        "Chamando o Serviço de Notas via socket",
        f"Operação solicitada: criar nota para o aluno {aluno}."
    )

    requisicao = {
        "acao": "criar_nota",
        "usuario": usuario,
        "aluno": aluno,
        "disciplina": disciplina,
        "valor": valor,
        "ticket_servico": ticket_servico,
        "autenticador": autenticador,
    }

    log_dados("CLIENTE WEB", "Requisição enviada ao Serviço de Notas", requisicao)

    resposta = chamar_servidor(
        HOST_SERVICO_NOTAS,
        PORTA_SERVICO_NOTAS,
        requisicao
    )

    log_dados("CLIENTE WEB", "Resposta recebida do Serviço de Notas", resposta)

    if not resposta.get("ok"):
        log_erro("CLIENTE WEB", resposta.get("erro", "Erro ao criar nota."))
        raise ValueError(resposta.get("erro", "Erro ao criar nota."))

    log_ok("CLIENTE WEB", "Serviço de Notas criou a nota com sucesso.")

    return resposta["dados"]
