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