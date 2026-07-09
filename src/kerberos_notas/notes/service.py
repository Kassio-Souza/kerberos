"""
@file service.py
@brief Regras do Serviço de Notas protegido por Kerberos.

@details
Autentica tickets de serviço e autenticadores Cliente-Serviço, aplica controle
de acesso por tipo de usuário e executa operações de listagem e criação de notas.

Componentes principais:
- _autenticar_no_servico
- listar_notas
- criar_nota

Papel na arquitetura:
Representa o serviço protegido que só aceita operações após ticket válido,
autenticador recente e confirmação de autenticação mútua via AP-REP.
"""

from kerberos_notas.crypto.crypto_utils import base64_para_bytes, criptografar_json
from kerberos_notas.kerberos.authenticator import abrir_autenticador
from kerberos_notas.kerberos.tgs_server import abrir_ticket_servico
from kerberos_notas.kerberos.tickets import ticket_expirou, timestamp_atual
from kerberos_notas.notes.repository import (
    adicionar_nota_aluno,
    listar_notas_usuario,
    listar_todas_notas,
)
from kerberos_notas.usuarios import usuario_e_professor

NOME_SERVICO = "notas"
TEMPO_MAXIMO_AUTENTICADOR = 60 * 5
NONCES_USADOS = set()


def _autenticar_no_servico(
        usuario: str,
        ticket_servico_criptografado: dict,
        autenticador_criptografado: dict,
) -> dict:
    """
    ***************************************************************************
    Função: _autenticar_no_servico

    @brief Valida ticket de serviço e autenticador Cliente-Serviço.

    Descrição:
    Abre o ticket emitido pelo TGS, confirma o usuário, descriptografa o
    autenticador com a chave Cliente-Serviço, verifica timestamp e nonce contra
    replay e gera AP-REP para autenticação mútua.

    Parâmetros:
    @param usuario Usuário declarado na operação protegida.
    @param ticket_servico_criptografado Ticket de serviço recebido do cliente.
    @param autenticador_criptografado Autenticador Cliente-Serviço.

    Valor retornado:
    @return Retorna dict AP-REP criptografado com a chave Cliente-Serviço.

    Assertiva de entrada:
    @pre usuario != None
    @pre ticket_servico_criptografado deve ter sido emitido para o serviço notas.
    @pre autenticador_criptografado deve conter usuário, timestamp e nonce válidos.

    Assertiva de saída:
    @post Retorna AP-REP com timestamp_confirmado e nonce_confirmado quando a validação
    @post é bem-sucedida.

    Exceções:
    @throws ValueError para ticket de outro usuário, autenticador ausente,

    Observações:
    NONCES_USADOS guarda chaves de replay em memória durante a execução do serviço.
    ***************************************************************************
    """
    ticket_servico = abrir_ticket_servico(NOME_SERVICO, ticket_servico_criptografado)

    if ticket_servico.get("usuario") != usuario:
        raise ValueError("Ticket pertence a outro usuário.")

    chave_sessao_base64 = ticket_servico["chave_sessao_cliente_servico"]

    if not autenticador_criptografado:
        raise ValueError("Autenticador não informado.")

    try:
        autenticador = abrir_autenticador(chave_sessao_base64, autenticador_criptografado)
    except Exception as erro:
        raise ValueError(
            "Autenticador inválido ou não pode ser descriptografado."
        ) from erro

    if autenticador.get("usuario") != usuario:
        raise ValueError("Usuário do autenticador diferente do usuário do ticket.")

    timestamp = autenticador.get("timestamp")
    if timestamp is None:
        raise ValueError("Autenticador sem timestamp.")

    if ticket_expirou(timestamp, TEMPO_MAXIMO_AUTENTICADOR):
        raise ValueError("Autenticador expirado.")

    if timestamp > timestamp_atual() + TEMPO_MAXIMO_AUTENTICADOR:
        raise ValueError("Autenticador com timestamp inválido.")

    nonce = autenticador.get("nonce")

    if not nonce:
        raise ValueError("Autenticador sem nonce.")

    chave_replay = f"{usuario}:{timestamp}:{nonce}"

    if chave_replay in NONCES_USADOS:
        raise ValueError("Autenticador rejeitado: possível tentativa de replay.")

    NONCES_USADOS.add(chave_replay)

    chave_sessao_bytes = base64_para_bytes(chave_sessao_base64)

    ap_rep = criptografar_json(
        chave_sessao_bytes,
        {
            "timestamp_confirmado": timestamp + 1,
            "nonce_confirmado": nonce,
        }
    )

    return ap_rep


def listar_notas(
        usuario: str,
        ticket_servico_criptografado: dict,
        autenticador_criptografado: dict,
) -> dict:
    """
    ***************************************************************************
    Função: listar_notas

    @brief Lista notas após autenticação Kerberos no serviço.

    Descrição:
    Autentica a requisição, decide se o usuário é professor ou aluno e consulta
    todas as notas ou apenas as notas do próprio usuário.

    Parâmetros:
    @param usuario Usuário autenticado que solicita a listagem.
    @param ticket_servico_criptografado Ticket de serviço emitido pelo TGS.
    @param autenticador_criptografado Autenticador Cliente-Serviço.

    Valor retornado:
    @return Retorna dict com lista de notas e AP-REP.

    Assertiva de entrada:
    @pre Credenciais Kerberos devem ser válidas para o serviço notas.

    Assertiva de saída:
    @post Professor recebe todas as notas; aluno recebe somente suas notas.

    Exceções:
    @throws Exception Propaga ValueError de _autenticar_no_servico e erros do repositório.

    Observações:
    Combina autenticação Kerberos com autorização simples baseada no tipo de usuário.
    ***************************************************************************
    """
    ap_rep = _autenticar_no_servico(
        usuario,
        ticket_servico_criptografado,
        autenticador_criptografado
    )

    if usuario_e_professor(usuario):
        notas = listar_todas_notas()
    else:
        notas = listar_notas_usuario(usuario)

    return {
        "notas": notas,
        "ap_rep": ap_rep
    }


def criar_nota(
        usuario: str,
        aluno: str,
        disciplina: str,
        valor: str,
        ticket_servico_criptografado: dict,
        autenticador_criptografado: dict,
) -> dict:
    """
    ***************************************************************************
    Função: criar_nota

    @brief Cria uma nota escolar após autenticação e autorização.

    Descrição:
    Valida credenciais Kerberos, exige que o usuário seja professor, normaliza os
    campos de entrada e grava a nota para o aluno informado.

    Parâmetros:
    @param usuario Usuário autenticado que tenta criar a nota.
    @param aluno Nome do aluno que receberá a nota.
    @param disciplina Nome da disciplina.
    @param valor Valor textual da nota.
    @param ticket_servico_criptografado Ticket emitido pelo TGS.
    @param autenticador_criptografado Autenticador Cliente-Serviço.

    Valor retornado:
    @return Retorna dict com a nota criada e AP-REP.

    Assertiva de entrada:
    @pre usuario deve ser professor.
    @pre aluno, disciplina e valor devem conter texto após strip.
    @pre Credenciais Kerberos devem ser válidas.

    Assertiva de saída:
    @post Persiste a nota e retorna os dados cadastrados.

    Exceções:
    @throws ValueError se usuário não for professor ou campos obrigatórios faltarem.

    Observações:
    A função separa autenticação Kerberos de autorização acadêmica por papel.
    ***************************************************************************
    """
    ap_rep = _autenticar_no_servico(
        usuario,
        ticket_servico_criptografado,
        autenticador_criptografado
    )

    if not usuario_e_professor(usuario):
        raise ValueError("Apenas professores podem cadastrar ou alterar notas.")
    aluno = aluno.strip()
    disciplina = disciplina.strip()
    valor = valor.strip()

    if not aluno or not disciplina or not valor:
        raise ValueError("Aluno, disciplina e nota são obrigatórios.")

    nova_nota = adicionar_nota_aluno(
        aluno=aluno,
        disciplina=disciplina,
        valor=valor,
        professor=usuario,
    )

    return {
        "nota": nova_nota,
        "ap_rep": ap_rep
    }
