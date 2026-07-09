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