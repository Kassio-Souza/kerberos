import json

import pytest

from kerberos_notas.config import CHAVE_SECRETA_SERVICO_NOTAS
from kerberos_notas.crypto.crypto_utils import (
    bytes_para_base64,
    criptografar_json,
    descriptografar_json,
    gerar_chave_simetrica,
    base64_para_bytes,
)
from kerberos_notas.kerberos.authenticator import criar_autenticador
from kerberos_notas.kerberos.tickets import criar_ticket_servico, timestamp_atual
from kerberos_notas.notes import repository
from kerberos_notas.notes import service


def gerar_ticket_e_autenticador(usuario: str):
    chave_sessao = gerar_chave_simetrica()
    chave_sessao_base64 = bytes_para_base64(chave_sessao)

    ticket_aberto = criar_ticket_servico(
        usuario=usuario,
        servico="notas",
        chave_sessao_cliente_servico_base64=chave_sessao_base64
    )

    ticket_criptografado = criptografar_json(
        CHAVE_SECRETA_SERVICO_NOTAS,
        ticket_aberto
    )

    timestamp = timestamp_atual()
    nonce = f"nonce-{usuario}-{timestamp}"

    autenticador = criar_autenticador(
        usuario,
        chave_sessao_base64,
        timestamp=timestamp,
        nonce=nonce
    )

    return ticket_criptografado, autenticador, chave_sessao_base64, timestamp, nonce


def preparar_ambiente(tmp_path, monkeypatch):
    caminho = tmp_path / "notas.json"
    caminho.write_text("{}", encoding="utf-8")

    monkeypatch.setattr(repository, "CAMINHO_NOTAS", caminho)
    monkeypatch.setattr(service, "usuario_e_professor", lambda usuario: usuario == "prof1")

    service.NONCES_USADOS.clear()

    return caminho


def test_professor_cria_nota_para_aluno(tmp_path, monkeypatch):
    caminho = preparar_ambiente(tmp_path, monkeypatch)

    ticket, autenticador, chave_sessao, timestamp, nonce = gerar_ticket_e_autenticador("prof1")

    resultado = service.criar_nota(
        usuario="prof1",
        aluno="aluno1",
        disciplina="Segurança Computacional",
        valor="9.5",
        ticket_servico_criptografado=ticket,
        autenticador_criptografado=autenticador
    )

    assert resultado["nota"]["aluno"] == "aluno1"
    assert resultado["nota"]["disciplina"] == "Segurança Computacional"
    assert resultado["nota"]["valor"] == "9.5"

    dados = json.loads(caminho.read_text(encoding="utf-8"))

    assert "aluno1" in dados
    assert "prof1" not in dados

    ap_rep_aberto = descriptografar_json(
        base64_para_bytes(chave_sessao),
        resultado["ap_rep"]
    )

    assert ap_rep_aberto["timestamp_confirmado"] == timestamp + 1
    assert ap_rep_aberto["nonce_confirmado"] == nonce


def test_aluno_nao_consegue_criar_nota(tmp_path, monkeypatch):
    preparar_ambiente(tmp_path, monkeypatch)

    ticket, autenticador, _, _, _ = gerar_ticket_e_autenticador("aluno1")

    with pytest.raises(ValueError, match="Apenas professores"):
        service.criar_nota(
            usuario="aluno1",
            aluno="aluno1",
            disciplina="Segurança Computacional",
            valor="10",
            ticket_servico_criptografado=ticket,
            autenticador_criptografado=autenticador
        )


def test_aluno_lista_apenas_suas_notas(tmp_path, monkeypatch):
    caminho = preparar_ambiente(tmp_path, monkeypatch)

    caminho.write_text(
        json.dumps({
            "aluno1": [
                {
                    "aluno": "aluno1",
                    "disciplina": "Segurança Computacional",
                    "valor": "9.5",
                    "professor": "prof1"
                }
            ],
            "aluno2": [
                {
                    "aluno": "aluno2",
                    "disciplina": "Álgebra Linear",
                    "valor": "8.0",
                    "professor": "prof1"
                }
            ]
        }),
        encoding="utf-8"
    )

    ticket, autenticador, _, _, _ = gerar_ticket_e_autenticador("aluno1")

    resultado = service.listar_notas(
        usuario="aluno1",
        ticket_servico_criptografado=ticket,
        autenticador_criptografado=autenticador
    )

    assert len(resultado["notas"]) == 1
    assert resultado["notas"][0]["aluno"] == "aluno1"


def test_professor_lista_todas_as_notas(tmp_path, monkeypatch):
    caminho = preparar_ambiente(tmp_path, monkeypatch)

    caminho.write_text(
        json.dumps({
            "aluno1": [
                {
                    "disciplina": "Segurança Computacional",
                    "valor": "9.5",
                    "professor": "prof1"
                }
            ],
            "aluno2": [
                {
                    "disciplina": "Álgebra Linear",
                    "valor": "8.0",
                    "professor": "prof1"
                }
            ]
        }),
        encoding="utf-8"
    )

    ticket, autenticador, _, _, _ = gerar_ticket_e_autenticador("prof1")

    resultado = service.listar_notas(
        usuario="prof1",
        ticket_servico_criptografado=ticket,
        autenticador_criptografado=autenticador
    )

    assert len(resultado["notas"]) == 2
    alunos = {nota["aluno"] for nota in resultado["notas"]}
    assert alunos == {"aluno1", "aluno2"}


def test_servico_rejeita_replay_do_mesmo_autenticador(tmp_path, monkeypatch):
    preparar_ambiente(tmp_path, monkeypatch)

    ticket, autenticador, _, _, _ = gerar_ticket_e_autenticador("prof1")

    service.listar_notas(
        usuario="prof1",
        ticket_servico_criptografado=ticket,
        autenticador_criptografado=autenticador
    )

    with pytest.raises(ValueError, match="replay"):
        service.listar_notas(
            usuario="prof1",
            ticket_servico_criptografado=ticket,
            autenticador_criptografado=autenticador
        )