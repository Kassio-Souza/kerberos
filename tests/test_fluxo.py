import json

import pytest

from kerberos_notas.config import CHAVE_SECRETA_TGS
from kerberos_notas.crypto.crypto_utils import (
    base64_para_bytes,
    bytes_para_base64,
    criptografar_json,
    descriptografar_json,
    gerar_chave_simetrica,
)
from kerberos_notas.crypto.kdf import derivar_chave_senha, gerar_salt, gerar_verificador_chave
from kerberos_notas.kerberos import as_server
from kerberos_notas.kerberos.authenticator import criar_autenticador
from kerberos_notas.kerberos.tgs_server import emitir_ticket_servico
from kerberos_notas.kerberos.tickets import criar_tgt, timestamp_atual
from kerberos_notas.notes import repository, service


def _usuario_para_json(senha: str, tipo: str) -> dict:
    salt = gerar_salt()
    chave = derivar_chave_senha(senha, salt)

    return {
        "salt": salt,
        "verificador": gerar_verificador_chave(chave),
        "tipo": tipo,
    }


@pytest.fixture()
def ambiente_kerberos(tmp_path, monkeypatch):
    usuarios_path = tmp_path / "usuarios.json"
    notas_path = tmp_path / "notas.json"

    usuarios_path.write_text(
        json.dumps(
            {
                "usuarios": {
                    "prof": _usuario_para_json("123", "professor"),
                    "aluno1": _usuario_para_json("123", "aluno"),
                    "aluno2": _usuario_para_json("123", "aluno"),
                }
            }
        ),
        encoding="utf-8",
    )
    notas_path.write_text(
        json.dumps(
            {
                "aluno1": [
                    {
                        "disciplina": "Segurança Computacional",
                        "valor": "9.0",
                        "professor": "prof",
                    }
                ],
                "aluno2": [
                    {
                        "disciplina": "Redes",
                        "valor": "8.0",
                        "professor": "prof",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(as_server, "CAMINHO_USUARIOS", usuarios_path)
    monkeypatch.setattr(repository, "CAMINHO_NOTAS", notas_path)
    monkeypatch.setattr(service, "usuario_e_professor", lambda usuario: usuario == "prof")
    service.NONCES_USADOS.clear()

    yield {
        "usuarios_path": usuarios_path,
        "notas_path": notas_path,
    }

    service.NONCES_USADOS.clear()


def _credenciais_servico(usuario: str, senha: str):
    resposta_as_criptografada = as_server.autenticar_no_as(usuario, senha)
    dados_usuario = as_server.carregar_usuarios()["usuarios"][usuario]
    chave_cliente = derivar_chave_senha(senha, dados_usuario["salt"])
    resposta_as = descriptografar_json(chave_cliente, resposta_as_criptografada)

    chave_cliente_tgs = resposta_as["chave_sessao_cliente_tgs"]
    autenticador_tgs = criar_autenticador(usuario, chave_cliente_tgs)

    resposta_tgs = emitir_ticket_servico(
        usuario=usuario,
        servico="notas",
        tgt_criptografado=resposta_as["tgt"],
        autenticador_criptografado=autenticador_tgs,
    )
    dados_cliente = descriptografar_json(
        base64_para_bytes(chave_cliente_tgs),
        resposta_tgs["resposta_cliente"],
    )

    return {
        "resposta_as": resposta_as,
        "resposta_tgs": resposta_tgs,
        "chave_cliente_tgs": chave_cliente_tgs,
        "ticket_servico": resposta_tgs["ticket_servico"],
        "chave_servico": dados_cliente["chave_sessao_cliente_servico"],
    }


def test_fluxo_completo_professor_cria_nota_e_valida_autenticacao_mutua(ambiente_kerberos):
    credenciais = _credenciais_servico("prof", "123")
    timestamp = timestamp_atual()
    nonce = "nonce-fluxo-professor"
    autenticador_servico = criar_autenticador(
        "prof",
        credenciais["chave_servico"],
        nonce=nonce,
        timestamp=timestamp,
    )

    resultado = service.criar_nota(
        usuario="prof",
        aluno="aluno1",
        disciplina="Criptografia",
        valor="10",
        ticket_servico_criptografado=credenciais["ticket_servico"],
        autenticador_criptografado=autenticador_servico,
    )
    ap_rep = descriptografar_json(
        base64_para_bytes(credenciais["chave_servico"]),
        resultado["ap_rep"],
    )
    dados_notas = json.loads(ambiente_kerberos["notas_path"].read_text(encoding="utf-8"))

    assert credenciais["resposta_as"]["id_tgs"] == "tgs"
    assert "tgt" in credenciais["resposta_as"]
    assert credenciais["resposta_tgs"]["servico"] == "notas"
    assert "ticket_servico" in credenciais["resposta_tgs"]
    assert resultado["nota"]["aluno"] == "aluno1"
    assert resultado["nota"]["disciplina"] == "Criptografia"
    assert resultado["nota"]["valor"] == "10"
    assert dados_notas["aluno1"][-1]["professor"] == "prof"
    assert ap_rep == {
        "timestamp_confirmado": timestamp + 1,
        "nonce_confirmado": nonce,
    }


def test_fluxo_aluno_autenticado_lista_apenas_suas_notas(ambiente_kerberos):
    credenciais = _credenciais_servico("aluno1", "123")
    autenticador_servico = criar_autenticador(
        "aluno1",
        credenciais["chave_servico"],
        nonce="nonce-listagem-aluno",
        timestamp=timestamp_atual(),
    )

    resultado = service.listar_notas(
        usuario="aluno1",
        ticket_servico_criptografado=credenciais["ticket_servico"],
        autenticador_criptografado=autenticador_servico,
    )

    assert len(resultado["notas"]) == 1
    assert resultado["notas"][0]["disciplina"] == "Segurança Computacional"
    assert all(nota.get("aluno", "aluno1") == "aluno1" for nota in resultado["notas"])
    assert "ap_rep" in resultado


def test_as_rejeita_senha_incorreta(ambiente_kerberos):
    with pytest.raises(ValueError, match="Senha inválida"):
        as_server.autenticar_no_as("prof", "senha-errada")


def test_tgs_rejeita_tgt_adulterado(ambiente_kerberos):
    resposta_as_criptografada = as_server.autenticar_no_as("prof", "123")
    dados_usuario = as_server.carregar_usuarios()["usuarios"]["prof"]
    chave_cliente = derivar_chave_senha("123", dados_usuario["salt"])
    resposta_as = descriptografar_json(chave_cliente, resposta_as_criptografada)
    autenticador_tgs = criar_autenticador("prof", resposta_as["chave_sessao_cliente_tgs"])

    tgt_adulterado = dict(resposta_as["tgt"])
    tgt_adulterado["ciphertext"] = tgt_adulterado["ciphertext"][:-4] + "AAAA"

    with pytest.raises(ValueError, match="TGT invalido"):
        emitir_ticket_servico("prof", "notas", tgt_adulterado, autenticador_tgs)


def test_servico_rejeita_replay_do_mesmo_autenticador(ambiente_kerberos):
    credenciais = _credenciais_servico("prof", "123")
    autenticador_servico = criar_autenticador(
        "prof",
        credenciais["chave_servico"],
        nonce="nonce-replay",
        timestamp=timestamp_atual(),
    )

    service.listar_notas(
        usuario="prof",
        ticket_servico_criptografado=credenciais["ticket_servico"],
        autenticador_criptografado=autenticador_servico,
    )

    with pytest.raises(ValueError, match="replay"):
        service.listar_notas(
            usuario="prof",
            ticket_servico_criptografado=credenciais["ticket_servico"],
            autenticador_criptografado=autenticador_servico,
        )


def test_servico_rejeita_ticket_de_servico_de_outro_usuario(ambiente_kerberos):
    credenciais = _credenciais_servico("aluno1", "123")
    autenticador_prof = criar_autenticador(
        "prof",
        credenciais["chave_servico"],
        nonce="nonce-usuario-errado",
        timestamp=timestamp_atual(),
    )

    with pytest.raises(ValueError, match="Ticket pertence a outro usuário"):
        service.listar_notas(
            usuario="prof",
            ticket_servico_criptografado=credenciais["ticket_servico"],
            autenticador_criptografado=autenticador_prof,
        )


def test_tgs_emite_ticket_com_tgt_valido_montado_diretamente(ambiente_kerberos):
    chave_cliente_tgs = gerar_chave_simetrica()
    chave_cliente_tgs_base64 = bytes_para_base64(chave_cliente_tgs)
    tgt = criar_tgt(
        id_cliente="prof",
        chave_sessao_cliente_tgs_base64=chave_cliente_tgs_base64,
    )
    tgt_criptografado = criptografar_json(CHAVE_SECRETA_TGS, tgt)
    autenticador_tgs = criar_autenticador("prof", chave_cliente_tgs_base64)

    resposta = emitir_ticket_servico("prof", "notas", tgt_criptografado, autenticador_tgs)
    dados_cliente = descriptografar_json(
        chave_cliente_tgs,
        resposta["resposta_cliente"],
    )

    assert resposta["servico"] == "notas"
    assert dados_cliente["usuario"] == "prof"
    assert dados_cliente["servico"] == "notas"
    assert dados_cliente["chave_sessao_cliente_servico"]
