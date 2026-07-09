import base64

import pytest

from kerberos_notas.crypto.crypto_utils import (
    TAMANHO_CHAVE_AES,
    TAMANHO_NONCE,
    base64_para_bytes,
    bytes_para_base64,
    criptografar_json,
    descriptografar_json,
    gerar_chave_simetrica,
)
from kerberos_notas.crypto.kdf import (
    TAMANHO_CHAVE,
    derivar_chave_senha,
    gerar_salt,
    gerar_verificador_chave,
    verificar_senha,
)


def test_kdf_e_deterministica_com_mesma_senha_e_mesmo_salt():
    salt = gerar_salt()

    chave_1 = derivar_chave_senha("senha-academica", salt)
    chave_2 = derivar_chave_senha("senha-academica", salt)

    assert chave_1 == chave_2
    assert isinstance(chave_1, bytes)
    assert len(chave_1) == TAMANHO_CHAVE


def test_kdf_depende_da_senha():
    salt = gerar_salt()

    chave_correta = derivar_chave_senha("senha-correta", salt)
    chave_errada = derivar_chave_senha("senha-errada", salt)

    assert chave_correta != chave_errada


def test_kdf_depende_do_salt():
    senha = "mesma-senha"

    chave_1 = derivar_chave_senha(senha, gerar_salt())
    chave_2 = derivar_chave_senha(senha, gerar_salt())

    assert chave_1 != chave_2


def test_verificador_confirma_senha_correta_e_rejeita_senha_errada():
    salt = gerar_salt()
    chave = derivar_chave_senha("123", salt)
    verificador = gerar_verificador_chave(chave)

    assert verificar_senha("123", salt, verificador) is True
    assert verificar_senha("senha-incorreta", salt, verificador) is False


def test_base64_preserva_bytes_originais():
    dados = b"kerberos-notas-seguranca-computacional"

    dados_base64 = bytes_para_base64(dados)

    assert isinstance(dados_base64, str)
    assert base64_para_bytes(dados_base64) == dados


def test_gerar_chave_simetrica_tem_tamanho_esperado_e_usa_aleatoriedade():
    chave_1 = gerar_chave_simetrica()
    chave_2 = gerar_chave_simetrica()

    assert isinstance(chave_1, bytes)
    assert isinstance(chave_2, bytes)
    assert len(chave_1) == TAMANHO_CHAVE_AES
    assert len(chave_2) == TAMANHO_CHAVE_AES
    assert chave_1 != chave_2


def test_criptografia_recupera_mensagem_com_chave_correta():
    chave = gerar_chave_simetrica()
    mensagem = {
        "usuario": "prof",
        "servico": "notas",
        "papel": "professor",
        "conteudo": "mensagem protegida",
    }

    pacote = criptografar_json(chave, mensagem)
    mensagem_aberta = descriptografar_json(chave, pacote)

    assert mensagem_aberta == mensagem


def test_pacote_criptografado_tem_formato_esperado_e_nao_expoe_texto_claro():
    chave = gerar_chave_simetrica()
    mensagem = {"segredo": "nota 10", "usuario": "aluno1"}

    pacote = criptografar_json(chave, mensagem)

    assert set(pacote) == {"nonce", "ciphertext"}
    assert isinstance(pacote["nonce"], str)
    assert isinstance(pacote["ciphertext"], str)
    assert len(base64.b64decode(pacote["nonce"])) == TAMANHO_NONCE
    assert "nota 10" not in str(pacote)
    assert "aluno1" not in str(pacote)


def test_descriptografia_falha_com_chave_errada():
    chave_correta = gerar_chave_simetrica()
    chave_errada = gerar_chave_simetrica()
    pacote = criptografar_json(chave_correta, {"ticket": "conteudo secreto"})

    with pytest.raises(Exception):
        descriptografar_json(chave_errada, pacote)


def test_descriptografia_rejeita_ciphertext_adulterado():
    chave = gerar_chave_simetrica()
    pacote = criptografar_json(chave, {"ticket": "conteudo secreto"})
    ciphertext = bytearray(base64.b64decode(pacote["ciphertext"]))
    ciphertext[-1] ^= 1

    pacote_adulterado = {
        "nonce": pacote["nonce"],
        "ciphertext": bytes_para_base64(bytes(ciphertext)),
    }

    with pytest.raises(Exception):
        descriptografar_json(chave, pacote_adulterado)


def test_descriptografia_rejeita_nonce_adulterado():
    chave = gerar_chave_simetrica()
    pacote = criptografar_json(chave, {"ticket": "conteudo secreto"})
    nonce = bytearray(base64.b64decode(pacote["nonce"]))
    nonce[0] ^= 1

    pacote_adulterado = {
        "nonce": bytes_para_base64(bytes(nonce)),
        "ciphertext": pacote["ciphertext"],
    }

    with pytest.raises(Exception):
        descriptografar_json(chave, pacote_adulterado)
