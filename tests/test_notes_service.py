"""
---
* Arquivo: test_notes_service.py
* @file test_notes_service.py
* @brief Testes do Serviço de Notas protegido por Kerberos.
*
* Descrição
* Verifica criação e listagem de notas com ticket de serviço, autenticador,
* autorização por papel e proteção contra replay.
*
* Componentes principais
* * gerar_ticket_e_autenticador
* * preparar_ambiente
* * test_professor_cria_nota_para_aluno
* * test_servico_rejeita_replay_do_mesmo_autenticador
*
* Papel na arquitetura
* Valida a etapa final do Kerberos Notas, incluindo AP-REQ e AP-REP.
---
"""

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
    """
    ---
    * Função: gerar_ticket_e_autenticador
    * @brief Cria ticket de serviço e autenticador para testes.
    *
    * Descrição
    * Gera chave Cliente-Serviço, cria ticket para o serviço notas, criptografa com
    * a chave do serviço e monta autenticador com timestamp e nonce previsíveis.
    *
    * Parâmetros
    * @param usuario Usuário que constará no ticket e no autenticador.
    *
    * Valor retornado
    * @return Retorna ticket, autenticador, chave Base64, timestamp e nonce.
    *
    * Assertiva de entrada
    * usuario deve ser string usada nos testes.
    *
    * Assertiva de saída
    * Retorna credenciais válidas para o serviço notas.
    *
    * Exceções
    * Pode propagar erros de criptografia ou geração de chave.
    *
    * Observações
    * Helper de teste para simular ticket emitido pelo TGS.
    ---
    """
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
    """
    ---
    * Função: preparar_ambiente
    * @brief Prepara armazenamento e autorização isolados para teste.
    *
    * Descrição
    * Cria arquivo temporário de notas, redireciona CAMINHO_NOTAS, substitui a
    * função de professor e limpa nonces usados.
    *
    * Parâmetros
    * @param tmp_path Fixture pytest para diretório temporário.
    * @param monkeypatch Fixture pytest para substituir atributos.
    *
    * Valor retornado
    * @return Retorna Path do arquivo temporário de notas.
    *
    * Assertiva de entrada
    * Fixtures pytest devem estar disponíveis.
    *
    * Assertiva de saída
    * Ambiente fica isolado e NONCES_USADOS vazio.
    *
    * Exceções
    * Pode propagar erros de escrita em tmp_path.
    *
    * Observações
    * Evita interferência com dados reais do projeto.
    ---
    """
    caminho = tmp_path / "notas.json"
    caminho.write_text("{}", encoding="utf-8")

    monkeypatch.setattr(repository, "CAMINHO_NOTAS", caminho)
    monkeypatch.setattr(service, "usuario_e_professor", lambda usuario: usuario == "prof1")

    service.NONCES_USADOS.clear()

    return caminho


def test_professor_cria_nota_para_aluno(tmp_path, monkeypatch):
    """
    ---
    * Função: test_professor_cria_nota_para_aluno
    * @brief Verifica criação de nota por professor autenticado.
    *
    * Descrição
    * Gera credenciais para prof1, chama criar_nota, confirma persistência da nota
    * no aluno correto e valida o AP-REP retornado.
    *
    * Parâmetros
    * @param tmp_path Fixture pytest para armazenamento temporário.
    * @param monkeypatch Fixture pytest para isolamento de dependências.
    *
    * Valor retornado
    * @return Não retorna valor.
    *
    * Assertiva de entrada
    * prof1 é tratado como professor no ambiente do teste.
    *
    * Assertiva de saída
    * Nota é criada e AP-REP confirma timestamp e nonce.
    *
    * Exceções
    * AssertionError se criação, persistência ou AP-REP divergirem.
    *
    * Observações
    * Cobre autenticação mútua no caminho de escrita.
    ---
    """
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
    """
    ---
    * Função: test_aluno_nao_consegue_criar_nota
    * @brief Verifica bloqueio de criação por aluno.
    *
    * Descrição
    * Autentica aluno1 no serviço e confirma que criar_nota rejeita a operação por
    * falta de papel professor.
    *
    * Parâmetros
    * @param tmp_path Fixture pytest para arquivo temporário.
    * @param monkeypatch Fixture pytest para substituir autorização.
    *
    * Valor retornado
    * @return Não retorna valor.
    *
    * Assertiva de entrada
    * aluno1 não é professor no ambiente do teste.
    *
    * Assertiva de saída
    * criar_nota lança ValueError sobre professores.
    *
    * Exceções
    * O teste espera ValueError.
    *
    * Observações
    * Distingue autenticação Kerberos de autorização da aplicação.
    ---
    """
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
    """
    ---
    * Função: test_aluno_lista_apenas_suas_notas
    * @brief Verifica visão restrita do aluno.
    *
    * Descrição
    * Prepara notas de dois alunos, autentica aluno1 e confirma que apenas suas
    * notas são retornadas.
    *
    * Parâmetros
    * @param tmp_path Fixture pytest para arquivo temporário.
    * @param monkeypatch Fixture pytest para isolamento.
    *
    * Valor retornado
    * @return Não retorna valor.
    *
    * Assertiva de entrada
    * O armazenamento contém notas de aluno1 e aluno2.
    *
    * Assertiva de saída
    * Resultado contém somente nota de aluno1.
    *
    * Exceções
    * AssertionError se o serviço expuser notas indevidas.
    *
    * Observações
    * Valida autorização de leitura para alunos.
    ---
    """
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
    """
    ---
    * Função: test_professor_lista_todas_as_notas
    * @brief Verifica visão completa do professor.
    *
    * Descrição
    * Prepara notas de dois alunos, autentica prof1 e confirma que a listagem inclui
    * todos os registros.
    *
    * Parâmetros
    * @param tmp_path Fixture pytest para arquivo temporário.
    * @param monkeypatch Fixture pytest para isolamento.
    *
    * Valor retornado
    * @return Não retorna valor.
    *
    * Assertiva de entrada
    * prof1 é professor e existem notas de dois alunos.
    *
    * Assertiva de saída
    * Retorna notas dos dois alunos.
    *
    * Exceções
    * AssertionError se a listagem completa falhar.
    *
    * Observações
    * Cobre autorização de leitura ampla para professores.
    ---
    """
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
    """
    ---
    * Função: test_servico_rejeita_replay_do_mesmo_autenticador
    * @brief Verifica rejeição de replay do autenticador.
    *
    * Descrição
    * Usa o mesmo autenticador duas vezes; a primeira chamada é aceita e a segunda
    * deve ser rejeitada pelo controle de nonces usados.
    *
    * Parâmetros
    * @param tmp_path Fixture pytest para arquivo temporário.
    * @param monkeypatch Fixture pytest para isolamento.
    *
    * Valor retornado
    * @return Não retorna valor.
    *
    * Assertiva de entrada
    * O mesmo ticket e autenticador são reutilizados.
    *
    * Assertiva de saída
    * A segunda chamada lança ValueError com indicação de replay.
    *
    * Exceções
    * O teste espera ValueError na segunda chamada.
    *
    * Observações
    * Cobre proteção básica contra repetição no serviço.
    ---
    """
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
