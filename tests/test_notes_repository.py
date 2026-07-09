"""
---
* Arquivo: test_notes_repository.py
* @file test_notes_repository.py
* @brief Testes do repositório JSON de notas.
*
* Descrição
* Verifica persistência de notas por aluno e montagem da listagem global com nome
* do aluno incluído.
*
* Componentes principais
* * test_adicionar_nota_para_aluno_correto
* * test_listar_todas_notas_inclui_nome_do_aluno
*
* Papel na arquitetura
* Garante que a camada de armazenamento usada pelo serviço protegido preserva os
* dados esperados.
---
"""

import json

from kerberos_notas.notes import repository


def test_adicionar_nota_para_aluno_correto(tmp_path, monkeypatch):
    """
    ---
    * Função: test_adicionar_nota_para_aluno_correto
    * @brief Verifica persistência de nota no aluno correto.
    *
    * Descrição
    * Usa arquivo temporário, redireciona CAMINHO_NOTAS e confirma que a nota
    * adicionada aparece sob a chave do aluno informado.
    *
    * Parâmetros
    * @param tmp_path Fixture pytest para diretório temporário.
    * @param monkeypatch Fixture pytest para substituir CAMINHO_NOTAS.
    *
    * Valor retornado
    * @return Não retorna valor; falha por assert em regressão.
    *
    * Assertiva de entrada
    * O arquivo temporário começa com JSON vazio.
    *
    * Assertiva de saída
    * O JSON salvo contém aluno, disciplina, valor e professor esperados.
    *
    * Exceções
    * Pytest registra AssertionError se a persistência divergir.
    *
    * Observações
    * Testa armazenamento, não autenticação Kerberos.
    ---
    """
    caminho = tmp_path / "notas.json"
    caminho.write_text("{}", encoding="utf-8")

    monkeypatch.setattr(repository, "CAMINHO_NOTAS", caminho)

    repository.adicionar_nota_aluno(
        aluno="aluno1",
        disciplina="Segurança Computacional",
        valor="9.5",
        professor="prof1"
    )

    dados = json.loads(caminho.read_text(encoding="utf-8"))

    assert "aluno1" in dados
    assert dados["aluno1"][0]["disciplina"] == "Segurança Computacional"
    assert dados["aluno1"][0]["valor"] == "9.5"
    assert dados["aluno1"][0]["professor"] == "prof1"


def test_listar_todas_notas_inclui_nome_do_aluno(tmp_path, monkeypatch):
    """
    ---
    * Função: test_listar_todas_notas_inclui_nome_do_aluno
    * @brief Verifica listagem global com campo aluno.
    *
    * Descrição
    * Prepara notas de dois alunos e confirma que listar_todas_notas retorna itens
    * com identificação do aluno de origem.
    *
    * Parâmetros
    * @param tmp_path Fixture pytest para arquivo temporário.
    * @param monkeypatch Fixture pytest para trocar CAMINHO_NOTAS.
    *
    * Valor retornado
    * @return Não retorna valor.
    *
    * Assertiva de entrada
    * O JSON temporário contém duas chaves de aluno.
    *
    * Assertiva de saída
    * A lista retornada contém duas notas com campo aluno preenchido.
    *
    * Exceções
    * AssertionError se a listagem não preservar os dados esperados.
    *
    * Observações
    * Esse comportamento é usado pela visão de professor no serviço.
    ---
    """
    caminho = tmp_path / "notas.json"

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

    monkeypatch.setattr(repository, "CAMINHO_NOTAS", caminho)

    notas = repository.listar_todas_notas()

    assert len(notas) == 2
    assert notas[0]["aluno"] == "aluno1"
    assert notas[1]["aluno"] == "aluno2"
