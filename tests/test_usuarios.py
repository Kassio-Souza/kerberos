"""
---
* Arquivo: test_usuarios.py
* @file test_usuarios.py
* @brief Testes de consulta de tipo de usuário.
*
* Descrição
* Verifica identificação de professores e o comportamento padrão para usuários
* sem tipo explícito.
*
* Componentes principais
* * test_obter_tipo_usuario_professor
* * test_usuario_sem_tipo_vira_aluno_por_padrao
*
* Papel na arquitetura
* Garante a base do controle de acesso usado pelo Serviço de Notas.
---
"""

import json

from kerberos_notas import usuarios


def test_obter_tipo_usuario_professor(tmp_path, monkeypatch):
    """
    ---
    * Função: test_obter_tipo_usuario_professor
    * @brief Verifica usuário cadastrado como professor.
    *
    * Descrição
    * Monta cadastro temporário com tipo "professor" e confirma que as funções de
    * consulta retornam professor e True para permissão de professor.
    *
    * Parâmetros
    * @param tmp_path Fixture pytest para arquivo temporário.
    * @param monkeypatch Fixture pytest para redirecionar CAMINHO_USUARIOS.
    *
    * Valor retornado
    * @return Não retorna valor.
    *
    * Assertiva de entrada
    * O cadastro temporário contém prof1 com tipo professor.
    *
    * Assertiva de saída
    * obter_tipo_usuario retorna professor e usuario_e_professor retorna True.
    *
    * Exceções
    * AssertionError se a regra de consulta mudar.
    *
    * Observações
    * Sustenta a autorização para criação de notas.
    ---
    """
    caminho = tmp_path / "usuarios.json"

    caminho.write_text(
        json.dumps({
            "usuarios": {
                "prof1": {
                    "salt": "abc",
                    "verificador": "def",
                    "tipo": "professor"
                }
            }
        }),
        encoding="utf-8"
    )

    monkeypatch.setattr(usuarios, "CAMINHO_USUARIOS", caminho)

    assert usuarios.obter_tipo_usuario("prof1") == "professor"
    assert usuarios.usuario_e_professor("prof1") is True


def test_usuario_sem_tipo_vira_aluno_por_padrao(tmp_path, monkeypatch):
    """
    ---
    * Função: test_usuario_sem_tipo_vira_aluno_por_padrao
    * @brief Verifica padrão aluno para usuário sem tipo.
    *
    * Descrição
    * Cria cadastro temporário sem campo tipo e confirma que o sistema não concede
    * papel de professor por ausência de informação.
    *
    * Parâmetros
    * @param tmp_path Fixture pytest para arquivo temporário.
    * @param monkeypatch Fixture pytest para redirecionar CAMINHO_USUARIOS.
    *
    * Valor retornado
    * @return Não retorna valor.
    *
    * Assertiva de entrada
    * O usuário aluno1 existe sem campo tipo.
    *
    * Assertiva de saída
    * obter_tipo_usuario retorna aluno e usuario_e_professor retorna False.
    *
    * Exceções
    * AssertionError se o padrão deixar de ser aluno.
    *
    * Observações
    * Evita elevação de privilégio por dado cadastral incompleto.
    ---
    """
    caminho = tmp_path / "usuarios.json"

    caminho.write_text(
        json.dumps({
            "usuarios": {
                "aluno1": {
                    "salt": "abc",
                    "verificador": "def"
                }
            }
        }),
        encoding="utf-8"
    )

    monkeypatch.setattr(usuarios, "CAMINHO_USUARIOS", caminho)

    assert usuarios.obter_tipo_usuario("aluno1") == "aluno"
    assert usuarios.usuario_e_professor("aluno1") is False
