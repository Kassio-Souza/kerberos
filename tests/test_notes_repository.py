import json

from kerberos_notas.notes import repository


def test_adicionar_nota_para_aluno_correto(tmp_path, monkeypatch):
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