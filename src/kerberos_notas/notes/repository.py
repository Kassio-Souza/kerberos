from pathlib import Path

from kerberos_notas.storage.json_store import carregar_json, salvar_json

CAMINHO_NOTAS = Path(__file__).resolve().parents[3] / "data" / "notas.json"


def _carregar_notas() -> dict:
    return carregar_json(CAMINHO_NOTAS)


def _salvar_notas(dados: dict) -> None:
    salvar_json(CAMINHO_NOTAS, dados)


def listar_notas_usuario(usuario: str) -> list:
    dados = _carregar_notas()
    return dados.get(usuario, [])


def listar_todas_notas() -> list:
    dados = _carregar_notas()
    todas_as_notas = []

    for aluno, notas in dados.items():
        for nota in notas:
            nota_com_aluno = dict(nota)
            nota_com_aluno["aluno"] = aluno
            todas_as_notas.append(nota_com_aluno)

    return todas_as_notas


def adicionar_nota_aluno(aluno: str, disciplina: str, valor: str, professor: str) -> dict:
    dados = _carregar_notas()
    notas_do_aluno = dados.setdefault(aluno, [])

    nova_nota = {
        "aluno": aluno,
        "disciplina": disciplina,
        "valor": valor,
        "professor": professor,
    }

    notas_do_aluno.append(nova_nota)
    _salvar_notas(dados)

    return nova_nota