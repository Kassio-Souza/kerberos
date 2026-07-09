from pathlib import Path

from kerberos_notas.storage.json_store import carregar_json

CAMINHO_USUARIOS = Path(__file__).resolve().parents[2] / "data" / "usuarios.json"


def carregar_usuarios_cadastrados() -> dict:
    dados = carregar_json(CAMINHO_USUARIOS)
    return dados.get("usuarios", {})


def obter_tipo_usuario(nome_usuario: str) -> str:
    usuarios = carregar_usuarios_cadastrados()

    usuario = usuarios.get(nome_usuario)

    if not usuario:
        return "aluno"

    return usuario.get("tipo", "aluno")


def usuario_e_professor(nome_usuario: str) -> bool:
    return obter_tipo_usuario(nome_usuario) == "professor"


def listar_usuarios_por_tipo(tipo: str) -> list:
    usuarios = carregar_usuarios_cadastrados()

    nomes = []

    for nome_usuario, dados_usuario in usuarios.items():
        tipo_usuario = dados_usuario.get("tipo", "aluno")

        if tipo_usuario == tipo:
            nomes.append(nome_usuario)

    return sorted(nomes)


def listar_alunos() -> list:
    return listar_usuarios_por_tipo("aluno")


def listar_professores() -> list:
    return listar_usuarios_por_tipo("professor")