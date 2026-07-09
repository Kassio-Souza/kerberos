import json
from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1] / "src"))

from kerberos_notas.crypto.kdf import (
    gerar_salt,
    derivar_chave_senha,
    gerar_verificador_chave
)

CAMINHO_USUARIOS = Path(__file__).resolve().parents[1] / "data" / "usuarios.json"


def carregar_usuarios() -> dict:
    if not CAMINHO_USUARIOS.exists():
        return {"usuarios": {}}

    with open(CAMINHO_USUARIOS, "r", encoding="utf-8") as arquivo:
        return json.load(arquivo)


def salvar_usuarios(dados: dict) -> None:
    with open(CAMINHO_USUARIOS, "w", encoding="utf-8") as arquivo:
        json.dump(dados, arquivo, indent=4, ensure_ascii=False)


def criar_usuario(nome_usuario: str, senha: str, tipo: str) -> None:
    dados = carregar_usuarios()

    if "usuarios" not in dados:
        dados["usuarios"] = {}

    if nome_usuario in dados["usuarios"]:
        print("Usuário já existe.")
        return

    if tipo not in ["aluno", "professor"]:
        print("Tipo inválido. Use apenas 'aluno' ou 'professor'.")
        return

    salt = gerar_salt()
    chave = derivar_chave_senha(senha, salt)
    verificador = gerar_verificador_chave(chave)

    dados["usuarios"][nome_usuario] = {
        "salt": salt,
        "verificador": verificador,
        "tipo": tipo
    }

    salvar_usuarios(dados)

    print(f"Usuário '{nome_usuario}' criado com sucesso como {tipo}.")


def main():
    print("=== Cadastro de usuário Kerberos ===")

    nome_usuario = input("Usuário: ").strip()
    senha = input("Senha: ").strip()

    print("\nTipo de usuário:")
    print("1 - Aluno")
    print("2 - Professor")

    opcao_tipo = input("Escolha o tipo: ").strip()

    if opcao_tipo == "1":
        tipo = "aluno"
    elif opcao_tipo == "2":
        tipo = "professor"
    else:
        print("Opção inválida.")
        return

    if not nome_usuario or not senha:
        print("Usuário e senha são obrigatórios.")
        return

    criar_usuario(nome_usuario, senha, tipo)


if __name__ == "__main__":
    main()