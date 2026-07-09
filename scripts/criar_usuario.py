"""
@file criar_usuario.py
@brief Script de cadastro de usuários para o Kerberos Notas.

@details
Lê dados de usuário pelo terminal, gera salt, deriva chave, calcula verificador
e salva o cadastro em usuarios.json.

Componentes principais:
- criar_usuario
- carregar_usuarios
- salvar_usuarios

Papel na arquitetura:
Prepara identidades e chaves de longo prazo usadas pelo AS no fluxo Kerberos.
"""

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
    """
    ***************************************************************************
    Função: carregar_usuarios

    @brief Carrega o cadastro de usuários do script.

    Descrição:
    Retorna estrutura inicial se o arquivo ainda não existir; caso contrário,
    lê usuarios.json.

    Parâmetros:
    Não recebe parâmetros explícitos.

    Valor retornado:
    @return Retorna dict com chave "usuarios".

    Assertiva de entrada:
    @pre CAMINHO_USUARIOS deve ser um caminho acessível quando existir.

    Assertiva de saída:
    @post Retorna cadastro pronto para consulta ou alteração.

    Exceções:
    @throws Exception Pode propagar erros de leitura ou JSON inválido.

    Observações:
    Usado apenas para manutenção do arquivo de usuários.
    ***************************************************************************
    """
    if not CAMINHO_USUARIOS.exists():
        return {"usuarios": {}}

    with open(CAMINHO_USUARIOS, "r", encoding="utf-8") as arquivo:
        return json.load(arquivo)


def salvar_usuarios(dados: dict) -> None:
    """
    ***************************************************************************
    Função: salvar_usuarios

    @brief Salva o cadastro de usuários em JSON.

    Descrição:
    Serializa o dicionário recebido com indentação e caracteres Unicode preservados.

    Parâmetros:
    @param dados Dicionário de cadastro de usuários.

    Valor retornado:
    @return Não retorna valor.

    Assertiva de entrada:
    @pre dados deve ser serializável em JSON.

    Assertiva de saída:
    @post usuarios.json é atualizado com os dados recebidos.

    Exceções:
    @throws Exception Pode propagar erros de escrita ou serialização.

    Observações:
    Não valida regras de senha; apenas persiste a estrutura já montada.
    ***************************************************************************
    """
    with open(CAMINHO_USUARIOS, "w", encoding="utf-8") as arquivo:
        json.dump(dados, arquivo, indent=4, ensure_ascii=False)


def criar_usuario(nome_usuario: str, senha: str, tipo: str) -> None:
    """
    ***************************************************************************
    Função: criar_usuario

    @brief Cadastra um usuário com salt e verificador de chave.

    Descrição:
    Valida duplicidade e tipo, gera salt, deriva a chave da senha, calcula o
    verificador e grava os dados do usuário.

    Parâmetros:
    @param nome_usuario Nome do usuário a cadastrar.
    @param senha Senha textual usada para derivar a chave.
    @param tipo Papel do usuário, "aluno" ou "professor".

    Valor retornado:
    @return Não retorna valor.

    Assertiva de entrada:
    @pre nome_usuario e senha devem ter sido informados.
    @pre tipo deve ser "aluno" ou "professor".

    Assertiva de saída:
    @post Usuário é salvo quando válido e ainda inexistente.

    Exceções:
    @throws Exception Pode propagar erros de KDF ou persistência.

    Observações:
    O script não salva a senha, apenas salt e verificador usados pelo AS.
    ***************************************************************************
    """
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
    """
    ***************************************************************************
    Função: main

    @brief Executa o fluxo interativo de cadastro.

    Descrição:
    Solicita usuário, senha e tipo no terminal, valida campos mínimos e chama
    criar_usuario.

    Parâmetros:
    Não recebe parâmetros explícitos.

    Valor retornado:
    @return Não retorna valor.

    Assertiva de entrada:
    @pre Entrada padrão deve estar disponível para leitura.

    Assertiva de saída:
    @post Usuário é criado ou uma mensagem de validação é impressa.

    Exceções:
    @throws Exception Pode propagar exceções de input ou criação do usuário.

    Observações:
    Ferramenta auxiliar para demonstração e preparação do ambiente.
    ***************************************************************************
    """
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
