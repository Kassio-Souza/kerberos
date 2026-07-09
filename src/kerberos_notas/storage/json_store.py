"""
@file json_store.py
@brief Utilitários de leitura e escrita de arquivos JSON.

@details
Centraliza acesso a arquivos JSON usados como armazenamento simples do projeto.

Componentes principais:
- carregar_json
- salvar_json

Papel na arquitetura:
Dá suporte ao cadastro de usuários e ao repositório de notas.
"""

import json
from pathlib import Path

def carregar_json(caminho: Path) -> dict:
    """
    ***************************************************************************
    Função: carregar_json

    @brief Lê um arquivo JSON para dicionário.

    Descrição:
    Abre o caminho informado, remove espaços externos e retorna JSON parseado ou
    dicionário vazio quando o arquivo está vazio.

    Parâmetros:
    @param caminho Path do arquivo JSON.

    Valor retornado:
    @return Retorna dict com o conteúdo do arquivo.

    Assertiva de entrada:
    @pre caminho deve apontar para arquivo legível.

    Assertiva de saída:
    @post Retorna dict vazio para conteúdo vazio ou dados parseados.

    Exceções:
    @throws Exception Pode propagar FileNotFoundError, PermissionError ou JSONDecodeError.

    Observações:
    Não valida esquema dos dados lidos.
    ***************************************************************************
    """
    with open(caminho, "r", encoding="utf-8") as arquivo:
        conteudo = arquivo.read().strip()
        return json.loads(conteudo) if conteudo else {}

def salvar_json(caminho: Path, dados: dict) -> None:
    """
    ***************************************************************************
    Função: salvar_json

    @brief Grava um dicionário em arquivo JSON.

    Descrição:
    Serializa os dados recebidos com indentação e preservação de caracteres não
    ASCII para facilitar inspeção acadêmica.

    Parâmetros:
    @param caminho Path do arquivo que será escrito.
    @param dados Dicionário serializável em JSON.

    Valor retornado:
    @return Não retorna valor.

    Assertiva de entrada:
    @pre dados deve ser serializável por json.dump.

    Assertiva de saída:
    @post Arquivo passa a conter a representação JSON dos dados.

    Exceções:
    @throws Exception Pode propagar erros de escrita ou serialização.

    Observações:
    Usado pelo repositório de notas e scripts de manutenção.
    ***************************************************************************
    """
    with open(caminho, "w", encoding="utf-8") as arquivo:
        json.dump(dados, arquivo, ensure_ascii=False, indent=2)
