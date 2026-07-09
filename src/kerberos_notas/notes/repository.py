"""
@file repository.py
@brief Persistência simples das notas em arquivo JSON.

@details
Fornece leitura, gravação, listagem e criação de notas escolares armazenadas
em data/notas.json.

Componentes principais:
- listar_notas_usuario
- listar_todas_notas
- adicionar_nota_aluno

Papel na arquitetura:
É a camada de armazenamento usada pelo Serviço de Notas após autenticação Kerberos.
"""

from pathlib import Path

from kerberos_notas.storage.json_store import carregar_json, salvar_json

CAMINHO_NOTAS = Path(__file__).resolve().parents[3] / "data" / "notas.json"


def _carregar_notas() -> dict:
    """
    ***************************************************************************
    Função: _carregar_notas

    @brief Carrega o arquivo de notas.

    Descrição:
    Lê data/notas.json e retorna seu conteúdo como dicionário.

    Parâmetros:
    Não recebe parâmetros explícitos.

    Valor retornado:
    @return Retorna dict com notas agrupadas por aluno.

    Assertiva de entrada:
    @pre CAMINHO_NOTAS deve apontar para arquivo JSON válido ou vazio.

    Assertiva de saída:
    @post Retorna dicionário usado pelas operações do repositório.

    Exceções:
    @throws Exception Pode propagar erros de arquivo ou JSON.

    Observações:
    Função interna; não realiza autenticação ou autorização.
    ***************************************************************************
    """
    return carregar_json(CAMINHO_NOTAS)


def _salvar_notas(dados: dict) -> None:
    """
    ***************************************************************************
    Função: _salvar_notas

    @brief Salva o dicionário de notas no arquivo JSON.

    Descrição:
    Persiste a estrutura recebida em data/notas.json usando indentação legível.

    Parâmetros:
    @param dados Dicionário completo de notas por aluno.

    Valor retornado:
    @return Não retorna valor.

    Assertiva de entrada:
    @pre dados deve ser serializável em JSON.

    Assertiva de saída:
    @post O arquivo de notas passa a refletir os dados recebidos.

    Exceções:
    @throws Exception Pode propagar erros de escrita ou serialização JSON.

    Observações:
    A função não aplica controle de concorrência entre processos.
    ***************************************************************************
    """
    salvar_json(CAMINHO_NOTAS, dados)


def listar_notas_usuario(usuario: str) -> list:
    """
    ***************************************************************************
    Função: listar_notas_usuario

    @brief Lista notas de um único aluno.

    Descrição:
    Carrega todas as notas e retorna a lista associada ao nome do usuário.

    Parâmetros:
    @param usuario Nome do aluno consultado.

    Valor retornado:
    @return Retorna lista de notas do usuário ou lista vazia.

    Assertiva de entrada:
    @pre usuario deve ser string usada como chave no JSON.

    Assertiva de saída:
    @post Retorna lista sem modificar o arquivo.

    Exceções:
    @throws Exception Pode propagar erros de leitura.

    Observações:
    Usada para visão de aluno no serviço protegido.
    ***************************************************************************
    """
    dados = _carregar_notas()
    return dados.get(usuario, [])


def listar_todas_notas() -> list:
    """
    ***************************************************************************
    Função: listar_todas_notas

    @brief Lista todas as notas com identificação do aluno.

    Descrição:
    Percorre o armazenamento por aluno e adiciona o campo "aluno" a cada nota
    copiada para a lista de retorno.

    Parâmetros:
    Não recebe parâmetros explícitos.

    Valor retornado:
    @return Retorna lista de dicionários de notas.

    Assertiva de entrada:
    @pre O arquivo de notas deve conter dicionário de listas.

    Assertiva de saída:
    @post Retorna cópias das notas com campo aluno incluído.

    Exceções:
    @throws Exception Pode propagar erros de leitura ou iteração sobre formato inesperado.

    Observações:
    Usada para visão de professor após autorização.
    ***************************************************************************
    """
    dados = _carregar_notas()
    todas_as_notas = []

    for aluno, notas in dados.items():
        for nota in notas:
            nota_com_aluno = dict(nota)
            nota_com_aluno["aluno"] = aluno
            todas_as_notas.append(nota_com_aluno)

    return todas_as_notas


def adicionar_nota_aluno(aluno: str, disciplina: str, valor: str, professor: str) -> dict:
    """
    ***************************************************************************
    Função: adicionar_nota_aluno

    @brief Adiciona uma nota ao aluno informado.

    Descrição:
    Carrega o arquivo, cria a estrutura da nota, anexa à lista do aluno e salva o
    resultado no JSON.

    Parâmetros:
    @param aluno Nome do aluno.
    @param disciplina Nome da disciplina.
    @param valor Valor textual da nota.
    @param professor Nome do professor responsável.

    Valor retornado:
    @return Retorna dict da nova nota persistida.

    Assertiva de entrada:
    @pre aluno, disciplina, valor e professor devem estar previamente validados.

    Assertiva de saída:
    @post A nova nota é salva e retornada.

    Exceções:
    @throws Exception Pode propagar erros de leitura, escrita ou serialização.

    Observações:
    A autorização de professor é feita no serviço antes desta chamada.
    ***************************************************************************
    """
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
