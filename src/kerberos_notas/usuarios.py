"""
@file usuarios.py
@brief Consulta usuários e papéis do sistema acadêmico.

@details
Lê o cadastro de usuários e fornece funções para identificar professores,
alunos e listas por tipo.

Componentes principais:
- obter_tipo_usuario
- usuario_e_professor
- listar_alunos

Papel na arquitetura:
Apoia autorização do Serviço de Notas após a autenticação Kerberos.
"""

from pathlib import Path

from kerberos_notas.storage.json_store import carregar_json

CAMINHO_USUARIOS = Path(__file__).resolve().parents[2] / "data" / "usuarios.json"


def carregar_usuarios_cadastrados() -> dict:
    """
    ***************************************************************************
    Função: carregar_usuarios_cadastrados

    @brief Carrega o mapa de usuários cadastrados.

    Descrição:
    Lê usuarios.json por meio do utilitário de armazenamento e retorna somente
    o dicionário interno de usuários.

    Parâmetros:
    Não recebe parâmetros explícitos.

    Valor retornado:
    @return Retorna dict de usuários, ou dict vazio se a chave não existir.

    Assertiva de entrada:
    @pre CAMINHO_USUARIOS deve apontar para JSON válido.

    Assertiva de saída:
    @post Retorna estrutura consultável por nome de usuário.

    Exceções:
    @throws Exception Pode propagar erros de leitura ou parse JSON.

    Observações:
    Não autentica senha; apenas consulta dados cadastrais.
    ***************************************************************************
    """
    dados = carregar_json(CAMINHO_USUARIOS)
    return dados.get("usuarios", {})


def obter_tipo_usuario(nome_usuario: str) -> str:
    """
    ***************************************************************************
    Função: obter_tipo_usuario

    @brief Obtém o papel de um usuário.

    Descrição:
    Busca o usuário no cadastro e retorna seu tipo; se não existir ou não tiver
    tipo definido, usa "aluno" como padrão.

    Parâmetros:
    @param nome_usuario Nome do usuário consultado.

    Valor retornado:
    @return Retorna "professor", "aluno" ou outro tipo armazenado no JSON.

    Assertiva de entrada:
    @pre nome_usuario deve ser string consultável no cadastro.

    Assertiva de saída:
    @post Sempre retorna uma string de tipo.

    Exceções:
    @throws Exception Pode propagar erros de leitura do cadastro.

    Observações:
    O padrão "aluno" evita conceder privilégio de professor por ausência de dado.
    ***************************************************************************
    """
    usuarios = carregar_usuarios_cadastrados()

    usuario = usuarios.get(nome_usuario)

    if not usuario:
        return "aluno"

    return usuario.get("tipo", "aluno")


def usuario_e_professor(nome_usuario: str) -> bool:
    """
    ***************************************************************************
    Função: usuario_e_professor

    @brief Verifica se um usuário é professor.

    Descrição:
    Consulta o tipo do usuário e compara com o literal "professor".

    Parâmetros:
    @param nome_usuario Nome do usuário consultado.

    Valor retornado:
    @return Retorna True para professor e False nos demais casos.

    Assertiva de entrada:
    @pre nome_usuario deve identificar o usuário a consultar.

    Assertiva de saída:
    @post Retorna booleano usado no controle de acesso.

    Exceções:
    @throws Exception Pode propagar erros de obter_tipo_usuario.

    Observações:
    É usada pelo serviço protegido para autorizar criação de notas.
    ***************************************************************************
    """
    return obter_tipo_usuario(nome_usuario) == "professor"


def listar_usuarios_por_tipo(tipo: str) -> list:
    """
    ***************************************************************************
    Função: listar_usuarios_por_tipo

    @brief Lista usuários cujo tipo corresponde ao solicitado.

    Descrição:
    Percorre o cadastro, compara o campo tipo com o parâmetro e retorna nomes em
    ordem alfabética.

    Parâmetros:
    @param tipo Tipo de usuário a filtrar.

    Valor retornado:
    @return Retorna lista ordenada de nomes.

    Assertiva de entrada:
    @pre tipo deve ser string comparável com o campo tipo do cadastro.

    Assertiva de saída:
    @post Retorna lista, possivelmente vazia.

    Exceções:
    @throws Exception Pode propagar erros de leitura do cadastro.

    Observações:
    Usuários sem tipo explícito são tratados como alunos.
    ***************************************************************************
    """
    usuarios = carregar_usuarios_cadastrados()

    nomes = []

    for nome_usuario, dados_usuario in usuarios.items():
        tipo_usuario = dados_usuario.get("tipo", "aluno")

        if tipo_usuario == tipo:
            nomes.append(nome_usuario)

    return sorted(nomes)


def listar_alunos() -> list:
    """
    ***************************************************************************
    Função: listar_alunos

    @brief Lista usuários do tipo aluno.

    Descrição:
    Especializa listar_usuarios_por_tipo para o tipo "aluno".

    Parâmetros:
    Não recebe parâmetros explícitos.

    Valor retornado:
    @return Retorna lista ordenada de alunos.

    Assertiva de entrada:
    @pre O cadastro deve estar legível.

    Assertiva de saída:
    @post Retorna lista de nomes de alunos.

    Exceções:
    @throws Exception Pode propagar erros de listar_usuarios_por_tipo.

    Observações:
    Usada pela interface web para montar opções de lançamento de nota.
    ***************************************************************************
    """
    return listar_usuarios_por_tipo("aluno")


def listar_professores() -> list:
    """
    ***************************************************************************
    Função: listar_professores

    @brief Lista usuários do tipo professor.

    Descrição:
    Especializa listar_usuarios_por_tipo para o tipo "professor".

    Parâmetros:
    Não recebe parâmetros explícitos.

    Valor retornado:
    @return Retorna lista ordenada de professores.

    Assertiva de entrada:
    @pre O cadastro deve estar legível.

    Assertiva de saída:
    @post Retorna lista de nomes de professores.

    Exceções:
    @throws Exception Pode propagar erros de listar_usuarios_por_tipo.

    Observações:
    Auxilia consultas acadêmicas e testes de autorização.
    ***************************************************************************
    """
    return listar_usuarios_por_tipo("professor")
