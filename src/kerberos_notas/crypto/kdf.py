"""
@file kdf.py
@brief Funções de derivação e verificação de chaves baseadas em senha.

@details
Implementa geração de salt, PBKDF2-HMAC-SHA256 e verificação de senha sem
armazenar a senha em texto puro.

Componentes principais:
- gerar_salt
- derivar_chave_senha
- verificar_senha

Papel na arquitetura:
Representa a chave de longo prazo do cliente no fluxo Kerberos Notas, usada
pelo cliente e pelo AS para proteger a resposta inicial de autenticação.
"""

import os
import base64
import hashlib

TAMANHO_SALT = 16
TAMANHO_CHAVE = 32
ITERACOES_PBKDF2 = 200_000


def gerar_salt() -> str:
    """
    ***************************************************************************
    Função: gerar_salt

    @brief Gera um salt aleatório para derivação de chave.

    Descrição:
    Cria bytes aleatórios e os codifica em Base64 para armazenamento no cadastro
    do usuário.

    Parâmetros:
    Não recebe parâmetros explícitos.

    Valor retornado:
    @return Retorna uma string Base64 contendo o salt.

    Assertiva de entrada:
    @pre A fonte de aleatoriedade do sistema operacional deve estar disponível.

    Assertiva de saída:
    @post Retorna um salt textual que pode ser usado por derivar_chave_senha.

    Exceções:
    @throws Exception Pode propagar exceções de os.urandom se a geração aleatória falhar.

    Observações:
    O salt não é secreto; ele reduz reutilização direta de hashes entre senhas
    iguais e dificulta tabelas pré-computadas.
    ***************************************************************************
    """
    salt = os.urandom(TAMANHO_SALT)
    return base64.b64encode(salt).decode("utf-8")

def derivar_chave_senha(senha: str, salt_base64: str) -> bytes:
    """
    ***************************************************************************
    Função: derivar_chave_senha

    @brief Deriva uma chave simétrica a partir da senha do usuário.

    Descrição:
    Usa PBKDF2-HMAC-SHA256 com salt persistido e número fixo de iterações para
    transformar a senha textual em uma chave de 32 bytes.

    Parâmetros:
    @param senha Senha informada pelo usuário em formato str.
    @param salt_base64 Salt do cadastro do usuário codificado em Base64.

    Valor retornado:
    @return Retorna bytes da chave derivada.

    Assertiva de entrada:
    @pre senha != None
    @pre salt_base64 deve ser Base64 válido.

    Assertiva de saída:
    @post Retorna uma chave com TAMANHO_CHAVE bytes.

    Exceções:
    @throws Exception Pode propagar erro de Base64 se o salt for inválido.
    @throws Exception Pode propagar AttributeError se senha não for string.

    Observações:
    No fluxo Kerberos, esta chave permite que o cliente abra a resposta do AS e
    serve para comparar o verificador armazenado.
    ***************************************************************************
    """

    salt = base64.b64decode(salt_base64)

    chave = hashlib.pbkdf2_hmac(
        "sha256",
        senha.encode("utf-8"),
        salt,
        ITERACOES_PBKDF2,
        dklen= TAMANHO_CHAVE
    )

    return chave


def gerar_verificador_chave(chave: bytes) -> str:
    """
    ***************************************************************************
    Função: gerar_verificador_chave

    @brief Calcula o verificador persistido de uma chave derivada.

    Descrição:
    Aplica SHA-256 sobre a chave derivada e codifica o resultado em Base64 para
    comparação futura durante o login.

    Parâmetros:
    @param chave Chave derivada em bytes.

    Valor retornado:
    @return Retorna string Base64 do hash da chave.

    Assertiva de entrada:
    @pre chave != None
    @pre chave deve ser bytes.

    Assertiva de saída:
    @post Retorna texto compatível com o campo verificador do cadastro.

    Exceções:
    @throws Exception Pode propagar TypeError se chave não for bytes-like.

    Observações:
    O projeto não salva a senha; salva apenas um verificador derivado, reduzindo
    exposição de credenciais em repouso.
    ***************************************************************************
    """


    hash_chave = hashlib.sha256(chave).digest()
    return base64.b64encode(hash_chave).decode("utf-8")


def verificar_senha(senha: str, salt_base64: str, verificador_salvo: str) -> bool:
    """
    ***************************************************************************
    Função: verificar_senha

    @brief Verifica se uma senha corresponde ao verificador salvo.

    Descrição:
    Deriva novamente a chave da senha e do salt informados, gera seu verificador
    e compara com o valor salvo no cadastro.

    Parâmetros:
    @param senha Senha textual fornecida pelo usuário.
    @param salt_base64 Salt do usuário em Base64.
    @param verificador_salvo Verificador persistido no cadastro.

    Valor retornado:
    @return Retorna True se o verificador calculado for igual ao salvo.

    Assertiva de entrada:
    @pre senha != None
    @pre salt_base64 deve ser Base64 válido.
    @pre verificador_salvo deve ser string comparável.

    Assertiva de saída:
    @post Retorna booleano indicando sucesso ou falha da verificação.

    Exceções:
    @throws Exception Pode propagar exceções de derivar_chave_senha para entradas inválidas.

    Observações:
    Esta função expressa a validação de senha usada conceitualmente pelo AS.
    ***************************************************************************
    """

    chave = derivar_chave_senha(senha, salt_base64)
    verificador_calculado = gerar_verificador_chave(chave)

    return verificador_calculado == verificador_salvo

