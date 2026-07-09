import os 
import base64
import hashlib

TAMANHO_SALT = 16
TAMANHO_CHAVE = 32
ITERACOES_PBKDF2 = 200_000


def gerar_salt() -> str:
    """
    Gera um salt aleatório para ser usado na derivação da chave.

    O salt impede que duas senhas iguais gerem a mesma chave derivada.
    Ele é salvo em Base64 para facilitar o armazenamento no JSON.
    """
    salt = os.urandom(TAMANHO_SALT)
    return base64.b64encode(salt).decode("utf-8")

def derivar_chave_senha(senha: str, salt_base64: str) -> bytes:
    """
    Deriva uma chave simétrica a partir da senha do usuário usando PBKDF2-HMAC-SHA256.

    Entrada:
        senha: senha digitada pelo usuário
        salt_base64: salt salvo no cadastro do usuário

    Saída:
        chave derivada em bytes

    Essa chave será usada pelo cliente e pelo AS como chave de longo prazo.
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
    Gera um verificador da chave derivada.

    Em vez de salvar a senha em texto puro, salvamos apenas um hash da chave derivada.
    Assim, durante o login, o AS deriva novamente a chave e compara o hash.
    """


    hash_chave = hashlib.sha256(chave).digest()
    return base64.b64encode(hash_chave).decode("utf-8")


def verificar_senha(senha: str, salt_base64: str, verificador_salvo: str) -> bool:
    """
    Verifica se a senha digitada gera a mesma chave cadastrada anteriormente.
    """

    chave = derivar_chave_senha(senha, salt_base64)
    verificador_calculado = gerar_verificador_chave(chave)

    return verificador_calculado == verificador_salvo
     