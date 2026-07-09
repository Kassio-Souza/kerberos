from datetime import datetime
import json


MOSTRAR_LOGS = True


def _hora_atual() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _mascarar_texto(valor: str) -> str:
    if len(valor) <= 12:
        return "***"

    return f"{valor[:8]}...{valor[-6:]} ({len(valor)} chars)"


def _eh_campo_sensivel(chave: str) -> bool:
    chave = chave.lower()

    campos_sensiveis = [
        "senha",
        "password",
        "chave",
        "key",
        "verificador",
        "ciphertext",
        "tag",
        "nonce",
        "salt",
    ]

    return any(campo in chave for campo in campos_sensiveis)


def _preparar_valor(chave, valor):
    if isinstance(valor, dict):
        return {k: _preparar_valor(k, v) for k, v in valor.items()}

    if isinstance(valor, list):
        return [_preparar_valor(chave, item) for item in valor]

    if isinstance(valor, str):
        if _eh_campo_sensivel(str(chave)):
            return _mascarar_texto(valor)

        if len(valor) > 80:
            return _mascarar_texto(valor)

        return valor

    return valor


def sanitizar(dados):
    """
    Remove ou mascara informações sensíveis antes de exibir no terminal.
    """
    if isinstance(dados, dict):
        return {k: _preparar_valor(k, v) for k, v in dados.items()}

    if isinstance(dados, list):
        return [_preparar_valor("", item) for item in dados]

    return dados


def log_linha(componente: str, mensagem: str = ""):
    if not MOSTRAR_LOGS:
        return

    print(f"[{_hora_atual()}] [{componente}] {mensagem}", flush=True)


def log_titulo(componente: str, titulo: str):
    if not MOSTRAR_LOGS:
        return

    print("\n" + "=" * 78, flush=True)
    print(f"[{_hora_atual()}] [{componente}] {titulo}", flush=True)
    print("=" * 78, flush=True)


def log_passo(componente: str, numero: int, titulo: str, detalhe: str | None = None):
    if not MOSTRAR_LOGS:
        return

    print(f"[{_hora_atual()}] [{componente}] ETAPA {numero} - {titulo}", flush=True)

    if detalhe:
        print(f"    -> {detalhe}", flush=True)


def log_ok(componente: str, mensagem: str):
    if not MOSTRAR_LOGS:
        return

    print(f"[{_hora_atual()}] [{componente}] OK - {mensagem}", flush=True)


def log_erro(componente: str, mensagem: str):
    if not MOSTRAR_LOGS:
        return

    print(f"[{_hora_atual()}] [{componente}] ERRO - {mensagem}", flush=True)


def log_dados(componente: str, titulo: str, dados):
    if not MOSTRAR_LOGS:
        return

    dados_limpos = sanitizar(dados)
    texto = json.dumps(dados_limpos, indent=4, ensure_ascii=False)

    print(f"[{_hora_atual()}] [{componente}] {titulo}:", flush=True)

    for linha in texto.splitlines():
        print(f"    {linha}", flush=True)