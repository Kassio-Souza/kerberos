from pathlib import Path
import platform
import subprocess
import sys
import threading
import webbrowser

from kerberos_notas.client.routes import create_app


def esta_no_wsl() -> bool:
    """
    Verifica se o programa está sendo executado dentro do WSL.
    """
    return "microsoft" in platform.uname().release.lower()


def abrir_documentacao_doxygen() -> None:
    """
    Abre a documentação Doxygen usando o script abrir_documentacao.py.
    """
    raiz_projeto = Path(__file__).resolve().parent
    script_documentacao = raiz_projeto / "abrir_documentacao.py"

    if not script_documentacao.exists():
        print("Aviso: abrir_documentacao.py não encontrado.")
        return

    try:
        subprocess.Popen(
            [sys.executable, str(script_documentacao)],
            cwd=str(raiz_projeto),
        )
    except Exception as erro:
        print(f"Aviso: não foi possível abrir a documentação: {erro}")


def abrir_aplicacao_web() -> None:
    """
    Abre a aplicação Flask no navegador padrão.
    """
    url = "http://127.0.0.1:5000"

    try:
        if esta_no_wsl():
            subprocess.Popen(["explorer.exe", url])
        else:
            webbrowser.open(url)
    except Exception as erro:
        print(f"Aviso: não foi possível abrir a aplicação no navegador: {erro}")


app = create_app()


if __name__ == "__main__":
    threading.Timer(1.0, abrir_aplicacao_web).start()
    threading.Timer(3.0, abrir_documentacao_doxygen).start()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True,
        use_reloader=False,
    )