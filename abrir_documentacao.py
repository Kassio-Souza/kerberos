#!/usr/bin/env python3
"""
Abre a documentação HTML gerada pelo Doxygen.

Este script procura o arquivo docs/html/index.html na raiz do projeto
e abre automaticamente no navegador padrão. Caso a documentação ainda
não tenha sido gerada, tenta executar o comando doxygen Doxyfile antes
de abrir a página.
"""

from pathlib import Path
import platform
import subprocess
import sys
import webbrowser


def esta_no_wsl() -> bool:
    """Verifica se o script está sendo executado dentro do WSL."""
    return "microsoft" in platform.uname().release.lower()


def gerar_documentacao_se_necessario(index_html: Path) -> None:
    """Gera a documentação com Doxygen caso o index.html não exista."""
    if index_html.exists():
        return

    doxyfile = Path("Doxyfile")

    if not doxyfile.exists():
        print("Erro: Doxyfile não encontrado na raiz do projeto.")
        sys.exit(1)

    print("Documentação não encontrada. Gerando com Doxygen...")

    try:
        subprocess.run(["doxygen", "Doxyfile"], check=True)
    except FileNotFoundError:
        print("Erro: Doxygen não está instalado ou não está no PATH.")
        sys.exit(1)
    except subprocess.CalledProcessError:
        print("Erro: falha ao gerar documentação com Doxygen.")
        sys.exit(1)


def abrir_documentacao(index_html: Path) -> None:
    """Abre o index.html da documentação no navegador."""
    caminho_absoluto = index_html.resolve()

    if not caminho_absoluto.exists():
        print("Erro: docs/html/index.html não foi encontrado.")
        sys.exit(1)

    print(f"Abrindo documentação: {caminho_absoluto}")

    if esta_no_wsl():
        try:
            resultado = subprocess.run(
                ["wslpath", "-w", str(caminho_absoluto)],
                check=True,
                capture_output=True,
                text=True,
            )
            caminho_windows = resultado.stdout.strip()
            subprocess.run(["explorer.exe", caminho_windows], check=True)
            return
        except Exception:
            pass

    webbrowser.open(caminho_absoluto.as_uri())


def main() -> None:
    """Função principal do script."""
    raiz_projeto = Path(__file__).resolve().parent
    index_html = raiz_projeto / "docs" / "html" / "index.html"

    gerar_documentacao_se_necessario(index_html)
    abrir_documentacao(index_html)


if __name__ == "__main__":
    main()