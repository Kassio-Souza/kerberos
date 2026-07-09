import json
from pathlib import Path

def carregar_json(caminho: Path) -> dict:
    with open(caminho, "r", encoding="utf-8") as arquivo:
        conteudo = arquivo.read().strip()
        return json.loads(conteudo) if conteudo else {}

def salvar_json(caminho: Path, dados: dict) -> None:
    with open(caminho, "w", encoding="utf-8") as arquivo:
        json.dump(dados, arquivo, ensure_ascii=False, indent=2)
