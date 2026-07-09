import json

from kerberos_notas import usuarios


def test_obter_tipo_usuario_professor(tmp_path, monkeypatch):
    caminho = tmp_path / "usuarios.json"

    caminho.write_text(
        json.dumps({
            "usuarios": {
                "prof1": {
                    "salt": "abc",
                    "verificador": "def",
                    "tipo": "professor"
                }
            }
        }),
        encoding="utf-8"
    )

    monkeypatch.setattr(usuarios, "CAMINHO_USUARIOS", caminho)

    assert usuarios.obter_tipo_usuario("prof1") == "professor"
    assert usuarios.usuario_e_professor("prof1") is True


def test_usuario_sem_tipo_vira_aluno_por_padrao(tmp_path, monkeypatch):
    caminho = tmp_path / "usuarios.json"

    caminho.write_text(
        json.dumps({
            "usuarios": {
                "aluno1": {
                    "salt": "abc",
                    "verificador": "def"
                }
            }
        }),
        encoding="utf-8"
    )

    monkeypatch.setattr(usuarios, "CAMINHO_USUARIOS", caminho)

    assert usuarios.obter_tipo_usuario("aluno1") == "aluno"
    assert usuarios.usuario_e_professor("aluno1") is False