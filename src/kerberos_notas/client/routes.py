from pathlib import Path
import uuid
from kerberos_notas.rede.logs import log_titulo, log_passo, log_ok, log_dados
from flask import Flask, render_template, request, redirect, url_for, session, flash

from kerberos_notas.client.cliente_socket import (
    chamar_as_autenticacao,
    chamar_tgs_emitir_ticket,
    chamar_servico_notas_listar,
    chamar_servico_notas_criar,
)
from kerberos_notas.crypto.crypto_utils import base64_para_bytes, descriptografar_json
from kerberos_notas.crypto.kdf import derivar_chave_senha
from kerberos_notas.kerberos.authenticator import criar_autenticador
from kerberos_notas.kerberos.tickets import timestamp_atual
from kerberos_notas.storage.json_store import carregar_json
from kerberos_notas.usuarios import obter_tipo_usuario, usuario_e_professor, listar_alunos

BASE_DIR = Path(__file__).resolve().parents[3]
CAMINHO_USUARIOS = BASE_DIR / "data" / "usuarios.json"

DISCIPLINAS_PADRAO = [
    "Segurança Computacional",
    "Algoritmos",
    "Estrutura de Dados",
    "Banco de Dados",
    "Redes de Computadores",
    "Engenharia de Software",
    "Sistemas Operacionais",
    "Álgebra Linear",
    "Cálculo",
    "Programação Orientada a Objetos",
]

def agrupar_notas_por_aluno(notas: list) -> dict:
    """
    Agrupa as notas pelo nome do aluno para facilitar a visualização do professor.
    """
    notas_por_aluno = {}

    for nota in notas:
        aluno = nota.get("aluno", "Aluno não identificado")

        if aluno not in notas_por_aluno:
            notas_por_aluno[aluno] = []

        notas_por_aluno[aluno].append(nota)

    return dict(sorted(notas_por_aluno.items()))


def obter_salt_usuario(usuario: str) -> str:
    """
    O cliente precisa do salt do usuário para derivar a chave a partir da senha.

    Neste projeto acadêmico, o salt fica salvo no arquivo data/usuarios.json.
    O salt não é secreto, por isso pode ser consultado pelo cliente.
    """
    dados = carregar_json(CAMINHO_USUARIOS)
    usuarios = dados.get("usuarios", {})

    if usuario not in usuarios:
        raise ValueError("Usuário não encontrado.")

    return usuarios[usuario]["salt"]


def autenticar_com_kerberos(usuario: str, senha: str) -> dict:
    """
    Executa o fluxo Kerberos usando sockets.
    """

    log_titulo("CLIENTE WEB", "Iniciando fluxo Kerberos completo")

    log_passo(
        "CLIENTE WEB",
        1,
        "Usuário informou login e senha",
        "A senha será usada apenas para derivar a chave do cliente."
    )

    resposta_as_criptografada = chamar_as_autenticacao(usuario, senha)

    log_passo(
        "CLIENTE WEB",
        2,
        "Buscando salt do usuário",
        "O salt não é secreto. Ele serve para derivar a chave a partir da senha."
    )

    salt = obter_salt_usuario(usuario)

    log_dados(
        "CLIENTE WEB",
        "Salt encontrado para derivação da chave",
        {"usuario": usuario, "salt": salt}
    )

    log_passo(
        "CLIENTE WEB",
        3,
        "Derivando chave do cliente com KDF",
        "Aqui é usada a senha + salt para gerar a chave simétrica do cliente."
    )

    chave_cliente = derivar_chave_senha(senha, salt)

    log_ok("CLIENTE WEB", "Chave do cliente derivada com sucesso usando KDF.")

    log_passo(
        "CLIENTE WEB",
        4,
        "Abrindo resposta do AS",
        "O cliente consegue abrir porque conhece a senha correta."
    )

    resposta_as = descriptografar_json(chave_cliente, resposta_as_criptografada)

    log_dados("CLIENTE WEB", "Resposta aberta do AS", resposta_as)

    chave_sessao_cliente_tgs = resposta_as["chave_sessao_cliente_tgs"]
    tgt = resposta_as["tgt"]

    log_ok("CLIENTE WEB", "Chave de sessão Cliente-TGS obtida.")
    log_ok("CLIENTE WEB", "TGT recebido. O cliente transporta o TGT, mas não consegue abrir seu conteúdo.")

    log_passo(
        "CLIENTE WEB",
        5,
        "Criando autenticador para o TGS",
        "Esse autenticador prova que o cliente conhece a chave Cliente-TGS."
    )

    autenticador_tgs = criar_autenticador(
        usuario,
        chave_sessao_cliente_tgs
    )

    log_dados("CLIENTE WEB", "Autenticador Cliente-TGS criado", autenticador_tgs)

    resposta_tgs = chamar_tgs_emitir_ticket(
        usuario,
        tgt,
        "notas",
        autenticador_tgs
    )

    log_passo(
        "CLIENTE WEB",
        6,
        "Abrindo resposta do TGS",
        "O cliente abre a parte criptografada com a chave Cliente-TGS."
    )

    dados_cliente = descriptografar_json(
        base64_para_bytes(chave_sessao_cliente_tgs),
        resposta_tgs["resposta_cliente"]
    )

    log_dados("CLIENTE WEB", "Dados abertos da resposta do TGS", dados_cliente)

    log_ok("CLIENTE WEB", "Chave de sessão Cliente-Serviço obtida.")
    log_ok("CLIENTE WEB", "Ticket do Serviço de Notas recebido.")

    log_passo(
        "CLIENTE WEB",
        7,
        "Fluxo inicial concluído",
        "Agora o cliente pode acessar o Serviço de Notas usando ticket + autenticador."
    )

    return {
        "ticket_servico": resposta_tgs["ticket_servico"],
        "chave_sessao_servico": dados_cliente["chave_sessao_cliente_servico"],
    }



def validar_autenticacao_mutua(
        chave_sessao_servico: str,
        ap_rep: dict,
        timestamp_enviado: int,
        nonce_enviado: str,
) -> bool:
    """
    Valida o AP-REP retornado pelo serviço de notas.
    """

    log_passo(
        "CLIENTE WEB",
        8,
        "Validando autenticação mútua",
        "O cliente vai abrir o AP-REP para confirmar se o serviço conhece a chave Cliente-Serviço."
    )

    chave_bytes = base64_para_bytes(chave_sessao_servico)
    ap_rep_aberto = descriptografar_json(chave_bytes, ap_rep)

    log_dados("CLIENTE WEB", "AP-REP aberto pelo cliente", ap_rep_aberto)

    if not ap_rep_aberto:
        raise ValueError("Falha na autenticação mútua: resposta AP-REP inválida.")

    if ap_rep_aberto.get("timestamp_confirmado") != timestamp_enviado + 1:
        raise ValueError("Falha na autenticação mútua: timestamp não confirmado.")

    if ap_rep_aberto.get("nonce_confirmado") != nonce_enviado:
        raise ValueError("Falha na autenticação mútua: nonce não confirmado.")

    log_ok("CLIENTE WEB", "Autenticação mútua confirmada.")
    log_ok("CLIENTE WEB", "O serviço provou que conhece a chave de sessão Cliente-Serviço.")

    return True


def listar_notas_protegidas(
        usuario: str,
        ticket_servico: dict,
        chave_sessao_servico: str,
) -> list:
    """
    Lista notas usando socket para se comunicar com o Serviço de Notas.
    """

    timestamp_enviado = timestamp_atual()
    nonce_enviado = uuid.uuid4().hex

    autenticador_servico = criar_autenticador(
        usuario,
        chave_sessao_servico,
        nonce=nonce_enviado,
        timestamp=timestamp_enviado,
    )

    resultado = chamar_servico_notas_listar(
        usuario,
        ticket_servico,
        autenticador_servico
    )

    validar_autenticacao_mutua(
        chave_sessao_servico,
        resultado["ap_rep"],
        timestamp_enviado,
        nonce_enviado,
    )

    return resultado.get("notas", [])


def criar_nota_protegida(
        usuario: str,
        aluno: str,
        disciplina: str,
        valor: str,
        ticket_servico: dict,
        chave_sessao_servico: str,
) -> dict:
    """
    Cria uma nota usando socket para se comunicar com o Serviço de Notas.
    """

    timestamp_enviado = timestamp_atual()
    nonce_enviado = uuid.uuid4().hex

    autenticador_servico = criar_autenticador(
        usuario,
        chave_sessao_servico,
        nonce=nonce_enviado,
        timestamp=timestamp_enviado,
    )

    resultado = chamar_servico_notas_criar(
        usuario,
        aluno,
        disciplina,
        valor,
        ticket_servico,
        autenticador_servico
    )

    validar_autenticacao_mutua(
        chave_sessao_servico,
        resultado["ap_rep"],
        timestamp_enviado,
        nonce_enviado,
    )

    return resultado.get("nota")


def create_app():
    app = Flask(
        __name__,
        template_folder=str(BASE_DIR / "templates"),
        static_folder=str(BASE_DIR / "static"),
    )

    app.secret_key = "chave-dev-apenas-para-trabalho"

    @app.route("/")
    def index():
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return render_template("login.html")

        usuario = request.form.get("usuario", "").strip()
        senha = request.form.get("senha", "").strip()

        if not usuario or not senha:
            flash("Informe usuário e senha.")
            return redirect(url_for("login"))

        try:
            resultado = autenticar_com_kerberos(usuario, senha)

            session["usuario"] = usuario
            session["ticket_servico"] = resultado["ticket_servico"]
            session["chave_sessao_servico"] = resultado["chave_sessao_servico"]

            return redirect(url_for("notas"))

        except Exception as erro:
            return render_template(
                "erro.html",
                mensagem=f"Falha na autenticação: {erro}",
            )

    @app.route("/notas", methods=["GET", "POST"])
    def notas():
            if "usuario" not in session:
                flash("Faça login para acessar o sistema de notas.")
                return redirect(url_for("login"))

            usuario = session["usuario"]
            tipo_usuario = obter_tipo_usuario(usuario)
            ticket_servico = session.get("ticket_servico")
            chave_sessao_servico = session.get("chave_sessao_servico")

            if not ticket_servico or not chave_sessao_servico:
                flash("Sessão Kerberos inválida. Faça login novamente.")
                return redirect(url_for("logout"))

            try:
                if request.method == "POST":
                    if not usuario_e_professor(usuario):
                        flash("Erro: apenas professores podem lançar ou alterar notas escolares.")
                        return redirect(url_for("notas"))

                    aluno = request.form.get("aluno", "").strip()

                    disciplinas = request.form.getlist("disciplina[]")
                    disciplinas_extras = request.form.getlist("disciplina_extra[]")
                    valores = request.form.getlist("valor[]")

                    if not aluno:
                        flash("Selecione o aluno.")
                        return redirect(url_for("notas"))

                    quantidade_lancada = 0

                    for indice, disciplina_opcao in enumerate(disciplinas):
                        disciplina_opcao = disciplina_opcao.strip()

                        disciplina_extra = ""
                        valor = ""

                        if indice < len(disciplinas_extras):
                            disciplina_extra = disciplinas_extras[indice].strip()

                        if indice < len(valores):
                            valor = valores[indice].strip()

                        if disciplina_opcao == "__outra__":
                            disciplina = disciplina_extra
                        else:
                            disciplina = disciplina_opcao

                        if not disciplina or not valor:
                            continue

                        criar_nota_protegida(
                            usuario,
                            aluno,
                            disciplina,
                            valor,
                            ticket_servico,
                            chave_sessao_servico
                        )

                        quantidade_lancada += 1

                    if quantidade_lancada == 0:
                        flash("Informe pelo menos uma disciplina e uma nota.")
                        return redirect(url_for("notas"))

                    flash(f"{quantidade_lancada} nota(s) lançada(s) com sucesso.")
                    return redirect(url_for("notas"))

                lista_notas = listar_notas_protegidas(
                    usuario,
                    ticket_servico,
                    chave_sessao_servico
                )

                return render_template(
                    "notas.html",
                    usuario=usuario,
                    tipo_usuario=tipo_usuario,
                    notas=lista_notas,
                    notas_por_aluno=agrupar_notas_por_aluno(lista_notas),
                    alunos=listar_alunos(),
                    disciplinas=DISCIPLINAS_PADRAO,
                )

            except Exception as erro:
                return render_template(
                    "erro.html",
                    mensagem=f"Erro ao acessar notas: {erro}",
                )

    @app.route("/logout")
    def logout():
        session.clear()
        flash("Você saiu do sistema.")
        return redirect(url_for("login"))

    return app