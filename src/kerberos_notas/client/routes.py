"""
@file routes.py
@brief Aplicação web Flask que consome o fluxo Kerberos Notas.

@details
Define as rotas de login, listagem e criação de notas, executando autenticação
Kerberos por sockets e validando AP-REP para autenticação mútua.

Componentes principais:
- autenticar_com_kerberos
- validar_autenticacao_mutua
- listar_notas_protegidas
- criar_nota_protegida
- create_app

Papel na arquitetura:
Representa o cliente web que inicia o fluxo AS/TGS e acessa o Serviço de Notas
protegido.
"""

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
    ***************************************************************************
    Função: agrupar_notas_por_aluno

    @brief Agrupa notas pelo nome do aluno.

    Descrição:
    Percorre a lista de notas retornada pelo serviço e monta um dicionário
    ordenado por aluno para facilitar a visualização do professor.

    Parâmetros:
    @param notas Lista de dicionários de nota.

    Valor retornado:
    @return Retorna dict em que cada chave é o nome do aluno e o valor é lista de notas.

    Assertiva de entrada:
    @pre notas deve ser iterável e conter dicionários.

    Assertiva de saída:
    @post Retorna agrupamento ordenado alfabeticamente pelas chaves.

    Exceções:
    @throws Exception Pode propagar AttributeError se algum item não possuir método get.

    Observações:
    É uma função de apresentação; não altera dados nem credenciais Kerberos.
    ***************************************************************************
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
    ***************************************************************************
    Função: obter_salt_usuario

    @brief Obtém o salt cadastrado para um usuário.

    Descrição:
    Lê o arquivo de usuários e retorna o salt necessário para derivar localmente
    a chave do cliente a partir da senha informada.

    Parâmetros:
    @param usuario Nome do usuário autenticado.

    Valor retornado:
    @return Retorna string Base64 do salt do usuário.

    Assertiva de entrada:
    @pre usuario != None
    @pre O usuário deve existir no arquivo de cadastro.

    Assertiva de saída:
    @post Retorna salt usado pela KDF do cliente.

    Exceções:
    @throws ValueError se o usuário não existir.

    Observações:
    O salt não é secreto; a senha não é lida do arquivo nesta função.
    ***************************************************************************
    """
    dados = carregar_json(CAMINHO_USUARIOS)
    usuarios = dados.get("usuarios", {})

    if usuario not in usuarios:
        raise ValueError("Usuário não encontrado.")

    return usuarios[usuario]["salt"]


def autenticar_com_kerberos(usuario: str, senha: str) -> dict:
    """
    ***************************************************************************
    Função: autenticar_com_kerberos

    @brief Executa o fluxo Kerberos inicial via sockets.

    Descrição:
    Chama o AS, deriva a chave do cliente com senha e salt, abre a resposta do
    AS, cria autenticador para o TGS, solicita ticket de serviço e abre a parte
    da resposta destinada ao cliente.

    Parâmetros:
    @param usuario Nome do usuário do login.
    @param senha Senha informada no formulário.

    Valor retornado:
    @return Retorna dict com ticket_servico e chave_sessao_servico.

    Assertiva de entrada:
    @pre usuario != None
    @pre senha != None
    @pre AS e TGS devem estar disponíveis nas portas configuradas.

    Assertiva de saída:
    @post Retorna credenciais para acessar o serviço de notas.

    Exceções:
    @throws Exception Propaga ValueError de autenticação, erros de rede e erros de descriptografia.

    Observações:
    Esta função concentra as etapas cliente do AS-REQ/AS-REP e TGS-REQ/TGS-REP.
    ***************************************************************************
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
    ***************************************************************************
    Função: validar_autenticacao_mutua

    @brief Valida o AP-REP retornado pelo serviço de notas.

    Descrição:
    Descriptografa o AP-REP com a chave Cliente-Serviço e confirma se o serviço
    devolveu timestamp incrementado e o mesmo nonce enviado pelo cliente.

    Parâmetros:
    @param chave_sessao_servico Chave Cliente-Serviço em Base64.
    @param ap_rep Resposta criptografada de autenticação mútua.
    @param timestamp_enviado Timestamp usado no autenticador do cliente.
    @param nonce_enviado Nonce usado no autenticador do cliente.

    Valor retornado:
    @return Retorna True quando a autenticação mútua é confirmada.

    Assertiva de entrada:
    @pre ap_rep deve estar cifrado com a chave Cliente-Serviço correta.

    Assertiva de saída:
    @post Retorna True ou lança ValueError em inconsistência.

    Exceções:
    @throws ValueError se AP-REP, timestamp ou nonce não forem confirmados.

    Observações:
    Confirma que o serviço conhece a chave de sessão e, portanto, é o serviço esperado.
    ***************************************************************************
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
    ***************************************************************************
    Função: listar_notas_protegidas

    @brief Lista notas usando ticket e autenticador Kerberos.

    Descrição:
    Cria autenticador Cliente-Serviço com timestamp e nonce, chama o Serviço de
    Notas e valida o AP-REP antes de retornar a lista.

    Parâmetros:
    @param usuario Usuário autenticado na sessão web.
    @param ticket_servico Ticket emitido pelo TGS.
    @param chave_sessao_servico Chave Cliente-Serviço em Base64.

    Valor retornado:
    @return Retorna lista de notas.

    Assertiva de entrada:
    @pre ticket_servico e chave_sessao_servico devem estar na sessão Flask.

    Assertiva de saída:
    @post Retorna notas apenas após autenticação mútua válida.

    Exceções:
    @throws Exception Propaga erros do serviço, rede, criptografia ou validação AP-REP.

    Observações:
    A função implementa a etapa AP-REQ/AP-REP do cliente para listagem.
    ***************************************************************************
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
    ***************************************************************************
    Função: criar_nota_protegida

    @brief Cria nota usando credenciais Kerberos de serviço.

    Descrição:
    Gera autenticador Cliente-Serviço, envia os dados da nota ao Serviço de Notas
    e valida o AP-REP antes de retornar a nota criada.

    Parâmetros:
    @param usuario Professor autenticado.
    @param aluno Aluno que receberá a nota.
    @param disciplina Disciplina informada.
    @param valor Valor textual da nota.
    @param ticket_servico Ticket de serviço emitido pelo TGS.
    @param chave_sessao_servico Chave Cliente-Serviço em Base64.

    Valor retornado:
    @return Retorna dict da nota criada.

    Assertiva de entrada:
    @pre Credenciais Kerberos devem existir na sessão.
    @pre aluno, disciplina e valor são validados no serviço.

    Assertiva de saída:
    @post Retorna a nota apenas se o serviço confirmar AP-REP.

    Exceções:
    @throws Exception Propaga erros de autorização, serviço, rede ou autenticação mútua.

    Observações:
    A autorização de professor é aplicada no serviço protegido.
    ***************************************************************************
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
    """
    ***************************************************************************
    Função: create_app

    @brief Cria e configura a aplicação Flask do cliente.

    Descrição:
    Instancia Flask, configura templates, arquivos estáticos, chave de sessão e
    registra as rotas web usadas no sistema de notas.

    Parâmetros:
    Não recebe parâmetros explícitos.

    Valor retornado:
    @return Retorna instância Flask configurada.

    Assertiva de entrada:
    @pre Templates e arquivos estáticos devem existir nos caminhos esperados.

    Assertiva de saída:
    @post Retorna aplicação com rotas de login, notas e logout.

    Exceções:
    @throws Exception Não trata exceções de configuração do Flask explicitamente.

    Observações:
    A sessão Flask armazena ticket de serviço e chave de sessão Cliente-Serviço.
    ***************************************************************************
    """
    app = Flask(
        __name__,
        template_folder=str(BASE_DIR / "templates"),
        static_folder=str(BASE_DIR / "static"),
    )

    app.secret_key = "chave-dev-apenas-para-trabalho"

    @app.route("/")
    def index():
        """
        ***************************************************************************
        Função: index

        @brief Redireciona a página inicial para o login.

        Descrição:
        Implementa a rota raiz da aplicação web e direciona o usuário para a
        rota de autenticação.

        Parâmetros:
        Não recebe parâmetros explícitos.

        Valor retornado:
        @return Retorna resposta Flask de redirecionamento.

        Assertiva de entrada:
        @pre A rota login deve estar registrada.

        Assertiva de saída:
        @post Cliente recebe redirecionamento HTTP para /login.

        Exceções:
        @throws Exception Pode propagar erros do Flask em geração de URL.

        Observações:
        Não participa diretamente da criptografia Kerberos.
        ***************************************************************************
        """
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        """
        ***************************************************************************
        Função: login

        @brief Processa tela e envio de credenciais de login.

        Descrição:
        Em GET renderiza o formulário; em POST valida campos, executa
        autenticar_com_kerberos e grava credenciais de serviço na sessão.

        Parâmetros:
        Não recebe parâmetros explícitos.

        Valor retornado:
        @return Retorna página HTML ou redirecionamento Flask.

        Assertiva de entrada:
        @pre Para POST, usuário e senha devem ser informados.

        Assertiva de saída:
        @post Em sucesso, sessão contém usuário, ticket_servico e chave_sessao_servico.

        Exceções:
        @throws Exception Captura exceções do fluxo Kerberos e renderiza página de erro.

        Observações:
        A senha não é armazenada na sessão; é usada para derivação de chave.
        ***************************************************************************
        """
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
            """
            ***************************************************************************
            Função: notas

            @brief Exibe notas e processa criação de notas.

            Descrição:
            Valida sessão Kerberos, lista notas em GET e, em POST, envia uma ou
            mais notas ao serviço protegido quando o usuário é professor.

            Parâmetros:
            Não recebe parâmetros explícitos.

            Valor retornado:
            @return Retorna HTML renderizado ou redirecionamento Flask.

            Assertiva de entrada:
            @pre Sessão deve conter usuario, ticket_servico e chave_sessao_servico.

            Assertiva de saída:
            @post Exibe notas autenticadas ou registra notas via serviço protegido.

            Exceções:
            @throws Exception Captura exceções de acesso ao serviço e renderiza página de erro.

            Observações:
            A rota usa AP-REQ/AP-REP a cada operação protegida.
            ***************************************************************************
            """
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
        """
        ***************************************************************************
        Função: logout

        @brief Encerra a sessão web do usuário.

        Descrição:
        Remove dados da sessão Flask, incluindo credenciais Kerberos armazenadas
        para o serviço de notas, e redireciona para login.

        Parâmetros:
        Não recebe parâmetros explícitos.

        Valor retornado:
        @return Retorna resposta Flask de redirecionamento.

        Assertiva de entrada:
        @pre A sessão Flask deve estar disponível.

        Assertiva de saída:
        @post Sessão fica limpa após session.clear.

        Exceções:
        @throws Exception Pode propagar erros do Flask em flash ou redirecionamento.

        Observações:
        Não revoga tickets no servidor; apenas remove credenciais locais da sessão.
        ***************************************************************************
        """
        session.clear()
        flash("Você saiu do sistema.")
        return redirect(url_for("login"))

    return app
