"""
@file servidor_notas.py
@brief Servidor TCP do Serviço de Notas protegido.

@details
Recebe requisições JSON para listar ou criar notas e delega a validação Kerberos
e regras de autorização ao módulo notes.service.

Componentes principais:
- ManipuladorNotas
- ServidorNotasTCP
- iniciar_servidor_notas

Papel na arquitetura:
Processo do serviço de aplicação protegido por tickets de serviço.
"""

import socketserver

from kerberos_notas.config import HOST_SERVICO_NOTAS, PORTA_SERVICO_NOTAS
from kerberos_notas.notes.service import criar_nota, listar_notas
from kerberos_notas.rede.protocolo import enviar_json, receber_json
from kerberos_notas.rede.logs import log_titulo, log_passo, log_ok, log_erro, log_dados


class ManipuladorNotas(socketserver.BaseRequestHandler):
    """
    ***************************************************************************
    Classe: ManipuladorNotas

    @brief Manipula conexões TCP ao Serviço de Notas e direciona cada ação para a.

    @details
    Manipula conexões TCP ao Serviço de Notas e direciona cada ação para a
    operação protegida correspondente.

    Responsabilidades principais:
    - Receber mensagens JSON do cliente.
    - Encaminhar listagem e criação de notas.
    - Enviar respostas com dados ou erros.

    Relação com o protocolo Kerberos:
    Representa o endpoint de serviço que valida ticket e autenticador antes de
    executar a regra de negócio.

    Observações:
    A autenticação mútua é gerada por notes.service e retornada ao cliente.
    ***************************************************************************
    """

    def handle(self):
        """
        ***************************************************************************
        Função: handle

        @brief Processa uma requisição TCP ao serviço de notas.

        Descrição:
        Lê a ação solicitada e delega para _listar_notas ou _criar_nota; ações
        desconhecidas recebem resposta de erro.

        Parâmetros:
        Não recebe parâmetros explícitos.

        Valor retornado:
        @return Não retorna valor.

        Assertiva de entrada:
        @pre A conexão deve fornecer JSON válido.

        Assertiva de saída:
        @post Envia resposta JSON ao cliente.

        Exceções:
        @throws Exception Captura exceções gerais e responde com ok falso.

        Observações:
        O método faz roteamento de ações, não valida credenciais diretamente.
        ***************************************************************************
        """
        log_titulo("SERVIÇO NOTAS", "Nova conexão recebida no serviço protegido")

        try:
            requisicao = receber_json(self.request)

            log_passo("SERVIÇO NOTAS", 1, "Requisição recebida via socket")
            log_dados("SERVIÇO NOTAS", "Conteúdo recebido", requisicao)

            acao = requisicao.get("acao")

            if acao == "listar_notas":
                self._listar_notas(requisicao)
                return

            if acao == "criar_nota":
                self._criar_nota(requisicao)
                return

            resposta = {
                "ok": False,
                "erro": "Ação inválida para o Serviço de Notas."
            }

            enviar_json(self.request, resposta)
            log_erro("SERVIÇO NOTAS", "Ação inválida recebida.")

        except Exception as erro:
            resposta = {
                "ok": False,
                "erro": str(erro)
            }

            enviar_json(self.request, resposta)
            log_erro("SERVIÇO NOTAS", str(erro))

    def _listar_notas(self, requisicao: dict) -> None:
        """
        ***************************************************************************
        Função: _listar_notas

        @brief Atende a operação protegida de listagem.

        Descrição:
        Extrai usuário, ticket de serviço e autenticador da requisição, valida
        campos obrigatórios e chama listar_notas.

        Parâmetros:
        @param requisicao Dicionário recebido por socket.

        Valor retornado:
        @return Não retorna valor.

        Assertiva de entrada:
        @pre requisicao deve conter usuario, ticket_servico e autenticador.

        Assertiva de saída:
        @post Envia resposta com notas e AP-REP, ou erro.

        Exceções:
        @throws Exception Pode propagar exceções de listar_notas para o handle, quando ocorrerem.

        Observações:
        A função mantém a camada TCP separada da regra Kerberos.
        ***************************************************************************
        """
        usuario = requisicao.get("usuario")
        ticket_servico = requisicao.get("ticket_servico")
        autenticador = requisicao.get("autenticador")

        if not usuario or not ticket_servico or not autenticador:
            resposta = {
                "ok": False,
                "erro": "Usuário, ticket de serviço e autenticador são obrigatórios."
            }
            enviar_json(self.request, resposta)
            log_erro("SERVIÇO NOTAS", "Dados obrigatórios não foram enviados.")
            return

        log_passo(
            "SERVIÇO NOTAS",
            2,
            "Validando ticket de serviço",
            "O serviço usa sua chave secreta para abrir o ticket emitido pelo TGS."
        )

        log_passo(
            "SERVIÇO NOTAS",
            3,
            "Validando autenticador Cliente-Serviço",
            "O autenticador prova que o cliente conhece a chave de sessão Cliente-Serviço."
        )

        log_passo(
            "SERVIÇO NOTAS",
            4,
            "Executando operação protegida",
            f"Operação: listar notas do usuário {usuario}"
        )

        resultado = listar_notas(
            usuario=usuario,
            ticket_servico_criptografado=ticket_servico,
            autenticador_criptografado=autenticador
        )

        log_ok("SERVIÇO NOTAS", "Ticket de serviço validado.")
        log_ok("SERVIÇO NOTAS", "Autenticador validado.")
        log_ok("SERVIÇO NOTAS", "Operação de listagem liberada.")
        log_ok("SERVIÇO NOTAS", "AP-REP gerado para autenticação mútua.")

        log_dados("SERVIÇO NOTAS", "Resultado da operação protegida", resultado)

        resposta = {
            "ok": True,
            "dados": resultado
        }

        enviar_json(self.request, resposta)

        log_passo(
            "SERVIÇO NOTAS",
            5,
            "Resposta enviada ao cliente",
            "O cliente ainda vai validar o AP-REP para confirmar que o serviço é verdadeiro."
        )

    def _criar_nota(self, requisicao: dict) -> None:
        """
        ***************************************************************************
        Função: _criar_nota

        @brief Atende a operação protegida de criação de nota.

        Descrição:
        Extrai dados acadêmicos e credenciais Kerberos, valida presença dos campos
        e chama criar_nota para autenticar, autorizar e persistir.

        Parâmetros:
        @param requisicao Dicionário recebido por socket.

        Valor retornado:
        @return Não retorna valor.

        Assertiva de entrada:
        @pre requisicao deve conter usuário, aluno, disciplina, valor, ticket e autenticador.

        Assertiva de saída:
        @post Envia resposta com nota criada e AP-REP, ou erro.

        Exceções:
        @throws Exception Pode propagar exceções de criar_nota para o handle.

        Observações:
        A permissão de professor é avaliada no serviço de domínio.
        ***************************************************************************
        """
        usuario = requisicao.get("usuario")
        aluno = requisicao.get("aluno")
        disciplina = requisicao.get("disciplina")
        valor = requisicao.get("valor")
        ticket_servico = requisicao.get("ticket_servico")
        autenticador = requisicao.get("autenticador")

        if not usuario or not aluno or not disciplina or not valor:
            resposta = {
                "ok": False,
                "erro": "Usuário, aluno, disciplina e nota são obrigatórios."
            }
            enviar_json(self.request, resposta)
            log_erro("SERVIÇO NOTAS", "Dados da nota incompletos.")
            return

        if not ticket_servico or not autenticador:
            resposta = {
                "ok": False,
                "erro": "Ticket de serviço e autenticador são obrigatórios."
            }
            enviar_json(self.request, resposta)
            log_erro("SERVIÇO NOTAS", "Ticket ou autenticador não enviado.")
            return

        log_passo(
            "SERVIÇO NOTAS",
            2,
            "Validando ticket de serviço",
            "O ticket foi emitido pelo TGS e só o serviço de notas consegue abrir."
        )

        log_passo(
            "SERVIÇO NOTAS",
            3,
            "Validando autenticador Cliente-Serviço",
            "Aqui é verificado usuário, timestamp e nonce."
        )

        log_passo(
            "SERVIÇO NOTAS",
            4,
            "Executando operação protegida",
            f"Professor {usuario} está lançando nota para o aluno {aluno}."
        )

        resultado = criar_nota(
            usuario=usuario,
            aluno=aluno,
            disciplina=disciplina,
            valor=valor,
            ticket_servico_criptografado=ticket_servico,
            autenticador_criptografado=autenticador
        )

        log_ok("SERVIÇO NOTAS", "Ticket de serviço validado.")
        log_ok("SERVIÇO NOTAS", "Autenticador validado.")
        log_ok("SERVIÇO NOTAS", "Permissão de professor validada.")
        log_ok("SERVIÇO NOTAS", "Nota cadastrada.")
        log_ok("SERVIÇO NOTAS", "AP-REP gerado para autenticação mútua.")

        log_dados("SERVIÇO NOTAS", "Resultado da operação protegida", resultado)

        resposta = {
            "ok": True,
            "dados": resultado
        }

        enviar_json(self.request, resposta)

        log_passo(
            "SERVIÇO NOTAS",
            5,
            "Resposta enviada ao cliente",
            "A resposta contém o resultado da operação e o AP-REP criptografado."
        )


class ServidorNotasTCP(socketserver.ThreadingTCPServer):
    """
    ***************************************************************************
    Classe: ServidorNotasTCP

    @brief Servidor TCP multithread do serviço protegido de notas.

    @details
    Servidor TCP multithread do serviço protegido de notas.

    Responsabilidades principais:
    - Escutar HOST_SERVICO_NOTAS e PORTA_SERVICO_NOTAS.
    - Criar ManipuladorNotas por conexão.
    - Permitir reutilização de endereço.

    Relação com o protocolo Kerberos:
    Hospeda o serviço final acessado após emissão do ticket de serviço pelo TGS.

    Observações:
    Herda ThreadingTCPServer e não adiciona lógica além da configuração de endereço.
    ***************************************************************************
    """
    allow_reuse_address = True


def iniciar_servidor_notas():
    """
    ***************************************************************************
    Função: iniciar_servidor_notas

    @brief Inicializa o servidor TCP do Serviço de Notas.

    Descrição:
    Instancia ServidorNotasTCP, inicia o atendimento contínuo e fecha o socket ao
    encerrar.

    Parâmetros:
    Não recebe parâmetros explícitos.

    Valor retornado:
    @return Não retorna valor em execução normal.

    Assertiva de entrada:
    @pre HOST_SERVICO_NOTAS e PORTA_SERVICO_NOTAS devem estar disponíveis.

    Assertiva de saída:
    @post Servidor é fechado no bloco finally.

    Exceções:
    @throws Exception Trata KeyboardInterrupt; erros de bind podem propagar.

    Observações:
    Deve ser executado junto do AS e TGS para o fluxo completo via web.
    ***************************************************************************
    """
    servidor = ServidorNotasTCP(
        (HOST_SERVICO_NOTAS, PORTA_SERVICO_NOTAS),
        ManipuladorNotas
    )

    print(
        f"[NOTAS] Serviço de Notas escutando em "
        f"{HOST_SERVICO_NOTAS}:{PORTA_SERVICO_NOTAS}"
    )

    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        print("\n[NOTAS] Servidor encerrado.")
    finally:
        servidor.server_close()


if __name__ == "__main__":
    iniciar_servidor_notas()
