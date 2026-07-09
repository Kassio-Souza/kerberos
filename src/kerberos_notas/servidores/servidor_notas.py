import socketserver

from kerberos_notas.config import HOST_SERVICO_NOTAS, PORTA_SERVICO_NOTAS
from kerberos_notas.notes.service import criar_nota, listar_notas
from kerberos_notas.rede.protocolo import enviar_json, receber_json
from kerberos_notas.rede.logs import log_titulo, log_passo, log_ok, log_erro, log_dados


class ManipuladorNotas(socketserver.BaseRequestHandler):
    """
    Serviço de Notas protegido por Kerberos.

    Ele recebe:
    - ticket de serviço;
    - autenticador Cliente-Serviço;
    - operação solicitada.

    Só libera a operação depois de validar o ticket e o autenticador.
    """

    def handle(self):
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
    allow_reuse_address = True


def iniciar_servidor_notas():
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