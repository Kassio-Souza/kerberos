import socketserver

from kerberos_notas.config import HOST_TGS, PORTA_TGS
from kerberos_notas.kerberos.tgs_server import emitir_ticket_servico
from kerberos_notas.rede.protocolo import enviar_json, receber_json
from kerberos_notas.rede.logs import log_titulo, log_passo, log_ok, log_erro, log_dados


class ManipuladorTGS(socketserver.BaseRequestHandler):
    """
    Ticket Granting Server.

    Ele recebe:
    - usuário;
    - TGT emitido pelo AS;
    - autenticador Cliente-TGS;
    - nome do serviço desejado.

    Se tudo estiver válido, emite:
    - chave de sessão Cliente-Serviço;
    - ticket de serviço criptografado para o serviço de notas.
    """

    def handle(self):
        log_titulo("TGS", "Nova conexão recebida no Ticket Granting Server")

        try:
            requisicao = receber_json(self.request)

            log_passo("TGS", 1, "Requisição recebida via socket")
            log_dados("TGS", "Conteúdo recebido", requisicao)

            acao = requisicao.get("acao")

            if acao != "emitir_ticket":
                resposta = {
                    "ok": False,
                    "erro": "Ação inválida para o Ticket Granting Server."
                }
                enviar_json(self.request, resposta)
                log_erro("TGS", "Ação inválida recebida.")
                return

            usuario = requisicao.get("usuario")
            tgt = requisicao.get("tgt")
            servico = requisicao.get("servico")
            autenticador = requisicao.get("autenticador")

            if not usuario or not tgt or not servico or not autenticador:
                resposta = {
                    "ok": False,
                    "erro": "Usuário, TGT, serviço e autenticador são obrigatórios."
                }
                enviar_json(self.request, resposta)
                log_erro("TGS", "Dados obrigatórios não foram enviados.")
                return

            log_passo(
                "TGS",
                2,
                "Abrindo o TGT",
                "O TGS usa sua chave secreta para abrir o TGT. O cliente não consegue abrir esse ticket."
            )

            log_passo(
                "TGS",
                3,
                "Validando autenticador Cliente-TGS",
                "O autenticador prova que o cliente conhece a chave de sessão Cliente-TGS."
            )

            log_passo(
                "TGS",
                4,
                "Emitindo ticket para o serviço solicitado",
                f"Serviço solicitado: {servico}"
            )

            resposta_tgs = emitir_ticket_servico(
                usuario=usuario,
                servico=servico,
                tgt_criptografado=tgt,
                autenticador_criptografado=autenticador
            )

            log_ok("TGS", "TGT validado com sucesso.")
            log_ok("TGS", "Autenticador Cliente-TGS validado.")
            log_ok("TGS", "Chave de sessão Cliente-Serviço gerada.")
            log_ok("TGS", "Ticket de serviço criado e criptografado com a chave do serviço.")

            log_dados("TGS", "Resposta enviada ao cliente", resposta_tgs)

            resposta = {
                "ok": True,
                "dados": resposta_tgs
            }

            enviar_json(self.request, resposta)

            log_passo(
                "TGS",
                5,
                "Resposta enviada ao cliente",
                "O cliente recebe a chave Cliente-Serviço criptografada e o ticket do serviço de notas."
            )

        except Exception as erro:
            resposta = {
                "ok": False,
                "erro": str(erro)
            }

            enviar_json(self.request, resposta)
            log_erro("TGS", str(erro))


class ServidorTGSTCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


def iniciar_servidor_tgs():
    servidor = ServidorTGSTCP((HOST_TGS, PORTA_TGS), ManipuladorTGS)

    print(f"[TGS] Ticket Granting Server escutando em {HOST_TGS}:{PORTA_TGS}")

    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        print("\n[TGS] Servidor encerrado.")
    finally:
        servidor.server_close()


if __name__ == "__main__":
    iniciar_servidor_tgs()