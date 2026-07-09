import socketserver

from kerberos_notas.config import HOST_AS, PORTA_AS
from kerberos_notas.kerberos.as_server import autenticar_no_as
from kerberos_notas.rede.protocolo import enviar_json, receber_json
from kerberos_notas.rede.logs import log_titulo, log_passo, log_ok, log_erro, log_dados


class ManipuladorAS(socketserver.BaseRequestHandler):
    """
    Servidor de Autenticação do Kerberos.

    Ele recebe usuário e senha, valida a senha usando KDF e emite:
    - chave de sessão Cliente-TGS;
    - TGT criptografado para o TGS.
    """

    def handle(self):
        log_titulo("AS", "Nova conexão recebida no Servidor de Autenticação")

        try:
            requisicao = receber_json(self.request)

            log_passo("AS", 1, "Requisição recebida via socket")
            log_dados("AS", "Conteúdo recebido", requisicao)

            acao = requisicao.get("acao")

            if acao != "autenticar":
                resposta = {
                    "ok": False,
                    "erro": "Ação inválida para o Servidor de Autenticação."
                }
                enviar_json(self.request, resposta)
                log_erro("AS", "Ação inválida recebida.")
                return

            usuario = requisicao.get("usuario")
            senha = requisicao.get("senha")

            if not usuario or not senha:
                resposta = {
                    "ok": False,
                    "erro": "Usuário e senha são obrigatórios."
                }
                enviar_json(self.request, resposta)
                log_erro("AS", "Usuário ou senha não informado.")
                return

            log_passo(
                "AS",
                2,
                "Validando usuário e senha",
                "O AS vai buscar o usuário, usar o salt cadastrado e derivar a chave com KDF."
            )

            log_passo(
                "AS",
                3,
                "Executando autenticação Kerberos no AS",
                "Se a senha estiver correta, o AS gera a chave Cliente-TGS e o TGT."
            )

            resposta_as = autenticar_no_as(usuario, senha)

            log_ok("AS", "Senha validada com sucesso.")
            log_ok("AS", "Chave de sessão Cliente-TGS gerada.")
            log_ok("AS", "TGT criado e criptografado com a chave secreta do TGS.")

            log_dados("AS", "Resposta criptografada que será enviada ao cliente", resposta_as)

            resposta = {
                "ok": True,
                "dados": resposta_as
            }

            enviar_json(self.request, resposta)

            log_passo(
                "AS",
                4,
                "Resposta enviada ao cliente",
                "O cliente recebe dados criptografados e um TGT que ele transporta, mas não consegue abrir."
            )

        except Exception as erro:
            resposta = {
                "ok": False,
                "erro": str(erro)
            }

            enviar_json(self.request, resposta)
            log_erro("AS", str(erro))


class ServidorASTCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


def iniciar_servidor_as():
    servidor = ServidorASTCP((HOST_AS, PORTA_AS), ManipuladorAS)

    print(f"[AS] Servidor de Autenticação escutando em {HOST_AS}:{PORTA_AS}")

    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        print("\n[AS] Servidor encerrado.")
    finally:
        servidor.server_close()


if __name__ == "__main__":
    iniciar_servidor_as()