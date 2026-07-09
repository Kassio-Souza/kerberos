"""
@file servidor_tgs.py
@brief Servidor TCP do Ticket Granting Server.

@details
Expõe por socket a emissão de tickets de serviço a partir de TGT e autenticador
Cliente-TGS.

Componentes principais:
- ManipuladorTGS
- ServidorTGSTCP
- iniciar_servidor_tgs

Papel na arquitetura:
Processo servidor da segunda etapa do fluxo Kerberos.
"""

import socketserver

from kerberos_notas.config import HOST_TGS, PORTA_TGS
from kerberos_notas.kerberos.tgs_server import emitir_ticket_servico
from kerberos_notas.rede.protocolo import enviar_json, receber_json
from kerberos_notas.rede.logs import log_titulo, log_passo, log_ok, log_erro, log_dados


class ManipuladorTGS(socketserver.BaseRequestHandler):
    """
    ***************************************************************************
    Classe: ManipuladorTGS

    @brief Manipula conexões TCP destinadas ao TGS e delega a emissão do ticket de.

    @details
    Manipula conexões TCP destinadas ao TGS e delega a emissão do ticket de
    serviço para emitir_ticket_servico.

    Responsabilidades principais:
    - Receber usuário, TGT, serviço e autenticador.
    - Validar ação solicitada.
    - Enviar resposta JSON com ticket de serviço ou erro.

    Relação com o protocolo Kerberos:
    Representa a interface de rede do TGS no fluxo TGS-REQ/TGS-REP.

    Observações:
    A validação criptográfica fica em kerberos.tgs_server.
    ***************************************************************************
    """

    def handle(self):
        """
        ***************************************************************************
        Função: handle

        @brief Processa requisição TCP de emissão de ticket.

        Descrição:
        Lê a requisição, exige ação "emitir_ticket" e campos obrigatórios, chama
        emitir_ticket_servico e envia resposta padronizada.

        Parâmetros:
        Não recebe parâmetros explícitos.

        Valor retornado:
        @return Não retorna valor.

        Assertiva de entrada:
        @pre Requisição deve conter JSON delimitado por newline.

        Assertiva de saída:
        @post Cliente recebe ok verdadeiro com dados ou ok falso com erro.

        Exceções:
        @throws Exception Captura exceções gerais e responde com mensagem de erro.

        Observações:
        Não descriptografa diretamente os tickets; delega à camada de domínio.
        ***************************************************************************
        """
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
    """
    ***************************************************************************
    Classe: ServidorTGSTCP

    @brief Servidor TCP multithread que hospeda o TGS.

    @details
    Servidor TCP multithread que hospeda o TGS.

    Responsabilidades principais:
    - Escutar HOST_TGS e PORTA_TGS.
    - Criar ManipuladorTGS por conexão.
    - Permitir reutilização de endereço.

    Relação com o protocolo Kerberos:
    Disponibiliza o TGS como processo de rede.

    Observações:
    Usa ThreadingTCPServer da biblioteca padrão.
    ***************************************************************************
    """
    allow_reuse_address = True


def iniciar_servidor_tgs():
    """
    ***************************************************************************
    Função: iniciar_servidor_tgs

    @brief Inicializa o servidor TCP do TGS.

    Descrição:
    Instancia ServidorTGSTCP, inicia loop de atendimento e fecha o servidor ao
    encerrar.

    Parâmetros:
    Não recebe parâmetros explícitos.

    Valor retornado:
    @return Não retorna valor em execução normal.

    Assertiva de entrada:
    @pre HOST_TGS e PORTA_TGS devem estar disponíveis.

    Assertiva de saída:
    @post Servidor é fechado ao sair do loop.

    Exceções:
    @throws Exception Trata KeyboardInterrupt; erros de criação do socket podem propagar.

    Observações:
    Usado quando o TGS é executado separadamente.
    ***************************************************************************
    """
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
