"""
@file servidor_as.py
@brief Servidor TCP do AS Kerberos Notas.

@details
Expõe a lógica do Servidor de Autenticação por socket TCP, recebendo JSON e
devolvendo respostas padronizadas.

Componentes principais:
- ManipuladorAS
- ServidorASTCP
- iniciar_servidor_as

Papel na arquitetura:
Processo servidor que atende a primeira etapa do fluxo Kerberos.
"""

import socketserver

from kerberos_notas.config import HOST_AS, PORTA_AS
from kerberos_notas.kerberos.as_server import autenticar_no_as
from kerberos_notas.rede.protocolo import enviar_json, receber_json
from kerberos_notas.rede.logs import log_titulo, log_passo, log_ok, log_erro, log_dados


class ManipuladorAS(socketserver.BaseRequestHandler):
    """
    ***************************************************************************
    Classe: ManipuladorAS

    @brief Manipula uma conexão TCP recebida pelo Servidor de Autenticação.

    @details
    Manipula uma conexão TCP recebida pelo Servidor de Autenticação.
    Interpreta a ação solicitada e delega a autenticação para autenticar_no_as.

    Responsabilidades principais:
    - Receber requisição JSON do cliente.
    - Validar ação e campos obrigatórios.
    - Enviar resposta de sucesso ou erro.

    Relação com o protocolo Kerberos:
    Representa a interface de rede do AS, responsável por AS-REQ e AS-REP.

    Observações:
    A classe não armazena estado entre conexões.
    ***************************************************************************
    """

    def handle(self):
        """
        ***************************************************************************
        Função: handle

        @brief Processa uma requisição TCP ao AS.

        Descrição:
        Lê JSON, valida ação "autenticar", verifica presença de usuário e senha,
        chama autenticar_no_as e envia resposta ao cliente.

        Parâmetros:
        Não recebe parâmetros explícitos.

        Valor retornado:
        @return Não retorna valor.

        Assertiva de entrada:
        @pre self.request deve conter uma conexão TCP ativa com mensagem JSON válida.

        Assertiva de saída:
        @post Envia JSON com ok verdadeiro e dados, ou ok falso e erro.

        Exceções:
        @throws Exception Captura exceções gerais e as converte em resposta de erro.

        Observações:
        Faz a ponte entre transporte TCP e lógica Kerberos do AS.
        ***************************************************************************
        """
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
    """
    ***************************************************************************
    Classe: ServidorASTCP

    @brief Servidor TCP com threads para atender conexões do AS.

    @details
    Servidor TCP com threads para atender conexões do AS.

    Responsabilidades principais:
    - Escutar HOST_AS e PORTA_AS.
    - Criar manipuladores ManipuladorAS.
    - Permitir reutilização do endereço.

    Relação com o protocolo Kerberos:
    Hospeda a interface de rede do Servidor de Autenticação.

    Observações:
    Herda o comportamento de ThreadingTCPServer.
    ***************************************************************************
    """
    allow_reuse_address = True


def iniciar_servidor_as():
    """
    ***************************************************************************
    Função: iniciar_servidor_as

    @brief Inicializa o servidor TCP do AS.

    Descrição:
    Cria ServidorASTCP no endereço configurado, imprime mensagem de escuta e
    executa serve_forever até interrupção.

    Parâmetros:
    Não recebe parâmetros explícitos.

    Valor retornado:
    @return Não retorna valor em execução normal.

    Assertiva de entrada:
    @pre HOST_AS e PORTA_AS devem estar livres para bind.

    Assertiva de saída:
    @post Servidor é fechado no bloco finally ao terminar.

    Exceções:
    @throws Exception Trata KeyboardInterrupt; outras exceções de bind podem propagar.

    Observações:
    Usado para executar o AS como processo independente.
    ***************************************************************************
    """
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
