"""
@file iniciar_servidores.py
@brief Inicializa AS, TGS e Serviço de Notas em threads.

@details
Executa os três servidores TCP do projeto no mesmo processo para facilitar a
demonstração local do fluxo Kerberos.

Componentes principais:
- iniciar_em_thread
- main

Papel na arquitetura:
Orquestra os processos simulados do Kerberos Notas durante testes manuais.
"""

import sys
import threading
import time
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1] / "src"))

from kerberos_notas.servidores.servidor_as import iniciar_servidor_as
from kerberos_notas.servidores.servidor_tgs import iniciar_servidor_tgs
from kerberos_notas.servidores.servidor_notas import iniciar_servidor_notas


def iniciar_em_thread(nome, funcao):
    """
    ***************************************************************************
    Função: iniciar_em_thread

    @brief Inicia uma função de servidor em thread daemon.

    Descrição:
    Cria uma thread com nome informado, aponta target para a função recebida,
    marca como daemon e inicia sua execução.

    Parâmetros:
    @param nome Nome da thread.
    @param funcao Função que será executada pela thread.

    Valor retornado:
    @return Retorna o objeto threading.Thread iniciado.

    Assertiva de entrada:
    @pre funcao deve ser chamável.

    Assertiva de saída:
    @post Thread é iniciada e retornada.

    Exceções:
    @throws Exception Pode propagar RuntimeError de threading.

    Observações:
    Facilita execução simultânea de AS, TGS e serviço no ambiente acadêmico.
    ***************************************************************************
    """
    thread = threading.Thread(target=funcao, name=nome, daemon=True)
    thread.start()
    return thread


def main():
    """
    ***************************************************************************
    Função: main

    @brief Sobe os três servidores e mantém o processo ativo.

    Descrição:
    Inicia AS, TGS e Serviço de Notas em threads daemon, imprime endereços e
    mantém loop até KeyboardInterrupt.

    Parâmetros:
    Não recebe parâmetros explícitos.

    Valor retornado:
    @return Não retorna valor em execução normal.

    Assertiva de entrada:
    @pre As portas configuradas devem estar livres.

    Assertiva de saída:
    @post Servidores permanecem ativos até interrupção.

    Exceções:
    @throws Exception Trata KeyboardInterrupt para encerramento manual.

    Observações:
    É um facilitador para demonstrações; não substitui implantação real.
    ***************************************************************************
    """
    print("Iniciando servidores Kerberos via sockets...\n")

    iniciar_em_thread("Servidor AS", iniciar_servidor_as)
    iniciar_em_thread("Servidor TGS", iniciar_servidor_tgs)
    iniciar_em_thread("Servidor Notas", iniciar_servidor_notas)

    print("\nServidores iniciados:")
    print("AS     -> 127.0.0.1:9001")
    print("TGS    -> 127.0.0.1:9002")
    print("NOTAS  -> 127.0.0.1:9003")
    print("\nPressione CTRL + C para encerrar.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nEncerrando servidores...")


if __name__ == "__main__":
    main()
