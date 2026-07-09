import sys
import threading
import time
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1] / "src"))

from kerberos_notas.servidores.servidor_as import iniciar_servidor_as
from kerberos_notas.servidores.servidor_tgs import iniciar_servidor_tgs
from kerberos_notas.servidores.servidor_notas import iniciar_servidor_notas


def iniciar_em_thread(nome, funcao):
    thread = threading.Thread(target=funcao, name=nome, daemon=True)
    thread.start()
    return thread


def main():
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