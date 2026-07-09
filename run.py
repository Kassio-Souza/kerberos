"""
@file run.py
@brief Ponto de entrada da aplicação web Kerberos Notas.

@details
Cria a aplicação Flask por meio de create_app e executa o servidor de
desenvolvimento quando o arquivo é chamado diretamente.

Componentes principais:
- app
- create_app

Papel na arquitetura:
Inicializa o cliente web que aciona o fluxo Kerberos com AS, TGS e serviço de notas.
"""

from kerberos_notas.client.routes import create_app

app = create_app()

if __name__ == "__main__":
    app.run(debug=True)
