"""
@file config.py
@brief Configura chaves e endereços dos componentes Kerberos Notas.

@details
Define chaves simétricas fixas em Base64 para TGS e Serviço de Notas e informa
host e porta dos servidores TCP usados no projeto.

Componentes principais:
- CHAVE_SECRETA_TGS
- CHAVE_SECRETA_SERVICO_NOTAS
- HOST_AS, PORTA_AS, HOST_TGS, PORTA_TGS, HOST_SERVICO_NOTAS, PORTA_SERVICO_NOTAS

Papel na arquitetura:
Centraliza parâmetros compartilhados entre cliente, AS, TGS e serviço protegido.
As chaves simulam segredos previamente compartilhados em um ambiente acadêmico.
"""

from kerberos_notas.crypto.crypto_utils import base64_para_bytes


CHAVE_SECRETA_TGS_BASE64 = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="
CHAVE_SECRETA_SERVICO_NOTAS_BASE64 = "MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTE="

CHAVE_SECRETA_TGS = base64_para_bytes(CHAVE_SECRETA_TGS_BASE64)
CHAVE_SECRETA_SERVICO_NOTAS = base64_para_bytes(CHAVE_SECRETA_SERVICO_NOTAS_BASE64)

HOST_AS = "127.0.0.1"
PORTA_AS = 9001

HOST_TGS = "127.0.0.1"
PORTA_TGS = 9002

HOST_SERVICO_NOTAS = "127.0.0.1"
PORTA_SERVICO_NOTAS = 9003
