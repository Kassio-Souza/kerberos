# Kerberos Notas

@mainpage Kerberos Notas

## Visao geral

Kerberos Notas e uma implementacao academica em Python de um fluxo Kerberos
simplificado aplicado a um sistema de notas. O projeto separa os papeis de
Cliente, Servidor de Autenticacao (AS), Ticket Granting Server (TGS) e Servico
de Notas protegido, demonstrando como tickets, autenticadores e chaves de
sessao podem ser usados para controlar o acesso a uma aplicacao.

A documentacao gerada pelo Doxygen descreve os modulos Python, as funcoes, as
classes de servidores TCP, as rotas do cliente web e os utilitarios
criptograficos que sustentam o fluxo.

## Execução rápida

Para preparar o ambiente, iniciar os servidores, acessar a aplicação web, rodar
os testes e gerar a documentação, consulte:
[Como executar o código](\ref como_executar).

## Objetivo academico

O objetivo do projeto e apresentar, em codigo executavel, os principais
conceitos do protocolo Kerberos em um contexto didatico:

- autenticacao inicial do usuario sem armazenar senha em texto puro;
- derivacao de chave de longo prazo a partir de senha e salt;
- emissao de Ticket Granting Ticket (TGT) pelo AS;
- emissao de ticket de servico pelo TGS;
- uso de autenticadores com timestamp e nonce;
- protecao de mensagens com criptografia simetrica;
- autenticacao mutua entre cliente e servico protegido;
- autorizacao de acesso ao sistema de notas por papel de usuario.

## Arquitetura

O sistema e dividido em quatro componentes principais.

### Cliente

O cliente web esta em `src/kerberos_notas/client`. Ele recebe usuario e senha,
executa o fluxo Kerberos por sockets, armazena em sessao o ticket de servico e a
chave Cliente-Servico, e chama o Servico de Notas para listar ou criar notas.

Arquivos principais:

- `client/routes.py`: rotas Flask, fluxo Kerberos do cliente e validacao AP-REP;
- `client/cliente_socket.py`: chamadas socket para AS, TGS e Servico de Notas.

### Servidor de Autenticacao (AS)

O AS valida a senha do usuario por meio de KDF e verificador salvo. Quando a
senha e valida, ele gera a chave de sessao Cliente-TGS e cria um TGT
criptografado com a chave secreta do TGS.

Arquivos principais:

- `kerberos/as_server.py`: logica de autenticacao inicial;
- `servidores/servidor_as.py`: servidor TCP que expõe o AS.

### Ticket Granting Server (TGS)

O TGS abre e valida o TGT, valida o autenticador Cliente-TGS e emite um ticket
para o servico solicitado. A resposta ao cliente contem a chave
Cliente-Servico protegida pela chave Cliente-TGS.

Arquivos principais:

- `kerberos/tgs_server.py`: validacao de TGT, autenticador e ticket de servico;
- `servidores/servidor_tgs.py`: servidor TCP do TGS.

### Servico de Notas

O Servico de Notas abre o ticket de servico, valida o autenticador
Cliente-Servico, rejeita replay por nonce e aplica a regra de autorizacao:
professores podem criar e listar todas as notas; alunos listam apenas suas
proprias notas.

Arquivos principais:

- `notes/service.py`: autenticacao no servico, AP-REP e regras de acesso;
- `notes/repository.py`: persistencia das notas em JSON;
- `servidores/servidor_notas.py`: servidor TCP do servico protegido.

## Fluxo Kerberos

1. O usuario informa login e senha no cliente web.
2. O cliente envia usuario e senha ao AS.
3. O AS carrega o salt do usuario, deriva a chave da senha e compara o
   verificador salvo.
4. O AS gera a chave Cliente-TGS e cria um TGT.
5. A resposta do AS e criptografada com a chave derivada da senha do cliente.
6. O cliente abre a resposta do AS, obtem a chave Cliente-TGS e transporta o TGT.
7. O cliente cria um autenticador Cliente-TGS e solicita ao TGS acesso ao
   servico `notas`.
8. O TGS abre o TGT, valida o autenticador e gera a chave Cliente-Servico.
9. O TGS cria o ticket de servico criptografado para o Servico de Notas.
10. O cliente cria um autenticador Cliente-Servico e chama o Servico de Notas.
11. O servico abre o ticket, valida o autenticador, verifica replay e executa a
    operacao autorizada.
12. O servico retorna AP-REP para que o cliente confirme a autenticacao mutua.

## Arquivos principais

- `src/kerberos_notas/config.py`: chaves compartilhadas e portas dos servidores;
- `src/kerberos_notas/crypto/kdf.py`: salt, PBKDF2-HMAC-SHA256 e verificador;
- `src/kerberos_notas/crypto/crypto_utils.py`: AES-GCM e conversoes Base64;
- `src/kerberos_notas/kerberos/tickets.py`: TGT, tickets de servico e validade;
- `src/kerberos_notas/kerberos/authenticator.py`: autenticadores criptografados;
- `src/kerberos_notas/kerberos/as_server.py`: logica do AS;
- `src/kerberos_notas/kerberos/tgs_server.py`: logica do TGS;
- `src/kerberos_notas/notes/service.py`: servico protegido e autenticacao mutua;
- `src/kerberos_notas/client/routes.py`: aplicacao web cliente;
- `src/kerberos_notas/rede/protocolo.py`: mensagens JSON sobre sockets.

## Criptografia utilizada

O projeto utiliza criptografia simetrica e derivacao de chave para representar
os conceitos centrais do Kerberos:

- PBKDF2-HMAC-SHA256 em `crypto/kdf.py` para derivar a chave do cliente a partir
  da senha e do salt;
- SHA-256 para gerar o verificador salvo no cadastro;
- AES-GCM em `crypto/crypto_utils.py` para confidencialidade e autenticidade de
  tickets, autenticadores e respostas;
- Base64 para transportar chaves, nonces e ciphertexts em estruturas JSON;
- nonces e timestamps para limitar reutilizacao de autenticadores e reduzir
  risco de replay.

As chaves secretas do TGS e do Servico de Notas ficam centralizadas em
`config.py`, como simplificacao academica para demonstracao local.

## Como navegar na documentacao

Use o menu lateral da documentacao HTML para navegar:

- **Inicio**: esta pagina, com a visao geral do projeto;
- **Paginas do Projeto**: paginas Markdown adicionais, incluindo o README;
- **Modulos Python**: namespaces e modulos gerados a partir do pacote
  `kerberos_notas`;
- **Classes**: classes dos servidores TCP e seus metodos;
- **Codigo-Fonte**: arquivos Python documentados e suas referencias.

Para entender o fluxo completo, uma boa ordem de leitura e:

1. `crypto/kdf.py` e `crypto/crypto_utils.py`;
2. `kerberos/tickets.py` e `kerberos/authenticator.py`;
3. `kerberos/as_server.py`;
4. `kerberos/tgs_server.py`;
5. `notes/service.py`;
6. `client/routes.py`.

## Execucao da documentacao

A documentacao e gerada com:

```bash
doxygen Doxyfile
```

O HTML gerado fica em `docs/html`.
