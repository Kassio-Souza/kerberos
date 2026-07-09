# Portal de Notas com Autenticação Kerberos

Este projeto implementa uma versão didática do protocolo de autenticação Kerberos utilizando Python. O sistema simula um Portal de Notas protegido por autenticação baseada em tickets, chaves de sessão e criptografia simétrica.

O projeto foi desenvolvido para a disciplina de Segurança Computacional, com foco principal na implementação prática do fluxo Kerberos envolvendo:

* Cliente;
* Servidor de Autenticação, AS;
* Ticket Granting Server, TGS;
* Serviço protegido de Notas.

A aplicação permite que professores lancem notas para alunos e que alunos consultem apenas suas próprias notas. O acesso ao serviço de notas é protegido pelo fluxo Kerberos.

---

# Objetivo do projeto

O objetivo principal é demonstrar, na prática, o funcionamento do protocolo Kerberos.

O sistema implementa:

* autenticação de usuário por senha;
* derivação de chave a partir da senha com KDF;
* emissão de Ticket Granting Ticket, TGT;
* emissão de ticket de serviço;
* autenticação por ticket;
* autenticação mútua entre cliente e serviço;
* comunicação entre componentes usando sockets TCP;
* serviço protegido de Portal de Notas.

---

# Arquitetura geral

A arquitetura foi separada em quatro partes principais:

```text
Cliente Web Flask
        |
        | socket TCP
        v
Servidor de Autenticação - AS
        |
        | socket TCP
        v
Ticket Granting Server - TGS
        |
        | socket TCP
        v
Serviço de Notas protegido
```

Na prática, o Cliente Flask se comunica com cada servidor por meio de sockets TCP e mensagens JSON.

Cada servidor roda em uma porta própria:

```text
AS                 127.0.0.1:9001
TGS                127.0.0.1:9002
Serviço de Notas   127.0.0.1:9003
Cliente Flask      127.0.0.1:5000
```

---

# Funcionamento resumido do Kerberos

O fluxo implementado segue estas etapas:

1. O usuário informa login e senha no Cliente Web.
2. O cliente envia a autenticação inicial para o AS.
3. O AS valida a senha usando uma chave derivada por KDF.
4. O AS emite uma chave de sessão Cliente-TGS e um TGT.
5. O cliente envia o TGT e um autenticador para o TGS.
6. O TGS valida o TGT e o autenticador.
7. O TGS emite uma chave de sessão Cliente-Serviço e um ticket para o Serviço de Notas.
8. O cliente envia o ticket de serviço e um novo autenticador ao Serviço de Notas.
9. O Serviço de Notas valida o ticket e o autenticador.
10. O Serviço de Notas responde com AP-REP para autenticação mútua.
11. O cliente valida o AP-REP e confirma que o serviço é legítimo.
12. A operação protegida é liberada.

---

# Serviço protegido implementado

O serviço protegido escolhido foi um Portal de Notas.

Existem dois tipos de usuário:

## Professor

O professor pode:

* acessar o sistema após autenticação Kerberos;
* selecionar um aluno cadastrado;
* lançar uma ou várias notas;
* escolher disciplinas cadastradas em uma lista;
* adicionar disciplina personalizada;
* visualizar as notas agrupadas por aluno.

## Aluno

O aluno pode:

* acessar o sistema após autenticação Kerberos;
* visualizar apenas suas próprias notas.

---

# Tecnologias utilizadas

O projeto utiliza:

* Python 3;
* Flask;
* sockets TCP;
* JSON para troca de mensagens;
* biblioteca `cryptography`;
* Pytest para testes.

---

# Algoritmos e mecanismos utilizados

## Criptografia simétrica

O projeto utiliza exclusivamente criptografia de chave simétrica, conforme exigido no trabalho.

São usadas chaves diferentes para funções diferentes:

* chave derivada da senha do usuário;
* chave secreta do TGS;
* chave secreta do Serviço de Notas;
* chave de sessão Cliente-TGS;
* chave de sessão Cliente-Serviço.

## KDF

A senha do usuário não é usada diretamente como chave.

Primeiro, ela é processada por uma Função de Derivação de Chave, KDF. O projeto utiliza:

```text
PBKDF2-HMAC-SHA256
```

A KDF usa:

* senha do usuário;
* salt individual;
* número de iterações;
* tamanho da chave desejada.

Isso torna mais difícil um ataque direto contra senhas fracas.

## Tickets

O projeto usa dois tipos principais de tickets:

```text
TGT - Ticket Granting Ticket
Ticket de Serviço
```

O TGT é emitido pelo AS e criptografado com a chave secreta do TGS.

O ticket de serviço é emitido pelo TGS e criptografado com a chave secreta do Serviço de Notas.

O cliente transporta os tickets, mas não consegue abrir nem alterar o conteúdo deles.

## Autenticadores

Os autenticadores são mensagens criptografadas com chaves de sessão.

Eles contêm:

* usuário;
* timestamp;
* nonce.

O autenticador prova que o cliente conhece a chave de sessão associada ao ticket.

## Autenticação mútua

A autenticação mútua é feita por meio de uma resposta AP-REP.

Depois que o Serviço de Notas valida o ticket e o autenticador, ele responde ao cliente com uma mensagem criptografada usando a chave Cliente-Serviço.

Essa resposta contém:

* timestamp confirmado;
* nonce confirmado.

O cliente abre essa resposta e confirma que o serviço realmente conhece a chave de sessão. Assim, o cliente também autentica o serviço.

## Proteção contra replay

O projeto usa timestamp e nonce para reduzir ataques de repetição.

O Serviço de Notas mantém em memória os nonces já utilizados durante a execução. Se o mesmo autenticador for enviado novamente, ele é rejeitado.

---

# Estrutura do projeto

```text
.
├── data/
│   ├── usuarios.json
│   └── notas.json
│
├── docs/
│   ├── fluxo_kerberos.md
│   └── fontes_algoritmos.md
│
├── scripts/
│   ├── criar_usuario.py
│   └── iniciar_servidores.py
│
├── src/
│   └── kerberos_notas/
│       ├── client/
│       │   ├── routes.py
│       │   └── cliente_socket.py
│       │
│       ├── crypto/
│       │   ├── crypto_utils.py
│       │   └── kdf.py
│       │
│       ├── kerberos/
│       │   ├── as_server.py
│       │   ├── tgs_server.py
│       │   ├── tickets.py
│       │   └── authenticator.py
│       │
│       ├── notes/
│       │   ├── service.py
│       │   └── repository.py
│       │
│       ├── rede/
│       │   ├── protocolo.py
│       │   └── logs.py
│       │
│       ├── servidores/
│       │   ├── servidor_as.py
│       │   ├── servidor_tgs.py
│       │   └── servidor_notas.py
│       │
│       ├── storage/
│       │   └── json_store.py
│       │
│       ├── usuarios.py
│       └── config.py
│
├── static/
│   └── style.css
│
├── templates/
│   ├── layout.html
│   ├── login.html
│   ├── notas.html
│   └── erro.html
│
├── tests/
├── requirements.txt
├── run.py
└── README.md
```

---

# Como executar no Linux ou WSL

## 1. Entrar na pasta do projeto

```bash
cd kerberos
```

Caso sua pasta tenha outro nome, entre na pasta correta do projeto.

---

## 2. Criar ambiente virtual

```bash
python3 -m venv .venv
```

---

## 3. Ativar ambiente virtual

```bash
source .venv/bin/activate
```

---

## 4. Instalar dependências

```bash
python3 -m pip install -r requirements.txt
```

---

## 5. Configurar o PYTHONPATH

```bash
export PYTHONPATH=src
```

Esse comando precisa ser executado no terminal onde o projeto será rodado.

---

# Como executar no Windows PowerShell

## 1. Entrar na pasta do projeto

```powershell
cd kerberos
```

Caso sua pasta tenha outro nome, entre na pasta correta do projeto.

---

## 2. Criar ambiente virtual

```powershell
py -m venv .venv
```

---

## 3. Ativar ambiente virtual

```powershell
.\.venv\Scripts\Activate.ps1
```

Se o PowerShell bloquear a ativação da venv, execute:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Depois tente ativar novamente:

```powershell
.\.venv\Scripts\Activate.ps1
```

---

## 4. Instalar dependências

```powershell
py -m pip install -r requirements.txt
```

---

## 5. Configurar o PYTHONPATH

```powershell
$env:PYTHONPATH='src'
```

---

# Cadastro de usuários

Antes de usar o sistema, é necessário criar usuários.

Execute:

## Linux ou WSL

```bash
python3 scripts/criar_usuario.py
```

## Windows PowerShell

```powershell
py scripts/criar_usuario.py
```

O sistema solicitará:

```text
Usuário:
Senha:

Tipo de usuário:
1 - Aluno
2 - Professor
Escolha o tipo:
```

Crie pelo menos um professor e um aluno.

Exemplo de professor:

```text
Usuário: professor
Senha: 123456
Tipo: 2
```

Exemplo de aluno:

```text
Usuário: aluno1
Senha: 123456
Tipo: 1
```

Os usuários são salvos no arquivo:

```text
data/usuarios.json
```

A senha original não é salva. O sistema salva apenas o salt, o verificador da chave derivada e o tipo do usuário.

---

# Executando o projeto

A execução completa usa dois terminais.

---

## Terminal 1 — iniciar AS, TGS e Serviço de Notas

No Linux ou WSL:

```bash
export PYTHONPATH=src
python3 scripts/iniciar_servidores.py
```

No Windows PowerShell:

```powershell
$env:PYTHONPATH='src'
py scripts/iniciar_servidores.py
```

Resultado esperado:

```text
Iniciando servidores Kerberos via sockets...

[AS] Servidor de Autenticação escutando em 127.0.0.1:9001
[TGS] Ticket Granting Server escutando em 127.0.0.1:9002
[NOTAS] Serviço de Notas escutando em 127.0.0.1:9003

Servidores iniciados:
AS     -> 127.0.0.1:9001
TGS    -> 127.0.0.1:9002
NOTAS  -> 127.0.0.1:9003
```

Esse terminal deve permanecer aberto.

---

## Terminal 2 — iniciar o Cliente Web Flask

No Linux ou WSL:

```bash
export PYTHONPATH=src
python3 run.py
```

No Windows PowerShell:

```powershell
$env:PYTHONPATH='src'
py run.py
```

Depois acesse no navegador:

```text
http://127.0.0.1:5000
```

---

# Fluxo recomendado para teste

Para testar o sistema completo:

1. Inicie os servidores Kerberos.
2. Inicie o Flask.
3. Acesse `http://127.0.0.1:5000`.
4. Faça login com um usuário do tipo professor.
5. Selecione um aluno na lista.
6. Selecione uma disciplina.
7. Informe a nota.
8. Se quiser, clique em adicionar outra disciplina.
9. Salve as notas.
10. Faça logout.
11. Faça login com o usuário aluno.
12. Confira se o aluno visualiza apenas suas próprias notas.

---

# Logs no terminal

O projeto possui logs organizados no terminal para facilitar a demonstração.

Os logs mostram o funcionamento das quatro partes:

```text
CLIENTE WEB
AS
TGS
SERVIÇO NOTAS
```

Durante o login, é possível acompanhar:

```text
[CLIENTE WEB] Iniciando fluxo Kerberos completo
[CLIENTE WEB] Chamando o AS via socket
[AS] Validando usuário e senha
[AS] Chave Cliente-TGS gerada
[AS] TGT criado e criptografado
[CLIENTE WEB] Abrindo resposta do AS
[CLIENTE WEB] Criando autenticador para o TGS
[CLIENTE WEB] Chamando o TGS via socket
[TGS] Abrindo o TGT
[TGS] Validando autenticador Cliente-TGS
[TGS] Emitindo ticket para o serviço de notas
[CLIENTE WEB] Obtendo chave Cliente-Serviço
```

Durante o acesso às notas, é possível acompanhar:

```text
[CLIENTE WEB] Chamando o Serviço de Notas via socket
[SERVIÇO NOTAS] Validando ticket de serviço
[SERVIÇO NOTAS] Validando autenticador Cliente-Serviço
[SERVIÇO NOTAS] Executando operação protegida
[SERVIÇO NOTAS] AP-REP gerado para autenticação mútua
[CLIENTE WEB] Validando autenticação mútua
[CLIENTE WEB] Autenticação mútua confirmada
```

Esses logs foram colocados para facilitar a apresentação e demonstrar claramente que AS, TGS e Serviço de Notas estão sendo chamados separadamente.

Por segurança, os logs não exibem senhas nem chaves completas. Valores sensíveis são mascarados.

---

# Executando testes

Com o ambiente virtual ativado, execute:

## Linux ou WSL

```bash
export PYTHONPATH=src
python3 -m pytest -q
```

## Windows PowerShell

```powershell
$env:PYTHONPATH='src'
py -m pytest -q
```

Resultado esperado:

```text
passed
```

A quantidade exata de testes pode variar conforme a versão do projeto.

---

# Principais arquivos do projeto

## `src/kerberos_notas/kerberos/as_server.py`

Contém a lógica principal do Servidor de Autenticação, AS.

Responsabilidades:

* validar usuário e senha;
* usar KDF para derivar a chave da senha;
* gerar chave de sessão Cliente-TGS;
* emitir o TGT.

---

## `src/kerberos_notas/kerberos/tgs_server.py`

Contém a lógica principal do Ticket Granting Server, TGS.

Responsabilidades:

* abrir e validar o TGT;
* validar o autenticador Cliente-TGS;
* gerar chave Cliente-Serviço;
* emitir ticket de serviço.

---

## `src/kerberos_notas/notes/service.py`

Contém a lógica do Serviço de Notas protegido.

Responsabilidades:

* validar ticket de serviço;
* validar autenticador Cliente-Serviço;
* bloquear replay simples por nonce;
* aplicar regra de permissão de professor;
* listar notas;
* criar notas;
* gerar AP-REP para autenticação mútua.

---

## `src/kerberos_notas/rede/protocolo.py`

Contém a camada básica de comunicação via socket.

Responsabilidades:

* enviar JSON por socket;
* receber JSON por socket;
* abrir conexão com servidor TCP.

---

## `src/kerberos_notas/servidores/servidor_as.py`

Servidor TCP do AS.

Escuta na porta:

```text
127.0.0.1:9001
```

---

## `src/kerberos_notas/servidores/servidor_tgs.py`

Servidor TCP do TGS.

Escuta na porta:

```text
127.0.0.1:9002
```

---

## `src/kerberos_notas/servidores/servidor_notas.py`

Servidor TCP do Serviço de Notas.

Escuta na porta:

```text
127.0.0.1:9003
```

---

## `src/kerberos_notas/client/routes.py`

Contém as rotas Flask.

Responsabilidades:

* login;
* execução do fluxo Kerberos pelo cliente;
* acesso à página de notas;
* chamada dos servidores via sockets;
* validação do AP-REP.

---

## `src/kerberos_notas/client/cliente_socket.py`

Contém as funções usadas pelo Cliente Web para chamar os servidores TCP.

Responsabilidades:

* chamar o AS;
* chamar o TGS;
* chamar o Serviço de Notas.

---

## `scripts/criar_usuario.py`

Script usado para cadastrar usuários.

Permite criar:

* aluno;
* professor.

---

## `scripts/iniciar_servidores.py`

Script usado para iniciar simultaneamente:

* AS;
* TGS;
* Serviço de Notas.

---

# Observações importantes de segurança

Este projeto foi desenvolvido para fins acadêmicos.

Algumas decisões foram simplificadas para facilitar a implementação e a explicação:

* as chaves secretas do TGS e do Serviço de Notas ficam no arquivo de configuração;
* os dados são salvos em arquivos JSON;
* os servidores rodam localmente em `127.0.0.1`;
* o controle de nonces usados fica em memória;
* não há banco de dados real;
* não há HTTPS, pois o foco do trabalho é o Kerberos.

Em um ambiente real, seria necessário:

* proteger melhor as chaves secretas;
* usar banco de dados;
* proteger os arquivos de configuração;
* usar TLS na comunicação de rede;
* implementar controle persistente de replay;
* adicionar logs de auditoria com rotação;
* melhorar validações e permissões.

---


# Limitações conhecidas

A implementação é acadêmica e simplificada.

As principais limitações são:

* as chaves secretas ficam fixas no arquivo de configuração;
* os usuários e notas são salvos em JSON;
* a proteção contra replay usa memória local;
* os servidores rodam localmente;
* não há interface administrativa completa;
* não há edição ou exclusão de notas;
* não há banco de dados relacional.

Essas limitações não impedem a demonstração do Kerberos, pois o foco principal do trabalho é o protocolo de autenticação, e não a complexidade do Portal de Notas.

---

# Resumo final

Este projeto demonstra o funcionamento do Kerberos em um Portal de Notas.

A implementação contempla:

* AS;
* TGS;
* Serviço protegido;
* autenticação por senha;
* KDF;
* tickets;
* chaves de sessão;
* autenticação mútua;
* proteção simples contra replay;
* comunicação por sockets;
* execução simultânea dos servidores;
* logs didáticos para apresentação.

O serviço de notas é simples, mas suficiente para demonstrar o uso do protocolo Kerberos protegendo uma aplicação real.
