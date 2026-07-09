# Fluxo Kerberos Implementado

Este documento descreve o fluxo de autenticação Kerberos implementado no projeto Portal de Notas.

O sistema foi dividido em quatro componentes principais:

* Cliente Web;
* Servidor de Autenticação, chamado AS;
* Servidor de Emissão de Tickets, chamado TGS;
* Serviço protegido de notas.

A implementação utiliza apenas criptografia de chave simétrica, conforme solicitado no trabalho.

## 1. Autenticação inicial no AS

O usuário acessa o sistema e informa seu nome de usuário e sua senha.

A senha não é enviada diretamente para outros serviços como chave criptográfica. Primeiro, o sistema utiliza uma função de derivação de chave, chamada KDF, para transformar a senha do usuário em uma chave simétrica.

No projeto, essa derivação é feita com PBKDF2-HMAC-SHA256, usando um salt individual para cada usuário e várias iterações. O objetivo é dificultar ataques de força bruta contra senhas fracas.

O AS consulta o arquivo de usuários e verifica se o usuário existe. Em seguida, deriva novamente a chave a partir da senha informada e compara o verificador gerado com o verificador armazenado no cadastro.

Se a senha estiver correta, o AS gera uma chave de sessão entre Cliente e TGS. Essa chave será usada pelo cliente para se comunicar com o TGS na próxima etapa.

O AS então devolve ao cliente:

1. uma parte criptografada com a chave derivada da senha do usuário;
2. um Ticket Granting Ticket, chamado TGT, criptografado com a chave secreta do TGS.

O cliente consegue abrir apenas a primeira parte, pois conhece a senha e consegue derivar a mesma chave. O cliente não consegue abrir o TGT, pois ele está criptografado com a chave secreta do TGS.

## 2. Obtenção do ticket de serviço no TGS

Após receber o TGT, o cliente precisa solicitar acesso ao serviço protegido de notas.

Para isso, o cliente envia ao TGS:

* o TGT recebido do AS;
* o nome do serviço desejado, neste caso `notas`;
* um autenticador criptografado com a chave de sessão Cliente-TGS.

O autenticador contém informações como:

* nome do usuário;
* timestamp;
* nonce.

O TGS abre o TGT usando sua chave secreta. Dentro do TGT, o TGS encontra o nome do usuário, a chave de sessão Cliente-TGS e o tempo de validade do ticket.

Depois, o TGS usa a chave de sessão Cliente-TGS para descriptografar o autenticador enviado pelo cliente. O TGS verifica se o usuário do autenticador é o mesmo usuário do TGT e se o timestamp está dentro da janela de validade.

Se tudo estiver correto, o TGS gera uma nova chave de sessão, agora entre Cliente e Serviço de Notas.

O TGS devolve ao cliente:

1. uma parte criptografada com a chave Cliente-TGS, contendo a chave Cliente-Serviço;
2. um ticket de serviço criptografado com a chave secreta do serviço de notas.

O cliente consegue abrir a primeira parte e obter a chave Cliente-Serviço. Porém, não consegue abrir o ticket de serviço, pois ele foi criptografado com a chave secreta do serviço de notas.

## 3. Acesso ao serviço protegido de notas

Com o ticket de serviço em mãos, o cliente pode acessar o serviço de notas.

Para isso, o cliente envia ao serviço:

* o ticket de serviço emitido pelo TGS;
* um novo autenticador criptografado com a chave de sessão Cliente-Serviço.

O serviço de notas abre o ticket usando sua própria chave secreta. Dentro do ticket, ele encontra o usuário autenticado e a chave de sessão Cliente-Serviço.

Em seguida, o serviço usa essa chave de sessão para abrir o autenticador enviado pelo cliente.

O serviço valida:

* se o usuário do ticket é o mesmo usuário do autenticador;
* se o timestamp do autenticador ainda é válido;
* se o nonce ainda não foi utilizado;
* se o ticket pertence ao serviço correto.

Se a validação for aprovada, o serviço libera a operação solicitada.

No caso do Portal de Notas:

* usuários do tipo professor podem cadastrar notas;
* usuários do tipo aluno podem consultar suas próprias notas;
* professores podem consultar todas as notas cadastradas.

## 4. Autenticação mútua

Além de o serviço autenticar o cliente, o cliente também precisa confirmar que está conversando com o serviço correto.

Para isso, o serviço retorna uma resposta chamada AP-REP.

Essa resposta é criptografada com a chave de sessão Cliente-Serviço. Ela contém:

* o timestamp recebido do cliente acrescido de 1;
* o mesmo nonce enviado pelo cliente.

O cliente descriptografa a resposta usando a chave de sessão Cliente-Serviço. Se conseguir abrir a resposta e confirmar o timestamp e o nonce, ele conclui que o serviço realmente conhece a chave de sessão emitida pelo TGS.

Dessa forma, ocorre autenticação mútua:

* o serviço confirma a identidade do cliente;
* o cliente confirma a identidade do serviço.

## 5. Proteção contra replay

O sistema usa timestamp e nonce nos autenticadores.

O timestamp reduz o tempo em que uma mensagem antiga pode ser reaproveitada. Já o nonce funciona como um identificador único da requisição.

No serviço de notas, os nonces utilizados são armazenados durante a execução do programa. Caso o mesmo autenticador seja enviado novamente, o serviço rejeita a requisição como uma possível tentativa de replay.

Essa proteção é simples e adequada para o contexto acadêmico do projeto. Em um sistema real, seria necessário armazenar os nonces de forma mais robusta e limpar registros antigos periodicamente.

## 6. Resumo do fluxo

O fluxo geral é:

```text
Cliente → AS:
    usuário e senha

AS → Cliente:
    chave Cliente-TGS criptografada
    TGT criptografado com chave do TGS

Cliente → TGS:
    TGT
    autenticador Cliente-TGS
    nome do serviço desejado

TGS → Cliente:
    chave Cliente-Serviço criptografada
    ticket de serviço criptografado com chave do serviço

Cliente → Serviço de Notas:
    ticket de serviço
    autenticador Cliente-Serviço

Serviço de Notas → Cliente:
    AP-REP criptografado confirmando autenticação mútua
```

Esse fluxo segue a ideia central do Kerberos apresentada em aula: o usuário se autentica uma vez no AS, obtém um TGT, solicita tickets ao TGS e usa esses tickets para acessar serviços protegidos sem enviar a senha novamente.
