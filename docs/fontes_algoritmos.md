# Algoritmos Criptográficos Utilizados

Este documento descreve os algoritmos criptográficos usados na implementação do Portal de Notas protegido por Kerberos.

A implementação utiliza apenas primitivas criptográficas básicas, sem bibliotecas prontas de Kerberos.

## 1. Criptografia simétrica

O protocolo Kerberos do projeto foi implementado exclusivamente com criptografia de chave simétrica.

Isso significa que as entidades envolvidas compartilham chaves secretas para criptografar e descriptografar dados.

No projeto, existem diferentes tipos de chave:

* chave derivada da senha do usuário;
* chave secreta do TGS;
* chave secreta do serviço de notas;
* chave de sessão Cliente-TGS;
* chave de sessão Cliente-Serviço.

As chaves de sessão são geradas aleatoriamente durante o fluxo de autenticação. Elas são temporárias e usadas apenas durante a comunicação entre duas partes específicas.

## 2. PBKDF2-HMAC-SHA256

A senha do usuário não é utilizada diretamente como chave criptográfica.

Primeiro, ela passa por uma Função de Derivação de Chave, conhecida como KDF.

A KDF escolhida foi PBKDF2-HMAC-SHA256.

Ela recebe:

* a senha do usuário;
* um salt individual;
* um número de iterações;
* o tamanho da chave desejada.

O salt impede que dois usuários com a mesma senha gerem exatamente o mesmo resultado. As iterações aumentam o custo computacional de ataques de força bruta.

No projeto, a chave derivada é usada para validar a senha do usuário e abrir a resposta do AS.

## 3. Salt

Cada usuário possui um salt armazenado no arquivo de usuários.

O salt não precisa ser secreto, mas precisa ser único ou aleatório. Ele é usado junto com a senha na KDF.

O objetivo do salt é dificultar ataques com tabelas pré-computadas, como rainbow tables.

## 4. Verificador de senha

O sistema não armazena a senha original do usuário.

Durante o cadastro, a senha é processada pela KDF e gera uma chave derivada. A partir dessa chave, o sistema gera um verificador.

Durante o login, o AS deriva novamente a chave usando a senha informada e compara o verificador resultante com o verificador armazenado.

Se os verificadores forem iguais, o sistema considera a senha correta.

## 5. AES-GCM

Para criptografar estruturas como tickets, autenticadores e respostas, o projeto utiliza AES-GCM.

AES é um algoritmo de criptografia simétrica amplamente utilizado. O modo GCM foi escolhido porque oferece confidencialidade e autenticação dos dados.

Isso significa que, além de esconder o conteúdo criptografado, o AES-GCM também permite detectar alterações indevidas na mensagem.

Se alguém modificar o conteúdo criptografado, a descriptografia falha.

## 6. Chaves de sessão

O Kerberos evita que a senha seja usada diretamente em todas as comunicações.

Por isso, o sistema gera chaves de sessão temporárias.

A chave Cliente-TGS é criada pelo AS e permite que o cliente se comunique com o TGS.

A chave Cliente-Serviço é criada pelo TGS e permite que o cliente se comunique com o serviço de notas.

Essas chaves são independentes e possuem finalidades diferentes.

## 7. Ticket Granting Ticket

O Ticket Granting Ticket, ou TGT, é emitido pelo AS.

Ele contém informações como:

* usuário autenticado;
* chave de sessão Cliente-TGS;
* timestamp de emissão;
* tempo de validade.

O TGT é criptografado com a chave secreta do TGS. Por isso, o cliente pode armazenar e encaminhar o TGT, mas não consegue ler nem alterar seu conteúdo.

## 8. Ticket de serviço

O ticket de serviço é emitido pelo TGS.

Ele contém informações como:

* usuário autenticado;
* nome do serviço;
* chave de sessão Cliente-Serviço;
* timestamp de emissão;
* tempo de validade.

Esse ticket é criptografado com a chave secreta do serviço de notas.

Assim como no TGT, o cliente pode transportar o ticket, mas não consegue modificar o conteúdo dele.

## 9. Autenticador

O autenticador é uma mensagem criada pelo cliente e criptografada com uma chave de sessão.

Ele contém:

* usuário;
* timestamp;
* nonce.

O autenticador serve para provar que o cliente conhece a chave de sessão associada ao ticket.

O timestamp ajuda a evitar reutilização de mensagens antigas. O nonce ajuda a identificar uma requisição única.

## 10. Autenticação mútua

A autenticação mútua foi implementada por meio de uma resposta criptografada do serviço para o cliente.

Depois que o serviço valida o ticket e o autenticador, ele envia uma resposta AP-REP criptografada com a chave de sessão Cliente-Serviço.

Essa resposta contém:

* timestamp do cliente acrescido de 1;
* nonce recebido do cliente.

O cliente abre essa resposta com a chave de sessão Cliente-Serviço. Se o timestamp e o nonce forem confirmados, o cliente sabe que o serviço também conhece a chave correta.

Isso confirma que o serviço é autêntico.

## 11. Geração de números aleatórios

As chaves de sessão e nonces são gerados com mecanismos aleatórios da linguagem e da biblioteca criptográfica utilizada.

A geração aleatória é importante porque impede que as chaves temporárias sejam previsíveis.

## 12. Justificativa das escolhas

PBKDF2-HMAC-SHA256 foi escolhido porque é uma KDF conhecida, simples de explicar e adequada para derivar chaves a partir de senhas.

AES-GCM foi escolhido porque combina criptografia e verificação de integridade em um único mecanismo.

O uso de tickets criptografados com chaves secretas de longo prazo segue a lógica central do Kerberos: o cliente transporta tickets, mas não consegue alterá-los.

O uso de timestamp e nonce nos autenticadores reduz o risco de ataques de replay.

Essas escolhas tornam a implementação compatível com o objetivo acadêmico do trabalho, sem recorrer a bibliotecas prontas de Kerberos.
