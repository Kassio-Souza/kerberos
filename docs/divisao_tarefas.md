# Divisão de Tarefas

## Pessoa 1 — AS, senha e KDF

Responsável por:

* Implementar a base de usuários;
* Implementar a derivação de chave a partir da senha do usuário;
* Validar usuário e senha;
* Gerar a chave de sessão Cliente-TGS;
* Criar e criptografar o Ticket Granting Ticket (TGT);
* Montar a resposta do Authentication Server (AS) para o cliente.

## Pessoa 2 — TGS e emissão de ticket de serviço

Responsável por:

* Receber o TGT e o autenticador enviados pelo cliente;
* Validar o TGT;
* Validar o autenticador do cliente;
* Gerar a chave de sessão Cliente-Serviço;
* Criar o ticket de serviço;
* Criptografar o ticket de serviço com a chave do serviço;
* Montar a resposta do Ticket Granting Server (TGS) para o cliente.

## Pessoa 3 — Serviço de Notas e autenticação mútua

Responsável por:

* Implementar o Serviço de Notas protegido por Kerberos;
* Validar o ticket de serviço recebido do cliente;
* Validar o autenticador do cliente;
* Implementar a autenticação mútua entre cliente e serviço;
* Criar funções de criar, listar, editar e excluir notas;
* Proteger o acesso às notas usando o fluxo Kerberos.

## Pessoa 4 — Cliente, integração e testes

Responsável por:

* Implementar o cliente da aplicação;
* Criar a interface web simples;
* Fazer login com usuário e senha;
* Chamar o Authentication Server (AS);
* Chamar o Ticket Granting Server (TGS);
* Chamar o Serviço de Notas;
* Exibir mensagens de erro de autenticação;
* Integrar a interface ao fluxo Kerberos completo;
* Organizar e executar os testes gerais do sistema;
* Auxiliar na integração final entre AS, TGS, Cliente e Serviço de Notas.

## Responsabilidade de todos

Todos devem participar de:

* Integração dos módulos;
* Testes das partes individuais e do fluxo completo;
* Correção de erros encontrados durante a integração;
* Escrita do relatório;
* Preparação da apresentação;
* Gravação do vídeo.
