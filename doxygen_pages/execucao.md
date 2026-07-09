# Como executar o código {#como_executar}

Esta página resume os comandos necessários para preparar o ambiente, executar o
Kerberos Notas, rodar os testes e gerar a documentação Doxygen.

## Pré-requisitos

Antes de executar o projeto, verifique se o ambiente possui:

- Python 3.10 ou superior;
- `pip`;
- suporte a ambiente virtual com `venv`;
- Doxygen instalado e disponível no terminal;
- terminal Linux, WSL ou Windows PowerShell;
- navegador web para acessar a aplicação Flask.

No Linux ou WSL, confira:

```bash
python3 --version
python3 -m pip --version
doxygen --version
```

No Windows PowerShell, confira:

```powershell
py --version
py -m pip --version
doxygen --version
```

## Criar a venv

Na raiz do projeto, crie o ambiente virtual:

### Linux ou WSL

```bash
python3 -m venv .venv
```

### Windows PowerShell

```powershell
py -m venv .venv
```

## Ativar a venv no WSL/Linux

```bash
source .venv/bin/activate
```

Depois de ativar, configure o `PYTHONPATH` para que o pacote em `src` seja
encontrado:

```bash
export PYTHONPATH=src
```

## Ativar a venv no Windows

No PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Se o PowerShell bloquear a ativação, libere scripts para o usuário atual:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Depois ative novamente:

```powershell
.\.venv\Scripts\Activate.ps1
```

Configure o `PYTHONPATH`:

```powershell
$env:PYTHONPATH='src'
```

## Instalar dependências

Com a venv ativada, instale as dependências do projeto:

### Linux ou WSL

```bash
python3 -m pip install -r requirements.txt
```

### Windows PowerShell

```powershell
py -m pip install -r requirements.txt
```

Para desenvolvimento e testes, garanta também o `pytest`:

```bash
python -m pip install pytest
```

## Executar a aplicação

A execução completa usa dois terminais com a venv ativada e `PYTHONPATH`
configurado.

### Terminal 1: iniciar AS, TGS e Serviço de Notas

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

Esse terminal deve permanecer aberto. Ele inicia:

- AS em `127.0.0.1:9001`;
- TGS em `127.0.0.1:9002`;
- Serviço de Notas em `127.0.0.1:9003`.

### Terminal 2: iniciar o Cliente Web Flask

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

## Endereço no navegador

Com os servidores e o Flask em execução, acesse:

```text
http://127.0.0.1:5000
```

## Usuários de teste

O arquivo `data/usuarios.json` do projeto contém usuários cadastrados para uso
local. Para demonstração acadêmica, use:

| Perfil | Usuário | Senha |
| ------ | ------- | ----- |
| Professor | `prof` | `123` |
| Aluno 1 | `aluno1` | `123` |
| Aluno 2 | `aluno2` | `123` |

Essas senhas são apenas para demonstração acadêmica em ambiente local.

As senhas não ficam armazenadas em texto puro; o cadastro mantém salt e
verificador da chave derivada. Para criar outros usuários, execute:

### Linux ou WSL

```bash
python3 scripts/criar_usuario.py
```

### Windows PowerShell

```powershell
py scripts/criar_usuario.py
```

Crie pelo menos um usuário professor e um usuário aluno para testar o fluxo
completo.

## Executar os testes com pytest

Com a venv ativada:

```bash
pytest
```

Se o comando `pytest` não estiver no `PATH`, execute:

```bash
python -m pytest
```

Também é possível chamar diretamente o executável da venv em Linux ou WSL:

```bash
.venv/bin/pytest
```

## Gerar a documentação com Doxygen

Na raiz do projeto, execute:

```bash
doxygen Doxyfile
```

O HTML gerado fica em:

```text
docs/html
```

Abra `docs/html/index.html` no navegador para consultar a documentação.
