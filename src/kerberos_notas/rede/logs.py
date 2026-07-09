"""
@file logs.py
@brief Logs didáticos com mascaramento de dados sensíveis.

@details
Imprime etapas do fluxo Kerberos no terminal e sanitiza campos como senha,
chaves, nonces, salts e ciphertexts antes de exibição.

Componentes principais:
- sanitizar
- log_passo
- log_dados

Papel na arquitetura:
Apoia demonstração acadêmica do protocolo sem expor segredos completos nos logs.
"""

from datetime import datetime
import json


MOSTRAR_LOGS = True


def _hora_atual() -> str:
    """
    ***************************************************************************
    Função: _hora_atual

    @brief Formata a hora corrente para logs.

    Descrição:
    Obtém datetime.now e retorna somente hora, minuto e segundo.

    Parâmetros:
    Não recebe parâmetros explícitos.

    Valor retornado:
    @return Retorna string no formato HH:MM:SS.

    Assertiva de entrada:
    @pre Relógio do sistema deve estar disponível.

    Assertiva de saída:
    @post Retorna texto usado nos prefixos de log.

    Exceções:
    @throws Exception Não trata exceções explicitamente.

    Observações:
    Função interna sem papel criptográfico.
    ***************************************************************************
    """
    return datetime.now().strftime("%H:%M:%S")


def _mascarar_texto(valor: str) -> str:
    """
    ***************************************************************************
    Função: _mascarar_texto

    @brief Mascara texto sensível ou longo.

    Descrição:
    Substitui valores curtos por asteriscos e resume valores longos mantendo
    apenas prefixo, sufixo e tamanho.

    Parâmetros:
    @param valor Texto que será mascarado.

    Valor retornado:
    @return Retorna string mascarada.

    Assertiva de entrada:
    @pre valor deve ser string.

    Assertiva de saída:
    @post Retorna texto que não expõe integralmente o valor original.

    Exceções:
    @throws Exception Pode propagar TypeError se valor não suportar len/fatiamento.

    Observações:
    Ajuda a demonstrar o fluxo sem imprimir chaves completas.
    ***************************************************************************
    """
    if len(valor) <= 12:
        return "***"

    return f"{valor[:8]}...{valor[-6:]} ({len(valor)} chars)"


def _eh_campo_sensivel(chave: str) -> bool:
    """
    ***************************************************************************
    Função: _eh_campo_sensivel

    @brief Identifica nomes de campos sensíveis.

    Descrição:
    Compara a chave em minúsculas com termos associados a senha, chave,
    verificador, ciphertext, nonce e salt.

    Parâmetros:
    @param chave Nome do campo a avaliar.

    Valor retornado:
    @return Retorna True se o campo deve ser mascarado.

    Assertiva de entrada:
    @pre chave deve ser string.

    Assertiva de saída:
    @post Retorna booleano usado por _preparar_valor.

    Exceções:
    @throws Exception Pode propagar AttributeError se chave não for string.

    Observações:
    A lista é heurística e voltada aos campos usados no projeto.
    ***************************************************************************
    """
    chave = chave.lower()

    campos_sensiveis = [
        "senha",
        "password",
        "chave",
        "key",
        "verificador",
        "ciphertext",
        "tag",
        "nonce",
        "salt",
    ]

    return any(campo in chave for campo in campos_sensiveis)


def _preparar_valor(chave, valor):
    """
    ***************************************************************************
    Função: _preparar_valor

    @brief Prepara valores para log seguro.

    Descrição:
    Percorre recursivamente dicionários e listas, mascarando strings sensíveis
    ou muito longas.

    Parâmetros:
    @param chave Nome do campo associado ao valor.
    @param valor Valor a preparar para exibição.

    Valor retornado:
    @return Retorna valor sanitizado.

    Assertiva de entrada:
    @pre valor pode ser dict, list, str ou outro tipo serializável.

    Assertiva de saída:
    @post Retorna estrutura equivalente com segredos mascarados.

    Exceções:
    @throws Exception Pode propagar exceções de iteração em estruturas incompatíveis.

    Observações:
    Preserva formato geral das mensagens Kerberos para fins didáticos.
    ***************************************************************************
    """
    if isinstance(valor, dict):
        return {k: _preparar_valor(k, v) for k, v in valor.items()}

    if isinstance(valor, list):
        return [_preparar_valor(chave, item) for item in valor]

    if isinstance(valor, str):
        if _eh_campo_sensivel(str(chave)):
            return _mascarar_texto(valor)

        if len(valor) > 80:
            return _mascarar_texto(valor)

        return valor

    return valor


def sanitizar(dados):
    """
    ***************************************************************************
    Função: sanitizar

    @brief Remove ou mascara informações sensíveis antes do log.

    Descrição:
    Aplica _preparar_valor sobre dicionários ou listas e retorna outros tipos sem
    alteração.

    Parâmetros:
    @param dados Estrutura a ser preparada para exibição.

    Valor retornado:
    @return Retorna dados sanitizados.

    Assertiva de entrada:
    @pre dados pode ser qualquer valor aceito pelos logs.

    Assertiva de saída:
    @post Estruturas com campos sensíveis têm valores mascarados.

    Exceções:
    @throws Exception Pode propagar exceções de _preparar_valor.

    Observações:
    Não altera os dados originais usados pelo protocolo.
    ***************************************************************************
    """
    if isinstance(dados, dict):
        return {k: _preparar_valor(k, v) for k, v in dados.items()}

    if isinstance(dados, list):
        return [_preparar_valor("", item) for item in dados]

    return dados


def log_linha(componente: str, mensagem: str = ""):
    """
    ***************************************************************************
    Função: log_linha

    @brief Imprime uma linha simples de log.

    Descrição:
    Exibe componente e mensagem com timestamp quando MOSTRAR_LOGS está ativo.

    Parâmetros:
    @param componente Nome do componente que gera o log.
    @param mensagem Texto opcional.

    Valor retornado:
    @return Não retorna valor.

    Assertiva de entrada:
    @pre componente e mensagem devem ser convertíveis para string.

    Assertiva de saída:
    @post Linha é impressa ou a função retorna sem efeito se logs estiverem desativados.

    Exceções:
    @throws Exception Pode propagar erros de print.

    Observações:
    Utilitário geral de apresentação do fluxo.
    ***************************************************************************
    """
    if not MOSTRAR_LOGS:
        return

    print(f"[{_hora_atual()}] [{componente}] {mensagem}", flush=True)


def log_titulo(componente: str, titulo: str):
    """
    ***************************************************************************
    Função: log_titulo

    @brief Imprime um título de seção de log.

    Descrição:
    Exibe separadores e título para destacar início de conexões ou fases.

    Parâmetros:
    @param componente Componente responsável.
    @param titulo Título da seção.

    Valor retornado:
    @return Não retorna valor.

    Assertiva de entrada:
    @pre componente e titulo devem ser strings.

    Assertiva de saída:
    @post Bloco visual é impresso quando logs estão ativos.

    Exceções:
    @throws Exception Pode propagar erros de saída padrão.

    Observações:
    Usado por AS, TGS, cliente e serviço para separar etapas.
    ***************************************************************************
    """
    if not MOSTRAR_LOGS:
        return

    print("\n" + "=" * 78, flush=True)
    print(f"[{_hora_atual()}] [{componente}] {titulo}", flush=True)
    print("=" * 78, flush=True)


def log_passo(componente: str, numero: int, titulo: str, detalhe: str | None = None):
    """
    ***************************************************************************
    Função: log_passo

    @brief Imprime uma etapa numerada do fluxo.

    Descrição:
    Mostra componente, número da etapa, título e detalhe opcional.

    Parâmetros:
    @param componente Componente responsável pelo passo.
    @param numero Número da etapa.
    @param titulo Descrição curta da etapa.
    @param detalhe Texto adicional opcional.

    Valor retornado:
    @return Não retorna valor.

    Assertiva de entrada:
    @pre numero deve representar a ordem do passo no fluxo mostrado.

    Assertiva de saída:
    @post Passo é impresso quando logs estão ativos.

    Exceções:
    @throws Exception Pode propagar erros de print.

    Observações:
    Ajuda a explicar visualmente AS, TGS e autenticação mútua.
    ***************************************************************************
    """
    if not MOSTRAR_LOGS:
        return

    print(f"[{_hora_atual()}] [{componente}] ETAPA {numero} - {titulo}", flush=True)

    if detalhe:
        print(f"    -> {detalhe}", flush=True)


def log_ok(componente: str, mensagem: str):
    """
    ***************************************************************************
    Função: log_ok

    @brief Imprime mensagem de sucesso.

    Descrição:
    Exibe prefixo OK associado ao componente informado.

    Parâmetros:
    @param componente Componente responsável.
    @param mensagem Texto de sucesso.

    Valor retornado:
    @return Não retorna valor.

    Assertiva de entrada:
    @pre componente e mensagem devem ser strings.

    Assertiva de saída:
    @post Mensagem é impressa quando logs estão ativos.

    Exceções:
    @throws Exception Pode propagar erros de saída padrão.

    Observações:
    Não altera estado do protocolo.
    ***************************************************************************
    """
    if not MOSTRAR_LOGS:
        return

    print(f"[{_hora_atual()}] [{componente}] OK - {mensagem}", flush=True)


def log_erro(componente: str, mensagem: str):
    """
    ***************************************************************************
    Função: log_erro

    @brief Imprime mensagem de erro.

    Descrição:
    Exibe prefixo ERRO associado ao componente informado.

    Parâmetros:
    @param componente Componente responsável.
    @param mensagem Texto do erro.

    Valor retornado:
    @return Não retorna valor.

    Assertiva de entrada:
    @pre componente e mensagem devem ser strings.

    Assertiva de saída:
    @post Erro é impresso quando logs estão ativos.

    Exceções:
    @throws Exception Pode propagar erros de saída padrão.

    Observações:
    Registra falhas sem tratá-las.
    ***************************************************************************
    """
    if not MOSTRAR_LOGS:
        return

    print(f"[{_hora_atual()}] [{componente}] ERRO - {mensagem}", flush=True)


def log_dados(componente: str, titulo: str, dados):
    """
    ***************************************************************************
    Função: log_dados

    @brief Imprime dados estruturados sanitizados.

    Descrição:
    Sanitiza dados, serializa em JSON indentado e imprime cada linha com recuo.

    Parâmetros:
    @param componente Componente responsável pelo log.
    @param titulo Título do bloco de dados.
    @param dados Estrutura a exibir.

    Valor retornado:
    @return Não retorna valor.

    Assertiva de entrada:
    @pre dados deve ser serializável por json.dumps após sanitização.

    Assertiva de saída:
    @post Dados são exibidos com campos sensíveis mascarados.

    Exceções:
    @throws Exception Pode propagar erros de sanitização ou serialização JSON.

    Observações:
    Útil para apresentação acadêmica dos pacotes sem expor chaves completas.
    ***************************************************************************
    """
    if not MOSTRAR_LOGS:
        return

    dados_limpos = sanitizar(dados)
    texto = json.dumps(dados_limpos, indent=4, ensure_ascii=False)

    print(f"[{_hora_atual()}] [{componente}] {titulo}:", flush=True)

    for linha in texto.splitlines():
        print(f"    {linha}", flush=True)
