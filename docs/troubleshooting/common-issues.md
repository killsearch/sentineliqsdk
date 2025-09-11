# Solução de Problemas: Problemas Comuns

- **Falhas de Lint (ruff/mypy)**
  - Execute `poe lint` e corrija os problemas encontrados. Garanta que os imports sejam absolutos e o comprimento da linha seja ≤ 100 caracteres.
  - Para erros de tipagem, prefira adicionar tipos precisos aos campos de dataclass e retornos de métodos.

- **Testes Falhando**
  - Execute `poe test` localmente e concentre-se na menor unidade que está falhando primeiro.
  - Use `-k <nome>` para selecionar testes específicos.

- **Erro de TLP/PAP na Inicialização**
  - Mensagem: `TLP is higher than allowed.` ou `PAP is higher than allowed.`
  - Correção: diminua o `tlp`/`pap` em `WorkerInput` ou aumente `max_tlp`/`max_pap` em `WorkerConfig`.

- **Rede Atrás de Proxy**
  - Configure `WorkerInput.config.proxy` (preferencial). O Worker exporta essas configurações para o ambiente do processo para clientes HTTP da stdlib.

- **Exemplo Imprime Apenas o Plano (sem rede)**
  - Adicione `--execute` para realizar chamadas de rede reais.
  - Algumas operações também exigem `--include-dangerous`.

- **Credenciais Ausentes**
  - Shodan: defina `shodan.api_key` em `WorkerConfig.secrets` ou passe `--api-key` para o exemplo.
  - Axur: defina `axur.api_token` em `WorkerConfig.secrets` ou passe `--token`.

- **Erros de Build do MkDocs**
  - Garanta que as dependências de desenvolvimento estejam instaladas: `pip install -e .[dev]` ou `uv sync --dev`.
  - Execute `poe docs` e revise os avisos com `--strict` habilitado.
