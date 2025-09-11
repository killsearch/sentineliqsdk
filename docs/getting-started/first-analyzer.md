# Seu Primeiro Analisador

Este tutorial irá guiá-lo através do processo de scaffolding, implementação e execução do seu primeiro analisador no SentinelIQ SDK.

## 1) Scaffolding com Poe

Comece criando a estrutura básica do seu analisador usando o comando `poe new-analyzer`:

```bash
poe new-analyzer -- --name Reputation
```

Este comando irá gerar os seguintes arquivos:

- `src/sentineliqsdk/analyzers/reputation.py`: Onde a lógica principal do seu analisador será implementada.
- `examples/analyzers/reputation_example.py`: Um exemplo executável para testar seu analisador.
- `tests/analyzers/test_reputation.py`: Arquivo de testes (se os templates de scaffolding incluírem testes).

## 2) Implementando `execute()` e `run()`

Edite o arquivo `src/sentineliqsdk/analyzers/reputation.py` para incluir a lógica do seu analisador. O esqueleto abaixo demonstra como marcar um IP específico como malicioso:

```python
from __future__ import annotations

from sentineliqsdk import Analyzer
from sentineliqsdk.models import AnalyzerReport


class ReputationAnalyzer(Analyzer):
    def execute(self) -> AnalyzerReport:
        observable = self.get_data()
        verdict = "malicious" if observable == "1.2.3.4" else "safe"
        tax = self.build_taxonomy(verdict, "reputation", "static", str(observable))
        return self.report({
            "observable": observable,
            "verdict": verdict,
            "taxonomy": [tax.to_dict()],
        })

    def run(self) -> AnalyzerReport:
        return self.execute()
```

## 3) Executando o Exemplo

Para testar seu analisador, execute o arquivo de exemplo gerado:

```bash
python examples/analyzers/reputation_example.py
```

## 4) Lint e Testes

É crucial garantir a qualidade do código. Execute as ferramentas de linting e testes para verificar conformidade e funcionalidade:

```bash
pore lint
pore test
```

## Dicas Importantes

- **Modo Dry-Run**: Exemplos devem ser executados em modo dry-run por padrão. Exija o uso de `--execute` para chamadas de rede ou operações que alteram o estado.
- **Taxonomia**: Sempre inclua a taxonomia no `full_report` usando `.to_dict()`.
- **Extração Automática**: Utilize `auto_extract` (padrão) para extrair IOCs (Indicadores de Compromisso) automaticamente do seu relatório completo.
