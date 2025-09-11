# Início Rápido

Esta página demonstra o caminho mínimo para criar e executar um analisador utilizando dataclasses no SentinelIQ SDK.

## Exemplo Mínimo de Analisador

```python
from __future__ import annotations

import json

from sentineliqsdk import Analyzer, WorkerInput
from sentineliqsdk.models import AnalyzerReport


class ReputationAnalyzer(Analyzer):
    """Marca '1.2.3.4' como malicioso, e outros como seguros."""

    def execute(self) -> AnalyzerReport:
        observable = self.get_data()
        verdict = "malicious" if observable == "1.2.3.4" else "safe"
        tax = self.build_taxonomy(level=verdict, namespace="reputation", predicate="static",
                                  value=str(observable))
        return self.report({
            "observable": observable,
            "verdict": verdict,
            "taxonomy": [tax.to_dict()],
        })

    def run(self) -> AnalyzerReport:
        return self.execute()


if __name__ == "__main__":
    report = ReputationAnalyzer(WorkerInput(data_type="ip", data="1.2.3.4")).run()
    print(json.dumps(report.full_report, ensure_ascii=False))
```

## Como Executar

Para executar o analisador, salve o código acima em um arquivo (por exemplo, `your_script.py`) e execute-o via terminal:

```bash
python path/to/your_script.py
```

## Utilizando o `runner` (Facilitador)

O SentinelIQ SDK oferece um `runner` para simplificar a execução de analisadores:

```python
from sentineliqsdk import runner, WorkerInput

runner(ReputationAnalyzer, WorkerInput(data_type="ip", data="1.2.3.4"))
```

## Próximos Passos

- Consulte o [Guia Completo do Agente](https://killsearch.github.io/sentineliqsdk/guides/guide/) para convenções e padrões de desenvolvimento.
- Utilize `poe new-analyzer -- --name MeuNovoAnalisador` para criar um novo analisador a partir de um template.
