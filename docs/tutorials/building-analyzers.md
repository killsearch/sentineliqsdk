# Construindo Analisadores

Este tutorial detalha a criação de um analisador com qualidade de produção, seguindo os padrões do SDK.

## O que você irá construir:

- Uma classe `<Nome>Analyzer` que estende `sentineliqsdk.analyzers.Analyzer`.
- Um método `execute() -> AnalyzerReport` que retorna um envelope estruturado via `self.report(...)`.
- Um método `run()` que retorna `self.execute()` para uso programático.
- Um exemplo executável em `examples/analyzers/` utilizando `WorkerInput`.

## 1) Definindo a Classe

```python
from __future__ import annotations

from sentineliqsdk import Analyzer
from sentineliqsdk.models import AnalyzerReport


class MyAnalyzer(Analyzer):
    def execute(self) -> AnalyzerReport:
        observable = self.get_data()
        taxonomy = self.build_taxonomy("safe", "namespace", "predicate", str(observable))
        full = {
            "observable": observable,
            "verdict": "safe",
            "taxonomy": [taxonomy.to_dict()],
        }
        return self.report(full)

    def run(self) -> AnalyzerReport:
        return self.execute()
```

## 2) Autoextração de Artefatos

- A autoextração é habilitada por padrão, a menos que `WorkerInput.config.auto_extract` seja `False`.
- O método `artifacts(full_report)` do analisador utiliza o Extractor para encontrar IOCs (Indicadores de Compromisso) no seu relatório, excluindo o observável original.
- Para itens personalizados, construa artefatos explicitamente com `self.build_artifact(...)` e inclua-os no envelope.

## 3) Operações e Ações de Acompanhamento

Utilize `self.build_operation("<tipo>", **params)` e sobrescreva `operations(full_report)` quando precisar sugerir próximos passos (por exemplo, caça, enriquecimento, bloqueio).

## 4) Exemplo e Flags da CLI

- Coloque um exemplo executável em `examples/analyzers/<snake>_example.py`.
- Por padrão, o exemplo deve ser dry-run. Adicione `--execute` para realizar chamadas de rede.
- Use `--include-dangerous` para proteger ações de alto impacto (por exemplo, varreduras).

## 5) Validação

- Execute `poe lint` (ruff + mypy) e `poe test` (pytest) localmente antes de abrir um Pull Request (PR).
