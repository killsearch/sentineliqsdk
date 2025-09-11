# Construindo Responders

Responders encapsulam ações como bloquear um endereço IP ou notificar um sistema externo.

## 1) Definindo a Classe

```python
from __future__ import annotations

from sentineliqsdk import Responder
from sentineliqsdk.models import ResponderReport


class BlockIpResponder(Responder):
    def execute(self) -> ResponderReport:
        ip = self.get_data()
        ops = [self.build_operation("block", target=ip)]
        return self.report({"action": "block", "target": ip})

    def run(self) -> ResponderReport:
        return self.execute()
```

## 2) Exemplos e Flags de Segurança

- Coloque os exemplos em `examples/responders/<nome>_example.py`.
- Por padrão, o exemplo deve ser dry-run; adicione `--execute` para realizar as alterações.
- Use `--include-dangerous` para explicitamente proteger operações de alto impacto.

## 3) Entrada e Saída

- Use `WorkerInput(data_type=..., data=...)` para passar o alvo.
- Retorne um `ResponderReport` usando `self.report(full_report)`, opcionalmente incluindo `operations` para tarefas de acompanhamento.
