---
title: CyberChef Analyzer
---

Processa dados usando um servidor CyberChef (endpoint `/bake`). Suporta receitas básicas: `FromHex`, `FromBase64`, `FromCharCode`.

## Uso Programático

```python
from __future__ import annotations
import json
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.cyberchef import CyberchefAnalyzer

input_data = WorkerInput(
    data_type="other",
    data="666f6f",  # "foo" em hex
    config=WorkerConfig(params={
        "cyberchef.url": "http://localhost:8000",
        "cyberchef.service": "FromHex",
    })
)

report = CyberchefAnalyzer(input_data).execute()
print(json.dumps(report.full_report, ensure_ascii=False))
```

## Parâmetros (WorkerConfig)

- `cyberchef.url` (obrigatório): Base URL do servidor CyberChef.
- `cyberchef.service` (obrigatório): `FromHex` | `FromBase64` | `FromCharCode`.
- `cyberchef.timeout` (opcional): Timeout HTTP em segundos (padrão: 30.0).

## Exemplo CLI

```bash
python examples/analyzers/cyberchef_example.py \
  --url http://localhost:8000 \
  --service FromHex \
  666f6f \
  --execute
```

Saída compacta JSON é impressa no STDOUT. Sem `--execute`, o exemplo permanece em modo seguro (dry‑run).


