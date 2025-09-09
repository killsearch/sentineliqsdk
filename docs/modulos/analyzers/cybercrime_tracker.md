---
title: CyberCrime Tracker Analyzer
---

Busca possíveis C2 servers no site `cybercrime-tracker.net` relacionados ao observável informado.

## Uso Programático

```python
from __future__ import annotations
import json
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.cybercrime_tracker import CyberCrimeTrackerAnalyzer

input_data = WorkerInput(
    data_type="other",
    data="example.com",
    config=WorkerConfig(params={
        "cct.limit": 40,
        "cct.timeout": 30.0,
    })
)

report = CyberCrimeTrackerAnalyzer(input_data).execute()
print(json.dumps(report.full_report, ensure_ascii=False))
```

## Parâmetros (WorkerConfig)

- `cct.limit` (opcional): Tamanho da página por requisição (padrão: 40)
- `cct.offset` (opcional): Offset inicial (padrão: 0)
- `cct.max_pages` (opcional): Guard rail para número máximo de páginas (padrão: 50)
- `cct.timeout` (opcional): Timeout HTTP em segundos (padrão: 30.0)

## Exemplo CLI

```bash
python examples/analyzers/cybercrime_tracker_example.py \
  example.com \
  --limit 40 \
  --timeout 30 \
  --execute
```

A saída JSON compacta é impressa no STDOUT. Sem `--execute`, o exemplo permanece em modo seguro (dry‑run).
