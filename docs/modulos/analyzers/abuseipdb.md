# AbuseIPDB Analyzer

Consulta a API v2 da AbuseIPDB para reputação de IPs e retorna um `AnalyzerReport` com
`verdict`, `taxonomy` e dados enriquecidos (países de reporte, categorias mais frequentes e
"freshness").

## Visão Geral

- Aceita `data_type == "ip"` e chama o endpoint `check`.
- Taxonomia resume: whitelist, TOR, usage type, `abuseConfidenceScore` e total de reports.
- Artefatos: adiciona dominios/hostnames reportados (domain/fqdn) e auto‑extração do relatório.
- Proxies são honrados via `WorkerInput.config.proxy`.

## Instalação / Requisitos

- SDK: utilize as dataclasses do pacote `sentineliqsdk`.
- Autenticação: `config.secrets['abuseipdb']['api_key']`.

## Uso Programático

```python
from __future__ import annotations
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.abuseipdb import AbuseIPDBAnalyzer

inp = WorkerInput(
    data_type="ip",
    data="1.2.3.4",
    config=WorkerConfig(
        secrets={"abuseipdb": {"api_key": "SUA_CHAVE"}},
        params={"abuseipdb": {"days": 30}},  # opcional
    ),
)
report = AbuseIPDBAnalyzer(inp).execute()
print(report.full_report["verdict"], report.full_report["taxonomy"][0])
```

## Exemplo (CLI)

Exemplo executável na pasta `examples/` (dry‑run por padrão; use `--execute` para chamar a API):

```bash
python examples/analyzers/abuseipdb_example.py --ip 1.2.3.4 --api-key YOUR_KEY           # plano
python examples/analyzers/abuseipdb_example.py --ip 1.2.3.4 --api-key YOUR_KEY --execute  # real
```

Arquivo: `examples/analyzers/abuseipdb_example.py`

## Taxonomia

- `info/safe/suspicious/malicious` conforme `abuseConfidenceScore` e whitelist.
- Campos gerados:
  - `is-whitelist` (info)
  - `is-tor` (info)
  - `usage-type` (info)
  - `abuse-confidence-score` (safe/suspicious/malicious)
  - `records` (safe/malicious ou info se whitelisted)

## Metadata

O analisador inclui `full_report.metadata` com:

```json
{
  "Name": "AbuseIPDB Analyzer",
  "Description": "Consulta reputação de IPs na AbuseIPDB (API v2)",
  "Author": ["SentinelIQ Team <team@sentineliq.com.br>"],
  "License": "SentinelIQ License",
  "pattern": "threat-intel",
  "doc_pattern": "MkDocs module page; programmatic usage",
  "doc": "https://killsearch.github.io/sentineliqsdk/modulos/analyzers/abuseipdb/",
  "VERSION": "TESTING"
}
```

