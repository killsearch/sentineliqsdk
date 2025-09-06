# Axur Analyzer

O Axur Analyzer é um invólucro dinâmico para a Axur Platform API. Ele aceita um método
permitido e parâmetros via `data_type == "other"` (JSON) ou `config.params`, executa a
chamada e retorna um `AnalyzerReport` com os detalhes da resposta.

## Visão Geral

- Chamadas dinâmicas: `config.params['axur']['method']`/`config.params['axur']['params']` ou
  `data_type == "other"` com `{ "method": "...", "params": {...} }`.
- Método genérico `call` permite invocar qualquer rota REST (`http_method`, `path`, `query`,
  `headers`, `json`, `data`, `dry_run`).

## Métodos Suportados

- Genérico: `call`
- Conveniência: `customers`, `users`, `users_stream`, `tickets_search`, `ticket_create`,
  `tickets_by_keys`, `filter_create`, `filter_results`, `ticket_get`, `ticket_types`,
  `ticket_texts`, `integration_feed`

## Como Funciona

- O analisador cria um cliente Axur a partir de `WorkerConfig.secrets['axur']['api_token']`.
- Valida o método contra uma lista de permitidos.
- Para `call`, mapeia os campos `http_method`, `path`, `query`, `headers`, `json`, `data`,
  `dry_run` para a função genérica do cliente.
- Retorna `AnalyzerReport` com `details.method`, `details.params` e `details.result`.

## Instanciação

```python
from __future__ import annotations
import json
from sentineliqsdk import WorkerInput
from sentineliqsdk.analyzers.axur import AxurAnalyzer

# Exemplo simples com método de conveniência
payload = {"method": "customers", "params": {}}
inp = WorkerInput(data_type="other", data=json.dumps(payload))
report = AxurAnalyzer(inp).execute()

# Chamada genérica para uma rota arbitrária
payload = {
    "method": "call",
    "params": {
        "http_method": "GET",
        "path": "/v1/customers",
        "query": {"page": 1},
        "dry_run": True
    },
}
inp = WorkerInput(data_type="other", data=json.dumps(payload))
report = AxurAnalyzer(inp).execute()
```

## Configuração

- `WorkerConfig.secrets['axur']['api_token']`
- `WorkerConfig.params['axur']['method']` e `WorkerConfig.params['axur']['params']` (dict)
- Proxies: `WorkerInput.config.proxy`

Nota: não há suporte por variáveis de ambiente.

## Uso Correto

- Sempre forneça `data_type == "other"` com JSON válido ao usar chamadas dinâmicas.
- Para `call`, `path` é obrigatório e `http_method` padrão é `GET`.
- `query`, `headers` e `json` devem ser objetos (mapeamentos JSON).

## Retorno

- `AnalyzerReport` com `full_report.details` incluindo:
  - `method`, `params`, `result`

## Metadata

O analisador inclui `full_report.metadata` com:

```json
{
  "Name": "Axur Analyzer",
  "Description": "Dynamic wrapper for Axur Platform API endpoints",
  "Author": ["SentinelIQ Team <team@sentineliq.com.br>"],
  "License": "SentinelIQ License",
  "pattern": "platform",
  "doc_pattern": "MkDocs module page; programmatic usage documented",
  "doc": "https://killsearch.github.io/sentineliqsdk/modulos/analyzers/axur/",
  "VERSION": "STABLE"
}
```
