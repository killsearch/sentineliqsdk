# Webhook Responder

Envia uma requisição HTTP para um webhook usando apenas a stdlib (`urllib`). Por padrão, roda
em dry‑run; o envio real é protegido por sinalizadores de segurança.

## Visão Geral

- URL alvo: `WorkerInput.data` (`data_type == "url"`) ou `webhook.url`.
- Método: `webhook.method` (padrão `POST`). Suporta `POST` e `GET`.
- Cabeçalhos: `webhook.headers` (dict).
- Corpo: `webhook.body` (string ou dict; JSON gera `application/json`).
- Portas de segurança: requer `config.params.execute=True` e `config.params.include_dangerous=True`.

## Como Funciona

- Constrói um `urllib.request.Request` com método, cabeçalhos e corpo.
- Quando em dry‑run, retorna o `ResponderReport` sem realizar a chamada.
- Quando executado, envia a requisição e adiciona `status` e `http_status`.

## Instanciação

```python
from __future__ import annotations
import json
from sentineliqsdk import WorkerInput
from sentineliqsdk.responders.webhook import WebhookResponder

inp = WorkerInput(data_type="url", data="https://example.invalid/webhook")
report = WebhookResponder(inp).execute()
print(json.dumps(report.full_report, ensure_ascii=False))
```

## Configuração

Preferencial (programática, sem variáveis de ambiente):

- `WorkerConfig.params`:
  - `webhook.url` (opcional quando a URL vem em `data`)
  - `webhook.method` (`POST`|`GET`)
  - `webhook.headers` (dict)
  - `webhook.body` (string ou dict)
  - `execute` (bool) e `include_dangerous` (bool)

Sem suporte por variáveis de ambiente.

Exemplo (dataclasses):

```python
from sentineliqsdk import WorkerInput, WorkerConfig

inp = WorkerInput(
    data_type="url",
    data="https://example.invalid/webhook",
    config=WorkerConfig(
        params={
            "webhook": {
                "method": "POST",
                "headers": {"X-Token": "abc"},
                "body": {"ok": True},
            },
            "execute": True,
            "include_dangerous": True,
        }
    ),
)
```

Proxies: via `WorkerConfig.proxy.http/https`.

## Uso Correto

- Para envio real, defina ambos os sinalizadores de segurança como verdadeiros.
- Defina `webhook.headers` como dict (por exemplo, `{ "Authorization": "Bearer ..." }`).
- Se `webhook.body` for JSON (dict), será enviado com `Content-Type: application/json`.

## Retorno

- `ResponderReport` com `full_report` contendo `action`, `url`, `method`, `headers`, `dry_run`,
  e em envio real, `status` e possivelmente `http_status`.

## Metadata

O responder inclui `full_report.metadata` com:

```json
{
  "Name": "Webhook Responder",
  "Description": "POST/GET to a webhook URL using stdlib",
  "Author": ["SentinelIQ Team <team@sentineliq.com.br>"],
  "License": "SentinelIQ License",
  "pattern": "webhook",
  "doc_pattern": "MkDocs module page; customer-facing usage and API",
  "doc": "https://killsearch.github.io/sentineliqsdk/modulos/responders/webhook/",
  "VERSION": "STABLE"
}
```
