# RabbitMQ HTTP Responder

Publica mensagens em um exchange do RabbitMQ via API HTTP. Por padrão, roda em dry‑run; o
envio real exige os dois sinalizadores de segurança.

## Visão Geral

- Base: `config.params['rabbitmq'].api_url` (ex.: `http://localhost:15672`)
- VHost: `config.params['rabbitmq'].vhost` (padrão: `/`)
- Exchange: `config.params['rabbitmq'].exchange` (obrigatório)
- Routing Key: `config.params['rabbitmq'].routing_key` (padrão: vazio)
- Autenticação: `config.secrets['rabbitmq'].username`/`config.secrets['rabbitmq'].password`
- Propriedades: `config.params['rabbitmq'].properties` (dict)
- Mensagem: `config.params['rabbitmq'].message` (padrão: `WorkerInput.data`)
- Portas de segurança: `config.params.execute` e `config.params.include_dangerous`

## Como Funciona

- `POST {base}/api/exchanges/{vhost}/{exchange}/publish` com payload string.
- Em dry‑run, retorna o plano; em execução real, adiciona `status` e `http_status`.

## Instanciação

```python
from __future__ import annotations
import json
from sentineliqsdk import WorkerInput
from sentineliqsdk.responders.rabbitmq_http import RabbitMqResponder

inp = WorkerInput(data_type="other", data="hello")
report = RabbitMqResponder(inp).execute()
print(json.dumps(report.full_report, ensure_ascii=False))
```

## Configuração

Preferencial (programática):

- `WorkerConfig.params`:
  - `rabbitmq.api_url`, `rabbitmq.vhost`, `rabbitmq.exchange`, `rabbitmq.routing_key`
  - `rabbitmq.message` (opcional; padrão: `WorkerInput.data`)
  - `rabbitmq.properties` (dict)
  - `execute` (bool) e `include_dangerous` (bool)
- `WorkerConfig.secrets`:
  - `rabbitmq.username`, `rabbitmq.password`

Sem suporte por variáveis de ambiente.

## Uso Correto

- Quando houver autenticação, informe usuário e senha; o responder monta o header Basic.
- `properties` é um dicionário JSON enviado no payload do publish.

## Retorno

- `ResponderReport` com `action`, `provider`, `url`, `exchange`, `routing_key`, `dry_run` e,
  em execução real, `status` e `http_status`.

## Metadata

O responder inclui `full_report.metadata` com:

```json
{
  "Name": "RabbitMQ HTTP Responder",
  "Description": "Publish messages to RabbitMQ via HTTP API",
  "Author": ["SentinelIQ Team <team@sentineliq.com.br>"],
  "License": "SentinelIQ License",
  "pattern": "rabbitmq",
  "doc_pattern": "MkDocs module page; customer-facing usage and API",
  "doc": "https://killsearch.github.io/sentineliqsdk/modulos/responders/rabbitmq_http/",
  "VERSION": "STABLE"
}
```
