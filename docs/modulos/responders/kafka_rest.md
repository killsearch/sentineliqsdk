# Kafka REST Responder

Publica mensagens em um tópico Kafka via Confluent REST Proxy. Por padrão, roda em dry‑run; o
envio real exige os dois sinalizadores de segurança.

## Visão Geral

- Endpoint: `config.params['kafka'].base_url` (ex.: `http://localhost:8082`)
- Tópico: `config.params['kafka'].topic`
- Valor: `config.params['kafka'].value` (opcional; padrão é `WorkerInput.data`)
- Cabeçalhos: `config.params['kafka'].headers` (dict)
- Autenticação: `config.secrets['kafka'].basic_auth` ("user:pass") ou `username/password`
- Portas de segurança: `config.params.execute` e `config.params.include_dangerous`

## Como Funciona

- Monta `POST {base}/topics/{topic}` com payload `{ "records": [{"value": value}] }`.
- Em dry‑run, retorna o plano; em execução real, adiciona `status` e `http_status` ao relatório.

## Instanciação

```python
from __future__ import annotations
import json
from sentineliqsdk import WorkerInput
from sentineliqsdk.responders.kafka_rest import KafkaResponder

inp = WorkerInput(data_type="other", data="hello")
report = KafkaResponder(inp).execute()
print(json.dumps(report.full_report, ensure_ascii=False))
```

## Configuração

Preferencial (programática):

- `WorkerConfig.params`:
  - `kafka.base_url`, `kafka.topic`
  - `kafka.value` (opcional)
  - `kafka.headers` (dict)
  - `execute` (bool) e `include_dangerous` (bool)
- `WorkerConfig.secrets`:
  - `kafka.basic_auth` ("user:pass") ou `kafka.username`/`kafka.password`

Sem suporte por variáveis de ambiente.

## Uso Correto

- Defina o tópico e o valor; use cabeçalhos adicionais conforme o proxy/segurança do cluster.
- Para Basic Auth, defina `config.secrets['kafka'].basic_auth = "user:pass"`.

## Retorno

- `ResponderReport` com `action`, `provider`, `url`, `topic`, `dry_run` e, em execução real,
  `status` e `http_status`.

## Metadata

O responder inclui `full_report.metadata` com:

```json
{
  "Name": "Kafka REST Responder",
  "Description": "Publish messages to Kafka via Confluent REST Proxy",
  "Author": ["SentinelIQ Team <team@sentineliq.com.br>"],
  "License": "SentinelIQ License",
  "pattern": "kafka",
  "doc_pattern": "MkDocs module page; customer-facing usage and API",
  "doc": "https://killsearch.github.io/sentineliqsdk/modulos/responders/kafka_rest/",
  "VERSION": "STABLE"
}
```
