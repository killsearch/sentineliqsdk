# ChainAbuse Analyzer

Consulta a API da ChainAbuse para reputação de endereços blockchain e URLs, retornando um
`AnalyzerReport` com `verdict`, `taxonomy` e dados de relatórios maliciosos e endereços sancionados.

## Visão Geral

- Aceita `data_type` em `["ip", "url", "domain", "hash"]` e consulta os endpoints de relatórios.
- Verifica se endereços/URLs foram reportados como maliciosos ou estão sancionados.
- Taxonomia resume: contagem de relatórios, status de sanção e tipo de dados.
- Suporta verificação de endereços blockchain sancionados via endpoint dedicado.
- Proxies são honrados via `WorkerInput.config.proxy`.

## Instalação / Requisitos

- SDK: utilize as dataclasses do pacote `sentineliqsdk`.
- Autenticação: `config.secrets['chainabuse']['api_key']`.
- API ChainAbuse: chave de API válida da ChainAbuse.

## Uso Programático

```python
from __future__ import annotations
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.chainabuse import ChainAbuseAnalyzer

# Análise de IP
inp = WorkerInput(
    data_type="ip",
    data="1.2.3.4",
    config=WorkerConfig(
        secrets={"chainabuse": {"api_key": "SUA_CHAVE"}},
        chainabuse_timeout=30,  # opcional, padrão 30s
    ),
)
report = ChainAbuseAnalyzer(inp).execute()
print(report.full_report["verdict"], report.full_report["taxonomy"][0])

# Análise de URL
inp_url = WorkerInput(
    data_type="url",
    data="https://malicious-site.com",
    config=WorkerConfig(secrets={"chainabuse": {"api_key": "SUA_CHAVE"}}),
)
report_url = ChainAbuseAnalyzer(inp_url).execute()

# Análise de endereço blockchain
inp_hash = WorkerInput(
    data_type="hash",
    data="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    config=WorkerConfig(secrets={"chainabuse": {"api_key": "SUA_CHAVE"}}),
)
report_hash = ChainAbuseAnalyzer(inp_hash).execute()
```

## Exemplo (CLI)

Exemplo executável na pasta `examples/` (dry‑run por padrão; use `--execute` para chamar a API):

```bash
python examples/analyzers/chainabuse_example.py --api-key YOUR_KEY                    # plano
python examples/analyzers/chainabuse_example.py --api-key YOUR_KEY --execute          # real
python examples/analyzers/chainabuse_example.py --api-key YOUR_KEY --execute --include-dangerous
```

Arquivo: `examples/analyzers/chainabuse_example.py`

## Endpoints da API

O analyzer utiliza os seguintes endpoints da ChainAbuse:

### GET /reports
- **Propósito**: Verificar se endereços/URLs foram reportados como maliciosos
- **Parâmetros**: `address` (endereço a verificar)
- **Resposta**: Lista de relatórios com categorias, confiança e timestamps

### GET /sanctioned-addresses/{address}
- **Propósito**: Verificar se um endereço blockchain está sancionado
- **Parâmetros**: `address` (endereço blockchain)
- **Resposta**: Status de sanção e detalhes (se aplicável)

## Taxonomia

- `safe/suspicious/malicious` baseado na contagem de relatórios e status de sanção.
- Campos gerados:
  - `report-count` (safe/suspicious/malicious) - número de relatórios
  - `sanctioned` (safe/malicious) - status de sanção
  - `data-type` (info) - tipo de dados analisado

### Lógica de Verdict

- **Malicious**: Endereço sancionado OU ≥5 relatórios
- **Suspicious**: 1-4 relatórios (não sancionado)
- **Safe**: 0 relatórios e não sancionado

## Configuração

### Secrets (Obrigatório)
```python
secrets = {
    "chainabuse": {
        "api_key": "sua_chave_api_chainabuse"
    }
}
```

### Configurações Opcionais
```python
config = WorkerConfig(
    secrets=secrets,
    chainabuse_timeout=60,  # timeout em segundos (padrão: 30)
    check_tlp=True,
    max_tlp=2,
    check_pap=True,
    max_pap=2
)
```

## Autenticação

A ChainAbuse utiliza autenticação HTTP Basic onde a chave da API é passada como
nome de usuário e senha:

```
Authorization: Basic <base64(api_key:api_key)>
```

## Tipos de Dados Suportados

- **ip**: Endereços IPv4/IPv6
- **url**: URLs completas
- **domain**: Nomes de domínio
- **hash**: Endereços blockchain (Bitcoin, Ethereum, etc.)

## Tratamento de Erros

- **401/403**: Chave de API inválida ou expirada
- **404**: Endereço não encontrado (tratado como não sancionado)
- **500**: Erro interno da API
- **Timeout**: Configurável via `chainabuse_timeout`

## Metadata

O analisador inclui `full_report.metadata` com:

```json
{
  "Name": "ChainAbuse Analyzer",
  "Description": "Consulta reputação de endereços blockchain e URLs na ChainAbuse",
  "Author": ["SentinelIQ Team <team@sentineliq.com.br>"],
  "License": "SentinelIQ License",
  "pattern": "threat-intel",
  "doc_pattern": "MkDocs module page; programmatic usage",
  "doc": "https://killsearch.github.io/sentineliqsdk/modulos/analyzers/chainabuse/",
  "VERSION": "TESTING"
}
```

## Exemplo de Resposta

```json
{
  "success": true,
  "summary": {},
  "artifacts": [],
  "operations": [],
  "full_report": {
    "observable": "1.2.3.4",
    "verdict": "suspicious",
    "taxonomy": [
      {
        "level": "suspicious",
        "namespace": "chainabuse",
        "predicate": "report-count",
        "value": "3"
      },
      {
        "level": "safe",
        "namespace": "chainabuse",
        "predicate": "sanctioned",
        "value": "False"
      },
      {
        "level": "info",
        "namespace": "chainabuse",
        "predicate": "data-type",
        "value": "ip"
      }
    ],
    "source": "chainabuse",
    "data_type": "ip",
    "reports": {
      "data": [...],
      "count": 3
    },
    "sanctioned": {
      "sanctioned": false,
      "data": null
    },
    "metadata": {...}
  }
}
```

## Limitações

- Requer chave de API válida da ChainAbuse
- Rate limits aplicados pela API ChainAbuse
- Endereços blockchain sancionados verificados apenas para `data_type="hash"`
- Timeout padrão de 30 segundos (configurável)
