# CIRCL Hashlookup Analyzer

O CIRCL Hashlookup Analyzer consulta o serviço público CIRCL hashlookup para análise de reputação de hashes, incluindo operações básicas, bulk, relacionamentos parent/child e gerenciamento de sessões.

## Visão Geral

- Analisa `hash` diretamente, retornando um `AnalyzerReport` com `verdict`, `taxonomy` e `details`.
- Suporta chamadas dinâmicas a todos os métodos da API via:
  - `circl.method` e `circl.params` (dict) em `WorkerConfig.params`
  - ou `data_type == "other"` com `data` em JSON: `{"method": "...", "params": {...}}`
- Detecta automaticamente o tipo de hash (MD5, SHA1, SHA256, SHA512) baseado no comprimento e formato.

## Como Funciona

- Hash: detecta o tipo automaticamente e consulta o endpoint apropriado (`/lookup/md5/`, `/lookup/sha1/`, `/lookup/sha256/`).
- Para SHA1, também tenta buscar relacionamentos parent/child quando disponível.
- Heurística de veredito: marca como `safe` se houver `hashlookup:trust` ou `KnownGood`, `info` se não encontrado ou outros erros.
- Rede: utiliza `httpx`; proxies são honrados via `WorkerConfig.proxy`.
- Não requer chave de API (serviço público).

## Métodos Suportados (dinâmico)

Permitidos via `method`:

### Lookups Básicos
- `lookup_md5` - Consulta hash MD5
- `lookup_sha1` - Consulta hash SHA1  
- `lookup_sha256` - Consulta hash SHA256

### Operações Bulk
- `bulk_md5` - Consulta múltiplos hashes MD5
- `bulk_sha1` - Consulta múltiplos hashes SHA1

### Relacionamentos
- `get_children` - Busca hashes filhos de um SHA1
- `get_parents` - Busca hashes pais de um SHA1

### Utilitários
- `get_info` - Informações sobre o banco de dados
- `get_stats_top` - Estatísticas top do banco

### Sessões
- `create_session` - Cria uma sessão para rastreamento
- `get_session` - Obtém resultados de uma sessão

## Instanciação

```python
from __future__ import annotations
import json
from sentineliqsdk import WorkerInput
from sentineliqsdk.analyzers.circl_hashlookup import CirclHashlookupAnalyzer

# Hash MD5
inp = WorkerInput(data_type="hash", data="5d41402abc4b2a76b9719d911017c592")
report = CirclHashlookupAnalyzer(inp).execute()

# Hash SHA1
inp = WorkerInput(data_type="hash", data="aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")
report = CirclHashlookupAnalyzer(inp).execute()

# Dinâmico (data payload)
payload = {"method": "bulk_md5", "params": {"hashes": ["5d41402abc4b2a76b9719d911017c592"]}}
inp = WorkerInput(data_type="other", data=json.dumps(payload))
report = CirclHashlookupAnalyzer(inp).execute()
```

## Configuração

- Autenticação: Não requerida (serviço público)
- Chamada dinâmica: `circl.method` e `circl.params` (dict) em `WorkerConfig.params`
- Proxies: `WorkerInput.config.proxy.http/https`

Exemplo (dataclasses):

```python
from sentineliqsdk import WorkerInput, WorkerConfig, ProxyConfig
from sentineliqsdk.analyzers.circl_hashlookup import CirclHashlookupAnalyzer

inp = WorkerInput(
    data_type="hash",
    data="5d41402abc4b2a76b9719d911017c592",
    config=WorkerConfig(
        proxy=ProxyConfig(http=None, https=None),
        params={"circl": {"method": None, "params": {}}},
    ),
)
report = CirclHashlookupAnalyzer(inp).execute()
```

## Exemplos de Uso

### Consulta Básica de Hash

```python
from sentineliqsdk import WorkerInput
from sentineliqsdk.analyzers.circl_hashlookup import CirclHashlookupAnalyzer

# Hash MD5 conhecido
input_data = WorkerInput(
    data_type="hash",
    data="5d41402abc4b2a76b9719d911017c592"  # "hello"
)

analyzer = CirclHashlookupAnalyzer(input_data)
report = analyzer.execute()

print(f"Verdict: {report.full_report['verdict']}")
print(f"Hash Type: {report.full_report['details']['hash_type']}")
print(f"Trust Level: {report.full_report['details']['lookup_result'].get('hashlookup:trust', 'N/A')}")
```

### Operação Bulk

```python
import json
from sentineliqsdk import WorkerInput
from sentineliqsdk.analyzers.circl_hashlookup import CirclHashlookupAnalyzer

# Consulta bulk de múltiplos hashes MD5
payload = {
    "method": "bulk_md5",
    "params": {
        "hashes": [
            "5d41402abc4b2a76b9719d911017c592",  # "hello"
            "d41d8cd98f00b204e9800998ecf8427e"   # empty string
        ]
    }
}

input_data = WorkerInput(
    data_type="other",
    data=json.dumps(payload)
)

analyzer = CirclHashlookupAnalyzer(input_data)
report = analyzer.execute()

results = report.full_report['details']['result']
for result in results:
    print(f"MD5: {result.get('MD5', 'N/A')} - Found: {'Yes' if 'MD5' in result else 'No'}")
```

### Busca de Relacionamentos

```python
import json
from sentineliqsdk import WorkerInput
from sentineliqsdk.analyzers.circl_hashlookup import CirclHashlookupAnalyzer

# Busca hashes filhos de um SHA1
payload = {
    "method": "get_children",
    "params": {
        "sha1": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
        "count": 10,
        "cursor": "0"
    }
}

input_data = WorkerInput(
    data_type="other",
    data=json.dumps(payload)
)

analyzer = CirclHashlookupAnalyzer(input_data)
report = analyzer.execute()

children = report.full_report['details']['result']
print(f"Children found: {len(children.get('children', []))}")
```

### Informações do Banco

```python
import json
from sentineliqsdk import WorkerInput
from sentineliqsdk.analyzers.circl_hashlookup import CirclHashlookupAnalyzer

# Obter informações sobre o banco de dados
payload = {"method": "get_info", "params": {}}

input_data = WorkerInput(
    data_type="other",
    data=json.dumps(payload)
)

analyzer = CirclHashlookupAnalyzer(input_data)
report = analyzer.execute()

info = report.full_report['details']['result']
print(f"Database version: {info.get('version', 'N/A')}")
print(f"Total hashes: {info.get('total', 'N/A')}")
```

## Uso Correto

- Para hashes, use `data_type="hash"`; para chamadas arbitrárias, use `data_type == "other"` com JSON válido.
- Em chamadas dinâmicas, valide `method` com a lista permitida e forneça `params` como objeto.
- Para operações bulk, forneça `hashes` como lista de strings.
- Para relacionamentos, use SHA1 como parâmetro `sha1`.

## Retorno

- `AnalyzerReport` com `full_report` contendo:
  - `observable`, `verdict`, `taxonomy`, `source`, `data_type`, `details`
  - `details` inclui `hash_type`, `lookup_result`, e `relationships` (quando aplicável)

## Tipos de Hash Suportados

- **MD5**: 32 caracteres hexadecimais (ex: `5d41402abc4b2a76b9719d911017c592`)
- **SHA1**: 40 caracteres hexadecimais (ex: `aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d`)
- **SHA256**: 64 caracteres hexadecimais (ex: `2cf24dba4f21a03f4b3d914f42305d25206eaf64a81f73b3e4e5b9bd3e978038`)
- **SHA512**: 128 caracteres hexadecimais

## Metadata

O analisador inclui `full_report.metadata` com:

```json
{
  "Name": "CIRCL Hashlookup Analyzer",
  "Description": "Query CIRCL hashlookup for hash reputation, relationships, and bulk operations",
  "Author": ["SentinelIQ Team <team@sentineliq.com.br>"],
  "License": "SentinelIQ License",
  "pattern": "threat-intel",
  "doc_pattern": "MkDocs module page; programmatic usage documented",
  "doc": "https://killsearch.github.io/sentineliqsdk/modulos/analyzers/circl_hashlookup/",
  "VERSION": "STABLE"
}
```

## Limitações

- Serviço público sem autenticação
- Rate limiting pode ser aplicado pelo CIRCL
- Relacionamentos parent/child disponíveis apenas para SHA1
- Sessões podem não estar habilitadas em todas as instâncias
