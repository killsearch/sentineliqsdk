# Cyberprotect ThreatScore Analyzer

Consulta a API ThreatScore da Cyberprotect para análise de ameaças e retorna um `AnalyzerReport` com
`verdict`, `taxonomy` e dados enriquecidos sobre o threat score do observável.

## Visão Geral

- Aceita `data_type` em `["domain", "hash", "ip", "url", "user-agent"]` e consulta o endpoint de busca.
- Taxonomia resume: threat score level e valor retornado pela API.
- Não requer autenticação - API pública da Cyberprotect.
- Mapeia levels da API para verdicts: malicious/high → malicious, suspicious/medium → suspicious, safe/low → safe.

## Instalação / Requisitos

- SDK: utilize as dataclasses do pacote `sentineliqsdk`.
- Autenticação: não requerida (API pública).

## Uso Programático

```python
from __future__ import annotations
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.cyberprotect import CyberprotectAnalyzer

inp = WorkerInput(
    data_type="domain",
    data="example.com",
    config=WorkerConfig(
        secrets={},  # Não requer credenciais
    ),
)
report = CyberprotectAnalyzer(inp).execute()
print(report.full_report["verdict"], report.full_report["taxonomy"][0])
```

## Exemplo (CLI)

Exemplo executável na pasta `examples/` (dry‑run por padrão; use `--execute` para chamar a API):

```bash
python examples/analyzers/cyberprotect_example.py --data "example.com" --data-type "domain"           # plano
python examples/analyzers/cyberprotect_example.py --data "example.com" --data-type "domain" --execute  # real
python examples/analyzers/cyberprotect_example.py --data "1.2.3.4" --data-type "ip" --execute
python examples/analyzers/cyberprotect_example.py --data "https://malicious-site.com" --data-type "url" --execute
```

Arquivo: `examples/analyzers/cyberprotect_example.py`

## Taxonomia

- `info/safe/suspicious/malicious` conforme threat score level retornado pela API.
- Campos gerados:
  - `ThreatScore` com valor do threat score ou status ("not in database", "not analyzed yet", "api error", "error")

## Tipos de Dados Suportados

- `domain`: Domínios e subdomínios
- `hash`: Hashes de arquivos (MD5, SHA1, SHA256)
- `ip`: Endereços IP (IPv4 e IPv6)
- `url`: URLs completas
- `user-agent`: User-Agent strings

## Mapeamento de Verdicts

| Level da API | Verdict |
|--------------|----------|
| malicious, high | malicious |
| suspicious, medium | suspicious |
| safe, low | safe |
| outros | info |

## Metadata

O analisador inclui `full_report.metadata` com:

```json
{
  "Name": "Cyberprotect ThreatScore",
  "Description": "Consulta a API ThreatScore da Cyberprotect para análise de ameaças",
  "Author": ["SentinelIQ Team <team@sentineliq.com.br>"],
  "License": "SentinelIQ License",
  "pattern": "threat-intel",
  "doc_pattern": "Página de módulo MkDocs; uso programático",
  "doc": "https://killsearch.github.io/sentineliqsdk/modulos/analyzers/cyberprotect/",
  "VERSION": "TESTING"
}
```

## Tratamento de Erros

- Tipos de dados não suportados retornam verdict `info` com erro explicativo
- Falhas de API retornam verdict `info` com detalhes do erro
- Timeouts e problemas de rede são capturados e reportados