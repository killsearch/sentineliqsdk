# DShield Analyzer

Consulta a API pública do SANS Internet Storm Center DShield para análise de reputação de IPs e retorna um `AnalyzerReport` com `verdict`, `taxonomy` e dados enriquecidos (informações AS, feeds de ameaças e cálculo de risco).

## Visão Geral

- Aceita `data_type == "ip"` e chama o endpoint público da API DShield.
- Taxonomia resume: nível de risco baseado em contadores de ataques e relatórios.
- Artefatos: adiciona informações de AS (Autonomous System) quando disponíveis.
- Não requer autenticação - utiliza API pública do SANS DShield.

## Instalação / Requisitos

- SDK: utilize as dataclasses do pacote `sentineliqsdk`.
- Autenticação: Não necessária (API pública).
- Configurações opcionais: `config.params['dshield']['timeout']` para timeout personalizado.

## Uso Programático

```python
from __future__ import annotations
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.dshield import DShieldAnalyzer

inp = WorkerInput(
    data_type="ip",
    data="1.2.3.4",
    config=WorkerConfig(
        params={"dshield": {"timeout": 30}},  # opcional
    ),
)
report = DShieldAnalyzer(inp).execute()
print(report.full_report["verdict"], report.full_report["taxonomy"][0])
```

## Exemplo (CLI)

Exemplo executável na pasta `examples/` (dry‑run por padrão; use `--execute` para chamar a API):

```bash
python examples/analyzers/dshield_example.py --ip 1.2.3.4           # dry-run
python examples/analyzers/dshield_example.py --ip 1.2.3.4 --execute  # real
```

Arquivo: `examples/analyzers/dshield_example.py`

## Taxonomia

- `safe/suspicious/malicious` conforme cálculo de risco baseado em:
  - Contadores de ataques (`attacks`)
  - Número de relatórios (`reports`)
  - Feeds de ameaças disponíveis
- Campos gerados:
  - `risk-level` (safe/suspicious/malicious)
  - `attack-count` (info)
  - `report-count` (info)
  - `threat-feeds` (info se disponível)

## Cálculo de Risco

O analyzer utiliza uma lógica de scoring baseada em:

1. **Contadores de ataques**: IPs com mais de 10 ataques são considerados suspeitos
2. **Número de relatórios**: IPs com mais de 5 relatórios são considerados suspeitos
3. **Combinação**: IPs com ambos os indicadores são considerados maliciosos
4. **Feeds de ameaças**: Presença em feeds aumenta o nível de risco

## Artefatos Extraídos

- **ASN**: Número do Sistema Autônomo quando disponível
- **Informações AS**: Detalhes do provedor/organização

## Metadata

O analisador inclui `full_report.metadata` com:

```json
{
  "Name": "DShield Analyzer",
  "Description": "Consulta reputação de IPs na API SANS DShield",
  "Author": ["SentinelIQ Team <team@sentineliq.com.br>"],
  "License": "SentinelIQ License",
  "pattern": "threat-intel",
  "doc_pattern": "MkDocs module page; programmatic usage",
  "doc": "https://killsearch.github.io/sentineliqsdk/modulos/analyzers/dshield/",
  "VERSION": "TESTING"
}
```

## Limitações

- Suporta apenas análise de IPs individuais
- Depende da disponibilidade da API pública do SANS DShield
- Não possui rate limiting interno (recomenda-se uso responsável)

## Referências

- [SANS Internet Storm Center](https://isc.sans.edu/)
- [DShield API Documentation](https://isc.sans.edu/api/)