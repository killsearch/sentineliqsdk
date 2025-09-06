# Shodan Analyzer

O Shodan Analyzer consulta a API do Shodan para enriquecer IPs e domínios/FQDNs, além de
expor chamadas dinâmicas a diversos endpoints do cliente Shodan.

## Visão Geral

- Analisa `ip`, `domain` e `fqdn` diretamente, retornando um `AnalyzerReport` com
  `verdict`, `taxonomy` e `details`.
- Suporta chamadas dinâmicas a métodos do cliente via:
  - `config.params['shodan']['method']` e `config.params['shodan']['params']` (dict)
  - ou `data_type == "other"` com `data` em JSON: `{"method": "...", "params": {...}}`

## Como Funciona

- IP: usa `host_information` e coleta catálogos (`ports`, `protocols`).
- Domínio/FQDN: usa `dns_domain`, resolve IPs com `dns_resolve` e busca `host_information`
  minificado para cada IP resolvido.
- Heurística de veredito: marca como `malicious` se houver tag `malware`, `suspicious` se
  houver vulnerabilidades; caso contrário, `safe`.
- Rede: utiliza `urllib`; proxies são honrados via `WorkerConfig.proxy`.

## Métodos Suportados (dinâmico)

Permitidos via `method`:

- host_information, search_host_count, search_host, search_host_facets, search_host_filters,
  search_host_tokens, ports, protocols
- scan, scan_internet, scans, scan_by_id
- alert_create, alert_info, alert_delete, alert_edit, alerts, alert_triggers,
  alert_enable_trigger, alert_disable_trigger, alert_whitelist_service,
  alert_unwhitelist_service, alert_add_notifier, alert_remove_notifier
- notifiers, notifier_providers, notifier_create, notifier_delete, notifier_get, notifier_update
- queries, query_search, query_tags
- data_datasets, data_dataset
- org, org_member_update, org_member_remove
- account_profile
- dns_domain, dns_resolve, dns_reverse
- tools_httpheaders, tools_myip, api_info

## Instanciação

```python
from __future__ import annotations
import json
from sentineliqsdk import WorkerInput
from sentineliqsdk.analyzers.shodan import ShodanAnalyzer

# IP
inp = WorkerInput(data_type="ip", data="1.2.3.4")
report = ShodanAnalyzer(inp).execute()

# Domínio
inp = WorkerInput(data_type="domain", data="example.com")
report = ShodanAnalyzer(inp).execute()

# Dinâmico (data payload)
payload = {"method": "search_host", "params": {"query": "port:22"}}
inp = WorkerInput(data_type="other", data=json.dumps(payload))
report = ShodanAnalyzer(inp).execute()
```

## Configuração

- Autenticação: `WorkerConfig.secrets['shodan']['api_key']`
- Chamada dinâmica: `WorkerConfig.params['shodan']['method']` e
  `WorkerConfig.params['shodan']['params']` (dict)
- Proxies: `WorkerInput.config.proxy.http/https`

Exemplo (dataclasses):

```python
from sentineliqsdk import WorkerInput, WorkerConfig, ProxyConfig
from sentineliqsdk.analyzers.shodan import ShodanAnalyzer

inp = WorkerInput(
    data_type="ip",
    data="1.2.3.4",
    config=WorkerConfig(
        proxy=ProxyConfig(http=None, https=None),
        secrets={"shodan": {"api_key": "SUA-CHAVE"}},
        params={"shodan": {"method": None, "params": {}}},
    ),
)
report = ShodanAnalyzer(inp).execute()
```

Nota: não há suporte por variáveis de ambiente.

## Uso Correto

- Para IP/Domínio/FQDN, use `data_type` correspondente; para chamadas arbitrárias, use
  `data_type == "other"` com JSON válido.
- Em chamadas dinâmicas, valide `method` com a lista permitida e forneça `params` como objeto.

## Retorno

- `AnalyzerReport` com `full_report` contendo:
  - `observable`, `verdict`, `taxonomy`, `source`, `data_type`, `details`

## Metadata

O analisador inclui `full_report.metadata` com:

```json
{
  "Name": "Shodan Analyzer",
  "Description": "Query Shodan for IP/domain intel and dynamic API calls",
  "Author": ["SentinelIQ Team <team@sentineliq.com.br>"],
  "License": "SentinelIQ License",
  "pattern": "threat-intel",
  "doc_pattern": "MkDocs module page; programmatic usage documented",
  "doc": "https://killsearch.github.io/sentineliqsdk/modulos/analyzers/shodan/",
  "VERSION": "STABLE"
}
```
