# DomainTools Analyzer

O DomainTools Analyzer fornece inteligência abrangente de domínios usando a API DomainTools Iris,
incluindo análise de risco, dados Whois, perfil de domínio e chamadas dinâmicas a diversos endpoints.

## Visão Geral

- Analisa `domain`, `fqdn`, `ip` e `mail` diretamente, retornando um `AnalyzerReport` com
  `verdict`, `taxonomy` e `details`.
- Suporta chamadas dinâmicas a métodos da API via:
  - `domaintools.method` e `domaintools.params` (dict) em `WorkerConfig.params`
  - ou `data_type == "other"` com `data` em JSON: `{"method": "...", "params": {...}}`

## Como Funciona

- **Domínio/FQDN**: usa `iris_enrich`, `domain_profile`, `risk`, `whois` e `whois_history`
  para análise completa.
- **IP**: usa `reverse_ip` e `host_domains` para descobrir domínios associados.
- **Email**: usa `reverse_whois` para encontrar domínios registrados com o email.
- **Heurística de veredito**: baseada no `risk_score` da API DomainTools:
  - `malicious` se risk_score >= 70
  - `suspicious` se risk_score >= 40
  - `safe` caso contrário
- **Rede**: utiliza a biblioteca `domaintools`; proxies são honrados via `WorkerConfig.proxy`.

## Métodos Suportados (dinâmico)

Permitidos via `method`:

- **Iris**: `iris_enrich`, `iris_investigate`
- **Domínio**: `domain_profile`, `domain_search`, `domain_suggestions`
- **Whois**: `whois`, `whois_history`, `parsed_whois`, `reverse_whois`, `whois_lookup`
- **IP**: `reverse_ip`, `host_domains`, `reverse_ip_whois`, `hosting_history`
- **DNS**: `name_server_domains`, `reverse_name_server`
- **Monitoramento**: `ip_registrant_monitor`, `name_server_monitor`, `ip_monitor`,
  `registrant_monitor`, `brand_monitor`
- **Reputação**: `reputation`, `risk`
- **PhishEye**: `phisheye`, `phisheye_term_list`
- **Conta**: `account_information`, `usage`

## Instanciação

```python
from __future__ import annotations
import json
from sentineliqsdk import WorkerInput
from sentineliqsdk.analyzers.domaintools import DomainToolsAnalyzer

# Domínio
inp = WorkerInput(data_type="domain", data="example.com")
report = DomainToolsAnalyzer(inp).execute()

# IP
inp = WorkerInput(data_type="ip", data="1.2.3.4")
report = DomainToolsAnalyzer(inp).execute()

# Email
inp = WorkerInput(data_type="mail", data="admin@example.com")
report = DomainToolsAnalyzer(inp).execute()

# Dinâmico (data payload)
payload = {"method": "iris_enrich", "params": {"domains": ["example.com"]}}
inp = WorkerInput(data_type="other", data=json.dumps(payload))
report = DomainToolsAnalyzer(inp).execute()
```

## Configuração

- **Autenticação**: `domaintools.username` e `domaintools.api_key` em `WorkerConfig.secrets`
- **Chamada dinâmica**: `domaintools.method` e `domaintools.params` (dict) em `WorkerConfig.params`
- **Proxies**: `WorkerInput.config.proxy.http/https`

Exemplo (dataclasses):

```python
from sentineliqsdk import WorkerInput, WorkerConfig, ProxyConfig
from sentineliqsdk.analyzers.domaintools import DomainToolsAnalyzer

inp = WorkerInput(
    data_type="domain",
    data="example.com",
    config=WorkerConfig(
        proxy=ProxyConfig(http=None, https=None),
        secrets={
            "domaintools": {
                "username": "SEU-USERNAME",
                "api_key": "SUA-API-KEY"
            }
        },
        params={"domaintools": {"method": None, "params": {}}},
    ),
)
report = DomainToolsAnalyzer(inp).execute()
```

Nota: não há suporte por variáveis de ambiente.

## Uso Correto

- Para Domínio/FQDN/IP/Email, use `data_type` correspondente; para chamadas arbitrárias, use
  `data_type == "other"` com JSON válido.
- Em chamadas dinâmicas, valide `method` com a lista permitida e forneça `params` como objeto.
- Credenciais DomainTools são obrigatórias para todas as operações.

## Retorno

- `AnalyzerReport` com `full_report` contendo:
  - `observable`, `verdict`, `taxonomy`, `source`, `data_type`, `details`
- Para análise padrão de domínios, `details` inclui resultados de múltiplos endpoints:
  - `iris_enrich`: dados de enriquecimento Iris
  - `domain_profile`: perfil completo do domínio
  - `risk`: pontuação de risco
  - `whois`: dados Whois atuais
  - `whois_history`: histórico Whois (quando disponível)

## Metadata

O analisador inclui `full_report.metadata` com:

```json
{
  "Name": "DomainTools Analyzer",
  "Description": "Comprehensive domain intelligence using DomainTools Iris API",
  "Author": ["SentinelIQ Team <team@sentineliq.com.br>"],
  "License": "SentinelIQ License",
  "pattern": "threat-intel",
  "doc_pattern": "MkDocs module page; programmatic usage documented",
  "doc": "https://killsearch.github.io/sentineliqsdk/modulos/analyzers/domaintools/",
  "VERSION": "TESTING"
}
```

## Exemplos Avançados

### Análise de Risco Personalizada

```python
# Usar método iris_investigate para análise detalhada
payload = {
    "method": "iris_investigate",
    "params": {
        "domains": ["suspicious-domain.com"],
        "include_context": True
    }
}
inp = WorkerInput(data_type="other", data=json.dumps(payload))
report = DomainToolsAnalyzer(inp).execute()
```

### Monitoramento de Marca

```python
# Configurar monitoramento de marca
payload = {
    "method": "brand_monitor",
    "params": {
        "query": "minha-marca",
        "exclude": ["minha-marca.com"]
    }
}
inp = WorkerInput(data_type="other", data=json.dumps(payload))
report = DomainToolsAnalyzer(inp).execute()
```

### Busca Reversa de Whois

```python
# Encontrar domínios registrados por uma organização
payload = {
    "method": "reverse_whois",
    "params": {
        "terms": "Example Organization",
        "mode": "purchase"
    }
}
inp = WorkerInput(data_type="other", data=json.dumps(payload))
report = DomainToolsAnalyzer(inp).execute()
```