# Domain Mail SPF DMARC Analyzer

O Domain Mail SPF DMARC Analyzer verifica registros SPF e DMARC de domínios para avaliar
a configuração de segurança de email e detectar possíveis vulnerabilidades.

## Visão Geral

- Analisa `domain` e `fqdn` diretamente, retornando um `AnalyzerReport` com
  `verdict`, `taxonomy` e `details`.
- Verifica a presença e configuração de registros SPF e DMARC via consultas DNS.
- Avalia a segurança da configuração de email baseada nas políticas encontradas.

## Como Funciona

- Domínio/FQDN: realiza consultas DNS TXT para buscar registros SPF e DMARC.
- SPF: verifica a presença do registro e analisa mecanismos de autorização.
- DMARC: verifica política de alinhamento e ações para emails não autenticados.
- Heurística de veredito:
  - `malicious`: configurações que permitem spoofing ou são muito permissivas
  - `suspicious`: configurações incompletas ou com falhas de segurança
  - `safe`: configurações adequadas de SPF e DMARC
- Rede: utiliza `dns.resolver` para consultas DNS; proxies são honrados via `WorkerConfig.proxy`.

## Tipos de Dados Suportados

- `domain`: Domínio para verificação (ex: "example.com")
- `fqdn`: Nome de domínio totalmente qualificado (ex: "mail.example.com")

## Instanciação

```python
from __future__ import annotations
from sentineliqsdk import WorkerInput
from sentineliqsdk.analyzers.domain_mail_spf_dmarc import DomainMailSpfDmarcAnalyzer

# Domínio
inp = WorkerInput(data_type="domain", data="example.com")
report = DomainMailSpfDmarcAnalyzer(inp).execute()

# FQDN
inp = WorkerInput(data_type="fqdn", data="mail.example.com")
report = DomainMailSpfDmarcAnalyzer(inp).execute()
```

## Configuração

- Timeout DNS: `domain_mail_spf_dmarc.dns_timeout` em `WorkerConfig.params` (padrão: 10 segundos)
- Proxies: `WorkerInput.config.proxy.http/https`

Exemplo (dataclasses):

```python
from sentineliqsdk import WorkerInput, WorkerConfig, ProxyConfig
from sentineliqsdk.analyzers.domain_mail_spf_dmarc import DomainMailSpfDmarcAnalyzer

inp = WorkerInput(
    data_type="domain",
    data="example.com",
    config=WorkerConfig(
        proxy=ProxyConfig(http=None, https=None),
        params={"domain_mail_spf_dmarc": {"dns_timeout": 15}},
    ),
)
report = DomainMailSpfDmarcAnalyzer(inp).execute()
```

Nota: não há suporte por variáveis de ambiente.

## Uso Correto

- Use `data_type="domain"` ou `data_type="fqdn"` com o domínio a ser verificado.
- O analyzer verifica automaticamente registros SPF e DMARC do domínio fornecido.
- Para subdomínios, o DMARC pode herdar a política do domínio organizacional.

## Retorno

- `AnalyzerReport` com `full_report` contendo:
  - `observable`, `verdict`, `taxonomy`, `source`, `data_type`, `details`
  - `spf_record`: registro SPF encontrado (se houver)
  - `dmarc_record`: registro DMARC encontrado (se houver)
  - `spf_analysis`: análise detalhada do SPF
  - `dmarc_analysis`: análise detalhada do DMARC

## Taxonomia

- **Namespace**: `domain-mail-security`
- **Predicates**:
  - `spf-configured`: SPF está configurado
  - `dmarc-configured`: DMARC está configurado
  - `spf-missing`: SPF não encontrado
  - `dmarc-missing`: DMARC não encontrado
  - `spf-permissive`: SPF muito permissivo
  - `dmarc-permissive`: DMARC muito permissivo
  - `secure-configuration`: Configuração segura

## Metadata

O analisador inclui `full_report.metadata` com:

```json
{
  "Name": "Domain Mail SPF DMARC Analyzer",
  "Description": "Verify SPF and DMARC records for domain email security assessment",
  "Author": ["SentinelIQ Team <team@sentineliq.com.br>"],
  "License": "SentinelIQ License",
  "pattern": "threat-intel",
  "doc_pattern": "MkDocs module page; programmatic usage documented",
  "doc": "https://killsearch.github.io/sentineliqsdk/modulos/analyzers/domain_mail_spf_dmarc/",
  "VERSION": "TESTING"
}
```