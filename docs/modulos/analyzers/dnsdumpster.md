# DNSdumpster Analyzer

O **DNSdumpster Analyzer** é um módulo de análise que realiza reconhecimento DNS utilizando o serviço DNSdumpster.com para coletar informações detalhadas sobre domínios.

## Visão Geral

Este analyzer realiza web scraping do DNSdumpster.com para obter dados de reconhecimento DNS, incluindo registros DNS, MX, TXT e informações de host. É uma ferramenta valiosa para análise de infraestrutura de domínios e coleta de inteligência sobre ameaças.

## Características

- **Sem API Key**: Não requer chave de API
- **Suporte a Proxy**: Honra proxies HTTP via `WorkerConfig.proxy`
- **Extração de Artefatos**: Extrai automaticamente endereços IPv4, IPv6, domínios e URLs
- **Múltiplos Tipos de Registro**: Coleta registros DNS, MX, TXT e informações de host
- **Mapa Visual**: Fornece URL para mapa visual da infraestrutura DNS

## Tipos de Dados Suportados

- `domain`: Domínios (ex: example.com)
- `fqdn`: Nomes de domínio totalmente qualificados

## Configurações

### Opcionais

- `dnsdumpster.timeout`: Timeout para requisições HTTP (padrão: 30.0 segundos)

## Uso Programático

### Exemplo Básico

```python
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.dnsdumpster import DnsdumpsterAnalyzer

# Configurar entrada
input_data = WorkerInput(
    data_type="domain",
    data="example.com",
    config=WorkerConfig(
        # Configurações opcionais
    )
)

# Executar análise
analyzer = DnsdumpsterAnalyzer(input_data)
report = analyzer.execute()

# Acessar resultados
print(f"Domínio analisado: {report.data['observable']}")
print(f"Total de registros: {report.data['total_records']}")
print(f"Veredicto: {report.data['verdict']}")
```

### Exemplo com Configurações

```python
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.dnsdumpster import DnsdumpsterAnalyzer

# Configurar com timeout personalizado
config = WorkerConfig()
config.set_config("dnsdumpster.timeout", 60.0)

input_data = WorkerInput(
    data_type="domain",
    data="example.com",
    config=config
)

analyzer = DnsdumpsterAnalyzer(input_data)
report = analyzer.execute()
```

## Estrutura do Relatório

### Campos Principais

- `observable`: Domínio analisado
- `verdict`: Sempre "info" (informacional)
- `taxonomy`: Classificação dos resultados
- `source`: "DNSdumpster.com"
- `data_type`: Tipo de dado analisado
- `results`: Dados brutos do DNSdumpster
- `total_records`: Número total de registros encontrados
- `artifacts`: Lista de artefatos extraídos
- `metadata`: Metadados do módulo

### Estrutura dos Resultados

```python
{
    "domain": "example.com",
    "dns_records": {
        "dns": [  # Registros DNS
            {
                "domain": "subdomain.example.com",
                "ip": "1.2.3.4",
                "reverse_dns": "reverse.example.com",
                "as": "AS12345",
                "provider": "Provider Name",
                "country": "US",
                "header": "Additional info"
            }
        ],
        "mx": [  # Registros MX
            {
                "domain": "mail.example.com",
                "ip": "5.6.7.8",
                "reverse_dns": "mail-reverse.example.com",
                "as": "AS67890",
                "provider": "Mail Provider",
                "country": "US",
                "header": "MX record info"
            }
        ],
        "txt": [  # Registros TXT
            "v=spf1 include:_spf.example.com ~all",
            "google-site-verification=abc123"
        ],
        "host": [  # Informações de host
            {
                "domain": "www.example.com",
                "ip": "9.10.11.12",
                "reverse_dns": "www-reverse.example.com",
                "as": "AS11111",
                "provider": "Web Provider",
                "country": "US",
                "header": "Web server info"
            }
        ],
        "map_url": "https://dnsdumpster.com/static/map/example.com.png"
    }
}
```

### Artefatos Extraídos

O analyzer extrai automaticamente:

- **Endereços IP**: De todos os registros DNS, MX e host
- **Domínios**: Subdomínios e domínios relacionados
- **URLs**: Encontradas em registros TXT

## Taxonomia

### Namespace
- `DNSdumpster`

### Predicados
- `Records Found`: Quando registros DNS são encontrados
- `No Records`: Quando nenhum registro é encontrado

### Níveis
- `info`: Sempre informacional (não indica ameaça)

## Tratamento de Erros

### Erros Comuns

1. **Token CSRF não encontrado**
   - Causa: Problema na página inicial do DNSdumpster
   - Solução: Verificar conectividade e tentar novamente

2. **Erro ao obter resultados**
   - Causa: DNSdumpster reportou erro interno
   - Solução: Verificar se o domínio é válido

3. **Código de status inesperado**
   - Causa: Problema na requisição HTTP
   - Solução: Verificar conectividade e configurações de proxy

### Logs de Debug

O analyzer registra informações detalhadas sobre:
- Obtenção do token CSRF
- Requisições HTTP
- Parsing de respostas
- Extração de artefatos

## Limitações

- Depende da disponibilidade do DNSdumpster.com
- Sujeito a rate limiting do serviço
- Requer conexão com a internet
- Parsing baseado em estrutura HTML (pode quebrar com mudanças no site)

## Casos de Uso

### Reconhecimento de Infraestrutura
```python
# Analisar infraestrutura de um domínio
report = analyzer.execute()
dns_records = report.data['results']['dns_records']

# Listar todos os subdomínios encontrados
subdomains = [record['domain'] for record in dns_records['dns']]
print(f"Subdomínios encontrados: {subdomains}")
```

### Análise de Registros MX
```python
# Analisar servidores de email
mx_records = report.data['results']['dns_records']['mx']
mail_servers = [record['domain'] for record in mx_records]
print(f"Servidores de email: {mail_servers}")
```

### Extração de Artefatos
```python
# Obter todos os artefatos extraídos
artifacts = report.data['artifacts']
ips = [a['value'] for a in artifacts if a['data_type'] == 'ip']
domains = [a['value'] for a in artifacts if a['data_type'] == 'domain']

print(f"IPs encontrados: {ips}")
print(f"Domínios encontrados: {domains}")
```

## Integração com Pipeline

```python
from sentineliqsdk import Pipeline
from sentineliqsdk.analyzers.dnsdumpster import DnsdumpsterAnalyzer

# Criar pipeline com DNSdumpster
pipeline = Pipeline()
pipeline.add_analyzer(DnsdumpsterAnalyzer)

# Processar domínio
results = pipeline.process("domain", "example.com")
```

## Metadados

- **Nome**: DNSdumpster Analyzer
- **Descrição**: Query DNS reconnaissance information for domains using DNSdumpster.com
- **Autor**: SentinelIQ Team
- **Padrão**: threat-intel
- **Estágio**: TESTING
- **Documentação**: [https://killsearch.github.io/sentineliqsdk/modulos/analyzers/dnsdumpster/](https://killsearch.github.io/sentineliqsdk/modulos/analyzers/dnsdumpster/)

## Veja Também

- [Building Analyzers](../../tutorials/building-analyzers.md)
- [Quick Start](../../getting-started/quick-start.md)
- [Threat Intelligence](../../examples/threat-intelligence.md)