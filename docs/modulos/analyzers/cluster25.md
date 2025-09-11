# Cluster25 Analyzer

O **Cluster25 Analyzer** é um módulo de análise de indicadores de ameaça que utiliza a plataforma de inteligência de ameaças Cluster25 para obter dados de reputação e classificação de segurança.

## Visão Geral

Este analyzer consulta a API do Cluster25 para obter informações de inteligência de ameaças sobre vários tipos de indicadores, incluindo IPs, domínios, URLs e outros observáveis. O Cluster25 fornece pontuações de reputação e classificações de segurança baseadas em sua base de dados de ameaças.

## Características

- **Análise de Reputação**: Obtém pontuações de reputação para indicadores
- **Classificação Automática**: Classifica indicadores como seguros, suspeitos ou maliciosos
- **Múltiplos Tipos de Dados**: Suporta IPs, domínios, URLs e outros observáveis
- **Taxonomia Estruturada**: Gera entradas de taxonomia padronizadas
- **Configuração Flexível**: Suporte a configurações personalizadas de timeout e retry

## Configuração

### Credenciais (Obrigatórias)

O analyzer requer as seguintes credenciais configuradas em `WorkerConfig.secrets`:

```python
secrets = {
    "cluster25": {
        "client_id": "seu_client_id_aqui",
        "client_key": "sua_client_key_aqui"
    }
}
```

### Configurações Opcionais

```python
config = WorkerConfig(
    # Configurações gerais
    check_tlp=True,
    max_tlp=2,
    check_pap=True,
    max_pap=2,
    auto_extract=True,
    # Configurações do Cluster25 via params
    params={
        "cluster25.base_url": "https://api.cluster25.com",  # URL base da API
        "cluster25.timeout": 30,                            # Timeout em segundos
        "cluster25.max_retries": 3,                         # Número máximo de tentativas
    },
    secrets=secrets
)
```

## Uso Programático

### Exemplo Básico

```python
from __future__ import annotations

from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.cluster25 import Cluster25Analyzer

# Configurar credenciais
secrets = {
    "cluster25": {
        "client_id": "seu_client_id_aqui",
        "client_key": "sua_client_key_aqui"
    }
}

# Configurar parâmetros
config = WorkerConfig(
    check_tlp=True,
    max_tlp=2,
    check_pap=True,
    max_pap=2,
    auto_extract=True,
    params={
        "cluster25.base_url": "https://api.cluster25.com",
        "cluster25.timeout": 30,
        "cluster25.max_retries": 3,
    },
    secrets=secrets
)

# Criar dados de entrada
input_data = WorkerInput(
    data_type="ip",
    data="1.2.3.4",
    tlp=2,
    pap=2,
    config=config
)

# Executar análise
analyzer = Cluster25Analyzer(input_data)
report = analyzer.execute()

# Acessar resultados
print(f"Observable: {report.full_report['observable']}")
print(f"Score: {report.full_report['indicator_data'].get('score', 'N/A')}")
print(f"Taxonomy: {report.full_report['taxonomy']}")
```

### Exemplo com Diferentes Tipos de Dados

```python
# Analisar IP
ip_data = WorkerInput(
    data_type="ip",
    data="192.168.1.1",
    config=config
)
ip_report = Cluster25Analyzer(ip_data).execute()

# Analisar domínio
domain_data = WorkerInput(
    data_type="domain",
    data="example.com",
    config=config
)
domain_report = Cluster25Analyzer(domain_data).execute()

# Analisar URL
url_data = WorkerInput(
    data_type="url",
    data="https://example.com/path",
    config=config
)
url_report = Cluster25Analyzer(url_data).execute()
```

### Processamento em Lote

```python
indicators = ["1.2.3.4", "8.8.8.8", "malicious.com"]
results = []

for indicator in indicators:
    # Determinar tipo de dados automaticamente
    data_type = "ip" if indicator.count(".") == 3 else "domain"
    
    input_data = WorkerInput(
        data_type=data_type,
        data=indicator,
        config=config
    )
    
    analyzer = Cluster25Analyzer(input_data)
    report = analyzer.execute()
    results.append(report)

# Processar resultados
for i, report in enumerate(results):
    if report.success:
        score = report.full_report['indicator_data'].get('score', 0)
        print(f"{indicators[i]}: Score {score}")
```

## Estrutura de Resposta

### Resposta de Sucesso

```json
{
  "success": true,
  "summary": {},
  "artifacts": [],
  "operations": [],
  "full_report": {
    "observable": "1.2.3.4",
    "indicator_data": {
      "indicator": "1.2.3.4",
      "indicator_type": "ip",
      "score": 75
    },
    "taxonomy": [
      {
        "level": "info",
        "namespace": "C25",
        "predicate": "Indicator",
        "value": "1.2.3.4"
      },
      {
        "level": "info",
        "namespace": "C25",
        "predicate": "Indicator Type",
        "value": "ip"
      },
      {
        "level": "suspicious",
        "namespace": "C25",
        "predicate": "Score",
        "value": "75"
      }
    ],
    "metadata": {
      "Name": "Cluster25 Analyzer",
      "Description": "Analyzes indicators using Cluster25 threat intelligence platform",
      "Author": ["SentinelIQ Team <team@sentineliq.com.br>"],
      "pattern": "threat-intel",
      "doc_pattern": "MkDocs module page; programmatic usage",
      "doc": "https://killsearch.github.io/sentineliqsdk/modulos/analyzers/cluster25/",
      "VERSION": "TESTING"
    }
  }
}
```

### Resposta de Erro

```json
{
  "success": true,
  "summary": {},
  "artifacts": [],
  "operations": [],
  "full_report": {
    "observable": "1.2.3.4",
    "error": "Unable to retrieve investigate result for indicator '1.2.3.4' from Cluster25 platform: 404 Not Found",
    "taxonomy": [
      {
        "level": "info",
        "namespace": "C25",
        "predicate": "Error",
        "value": "Unable to retrieve investigate result for indicator '1.2.3.4' from Cluster25 platform: 404 Not Found"
      }
    ],
    "metadata": { ... }
  }
}
```

## Níveis de Taxonomia

O analyzer classifica indicadores com base na pontuação retornada pela API:

- **Safe** (score < 50): Indicador considerado seguro
- **Suspicious** (50 ≤ score < 80): Indicador suspeito
- **Malicious** (score ≥ 80): Indicador malicioso confirmado

## Tipos de Dados Suportados

- `ip`: Endereços IPv4 e IPv6
- `url`: URLs completas
- `domain`: Nomes de domínio
- `fqdn`: Nomes de domínio totalmente qualificados
- `hash`: Hashes MD5, SHA1, SHA256
- `mail`: Endereços de email
- `user-agent`: User agents de navegadores
- `uri_path`: Caminhos de URI
- `registry`: Chaves de registro
- `file`: Arquivos (quando aplicável)
- `other`: Outros tipos de observáveis

## Tratamento de Erros

O analyzer trata erros de forma robusta:

- **Erro de Autenticação**: Falha ao obter token de acesso
- **Erro de API**: Falha na consulta à API de investigação
- **Erro de Rede**: Problemas de conectividade
- **Erro de Configuração**: Credenciais ou configurações ausentes

Em todos os casos, o analyzer retorna um relatório válido com informações de erro na taxonomia.

## Exemplo de Uso com CLI

```bash
# Executar exemplo básico
python examples/analyzers/cluster25_example.py

# Executar com chamadas reais da API
python examples/analyzers/cluster25_example.py --execute

# Analisar indicador específico
python examples/analyzers/cluster25_example.py --data-type ip --data 1.2.3.4 --execute

# Saída em formato JSON
python examples/analyzers/cluster25_example.py --execute --json
```

## Dependências

- `requests`: Para comunicação HTTP com a API
- `sentineliqsdk`: SDK base do SentinelIQ

## Limitações

- Requer credenciais válidas do Cluster25
- Dependente da disponibilidade da API do Cluster25
- Rate limiting pode se aplicar dependendo do plano da API
- Timeout configurável para evitar travamentos

## Suporte

Para suporte e dúvidas sobre o Cluster25 Analyzer:

- **Documentação**: [Agent Guide](../../guides/guide.md)
- **Exemplos**: [Threat Intelligence](../../examples/threat-intelligence.md)
- **Issues**: [GitHub Issues](https://github.com/killsearch/sentineliqsdk/issues)

## Changelog

### v1.0.0
- Implementação inicial do Cluster25 Analyzer
- Suporte a análise de múltiplos tipos de indicadores
- Sistema de taxonomia baseado em pontuação
- Configuração flexível via WorkerConfig
- Tratamento robusto de erros
