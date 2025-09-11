# MCAP Analyzer

O MCAP Analyzer utiliza a plataforma MCAP (Malware Configuration and Analysis Platform) da CIS Security para analisar observáveis e arquivos em busca de indicadores de comprometimento (IOCs).

## Características

- **Análise de observáveis**: IPs, domínios, URLs e hashes SHA-256
- **Análise de arquivos**: Submissão e análise de arquivos maliciosos
- **Feed de IOCs**: Consulta de feeds de indicadores conhecidos
- **Configuração flexível**: Limites de confiança e severidade personalizáveis
- **Modo seguro**: Dry-run por padrão, com flags de segurança

## Uso Programático

### Exemplo Básico

```python
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.mcap import MCAPAnalyzer

# Configurar credenciais
secrets = {
    "mcap": {
        "api_key": "sua_api_key_aqui"
    }
}

# Configurar parâmetros
config = WorkerConfig(
    check_tlp=True,
    max_tlp=2,
    check_pap=True,
    max_pap=2,
    auto_extract=True,
    # Configurações específicas do MCAP
    mcap_private_samples=False,
    mcap_minimum_confidence=80,
    mcap_minimum_severity=80,
    mcap_polling_interval=60,
    mcap_max_sample_result_wait=1000,
    secrets=secrets
)

# Criar entrada
input_data = WorkerInput(
    data_type="ip",
    data="1.2.3.4",
    tlp=2,
    pap=2,
    config=config
)

# Executar análise
analyzer = MCAPAnalyzer(input_data)
report = analyzer.execute()

print(report.full_report)
```

### Análise de Arquivo

```python
# Para análise de arquivo
input_data = WorkerInput(
    data_type="file",
    data="/caminho/para/arquivo.exe",
    tlp=2,
    pap=2,
    config=config
)

analyzer = MCAPAnalyzer(input_data)
report = analyzer.execute()

# O relatório incluirá o status da amostra e IOCs encontrados
print(f"Status: {report.full_report['sample_status']['state']}")
print(f"IOCs encontrados: {report.full_report['ioc_count']}")
```

### Análise de Diferentes Tipos de Observáveis

```python
# IP
ip_data = WorkerInput(data_type="ip", data="1.2.3.4", config=config)
ip_report = MCAPAnalyzer(ip_data).execute()

# Domínio
domain_data = WorkerInput(data_type="domain", data="example.com", config=config)
domain_report = MCAPAnalyzer(domain_data).execute()

# URL
url_data = WorkerInput(data_type="url", data="https://example.com/malware", config=config)
url_report = MCAPAnalyzer(url_data).execute()

# Hash SHA-256
hash_data = WorkerInput(data_type="hash", data="a" * 64, config=config)
hash_report = MCAPAnalyzer(hash_data).execute()
```

## Configuração

### Parâmetros de Configuração

| Parâmetro | Tipo | Padrão | Descrição |
|-----------|------|--------|-----------|
| `mcap.api_key` | str | - | Chave da API MCAP (obrigatório) |
| `mcap.private_samples` | bool | False | Marcar amostras como privadas |
| `mcap.minimum_confidence` | int | 80 | Limite mínimo de confiança |
| `mcap.minimum_severity` | int | 80 | Limite mínimo de severidade |
| `mcap.polling_interval` | int | 60 | Intervalo de polling em segundos |
| `mcap.max_sample_result_wait` | int | 1000 | Tempo máximo de espera em segundos |

### Configuração de Proxy

```python
config = WorkerConfig(
    # ... outras configurações ...
    proxy=ProxyConfig(
        http="http://proxy:8080",
        https="https://proxy:8080"
    )
)
```

## Estrutura do Relatório

### Relatório de Observável

```json
{
  "success": true,
  "summary": {"ioc_count": 2},
  "artifacts": [],
  "operations": [],
  "full_report": {
    "observable": "1.2.3.4",
    "data_type": "ip",
    "iocs": [
      {
        "ip": "1.2.3.4",
        "confidence": 90,
        "severity": 85
      }
    ],
    "ioc_count": 1,
    "taxonomy": [
      {
        "level": "malicious",
        "namespace": "CISMCAP",
        "predicate": "IOC count",
        "value": "1"
      }
    ],
    "metadata": {
      "name": "MCAP Analyzer",
      "description": "Analyzes observables using MCAP...",
      "version_stage": "TESTING"
    }
  }
}
```

### Relatório de Arquivo

```json
{
  "success": true,
  "summary": {"ioc_count": 3},
  "artifacts": [],
  "operations": [],
  "full_report": {
    "observable": "/path/to/file.exe",
    "data_type": "file",
    "sample_status": {
      "id": "sample_id",
      "state": "succ",
      "sha256": "a1b2c3...",
      "filename": "file.exe"
    },
    "iocs": [...],
    "ioc_count": 3,
    "taxonomy": [...],
    "metadata": {...}
  }
}
```

## Níveis de Taxonomia

- **`malicious`**: IOCs encontrados (ioc_count > 0)
- **`safe`**: Nenhum IOC encontrado (ioc_count = 0)

## Tratamento de Erros

O analisador trata os seguintes erros:

- **API Key ausente**: Erro fatal se não fornecida
- **Tipo de dados não suportado**: Erro para tipos não suportados
- **Hash inválido**: Erro para hashes que não sejam SHA-256
- **Arquivo não encontrado**: Erro se o arquivo não existir
- **Timeout de análise**: Erro se a análise demorar muito
- **Falha na API**: Erro com detalhes da resposta da API

## Exemplo de Uso via Linha de Comando

```bash
# Análise de IP (modo dry-run)
python examples/analyzers/mcap_example.py --data-type ip --data "1.2.3.4"

# Análise real de IP
python examples/analyzers/mcap_example.py --data-type ip --data "1.2.3.4" --execute

# Análise de arquivo (requer flag de perigo)
python examples/analyzers/mcap_example.py --data-type file --file "malware.exe" --execute --include-dangerous

# Com configurações personalizadas
python examples/analyzers/mcap_example.py --data-type domain --data "example.com" --execute --api-key "sua_key" --minimum-confidence 90
```

## Requisitos

- Python 3.13+
- Chave da API MCAP
- Conexão com a internet
- Para análise de arquivos: permissões de leitura do arquivo

## Limitações

- Apenas hashes SHA-256 são suportados para análise de hash
- Análise de arquivos pode demorar vários minutos
- Requer chave da API válida
- Limites de taxa podem se aplicar dependendo do plano da API
