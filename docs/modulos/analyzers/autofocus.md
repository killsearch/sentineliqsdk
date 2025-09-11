# AutoFocus Analyzer

O AutoFocus Analyzer permite consultar a plataforma de inteligência de ameaças AutoFocus da Palo Alto Networks para análise de amostras e busca de IOCs (Indicators of Compromise). Este analisador suporta múltiplos tipos de dados e serviços para análises abrangentes de segurança.

## Características

- **Múltiplos tipos de dados**: Suporta ip, domain, fqdn, hash, url, user-agent
- **Dois serviços principais**: `get_sample_analysis` (para hashes) e `search_ioc` (para outros tipos)
- **Metadados detalhados**: Retorna metadados, tags e resultados de análise do AutoFocus
- **Taxonomia inteligente**: Gera entradas de taxonomia baseadas nos resultados da busca
- **Busca personalizada**: Suporte para consultas JSON customizadas

## Configuração

### Parâmetros Obrigatórios

- **API Key**: Chave de API do AutoFocus
- **Service**: Tipo de serviço a ser utilizado

### Serviços Disponíveis

#### `get_sample_analysis`
- **Uso**: Análise detalhada de amostras por hash
- **Tipos suportados**: `hash`
- **Retorna**: Metadados, tags e análises detalhadas da amostra

#### `search_ioc`
- **Uso**: Busca de IOCs na base de dados do AutoFocus
- **Tipos suportados**: `ip`, `domain`, `fqdn`, `url`, `user-agent`
- **Retorna**: Lista de amostras que correspondem ao IOC

#### `search_json`
- **Uso**: Busca usando consulta JSON personalizada
- **Tipos suportados**: `other`
- **Retorna**: Resultados baseados na consulta customizada

## Uso Programático

### Análise de Hash (get_sample_analysis)

```python
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.autofocus import AutoFocusAnalyzer

# Configurar entrada para análise de hash
input_data = WorkerInput(
    data_type="hash",
    data="abc123def456...",
    config=WorkerConfig(
        secrets={"autofocus": {"apikey": "YOUR_API_KEY"}},
        params={"autofocus": {"service": "get_sample_analysis"}}
    ),
)

# Executar análise
analyzer = AutoFocusAnalyzer(input_data)
report = analyzer.execute()

# Verificar resultado
print(f"Metadados: {report.full_report['result']['metadata']}")
print(f"Tags: {report.full_report['result']['tags']}")
```

### Busca de IP (search_ioc)

```python
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.autofocus import AutoFocusAnalyzer

# Configurar entrada para busca de IP
input_data = WorkerInput(
    data_type="ip",
    data="1.2.3.4",
    config=WorkerConfig(
        secrets={"autofocus": {"apikey": "YOUR_API_KEY"}},
        params={"autofocus": {"service": "search_ioc"}}
    ),
)

# Executar busca
analyzer = AutoFocusAnalyzer(input_data)
report = analyzer.execute()

# Verificar resultados
records = report.full_report['result']['records']
print(f"Encontradas {len(records)} amostras")
```

### Busca de Domínio (search_ioc)

```python
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.autofocus import AutoFocusAnalyzer

# Configurar entrada para busca de domínio
input_data = WorkerInput(
    data_type="domain",
    data="malicious-domain.com",
    config=WorkerConfig(
        secrets={"autofocus": {"apikey": "YOUR_API_KEY"}},
        params={"autofocus": {"service": "search_ioc"}}
    ),
)

# Executar busca
analyzer = AutoFocusAnalyzer(input_data)
report = analyzer.execute()
```

### Busca de URL (search_ioc)

```python
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.autofocus import AutoFocusAnalyzer

# Configurar entrada para busca de URL
input_data = WorkerInput(
    data_type="url",
    data="https://malicious-site.com/payload.exe",
    config=WorkerConfig(
        secrets={"autofocus": {"apikey": "YOUR_API_KEY"}},
        params={"autofocus": {"service": "search_ioc"}}
    ),
)

# Executar busca
analyzer = AutoFocusAnalyzer(input_data)
report = analyzer.execute()
```

### Busca de User-Agent (search_ioc)

```python
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.autofocus import AutoFocusAnalyzer

# Configurar entrada para busca de User-Agent
input_data = WorkerInput(
    data_type="user-agent",
    data="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    config=WorkerConfig(
        secrets={"autofocus": {"apikey": "YOUR_API_KEY"}},
        params={"autofocus": {"service": "search_ioc"}}
    ),
)

# Executar busca
analyzer = AutoFocusAnalyzer(input_data)
report = analyzer.execute()
```


### Busca JSON Personalizada (search_json)

```python
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.autofocus import AutoFocusAnalyzer

# Configurar entrada para busca JSON personalizada
custom_query = '{"operator":"all","children":[{"field":"sample.tag","operator":"is in the list","value":["APT29"]}]}'

input_data = WorkerInput(
    data_type="other",
    data=custom_query,
    config=WorkerConfig(
        secrets={"autofocus": {"apikey": "YOUR_API_KEY"}},
        params={"autofocus": {"service": "search_json"}}
    ),
)

# Executar busca
analyzer = AutoFocusAnalyzer(input_data)
report = analyzer.execute()
```

## Estrutura do Relatório

### Relatório de Análise de Amostra (get_sample_analysis)

```json
{
  "observable": "abc123def456...",
  "data_type": "hash",
  "service": "get_sample_analysis",
  "result": {
    "metadata": {
      "sha256": "abc123def456...",
      "md5": "def456ghi789...",
      "sha1": "ghi789jkl012...",
      "file_type": "PE32 executable",
      "file_size": 1234567
    },
    "tags": [
      {
        "tag": "APT29",
        "public_tag_name": "APT29",
        "tag_class": "actor"
      }
    ],
    "analysis": {
      "StaticAnalysis": [
        {
          "analysis_type": "static",
          "results": {...}
        }
      ],
      "DynamicAnalysis": [
        {
          "analysis_type": "dynamic",
          "results": {...}
        }
      ]
    }
  },
  "taxonomy": [
    {
      "level": "info",
      "namespace": "PaloAltoNetworks",
      "predicate": "AutoFocus",
      "value": "Sample found"
    }
  ],
  "metadata": {
    "Name": "AutoFocus Analyzer",
    "Description": "Query Palo Alto Networks AutoFocus for threat intelligence and sample analysis",
    "Author": ["SentinelIQ Team <team@sentineliq.com.br>"],
    "License": "SentinelIQ License",
    "pattern": "threat-intel",
    "doc_pattern": "MkDocs module page; programmatic usage",
    "doc": "https://killsearch.github.io/sentineliqsdk/modulos/analyzers/autofocus/",
    "VERSION": "TESTING"
  }
}
```

### Relatório de Busca de IOC (search_ioc)

```json
{
  "observable": "1.2.3.4",
  "data_type": "ip",
  "service": "search_ioc",
  "result": {
    "search": {
      "operator": "all",
      "children": [
        {
          "field": "alias.ip_address",
          "operator": "contains",
          "value": "1.2.3.4"
        }
      ]
    },
    "records": [
      {
        "metadata": {
          "sha256": "sample1_sha256...",
          "file_type": "PE32 executable",
          "file_size": 1234567
        },
        "tags": [
          {
            "tag": "APT29",
            "public_tag_name": "APT29",
            "tag_class": "actor"
          }
        ]
      }
    ]
  },
  "taxonomy": [
    {
      "level": "suspicious",
      "namespace": "PaloAltoNetworks",
      "predicate": "AutoFocus",
      "value": "3 sample(s) found"
    }
  ],
  "metadata": {
    "Name": "AutoFocus Analyzer",
    "Description": "Query Palo Alto Networks AutoFocus for threat intelligence and sample analysis",
    "Author": ["SentinelIQ Team <team@sentineliq.com.br>"],
    "License": "SentinelIQ License",
    "pattern": "threat-intel",
    "doc_pattern": "MkDocs module page; programmatic usage",
    "doc": "https://killsearch.github.io/sentineliqsdk/modulos/analyzers/autofocus/",
    "VERSION": "TESTING"
  }
}
```

## Níveis de Taxonomia

O analisador gera entradas de taxonomia baseadas nos resultados da busca:

- **info**: Nenhum resultado encontrado ou amostra encontrada
- **suspicious**: Múltiplas amostras encontradas (indica possível atividade maliciosa)
- **malicious**: Amostra confirmada como maliciosa (baseado em tags e análise)

### Entradas de Taxonomia

- `PaloAltoNetworks/AutoFocus`: Resultado principal da busca
  - **info**: "Sample found" ou "No results"
  - **suspicious**: "X sample(s) found" (quando X > 0)

## Exemplo de Uso

Veja o arquivo de exemplo completo em `examples/analyzers/autofocus_example.py`:

```bash
# Busca de IP (modo dry-run)
python examples/analyzers/autofocus_example.py --data-type ip --data 1.2.3.4 --service search_ioc

# Análise de hash (modo dry-run)
python examples/analyzers/autofocus_example.py --data-type hash --data abc123... --service get_sample_analysis

# Busca de domínio (modo dry-run)
python examples/analyzers/autofocus_example.py --data-type domain --data malicious.com --service search_ioc

# Executar busca real
python examples/analyzers/autofocus_example.py --data-type ip --data 1.2.3.4 --service search_ioc --execute

# Busca com API key específica
python examples/analyzers/autofocus_example.py \
  --data-type url \
  --data "https://malicious.com/payload.exe" \
  --service search_ioc \
  --apikey YOUR_API_KEY \
  --execute
```

## Limitações e Considerações

1. **API Key**: É necessária uma chave de API válida do AutoFocus para uso em produção.

2. **Rate Limiting**: A API do AutoFocus tem limites de taxa. Monitore o uso para evitar bloqueios.

3. **Dependências**: O analisador requer a biblioteca `autofocus` instalada:
   ```bash
   pip install autofocus
   ```

4. **Tipos de Dados**: Nem todos os tipos de dados são suportados por todos os serviços:
   - `get_sample_analysis`: apenas `hash`
   - `search_ioc`: `ip`, `domain`, `fqdn`, `url`, `user-agent`
   - `search_json`: apenas `other`

5. **Resultados**: O número de resultados pode variar dependendo da disponibilidade de dados no AutoFocus.

## Tratamento de Erros

O analisador trata os seguintes cenários de erro:

- Chave de API inválida ou ausente
- Serviço não suportado para o tipo de dados
- Amostra não encontrada no AutoFocus
- Erros de servidor do AutoFocus
- Erros de cliente (parâmetros inválidos)
- Erros de rede e timeout

## Integração com Outros Módulos

Este analisador pode ser usado em conjunto com:

- **Extractors**: Para extrair IOCs dos relatórios de análise
- **Responders**: Para ações baseadas nos resultados da busca
- **Detectors**: Para detecção automática de tipos de dados suspeitos
- **Outros Analyzers**: Para correlação de dados de múltiplas fontes

## Referências

- [AutoFocus API Documentation](https://docs.paloaltonetworks.com/autofocus)
- [Palo Alto Networks AutoFocus](https://www.paloaltonetworks.com/products/autofocus)
- [AutoFocus Python Library](https://github.com/PaloAltoNetworks/autofocus-python)
