# EchoTrail Analyzer

O **EchoTrail Analyzer** é um módulo de análise que utiliza a API do EchoTrail para fornecer inteligência sobre hashes de arquivos, incluindo informações de prevalência, reputação e metadados associados.

## Visão Geral

Este analyzer consulta a API do EchoTrail para obter insights sobre arquivos baseados em seus hashes, fornecendo informações valiosas sobre prevalência, reputação, caminhos, processos pais e filhos, e informações de rede associadas.

## Características

- **API Key Obrigatória**: Requer chave de API do EchoTrail
- **Suporte a Proxy**: Honra proxies HTTP via `WorkerConfig.proxy`
- **Análise de Reputação**: Avalia arquivos com base em rank e prevalência
- **Detecção de Ameaças**: Identifica arquivos maliciosos e suspeitos
- **Metadados Ricos**: Fornece informações detalhadas sobre arquivos

## Tipos de Dados Suportados

- `hash`: Hashes de arquivos (MD5 ou SHA-256)

## Configurações

### Obrigatórias

- `echotrail.api_key`: Chave de API do EchoTrail (via secrets)

### Opcionais

- `echotrail.proxy`: Configuração de proxy HTTP

## Uso Programático

### Exemplo Básico

```python
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.echotrail import EchoTrailAnalyzer

# Configurar secrets
config = WorkerConfig(
    secrets={
        "echotrail": {
            "api_key": "sua_api_key_aqui"
        }
    }
)

# Configurar entrada
input_data = WorkerInput(
    data_type="hash",
    data="d41d8cd98f00b204e9800998ecf8427e",  # MD5 hash
    config=config
)

# Executar análise
analyzer = EchoTrailAnalyzer(input_data)
report = analyzer.execute()

# Acessar resultados
print(f"Hash analisado: {report.data['observable']}")
print(f"Veredicto: {report.data['verdict']}")
print(f"Matched: {report.data['details']['matched']}")
```

### Exemplo com SHA-256

```python
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.echotrail import EchoTrailAnalyzer

# Hash SHA-256
sha256_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

input_data = WorkerInput(
    data_type="hash",
    data=sha256_hash,
    config=config
)

analyzer = EchoTrailAnalyzer(input_data)
report = analyzer.execute()
```

### Exemplo com Proxy

```python
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.echotrail import EchoTrailAnalyzer

# Configurar com proxy
config = WorkerConfig(
    secrets={
        "echotrail": {
            "api_key": "sua_api_key_aqui"
        }
    }
)
config.set_config("echotrail.proxy", {
    "http": "http://proxy.example.com:8080",
    "https": "https://proxy.example.com:8080"
})

input_data = WorkerInput(
    data_type="hash",
    data="d41d8cd98f00b204e9800998ecf8427e",
    config=config
)

analyzer = EchoTrailAnalyzer(input_data)
report = analyzer.execute()
```

## Estrutura do Relatório

### Campos Principais

- `observable`: Hash analisado
- `verdict`: Veredicto da análise (info, safe, suspicious, malicious)
- `taxonomy`: Classificação dos resultados
- `source`: "echotrail"
- `data_type`: "hash"
- `details`: Dados detalhados da API do EchoTrail
- `metadata`: Metadados do módulo

### Estrutura dos Detalhes

```python
{
    "matched": True,  # Se o hash foi encontrado na base
    "rank": 50,       # Rank de reputação (menor = mais suspeito)
    "host_prev": 0.05,  # Prevalência em hosts (0-1)
    "eps": 500,       # Events Per Second
    "paths": [        # Caminhos onde o arquivo foi encontrado
        "C:\\Windows\\System32\\notepad.exe",
        "C:\\Program Files\\App\\file.exe"
    ],
    "parents": [      # Processos pais
        "explorer.exe",
        "cmd.exe"
    ],
    "children": [     # Processos filhos
        "child1.exe",
        "child2.exe"
    ],
    "network": {      # Informações de rede
        "connections": [
            {
                "ip": "1.2.3.4",
                "port": 80,
                "protocol": "tcp"
            }
        ]
    }
}
```

## Lógica de Veredicto

### Thresholds de Avaliação

```python
MALICIOUS_RANK_THRESHOLD = 10      # Rank <= 10 = malicioso
SUSPICIOUS_RANK_THRESHOLD = 100    # Rank <= 100 = suspeito
LOW_PREVALENCE_THRESHOLD = 0.01    # Prevalência < 1% = suspeito
HIGH_EPS_THRESHOLD = 1000          # EPS > 1000 = suspeito
```

### Critérios de Classificação

1. **Malicious**: Rank ≤ 10
2. **Suspicious**: 
   - Rank ≤ 100, ou
   - Prevalência < 1%, ou
   - EPS > 1000
3. **Safe**: Arquivo conhecido e confiável
4. **Info**: Hash não encontrado na base

## Taxonomia

### Namespace
- `echotrail`

### Predicados
- `reputation`: Reputação do hash

### Níveis
- `info`: Hash não encontrado
- `safe`: Arquivo seguro/confiável
- `suspicious`: Arquivo suspeito
- `malicious`: Arquivo malicioso

## Validação de Hash

O analyzer valida o formato dos hashes:

- **MD5**: 32 caracteres hexadecimais
- **SHA-256**: 64 caracteres hexadecimais

```python
# Exemplo de validação
if len(hash_str) not in (32, 64):
    raise ValueError("Hash deve ter 32 (MD5) ou 64 (SHA-256) caracteres")
```

## Tratamento de Erros

### Erros Comuns

1. **API Key inválida**
   - Causa: Chave de API não fornecida ou inválida
   - Solução: Verificar configuração de secrets

2. **Hash não encontrado**
   - Causa: Hash não existe na base do EchoTrail
   - Resultado: `matched: false`, veredicto `info`

3. **Formato de hash inválido**
   - Causa: Hash com comprimento incorreto
   - Solução: Usar MD5 (32 chars) ou SHA-256 (64 chars)

4. **Erro de rede**
   - Causa: Problemas de conectividade
   - Solução: Verificar proxy e conectividade

### Logs de Debug

O analyzer registra informações sobre:
- Requisições à API
- Respostas recebidas
- Erros de validação
- Determinação de veredicto

## Utilitários

### Cálculo de Hash de Arquivo

```python
from sentineliqsdk.analyzers.echotrail import EchoTrailAnalyzer

# Calcular hash SHA-256 de um arquivo
hash_value = EchoTrailAnalyzer.get_file_hash(
    "/path/to/file.exe",
    algorithm=hashlib.sha256
)

# Calcular hash MD5
hash_value = EchoTrailAnalyzer.get_file_hash(
    "/path/to/file.exe",
    algorithm=hashlib.md5
)
```

## Casos de Uso

### Análise de Malware
```python
# Analisar hash suspeito
report = analyzer.execute()
if report.data['verdict'] == 'malicious':
    details = report.data['details']
    print(f"Arquivo malicioso detectado!")
    print(f"Rank: {details.get('rank')}")
    print(f"Prevalência: {details.get('host_prev')}")
```

### Verificação de Reputação
```python
# Verificar se arquivo é conhecido e seguro
report = analyzer.execute()
if report.data['details']['matched']:
    if report.data['verdict'] == 'safe':
        print("Arquivo conhecido e seguro")
    else:
        print(f"Arquivo suspeito: {report.data['verdict']}")
else:
    print("Arquivo não encontrado na base")
```

### Análise de Prevalência
```python
# Analisar prevalência do arquivo
details = report.data['details']
if 'host_prev' in details:
    prevalence = details['host_prev'] * 100
    print(f"Arquivo encontrado em {prevalence:.2f}% dos hosts")
```

## Integração com Pipeline

```python
from sentineliqsdk import Pipeline
from sentineliqsdk.analyzers.echotrail import EchoTrailAnalyzer

# Criar pipeline com EchoTrail
pipeline = Pipeline()
pipeline.add_analyzer(EchoTrailAnalyzer)

# Processar hash
results = pipeline.process("hash", "d41d8cd98f00b204e9800998ecf8427e")
```

## Limitações

- Requer chave de API válida do EchoTrail
- Suporta apenas hashes MD5 e SHA-256
- Dependente da disponibilidade da API
- Rate limiting aplicado pela API
- Cobertura limitada à base de dados do EchoTrail

## Metadados

- **Nome**: EchoTrail Analyzer
- **Descrição**: File hash analysis using EchoTrail API for prevalence and reputation insights
- **Autor**: SentinelIQ Team
- **Padrão**: threat-intel
- **Estágio**: TESTING
- **Documentação**: [https://killsearch.github.io/sentineliqsdk/modulos/analyzers/echotrail/](https://killsearch.github.io/sentineliqsdk/modulos/analyzers/echotrail/)

## Veja Também

- [Analyzer Base](../base.md)
- [WorkerConfig](../../core/worker-config.md)
- [Secrets Management](../../core/secrets.md)
- [Taxonomy](../../core/taxonomy.md)
- [Hash Analysis](../../guides/hash-analysis.md)