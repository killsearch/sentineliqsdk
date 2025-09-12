# EclecticIQ Analyzer

O **EclecticIQ Analyzer** é um módulo de análise que busca observáveis em uma instância EclecticIQ configurada, fornecendo acesso à API EclecticIQ para buscar observáveis e entidades relacionadas.

## Visão Geral

Este analyzer conecta-se a uma instância EclecticIQ para buscar informações sobre observáveis, incluindo scores de maliciosidade, entidades relacionadas, fontes de inteligência e metadados associados. Suporta todos os tipos de dados padrão do Cortex.

## Características

- **API Key Obrigatória**: Requer credenciais de API da instância EclecticIQ
- **Instância Configurável**: Conecta-se a qualquer instância EclecticIQ
- **Suporte a Proxy**: Honra proxies HTTP via `WorkerConfig.proxy`
- **Análise de Reputação**: Avalia observáveis com base em scores de maliciosidade
- **Entidades Relacionadas**: Busca entidades associadas aos observáveis
- **Múltiplas Fontes**: Integra informações de diferentes fontes de inteligência

## Tipos de Dados Suportados

Todos os tipos de dados padrão do Cortex são suportados:
- `ip`: Endereços IP
- `domain`: Domínios
- `url`: URLs
- `hash`: Hashes de arquivos
- `mail`: Endereços de email
- `fqdn`: Nomes de domínio totalmente qualificados
- E outros tipos suportados pelo EclecticIQ

## Configurações

### Obrigatórias (via Secrets)

- `eclectiq.api_key`: Chave de API da instância EclecticIQ
- `eclectiq.url`: URL da instância EclecticIQ (ex: https://sua-instancia.eclecticiq.com)
- `eclectiq.name`: Nome identificador da instância

### Opcionais

- `eclectiq.cert_check`: Verificação de certificado SSL (padrão: true)
- `eclectiq.cert_path`: Caminho para certificado personalizado

## Uso Programático

### Exemplo Básico

```python
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.eclectiq import EclecticIQAnalyzer

# Configurar secrets
config = WorkerConfig(
    secrets={
        "eclectiq": {
            "api_key": "sua_chave_api_aqui",
            "url": "https://sua-instancia.eclecticiq.com",
            "name": "nome_da_instancia"
        }
    }
)

# Configurar entrada
input_data = WorkerInput(
    data_type="ip",
    data="1.2.3.4",
    config=config
)

# Executar análise
analyzer = EclecticIQAnalyzer(input_data)
report = analyzer.execute()

# Acessar resultados
print(f"Observável analisado: {report.data['observable']}")
print(f"Veredicto: {report.data['verdict']}")
print(f"Entidades encontradas: {report.data['details']['count']}")
```

### Exemplo com Domínio

```python
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.eclectiq import EclecticIQAnalyzer

input_data = WorkerInput(
    data_type="domain",
    data="malicious-domain.com",
    config=config
)

analyzer = EclecticIQAnalyzer(input_data)
report = analyzer.execute()

# Verificar score de maliciosidade
details = report.data['details']
if 'obs_score' in details:
    print(f"Score de maliciosidade: {details['obs_score']}")
```

### Exemplo com Hash

```python
input_data = WorkerInput(
    data_type="hash",
    data="d41d8cd98f00b204e9800998ecf8427e",
    config=config
)

analyzer = EclecticIQAnalyzer(input_data)
report = analyzer.execute()

# Listar entidades relacionadas
for entity in report.data['details'].get('entities', []):
    print(f"Entidade: {entity['title']} (Tipo: {entity['type']})")
```

### Exemplo com Certificado Personalizado

```python
config = WorkerConfig(
    secrets={
        "eclectiq": {
            "api_key": "sua_chave_api_aqui",
            "url": "https://sua-instancia.eclecticiq.com",
            "name": "nome_da_instancia"
        }
    }
)

# Configurar certificado personalizado
config.set_config("eclectiq.cert_check", True)
config.set_config("eclectiq.cert_path", "/path/to/certificate.pem")

analyzer = EclecticIQAnalyzer(input_data)
report = analyzer.execute()
```

## Estrutura do Relatório

### Campos Principais

- `observable`: Observável analisado
- `verdict`: Veredicto da análise (info, safe, suspicious, malicious)
- `taxonomy`: Classificação dos resultados
- `source`: "eclectiq"
- `data_type`: Tipo de dado analisado
- `details`: Dados detalhados da instância EclecticIQ
- `metadata`: Metadados do módulo

### Estrutura dos Detalhes

```python
{
    "name": "nome_da_instancia",
    "url": "https://sua-instancia.eclecticiq.com",
    "obs_value": "1.2.3.4",
    "obs_type": "ipv4-addr",
    "obs_score": 85,  # Score de maliciosidade (0-100)
    "count": 3,       # Número de entidades encontradas
    "entities": [
        {
            "id": "entity-uuid-123",
            "title": "Malicious IP Campaign",
            "type": "indicator",
            "confidence": "high",
            "tags": ["malware", "botnet"],
            "timestamp": "2024-01-15T10:30:00Z",
            "source_name": "Threat Intel Feed"
        },
        {
            "id": "entity-uuid-456",
            "title": "C2 Infrastructure",
            "type": "infrastructure",
            "confidence": "medium",
            "tags": ["c2", "apt"],
            "timestamp": "2024-01-14T15:45:00Z",
            "source_name": "Internal Research"
        }
    ]
}
```

## Lógica de Veredicto

### Thresholds de Avaliação

```python
HIGH_MALICIOUS_THRESHOLD = 70    # Score >= 70 = malicioso
SUSPICIOUS_THRESHOLD = 30        # Score >= 30 = suspeito
MAX_ENTITY_COUNT_THRESHOLD = 1000  # Limite máximo de entidades
```

### Critérios de Classificação

1. **Malicious**: Score de maliciosidade ≥ 70
2. **Suspicious**: 
   - Score de maliciosidade ≥ 30, ou
   - Observável encontrado com entidades relacionadas (sem score)
3. **Safe**: Score de maliciosidade < 30
4. **Info**: 
   - Observável não encontrado, ou
   - Observável encontrado sem entidades relacionadas

## Taxonomia

### Namespace
- `eclectiq`

### Predicados
- `search`: Para buscas sem resultados
- `reputation`: Para análise de reputação com resultados

### Níveis
- `info`: Observável não encontrado ou sem entidades
- `safe`: Observável conhecido e seguro
- `suspicious`: Observável suspeito
- `malicious`: Observável malicioso

## Tratamento de Erros

### Erros Comuns

1. **Credenciais inválidas**
   - Causa: API key, URL ou nome da instância incorretos
   - Solução: Verificar configuração de secrets

2. **Instância inacessível**
   - Causa: URL incorreta ou instância offline
   - Solução: Verificar conectividade e URL

3. **Certificado SSL inválido**
   - Causa: Problemas com certificado da instância
   - Solução: Configurar `cert_check` ou fornecer certificado válido

4. **Erro de autorização**
   - Causa: API key sem permissões adequadas
   - Solução: Verificar permissões da API key

### Logs de Debug

O analyzer registra informações sobre:
- Configuração do cliente
- Requisições à API
- Processamento de entidades
- Erros de parsing
- Determinação de veredicto

## Casos de Uso

### Análise de Reputação
```python
# Verificar reputação de um IP
report = analyzer.execute()
details = report.data['details']

if 'obs_score' in details:
    score = details['obs_score']
    if score >= 70:
        print(f"IP malicioso detectado! Score: {score}")
    elif score >= 30:
        print(f"IP suspeito. Score: {score}")
    else:
        print(f"IP aparentemente seguro. Score: {score}")
```

### Análise de Entidades
```python
# Analisar entidades relacionadas
entities = report.data['details'].get('entities', [])
for entity in entities:
    print(f"Título: {entity['title']}")
    print(f"Tipo: {entity['type']}")
    print(f"Confiança: {entity['confidence']}")
    print(f"Tags: {', '.join(entity.get('tags', []))}")
    print(f"Fonte: {entity['source_name']}")
    print("---")
```

### Filtragem por Confiança
```python
# Filtrar entidades por nível de confiança
high_confidence_entities = [
    entity for entity in report.data['details'].get('entities', [])
    if entity.get('confidence') == 'high'
]

print(f"Entidades de alta confiança: {len(high_confidence_entities)}")
```

### Análise Temporal
```python
# Analisar entidades por timestamp
from datetime import datetime

entities = report.data['details'].get('entities', [])
recent_entities = []

for entity in entities:
    if entity.get('timestamp'):
        timestamp = datetime.fromisoformat(entity['timestamp'].replace('Z', '+00:00'))
        # Filtrar entidades dos últimos 30 dias
        if (datetime.now() - timestamp).days <= 30:
            recent_entities.append(entity)

print(f"Entidades recentes: {len(recent_entities)}")
```

## Integração com Pipeline

```python
from sentineliqsdk import Pipeline
from sentineliqsdk.analyzers.eclectiq import EclecticIQAnalyzer

# Criar pipeline com EclecticIQ
pipeline = Pipeline()
pipeline.add_analyzer(EclecticIQAnalyzer)

# Processar observável
results = pipeline.process("ip", "1.2.3.4")
```

## Limitações

- Requer instância EclecticIQ configurada e acessível
- Dependente da disponibilidade da instância
- Requer credenciais válidas com permissões adequadas
- Performance dependente da latência de rede
- Limitado pelos rate limits da instância EclecticIQ
- Processamento de entidades pode falhar parcialmente sem afetar o resultado geral

## Segurança

### Boas Práticas

1. **Armazenamento Seguro de Credenciais**
   ```python
   # Use sempre secrets, nunca hardcode nem variáveis de ambiente
   config = WorkerConfig(
       secrets={
           "eclectiq": {
               "api_key": "sua_eclectiq_api_key",  # configure via WorkerConfig.secrets (recomendado)
               "url": "https://sua-instancia-eclectiq",
               "name": "seu_nome_de_instancia"
           }
       }
   )
   ```

2. **Verificação de Certificados**
   ```python
   # Sempre verificar certificados em produção
   config.set_config("eclectiq.cert_check", True)
   ```

3. **Logs Seguros**
   - O analyzer não registra credenciais nos logs
   - Informações sensíveis são mascaradas

## Metadados

- **Nome**: EclecticIQ Analyzer
- **Descrição**: Busca observáveis em instância EclecticIQ configurada
- **Autor**: SentinelIQ Team
- **Padrão**: threat-intel
- **Estágio**: TESTING
- **Documentação**: [https://killsearch.github.io/sentineliqsdk/modulos/analyzers/eclectiq/](https://killsearch.github.io/sentineliqsdk/modulos/analyzers/eclectiq/)

## Veja Também

- [Analyzer Base](../base.md)
- [WorkerConfig](../../core/worker-config.md)
- [Secrets Management](../../core/secrets.md)
- [Taxonomy](../../core/taxonomy.md)
- [Threat Intelligence](../../guides/threat-intelligence.md)