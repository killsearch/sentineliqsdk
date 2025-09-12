# Elasticsearch Analyzer

O **ElasticsearchAnalyzer** é um analyzer que permite consultar clusters Elasticsearch para análise de segurança e threat hunting. Ele oferece capacidades de busca flexíveis e análise automatizada de indicadores de segurança.

## Características

- ✅ **Busca Multi-Campo**: Consulta automaticamente campos relevantes baseados no tipo de dado
- ✅ **Análise de Segurança**: Identifica automaticamente indicadores de malware, atividades suspeitas e anomalias
- ✅ **Autenticação Flexível**: Suporta autenticação via usuário/senha ou API key
- ✅ **Chamadas Dinâmicas**: Permite execução de endpoints específicos da API Elasticsearch
- ✅ **Configuração Segura**: Usa `WorkerConfig.secrets` para credenciais
- ✅ **Taxonomia Automática**: Gera taxonomias baseadas nos resultados da análise

## Configuração

### Credenciais Obrigatórias

Configure as credenciais via `WorkerConfig.secrets['elasticsearch']`:

```python
from sentineliqsdk import WorkerConfig

config = WorkerConfig(
    secrets={
        "elasticsearch": {
            "host": "https://your-elasticsearch-host:9200",  # Obrigatório
            "username": "your_username",                      # Opcional
            "password": "your_password",                      # Opcional
            "api_key": "your_api_key",                       # Opcional (alternativa a user/pass)
            "ca_certs": "/path/to/ca.pem",                   # Opcional
        }
    }
)
```

### Configurações Opcionais

Personalize o comportamento via configurações:

```python
config = WorkerConfig(
    elasticsearch={
        "index": "security-*",           # Padrão de índices (padrão: "*")
        "max_results": 200,              # Máximo de resultados (padrão: 100)
        "timeout": 60,                   # Timeout em segundos (padrão: 30)
        "verify_ssl": True,              # Verificar SSL (padrão: True)
        "method": "_search",             # Método dinâmico (opcional)
        "params": {"size": 50},          # Parâmetros para método dinâmico
    }
)
```

## Tipos de Dados Suportados

| Tipo | Campos Pesquisados | Descrição |
|------|-------------------|------------|
| `ip` | `src_ip`, `dst_ip`, `client_ip`, `server_ip`, `ip`, `host.ip` | Endereços IP |
| `domain` | `domain`, `dns.question.name`, `url.domain`, `host.name` | Domínios |
| `url` | `url.full`, `url.original`, `http.request.referrer` | URLs completas |
| `hash` | `file.hash.md5`, `file.hash.sha1`, `file.hash.sha256`, `process.hash.md5` | Hashes de arquivos |
| `mail` | `email`, `user.email`, `source.user.email`, `destination.user.email` | Endereços de email |
| `fqdn` | Mesmos campos que `domain` | FQDNs |
| `other` | Payload JSON personalizado | Chamadas dinâmicas |

## Modos de Operação

### 1. Busca Padrão (Recomendado)

Busca automática baseada no tipo de dado:

```python
from sentineliqsdk import WorkerInput
from sentineliqsdk.analyzers.elasticsearch import ElasticsearchAnalyzer

# Analisar um IP
input_data = WorkerInput(
    data_type="ip",
    data="192.168.1.100",
    config=config
)

analyzer = ElasticsearchAnalyzer(input_data)
report = analyzer.execute()

print(f"Verdict: {report.verdict}")  # safe, info, suspicious, malicious
print(f"Total hits: {report.details['analysis']['total_hits']}")
```

### 2. Método Dinâmico via Configuração

Execute endpoints específicos da API:

```python
config = WorkerConfig(
    secrets={"elasticsearch": {"host": "https://localhost:9200"}},
    elasticsearch={
        "method": "_cluster/health",
        "params": {"level": "cluster"}
    }
)

input_data = WorkerInput(
    data_type="ip",
    data="any_value",  # Ignorado neste modo
    config=config
)

report = analyzer.execute()
# Retorna informações de saúde do cluster
```

### 3. Payload JSON Personalizado

Use `data_type="other"` com payload JSON:

```python
payload = {
    "endpoint": "_cat/indices",
    "method": "GET",
    "params": {"format": "json", "h": "index,health,status"}
}

input_data = WorkerInput(
    data_type="other",
    data=json.dumps(payload),
    config=config
)

report = analyzer.execute()
# Retorna informações dos índices
```

## Análise de Segurança

### Indicadores Detectados

O analyzer identifica automaticamente:

- **Assinaturas de Malware**: `malware`, `virus`, `trojan`, `backdoor`, `ransomware`
- **Processos Suspeitos**: `suspicious`, `anomaly`
- **Anomalias de Rede**: `attack`, `intrusion`, `breach`
- **Falhas de Login**: `failed`, `unauthorized`
- **Escalação de Privilégios**: `privilege`, `escalation`

### Níveis de Taxonomia

| Nível | Condição | Descrição |
|-------|----------|------------|
| `malicious` | Malware detectado OU >5 ataques | Confirmadamente malicioso |
| `suspicious` | >3 atividades suspeitas OU >10 falhas de login OU escalação de privilégios | Suspeito mas não confirmado |
| `info` | Resultados encontrados mas sem indicadores | Informacional |
| `safe` | Nenhum resultado encontrado | Seguro/limpo |

## Endpoints Permitidos

Por segurança, apenas endpoints de leitura são permitidos:

- `_search` - Busca em documentos
- `_count` - Contagem de documentos
- `_mapping` - Mapeamentos de campos
- `_settings` - Configurações de índices
- `_stats` - Estatísticas
- `_health` - Saúde do cluster
- `_nodes` - Informações dos nós
- `_cluster/health` - Saúde do cluster
- `_cluster/stats` - Estatísticas do cluster
- `_cat/indices` - Lista de índices
- `_cat/nodes` - Lista de nós
- `_cat/health` - Saúde em formato cat

## Exemplo Completo

```python
from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.elasticsearch import ElasticsearchAnalyzer

# Configuração
config = WorkerConfig(
    check_tlp=True,
    max_tlp=2,
    check_pap=True,
    max_pap=2,
    auto_extract=True,
    secrets={
        "elasticsearch": {
            "host": "https://elastic.company.com:9200",
            "username": "security_analyst",
            "password": "secure_password",
        }
    },
    elasticsearch={
        "index": "security-logs-*",
        "max_results": 500,
        "timeout": 45,
    }
)

# Análise de domínio suspeito
input_data = WorkerInput(
    data_type="domain",
    data="suspicious-domain.com",
    filename=None,
    tlp=2,
    pap=2,
    config=config
)

# Executar análise
analyzer = ElasticsearchAnalyzer(input_data)
report = analyzer.execute()

# Resultados
print(f"Observable: {report.observable}")
print(f"Verdict: {report.verdict}")
print(f"Source: {report.source}")

# Detalhes da análise
analysis = report.details['analysis']
print(f"Total hits: {analysis['total_hits']}")
print(f"Security indicators: {analysis['security_indicators']}")

# Taxonomia
for taxonomy in report.taxonomy:
    print(f"Taxonomy: {taxonomy['level']}:{taxonomy['namespace']}:{taxonomy['predicate']}")
```

## Tratamento de Erros

### Erros Comuns

| Erro | Causa | Solução |
|------|-------|----------|
| `Missing Elasticsearch host` | Host não configurado | Definir `secrets['elasticsearch']['host']` |
| `Unsupported data type` | Tipo de dado inválido | Usar tipos suportados ou `other` |
| `Unsupported Elasticsearch endpoint` | Endpoint não permitido | Usar apenas endpoints da lista permitida |
| `Elasticsearch API request failed` | Erro de conexão/autenticação | Verificar credenciais e conectividade |
| `JSON string` (para `other`) | Payload inválido | Fornecer JSON válido com `endpoint` |

### Exemplo de Tratamento

```python
try:
    report = analyzer.execute()
    print(f"Success: {report.verdict}")
except Exception as e:
    if "Missing Elasticsearch host" in str(e):
        print("Configure o host do Elasticsearch")
    elif "Unsupported data type" in str(e):
        print("Tipo de dado não suportado")
    else:
        print(f"Erro inesperado: {e}")
```

## Exemplo de Linha de Comando

Use o exemplo executável:

```bash
# Análise básica
python examples/analyzers/elasticsearch_example.py \
    --data "192.168.1.100" \
    --data-type ip \
    --host "https://localhost:9200" \
    --username "elastic" \
    --password "changeme" \
    --execute

# Consulta de saúde do cluster
python examples/analyzers/elasticsearch_example.py \
    --data '{"endpoint": "_cluster/health"}' \
    --data-type other \
    --host "https://localhost:9200" \
    --api-key "your_api_key" \
    --execute

# Busca com índice específico
python examples/analyzers/elasticsearch_example.py \
    --data "malicious.com" \
    --data-type domain \
    --host "https://localhost:9200" \
    --index "security-*" \
    --max-results 200 \
    --verbose \
    --execute
```

## Integração com Pipelines

```python
from sentineliqsdk.pipelines import Pipeline

# Pipeline de análise de segurança
pipeline = Pipeline([
    ElasticsearchAnalyzer,
    # Outros analyzers...
])

results = pipeline.run(input_data)
```

## Considerações de Performance

- **Índices**: Use padrões específicos (`security-*`) em vez de `*` para melhor performance
- **Resultados**: Limite `max_results` para evitar sobrecarga de memória
- **Timeout**: Ajuste o timeout baseado na latência do seu cluster
- **Campos**: O analyzer busca em múltiplos campos automaticamente

## Segurança

- ✅ **Somente Leitura**: Apenas endpoints de consulta são permitidos
- ✅ **Credenciais Seguras**: Usa `WorkerConfig.secrets`
- ✅ **Validação de Entrada**: Valida payloads JSON e endpoints
- ✅ **SSL/TLS**: Suporta verificação de certificados
- ✅ **Autenticação**: Múltiplos métodos de autenticação

---

**Próximos Passos**: Explore outros analyzers como [ShodanAnalyzer](../shodan/) para análise complementar de threat intelligence.