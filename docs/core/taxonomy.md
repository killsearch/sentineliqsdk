# Taxonomy

## Visão Geral

O sistema de taxonomia do SentinelIQ SDK fornece uma estrutura padronizada para classificar e categorizar resultados de análise de threat intelligence.

## Estrutura da Taxonomia

### Componentes Principais

Cada taxonomia é composta por quatro elementos:

1. **Level** (Nível): Indica a severidade/confiança
2. **Namespace**: Categoria ampla da análise
3. **Predicate**: Subcategoria específica
4. **Value**: Valor analisado

```python
taxonomy = self.build_taxonomy(
    level="malicious",
    namespace="threat-intel", 
    predicate="malware",
    value="hash_md5_example"
)
```

## Níveis de Taxonomia

### Definições dos Níveis

#### `info`
- **Uso**: Informações neutras, sem implicações de segurança
- **Exemplos**: Metadados, informações técnicas, dados de contexto
- **Cor**: Azul/Cinza

#### `safe`
- **Uso**: Confirmadamente seguro, sem ameaças detectadas
- **Exemplos**: IPs limpos, domínios legítimos, arquivos seguros
- **Cor**: Verde

#### `suspicious`
- **Uso**: Potencialmente problemático, requer investigação
- **Exemplos**: Comportamento anômalo, indicadores inconclusivos
- **Cor**: Amarelo/Laranja

#### `malicious`
- **Uso**: Confirmadamente malicioso ou perigoso
- **Exemplos**: Malware conhecido, IPs de C&C, domínios maliciosos
- **Cor**: Vermelho

### Critérios de Classificação

```python
def determine_level(self, score: float, confidence: float) -> str:
    """Determina o nível baseado em score e confiança."""
    if confidence < 0.3:
        return "info"
    elif score < 0.2:
        return "safe"
    elif score < 0.7:
        return "suspicious"
    else:
        return "malicious"
```

## Namespaces Padrão

### `threat-intel`
Análise de threat intelligence geral
```python
# Exemplos de predicates
"malware", "botnet", "phishing", "c2", "reputation"
```

### `network`
Análise de rede e infraestrutura
```python
# Exemplos de predicates  
"dns", "ssl", "port-scan", "geolocation", "asn"
```

### `file`
Análise de arquivos e hashes
```python
# Exemplos de predicates
"hash", "signature", "behavior", "static-analysis", "sandbox"
```

### `web`
Análise de conteúdo web
```python
# Exemplos de predicates
"url", "domain", "certificate", "content", "redirect"
```

### `email`
Análise de email e comunicação
```python
# Exemplos de predicates
"sender", "attachment", "header", "spf", "dmarc"
```

## Predicates Comuns

### Threat Intelligence
- **`malware`**: Malware conhecido
- **`botnet`**: Atividade de botnet
- **`phishing`**: Tentativas de phishing
- **`c2`**: Comando e controle
- **`reputation`**: Reputação geral
- **`ioc`**: Indicador de comprometimento

### Network Analysis
- **`dns`**: Análise DNS
- **`ssl`**: Certificados SSL/TLS
- **`geolocation`**: Localização geográfica
- **`asn`**: Autonomous System Number
- **`port`**: Análise de portas

### File Analysis
- **`hash`**: Hash de arquivo
- **`signature`**: Assinatura de malware
- **`behavior`**: Análise comportamental
- **`static`**: Análise estática
- **`dynamic`**: Análise dinâmica

## Construção de Taxonomias

### Método build_taxonomy()

```python
class MeuAnalyzer(Analyzer):
    def execute(self):
        observable = self.get_data()
        
        # Análise do observable
        result = self.analyze(observable)
        
        # Construir taxonomia baseada no resultado
        if result.is_malicious:
            level = "malicious"
            predicate = "malware"
        elif result.is_suspicious:
            level = "suspicious" 
            predicate = "reputation"
        else:
            level = "safe"
            predicate = "clean"
        
        taxonomy = self.build_taxonomy(
            level=level,
            namespace="threat-intel",
            predicate=predicate,
            value=str(observable)
        )
        
        return self.report({
            "observable": observable,
            "verdict": level,
            "taxonomy": [taxonomy.to_dict()],
            "analysis": result.details
        })
```

### Múltiplas Taxonomias

```python
def build_multiple_taxonomies(self, observable, results):
    """Constrói múltiplas taxonomias para um observable."""
    taxonomies = []
    
    # Taxonomia principal
    main_taxonomy = self.build_taxonomy(
        level=results.main_verdict,
        namespace="threat-intel",
        predicate="reputation",
        value=str(observable)
    )
    taxonomies.append(main_taxonomy)
    
    # Taxonomias específicas
    if results.malware_detected:
        malware_taxonomy = self.build_taxonomy(
            level="malicious",
            namespace="file",
            predicate="malware",
            value=results.malware_family
        )
        taxonomies.append(malware_taxonomy)
    
    if results.network_info:
        network_taxonomy = self.build_taxonomy(
            level="info",
            namespace="network",
            predicate="geolocation",
            value=results.country
        )
        taxonomies.append(network_taxonomy)
    
    return [t.to_dict() for t in taxonomies]
```

## Exemplos por Tipo de Analyzer

### IP Analyzer
```python
# IP malicioso
taxonomy = self.build_taxonomy(
    level="malicious",
    namespace="network",
    predicate="c2",
    value="192.168.1.100"
)

# IP com geolocalização
taxonomy = self.build_taxonomy(
    level="info",
    namespace="network", 
    predicate="geolocation",
    value="US"
)
```

### Hash Analyzer
```python
# Hash malicioso
taxonomy = self.build_taxonomy(
    level="malicious",
    namespace="file",
    predicate="malware",
    value="trojan.generic"
)

# Hash limpo
taxonomy = self.build_taxonomy(
    level="safe",
    namespace="file",
    predicate="hash",
    value="clean_file.exe"
)
```

### Domain Analyzer
```python
# Domínio de phishing
taxonomy = self.build_taxonomy(
    level="malicious",
    namespace="web",
    predicate="phishing",
    value="fake-bank.com"
)

# Domínio suspeito
taxonomy = self.build_taxonomy(
    level="suspicious",
    namespace="web",
    predicate="reputation",
    value="suspicious-domain.net"
)
```

### URL Analyzer
```python
# URL maliciosa
taxonomy = self.build_taxonomy(
    level="malicious",
    namespace="web",
    predicate="malware",
    value="http://malicious-site.com/payload.exe"
)
```

## Validação de Taxonomias

### Validação de Níveis
```python
VALID_LEVELS = ["info", "safe", "suspicious", "malicious"]

def validate_level(self, level: str) -> bool:
    """Valida se o nível é válido."""
    return level in VALID_LEVELS
```

### Validação de Namespaces
```python
VALID_NAMESPACES = [
    "threat-intel", "network", "file", "web", "email"
]

def validate_namespace(self, namespace: str) -> bool:
    """Valida se o namespace é válido."""
    return namespace in VALID_NAMESPACES
```

## Conversão e Serialização

### Método to_dict()
```python
taxonomy = self.build_taxonomy(
    level="malicious",
    namespace="threat-intel",
    predicate="malware",
    value="suspicious_file.exe"
)

# Converter para dicionário
taxonomy_dict = taxonomy.to_dict()
# {
#     "level": "malicious",
#     "namespace": "threat-intel",
#     "predicate": "malware", 
#     "value": "suspicious_file.exe"
# }
```

### Integração com Relatórios
```python
def build_report(self, observable, analysis_result):
    """Constrói relatório com taxonomias."""
    taxonomies = self.build_taxonomies(observable, analysis_result)
    
    return self.report({
        "observable": observable,
        "verdict": analysis_result.verdict,
        "taxonomy": [t.to_dict() for t in taxonomies],
        "metadata": self.METADATA.to_dict(),
        "details": analysis_result.details
    })
```

## Boas Práticas

### Consistência
- Use níveis consistentes entre analyzers similares
- Padronize namespaces e predicates
- Documente critérios de classificação

### Precisão
- Seja conservador com níveis "malicious"
- Use "suspicious" quando há dúvida
- Forneça contexto suficiente no value

### Completude
- Inclua taxonomias para todos os aspectos relevantes
- Combine taxonomias principais com informacionais
- Mantenha rastreabilidade dos critérios

## Veja Também

- [Building Analyzers](../tutorials/building-analyzers.md)
- [Analyzer Base](../modulos/base.md)
- [WorkerConfig](worker-config.md)
- [API Reference](../reference/api/models.md)