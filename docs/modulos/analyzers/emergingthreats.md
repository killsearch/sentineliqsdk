# EmergingThreats Analyzer

O **EmergingThreats Analyzer** é um módulo da SentinelIQ SDK que permite verificar a reputação de domínios, IPs e hashes usando a API do EmergingThreats. Este analisador fornece informações detalhadas sobre ameaças conhecidas e atividades maliciosas associadas aos observáveis.

## Características

- **Análise Multi-Tipo**: Suporta domínios, IPs, hashes e arquivos
- **Reputação Detalhada**: Fornece scores e categorias de ameaças
- **Detecção de Eventos**: Identifica assinaturas e eventos de segurança
- **Classificação Inteligente**: Categoriza ameaças em níveis de risco
- **API Robusta**: Integração completa com a API EmergingThreats

## Configuração

### Secrets Necessários

```python
from sentineliqsdk import WorkerConfig

# Configuração com API key (obrigatório)
config = WorkerConfig(
    secrets={
        "emergingthreats": {
            "api_key": "sua_api_key_aqui"
        }
    }
)
```

### Obtenção da API Key

1. Acesse [EmergingThreats.net](https://www.emergingthreats.net/)
2. Registre-se para obter uma conta
3. Gere sua API key no painel de controle
4. Configure a chave usando `WorkerConfig.secrets`

## Uso Básico

### Exemplo Simples

```python
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.emergingthreats import EmergingThreatsAnalyzer

# Configurar entrada
config = WorkerConfig(
    secrets={
        "emergingthreats": {
            "api_key": "sua_api_key"
        }
    }
)

input_data = WorkerInput(
    data_type="domain",
    data="malicious.com",
    config=config
)

# Executar análise
analyzer = EmergingThreatsAnalyzer(input_data)
report = analyzer.execute()

# Verificar resultado
print(f"Veredicto: {report.full_report['verdict']}")
print(f"Taxonomias: {len(report.full_report['taxonomy'])}")
print(f"Fonte: {report.full_report['source']}")
```

### Exemplo com Linha de Comando

```bash
# Análise básica (dry-run)
python examples/analyzers/emergingthreats_example.py --data malicious.com --data-type domain --api-key YOUR_KEY

# Análise real de domínio
python examples/analyzers/emergingthreats_example.py --data malicious.com --data-type domain --api-key YOUR_KEY --execute

# Análise de IP
python examples/analyzers/emergingthreats_example.py --data 1.2.3.4 --data-type ip --api-key YOUR_KEY --execute

# Análise de hash
python examples/analyzers/emergingthreats_example.py --data abc123def456 --data-type hash --api-key YOUR_KEY --execute
```

## Tipos de Dados Suportados

| Tipo | Descrição | Exemplo |
|------|-----------|----------|
| `domain` | Domínios | `malicious.com` |
| `fqdn` | Nomes de domínio totalmente qualificados | `www.malicious.com` |
| `ip` | Endereços IP | `1.2.3.4` |
| `hash` | Hashes de arquivos (MD5, SHA1, SHA256) | `abc123def456...` |
| `file` | Arquivos para análise de hash | `malware.exe` |

## Interpretação dos Resultados

### Níveis de Taxonomia

- **`malicious`**: Ameaça confirmada com alta confiança
- **`suspicious`**: Atividade suspeita detectada
- **`safe`**: Sem ameaças conhecidas
- **`info`**: Informações gerais sobre o observável

### Categorias de Ameaças

#### Categorias Maliciosas (RED)
- **CnC**: Command and Control servers
- **Bot**: Botnet infrastructure
- **Malware**: Malware distribution
- **Compromised**: Compromised hosts
- **Scanner**: Scanning activity
- **Spam**: Spam sources

#### Categorias Suspeitas (YELLOW)
- **DynDNS**: Dynamic DNS services
- **Proxy**: Proxy services
- **VPN**: VPN endpoints
- **TorNode**: Tor network nodes
- **P2P**: Peer-to-peer networks

#### Categorias Seguras (GREEN)
- **Utility**: Legitimate utility services

### Campos do Relatório

```python
{
    "verdict": "malicious",  # malicious, suspicious, safe, info
    "source": "emergingthreats",
    "values": [{
        "observable": "malicious.com",
        "reputation": [
            {"category": "CnC", "score": 85},
            {"category": "Malware", "score": 90}
        ],
        "events": [
            {"event_id": "123", "signature": "Malware detected"},
            {"event_id": "456", "signature": "C&C communication"}
        ],
        "threat_level": "malicious"
    }],
    "taxonomy": [{
        "level": "malicious",
        "namespace": "EmergingThreats",
        "predicate": "Reputation",
        "value": "CnC=85"
    }]
}
```

## Limitações

- **Rate Limiting**: A API do EmergingThreats possui limites de taxa
- **API Key Obrigatória**: Requer chave de API válida para funcionamento
- **Tipos Específicos**: Suporta apenas domínios, IPs, hashes e arquivos
- **Delay entre Requests**: Implementa delay de 1 segundo entre chamadas

## Tratamento de Erros

O analisador trata automaticamente:

- **Erros de API**: Rate limiting, chaves inválidas, timeouts
- **Tipos de dados inválidos**: Levanta `ValueError` para tipos não suportados
- **Chave de API ausente**: Levanta `ValueError` se não configurada
- **Problemas de conectividade**: Timeout e erros de rede
- **Respostas vazias**: Trata respostas sem dados como informacionais

## Exemplo Avançado

```python
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.emergingthreats import EmergingThreatsAnalyzer

def analyze_threat_intelligence(observable: str, data_type: str, api_key: str) -> dict:
    """Analisa um observável e retorna inteligência de ameaças estruturada."""
    
    config = WorkerConfig(
        secrets={"emergingthreats": {"api_key": api_key}}
    )
    
    input_data = WorkerInput(
        data_type=data_type,
        data=observable,
        config=config
    )
    
    # Executar análise
    analyzer = EmergingThreatsAnalyzer(input_data)
    report = analyzer.execute()
    
    # Extrair informações relevantes
    values = report.full_report.get("values", [{}])
    result_data = values[0] if values else {}
    
    # Processar reputação
    reputation_info = []
    if "reputation" in result_data and result_data["reputation"] not in ["-", "Error"]:
        for rep in result_data["reputation"]:
            if isinstance(rep, dict):
                reputation_info.append({
                    "category": rep.get("category", "unknown"),
                    "score": rep.get("score", 0),
                    "risk_level": _categorize_threat(rep.get("category"), rep.get("score", 0))
                })
    
    # Contar eventos
    events_count = 0
    if "events" in result_data and result_data["events"] not in ["-", "Error"]:
        events_count = len(result_data["events"]) if isinstance(result_data["events"], list) else 0
    
    return {
        "observable": observable,
        "data_type": data_type,
        "verdict": report.full_report.get("verdict", "unknown"),
        "threat_level": result_data.get("threat_level", "info"),
        "reputation": reputation_info,
        "events_count": events_count,
        "taxonomies_count": len(report.full_report.get("taxonomy", [])),
        "risk_score": _calculate_risk_score(reputation_info, events_count)
    }

def _categorize_threat(category: str, score: int) -> str:
    """Categoriza o nível de ameaça baseado na categoria e score."""
    red_categories = ["CnC", "Bot", "Malware", "Compromised", "Scanner", "Spam"]
    yellow_categories = ["DynDNS", "Proxy", "VPN", "TorNode", "P2P"]
    
    if category in red_categories and score >= 70:
        return "HIGH"
    elif category in red_categories or (category in yellow_categories and score >= 100):
        return "MEDIUM"
    elif category in yellow_categories:
        return "LOW"
    else:
        return "INFO"

def _calculate_risk_score(reputation: list, events_count: int) -> int:
    """Calcula um score de risco de 0-100."""
    base_score = 0
    
    # Score baseado na reputação
    for rep in reputation:
        if rep["risk_level"] == "HIGH":
            base_score += 40
        elif rep["risk_level"] == "MEDIUM":
            base_score += 25
        elif rep["risk_level"] == "LOW":
            base_score += 10
    
    # Score baseado em eventos
    base_score += min(events_count * 5, 30)
    
    return min(base_score, 100)

# Uso
result = analyze_threat_intelligence("malicious.com", "domain", "your_api_key")
print(f"Observable: {result['observable']}")
print(f"Verdict: {result['verdict']}")
print(f"Risk Score: {result['risk_score']}/100")
print(f"Events: {result['events_count']}")
```

## Metadados do Módulo

- **Nome**: EmergingThreats Analyzer
- **Autor**: SentinelIQ Team
- **Padrão**: threat-intel
- **Estágio**: TESTING
- **Tipos Suportados**: domain, fqdn, ip, hash, file

## Referências

- [EmergingThreats API Documentation](https://www.emergingthreats.net/)
- [SentinelIQ SDK Documentation](../../../index.md)
- [Guia de Threat Intelligence](../../../guides/threat-intelligence.md)
- [Análise de Hash](../../../guides/hash-analysis.md)