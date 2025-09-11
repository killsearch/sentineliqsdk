# CrowdSec Analyzer

O **CrowdSec Analyzer** é um módulo de análise de inteligência de ameaças que utiliza a API do CrowdSec para obter informações sobre endereços IP. O analyzer fornece dados de reputação, detalhes de ataques, comportamentos suspeitos e informações de CVE.

## Características

- **Reputação de IP**: Classifica endereços IP como maliciosos, suspeitos, seguros ou informativos
- **Detalhes de Ataque**: Identifica tipos específicos de ataques associados ao IP
- **Comportamentos**: Detecta padrões de comportamento suspeitos
- **Técnicas MITRE**: Mapeia para técnicas da matriz MITRE ATT&CK
- **CVEs**: Lista vulnerabilidades conhecidas associadas ao IP
- **Informações de ASN**: Fornece dados sobre o sistema autônomo
- **Histórico**: Mostra quando o IP foi visto pela última vez

## Configuração

### Credenciais

O analyzer requer uma chave de API do CrowdSec. Configure as credenciais usando `WorkerConfig.secrets`:

```python
from sentineliqsdk import WorkerInput, WorkerConfig

secrets = {
    "crowdsec": {
        "api_key": "sua-chave-api-crowdsec"
    }
}

config = WorkerConfig(secrets=secrets)
input_data = WorkerInput(
    data_type="ip",
    data="1.2.3.4",
    config=config
)
```

### Parâmetros de Configuração

| Parâmetro | Tipo | Obrigatório | Descrição |
|-----------|------|-------------|-----------|
| `api_key` | string | Sim | Chave de API do CrowdSec |

## Uso Programático

### Exemplo Básico

```python
from __future__ import annotations

import json
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.crowdsec import CrowdSecAnalyzer

# Configurar credenciais
secrets = {
    "crowdsec": {
        "api_key": "sua-chave-api-crowdsec"
    }
}

# Criar entrada de dados
input_data = WorkerInput(
    data_type="ip",
    data="1.2.3.4",
    tlp=2,
    pap=2,
    config=WorkerConfig(secrets=secrets)
)

# Executar análise
analyzer = CrowdSecAnalyzer(input_data=input_data)
report = analyzer.execute()

# Exibir resultados
print(json.dumps(report.full_report, indent=2, ensure_ascii=False))
```

### Exemplo com Tratamento de Erros

```python
from __future__ import annotations

import json
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.crowdsec import CrowdSecAnalyzer
from sentineliqsdk.clients.crowdsec import CrowdSecAPIError, CrowdSecRateLimitError

def analyze_ip(ip_address: str, api_key: str) -> dict:
    """Analisa um endereço IP usando CrowdSec."""
    try:
        # Configurar entrada
        secrets = {"crowdsec": {"api_key": api_key}}
        input_data = WorkerInput(
            data_type="ip",
            data=ip_address,
            config=WorkerConfig(secrets=secrets)
        )
        
        # Executar análise
        analyzer = CrowdSecAnalyzer(input_data=input_data)
        report = analyzer.execute()
        
        return report.full_report
        
    except CrowdSecRateLimitError as e:
        print(f"❌ Rate limit excedido: {e}")
        return {"error": "rate_limit_exceeded"}
        
    except CrowdSecAPIError as e:
        print(f"❌ Erro da API: {e}")
        return {"error": "api_error"}
        
    except Exception as e:
        print(f"❌ Erro inesperado: {e}")
        return {"error": "unexpected_error"}

# Uso
result = analyze_ip("1.2.3.4", "sua-chave-api")
print(json.dumps(result, indent=2, ensure_ascii=False))
```

## Estrutura de Resposta

### Relatório Completo

```json
{
  "success": true,
  "summary": {},
  "artifacts": [],
  "operations": [],
  "full_report": {
    "observable": "1.2.3.4",
    "raw_data": {
      "reputation": "malicious",
      "as_name": "Evil Corp",
      "ip_range_score": 0.95,
      "history": {
        "last_seen": "2024-01-01T12:00:00Z"
      },
      "attack_details": [
        {
          "name": "SSH Brute Force"
        },
        {
          "name": "Port Scan"
        }
      ],
      "behaviors": [
        {
          "name": "Suspicious Traffic"
        }
      ],
      "mitre_techniques": [
        {
          "name": "T1021.001"
        }
      ],
      "cves": [
        "CVE-2023-1234",
        "CVE-2023-5678"
      ]
    },
    "taxonomy": [
      {
        "level": "malicious",
        "namespace": "CrowdSec",
        "predicate": "Reputation",
        "value": "malicious"
      },
      {
        "level": "info",
        "namespace": "CrowdSec",
        "predicate": "ASN",
        "value": "Evil Corp"
      },
      {
        "level": "suspicious",
        "namespace": "CrowdSec",
        "predicate": "Attack",
        "value": "SSH Brute Force"
      }
    ],
    "metadata": {
      "name": "CrowdSec CTI Analyzer",
      "description": "Analyzes IP addresses using CrowdSec's threat intelligence API",
      "version_stage": "TESTING"
    }
  }
}
```

### Campos de Taxonomia

| Campo | Descrição | Valores Possíveis |
|-------|-----------|-------------------|
| `Reputation` | Reputação do IP | `malicious`, `suspicious`, `safe`, `info` |
| `ASN` | Nome do Sistema Autônomo | Nome da organização |
| `Score` | Pontuação do range de IP | 0.0 - 1.0 |
| `LastSeen` | Última vez visto | Timestamp ISO 8601 |
| `Attack` | Tipo de ataque detectado | Nome do ataque |
| `Behavior` | Comportamento suspeito | Nome do comportamento |
| `Mitre` | Técnica MITRE ATT&CK | ID da técnica |
| `CVE` | Vulnerabilidade conhecida | ID do CVE |
| `Threat` | Status de ameaça | `Not found` (quando não há dados) |

## Níveis de Taxonomia

- **`malicious`**: IP confirmadamente malicioso
- **`suspicious`**: IP com comportamento suspeito
- **`safe`**: IP considerado seguro
- **`info`**: Informações adicionais (ASN, score, etc.)

## Tratamento de Erros

### Rate Limiting

Quando a API retorna erro 429 (rate limit):

```python
try:
    report = analyzer.execute()
except CrowdSecRateLimitError as e:
    print(f"Rate limit excedido: {e}")
    # Aguardar e tentar novamente
```

### Erros de API

Para outros erros da API:

```python
try:
    report = analyzer.execute()
except CrowdSecAPIError as e:
    print(f"Erro da API: {e}")
    print(f"Status code: {e.status_code}")
```

## Exemplo de Uso com Múltiplos IPs

```python
from __future__ import annotations

import json
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.crowdsec import CrowdSecAnalyzer

def analyze_multiple_ips(ip_addresses: list[str], api_key: str) -> list[dict]:
    """Analisa múltiplos endereços IP."""
    results = []
    
    for ip in ip_addresses:
        try:
            secrets = {"crowdsec": {"api_key": api_key}}
            input_data = WorkerInput(
                data_type="ip",
                data=ip,
                config=WorkerConfig(secrets=secrets)
            )
            
            analyzer = CrowdSecAnalyzer(input_data=input_data)
            report = analyzer.execute()
            
            results.append({
                "ip": ip,
                "success": True,
                "data": report.full_report
            })
            
        except Exception as e:
            results.append({
                "ip": ip,
                "success": False,
                "error": str(e)
            })
    
    return results

# Uso
ips = ["1.2.3.4", "8.8.8.8", "5.6.7.8"]
results = analyze_multiple_ips(ips, "sua-chave-api")

for result in results:
    if result["success"]:
        taxonomy = result["data"]["taxonomy"]
        reputation = next((t for t in taxonomy if t["predicate"] == "Reputation"), None)
        print(f"{result['ip']}: {reputation['value'] if reputation else 'unknown'}")
    else:
        print(f"{result['ip']}: erro - {result['error']}")
```

## Integração com Outros Módulos

### Usando com Auto-Extração

```python
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.crowdsec import CrowdSecAnalyzer

# Habilitar auto-extração para detectar IOCs automaticamente
config = WorkerConfig(
    secrets={"crowdsec": {"api_key": "sua-chave"}},
    auto_extract=True  # Padrão: True
)

input_data = WorkerInput(
    data_type="ip",
    data="1.2.3.4",
    config=config
)

analyzer = CrowdSecAnalyzer(input_data=input_data)
report = analyzer.execute()

# Os artifacts serão automaticamente extraídos do relatório
print(f"Artifacts encontrados: {len(report.artifacts)}")
```

## Limitações e Considerações

1. **Rate Limiting**: A API do CrowdSec tem limites de taxa. Use com moderação em análises em lote.

2. **Chave de API**: Mantenha sua chave de API segura e não a exponha em código ou logs.

3. **Dados Sensíveis**: O analyzer pode retornar informações sensíveis sobre IPs. Configure TLP/PAP adequadamente.

4. **Conectividade**: Requer conexão com a internet para acessar a API do CrowdSec.

## Exemplo de Execução

```bash
# Executar exemplo
python examples/analyzers/crowdsec_example.py --ip 1.2.3.4 --execute

# Modo dry-run (sem chamadas reais)
python examples/analyzers/crowdsec_example.py --ip 1.2.3.4

# Saída completa em JSON
python examples/analyzers/crowdsec_example.py --ip 1.2.3.4 --execute --full
```

## Referências

- [CrowdSec CTI API Documentation](https://doc.crowdsec.net/docs/api/cti_api/)
- [CrowdSec Website](https://www.crowdsec.net/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
