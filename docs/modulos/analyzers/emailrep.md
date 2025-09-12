# EmailRep Analyzer

O **EmailRep Analyzer** é um módulo da SentinelIQ SDK que permite verificar a reputação de endereços de email usando a API do EmailRep. Este analisador fornece informações sobre a confiabilidade e histórico de atividades suspeitas de endereços de email.

## Características

- **Verificação de Reputação**: Analisa a reputação de endereços de email
- **Detecção de Atividades Suspeitas**: Identifica emails associados a atividades maliciosas
- **Análise de Referências**: Conta o número de referências do email em bases de dados
- **API Key Opcional**: Funciona com ou sem chave de API (funcionalidade limitada sem chave)

## Configuração

### Secrets Necessários

```python
from sentineliqsdk import WorkerConfig

# Configuração com API key (recomendado)
config = WorkerConfig(
    secrets={
        "emailrep": {
            "api_key": "sua_api_key_aqui"
        }
    }
)

# Configuração sem API key (funcionalidade limitada)
config = WorkerConfig(secrets={})
```

### Obtenção da API Key

1. Acesse [EmailRep.io](https://emailrep.io/)
2. Registre-se para obter uma conta
3. Gere sua API key no painel de controle
4. Configure a chave usando `WorkerConfig.secrets`

## Uso Básico

### Exemplo Simples

```python
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.emailrep import EmailRepAnalyzer

# Configurar entrada
config = WorkerConfig(
    secrets={
        "emailrep": {
            "api_key": "sua_api_key"
        }
    }
)

input_data = WorkerInput(
    data_type="mail",
    data="suspicious@example.com",
    config=config
)

# Executar análise
analyzer = EmailRepAnalyzer(input_data)
report = analyzer.execute()

# Verificar resultado
print(f"Veredicto: {report.full_report['verdict']}")
print(f"Suspeito: {report.full_report['values'][0].get('suspicious', False)}")
print(f"Referências: {report.full_report['values'][0].get('references', 0)}")
```

### Exemplo com Linha de Comando

```bash
# Análise básica (dry-run)
python examples/analyzers/emailrep_example.py --email test@example.com

# Análise real com API key
python examples/analyzers/emailrep_example.py --email test@example.com --api-key YOUR_KEY --execute

# Análise sem API key
python examples/analyzers/emailrep_example.py --email test@example.com --execute
```

## Tipos de Dados Suportados

| Tipo | Descrição | Exemplo |
|------|-----------|----------|
| `mail` | Endereços de email | `user@domain.com` |

## Interpretação dos Resultados

### Níveis de Taxonomia

- **`safe`**: Email com boa reputação, sem atividades suspeitas
- **`suspicious`**: Email com algumas atividades suspeitas ou referências
- **`malicious`**: Email com alta probabilidade de atividades maliciosas
- **`info`**: Informações gerais sobre o email

### Campos do Relatório

```python
{
    "verdict": "suspicious",  # safe, suspicious, malicious
    "source": "emailrep",
    "values": [{
        "email": "test@example.com",
        "reputation": "medium",  # high, medium, low, none
        "suspicious": True,      # boolean
        "references": 5,         # número de referências
        "details": {
            "blacklisted": False,
            "malicious_activity": False,
            "spam": True
        }
    }],
    "taxonomy": [{
        "level": "suspicious",
        "namespace": "EmailRep",
        "predicate": "References",
        "value": "5"
    }]
}
```

## Limitações

- **Rate Limiting**: A API do EmailRep possui limites de taxa
- **Funcionalidade Limitada**: Sem API key, algumas funcionalidades podem estar indisponíveis
- **Tipo de Dados**: Suporta apenas endereços de email (`mail`)

## Tratamento de Erros

O analisador trata automaticamente:

- **Erros de API**: Rate limiting, chaves inválidas
- **Tipos de dados inválidos**: Levanta `ValueError` para tipos não suportados
- **Problemas de conectividade**: Timeout e erros de rede

## Exemplo Avançado

```python
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.emailrep import EmailRepAnalyzer

def analyze_email_reputation(email: str, api_key: str = None) -> dict:
    """Analisa a reputação de um email e retorna resultado estruturado."""
    
    # Configurar secrets
    secrets = {}
    if api_key:
        secrets["emailrep"] = {"api_key": api_key}
    
    config = WorkerConfig(secrets=secrets)
    input_data = WorkerInput(
        data_type="mail",
        data=email,
        config=config
    )
    
    # Executar análise
    analyzer = EmailRepAnalyzer(input_data)
    report = analyzer.execute()
    
    # Extrair informações relevantes
    values = report.full_report.get("values", [{}])
    result_data = values[0] if values else {}
    
    return {
        "email": email,
        "verdict": report.full_report.get("verdict", "unknown"),
        "is_suspicious": result_data.get("suspicious", False),
        "reputation_score": result_data.get("reputation", "none"),
        "reference_count": result_data.get("references", 0),
        "risk_level": _calculate_risk_level(report.full_report)
    }

def _calculate_risk_level(report: dict) -> str:
    """Calcula nível de risco baseado no veredicto."""
    verdict = report.get("verdict", "unknown")
    
    if verdict == "malicious":
        return "HIGH"
    elif verdict == "suspicious":
        return "MEDIUM"
    elif verdict == "safe":
        return "LOW"
    else:
        return "UNKNOWN"

# Uso
result = analyze_email_reputation("test@example.com", "your_api_key")
print(f"Email: {result['email']}")
print(f"Risk Level: {result['risk_level']}")
print(f"Suspicious: {result['is_suspicious']}")
```

## Metadados do Módulo

- **Nome**: EmailRep Analyzer
- **Autor**: SentinelIQ Team
- **Padrão**: threat-intel
- **Estágio**: TESTING
- **Tipos Suportados**: mail

## Referências

- [EmailRep.io API Documentation](https://emailrep.io/docs/)
- [SentinelIQ SDK Documentation](../../../index.md)
- [Guia de Threat Intelligence](../../../guides/threat-intelligence.md)