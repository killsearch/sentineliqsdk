# EML Parser Analyzer

O **EML Parser Analyzer** é um módulo da SentinelIQ SDK que permite analisar arquivos de email no formato EML (Electronic Mail). Este analisador extrai informações detalhadas de emails, incluindo headers, anexos, URLs, e realiza verificações de autenticação (SPF, DKIM, DMARC).

## Características

- **Parsing Completo de EML**: Analisa estrutura completa de arquivos .eml
- **Extração de Headers**: Extrai todos os headers do email (From, To, Subject, Date, etc.)
- **Análise de Anexos**: Identifica e analisa anexos, incluindo detecção de tipos perigosos
- **Extração de URLs**: Encontra e categoriza URLs no corpo do email
- **Verificação de Autenticação**: Analisa SPF, DKIM e DMARC
- **Detecção de Phishing**: Identifica indicadores de phishing e emails suspeitos
- **Análise de Reputação**: Avalia a reputação do remetente e domínios

## Configuração

### Dependências Necessárias

O módulo requer a biblioteca `eml_parser`:

```bash
pip install eml_parser
```

### Secrets Opcionais

```python
from sentineliqsdk import WorkerConfig

# Configuração básica (sem secrets)
config = WorkerConfig(secrets={})

# Configuração com secrets para análises avançadas (futuro)
config = WorkerConfig(
    secrets={
        "eml_parser": {
            "reputation_api_key": "sua_chave_opcional"
        }
    }
)
```

## Uso Básico

### Exemplo Simples

```python
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.eml_parser import EmlParserAnalyzer

# Configurar entrada
config = WorkerConfig(secrets={})

input_data = WorkerInput(
    data_type="file",
    data="/path/to/email.eml",
    filename="suspicious_email.eml",
    config=config
)

# Executar análise
analyzer = EmlParserAnalyzer(input_data)
report = analyzer.execute()

# Verificar resultado
print(f"Veredicto: {report.full_report['verdict']}")
print(f"Remetente: {report.full_report['values'][0]['headers']['from']}")
print(f"Assunto: {report.full_report['values'][0]['headers']['subject']}")
print(f"URLs encontradas: {len(report.full_report['values'][0]['urls'])}")
print(f"Anexos: {len(report.full_report['values'][0]['attachments'])}")
```

### Exemplo com Linha de Comando

```bash
# Análise básica (dry-run)
python examples/analyzers/eml_parser_example.py --file email.eml

# Análise real
python examples/analyzers/eml_parser_example.py --file email.eml --execute

# Análise com arquivo de exemplo
python examples/analyzers/eml_parser_example.py --use-sample --execute
```

## Tipos de Dados Suportados

| Tipo | Descrição | Exemplo |
|------|-----------|----------|
| `file` | Arquivos EML | `email.eml`, `message.eml` |

## Interpretação dos Resultados

### Níveis de Taxonomia

- **`safe`**: Email legítimo sem indicadores suspeitos
- **`suspicious`**: Email com alguns indicadores de risco (anexos suspeitos, URLs duvidosas)
- **`malicious`**: Email com alta probabilidade de ser malicioso (phishing, malware)
- **`info`**: Informações gerais sobre o email

### Campos do Relatório

```python
{
    "verdict": "suspicious",  # safe, suspicious, malicious
    "source": "eml_parser",
    "values": [{
        "filename": "email.eml",
        "headers": {
            "from": "sender@example.com",
            "to": ["recipient@company.com"],
            "subject": "Important Document",
            "date": "2024-01-15T10:30:00Z",
            "message_id": "<123@example.com>",
            "received": [...],
            "x_originating_ip": "192.168.1.100"
        },
        "body": {
            "plain": "Email body in plain text",
            "html": "<html>Email body in HTML</html>"
        },
        "urls": [
            {
                "url": "https://suspicious-site.com/login",
                "domain": "suspicious-site.com",
                "is_suspicious": True,
                "reason": "Domain not matching sender"
            }
        ],
        "attachments": [
            {
                "filename": "document.pdf",
                "content_type": "application/pdf",
                "size": 1024000,
                "is_suspicious": False,
                "hash": "sha256:abc123..."
            }
        ],
        "authentication": {
            "spf": {
                "result": "pass",
                "details": "SPF validation passed"
            },
            "dkim": {
                "result": "fail",
                "details": "DKIM signature invalid"
            },
            "dmarc": {
                "result": "fail",
                "policy": "quarantine"
            }
        },
        "risk_indicators": [
            "DKIM validation failed",
            "Suspicious URL detected",
            "Sender domain mismatch"
        ]
    }],
    "taxonomy": [{
        "level": "suspicious",
        "namespace": "EmlParser",
        "predicate": "Authentication",
        "value": "DKIM Failed"
    }]
}
```

## Indicadores de Risco

O analisador identifica diversos indicadores de risco:

### Autenticação
- **SPF Fail**: Falha na validação SPF
- **DKIM Fail**: Falha na validação DKIM
- **DMARC Fail**: Falha na política DMARC

### URLs Suspeitas
- **Domain Mismatch**: URLs com domínios diferentes do remetente
- **Shortened URLs**: URLs encurtadas (bit.ly, tinyurl, etc.)
- **Suspicious TLDs**: Domínios com TLDs suspeitos
- **IP Addresses**: URLs usando endereços IP diretamente

### Anexos Perigosos
- **Executable Files**: .exe, .scr, .bat, .cmd
- **Script Files**: .js, .vbs, .ps1
- **Archive Files**: .zip, .rar (podem conter malware)
- **Office Macros**: Documentos com macros habilitados

### Headers Suspeitos
- **Spoofed Sender**: Indicadores de falsificação do remetente
- **Suspicious IPs**: IPs de origem suspeitos
- **Missing Headers**: Headers obrigatórios ausentes

## Limitações

- **Dependência Externa**: Requer a biblioteca `eml_parser`
- **Tipos de Arquivo**: Suporta apenas arquivos EML
- **Tamanho de Arquivo**: Arquivos muito grandes podem impactar performance
- **Análise de Conteúdo**: Não realiza análise profunda de malware em anexos

## Tratamento de Erros

O analisador trata automaticamente:

- **Arquivo Não Encontrado**: Levanta `FileNotFoundError`
- **Dependências Ausentes**: Levanta `ImportError` com instruções de instalação
- **Formato Inválido**: Trata arquivos EML malformados
- **Tipos de dados inválidos**: Levanta `ValueError` para tipos não suportados
- **Erros de Parsing**: Captura e reporta erros de análise

## Exemplo Avançado

```python
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.eml_parser import EmlParserAnalyzer
import json

def analyze_eml_file(file_path: str) -> dict:
    """Analisa um arquivo EML e retorna resultado estruturado."""
    
    config = WorkerConfig(secrets={})
    input_data = WorkerInput(
        data_type="file",
        data=file_path,
        filename=file_path.split('/')[-1],
        config=config
    )
    
    # Executar análise
    analyzer = EmlParserAnalyzer(input_data)
    report = analyzer.execute()
    
    # Extrair informações relevantes
    values = report.full_report.get("values", [{}])
    result_data = values[0] if values else {}
    
    return {
        "filename": result_data.get("filename", ""),
        "verdict": report.full_report.get("verdict", "unknown"),
        "sender": result_data.get("headers", {}).get("from", ""),
        "subject": result_data.get("headers", {}).get("subject", ""),
        "risk_level": _calculate_risk_level(report.full_report),
        "url_count": len(result_data.get("urls", [])),
        "suspicious_urls": len([u for u in result_data.get("urls", []) if u.get("is_suspicious")]),
        "attachment_count": len(result_data.get("attachments", [])),
        "suspicious_attachments": len([a for a in result_data.get("attachments", []) if a.get("is_suspicious")]),
        "authentication_issues": len([a for a in result_data.get("authentication", {}).values() if a.get("result") == "fail"]),
        "risk_indicators": result_data.get("risk_indicators", [])
    }

def _calculate_risk_level(report: dict) -> str:
    """Calcula nível de risco baseado no veredicto e indicadores."""
    verdict = report.get("verdict", "unknown")
    values = report.get("values", [{}])
    indicators = values[0].get("risk_indicators", []) if values else []
    
    if verdict == "malicious" or len(indicators) >= 5:
        return "HIGH"
    elif verdict == "suspicious" or len(indicators) >= 2:
        return "MEDIUM"
    elif verdict == "safe":
        return "LOW"
    else:
        return "UNKNOWN"

# Uso
result = analyze_eml_file("/path/to/email.eml")
print(f"Arquivo: {result['filename']}")
print(f"Remetente: {result['sender']}")
print(f"Assunto: {result['subject']}")
print(f"Nível de Risco: {result['risk_level']}")
print(f"URLs Suspeitas: {result['suspicious_urls']}/{result['url_count']}")
print(f"Anexos Suspeitos: {result['suspicious_attachments']}/{result['attachment_count']}")
print(f"Problemas de Autenticação: {result['authentication_issues']}")

if result['risk_indicators']:
    print("\nIndicadores de Risco:")
    for indicator in result['risk_indicators']:
        print(f"  - {indicator}")
```

## Casos de Uso

### Análise de Phishing
```python
# Detectar emails de phishing
report = analyzer.execute()
if report.full_report['verdict'] == 'malicious':
    indicators = report.full_report['values'][0]['risk_indicators']
    if 'Suspicious URL detected' in indicators:
        print("Possível email de phishing detectado!")
```

### Análise de Anexos
```python
# Verificar anexos suspeitos
attachments = report.full_report['values'][0]['attachments']
suspicious_attachments = [a for a in attachments if a['is_suspicious']]
if suspicious_attachments:
    print(f"Encontrados {len(suspicious_attachments)} anexos suspeitos")
```

### Verificação de Autenticação
```python
# Verificar falhas de autenticação
auth = report.full_report['values'][0]['authentication']
failed_checks = [k for k, v in auth.items() if v['result'] == 'fail']
if failed_checks:
    print(f"Falhas de autenticação: {', '.join(failed_checks)}")
```

## Metadados do Módulo

- **Nome**: EML Parser Analyzer
- **Autor**: SentinelIQ Team
- **Padrão**: threat-intel
- **Estágio**: TESTING
- **Tipos Suportados**: file (EML)

## Referências

- [eml_parser Library Documentation](https://pypi.org/project/eml_parser/)
- [RFC 5322 - Internet Message Format](https://tools.ietf.org/html/rfc5322)
- [SPF RFC 7208](https://tools.ietf.org/html/rfc7208)
- [DKIM RFC 6376](https://tools.ietf.org/html/rfc6376)
- [DMARC RFC 7489](https://tools.ietf.org/html/rfc7489)
- [SentinelIQ SDK Documentation](../../../index.md)
- [Guia de Threat Intelligence](../../../guides/threat-intelligence.md)