# CIRCL Passive DNS Analyzer

O **CIRCL Passive DNS Analyzer** é um módulo da SentinelIQ SDK que consulta o serviço CIRCL Passive DNS para obter registros DNS históricos de domínios, endereços IP e URLs.

## Visão Geral

O CIRCL Passive DNS é um banco de dados que armazena registros DNS históricos de várias fontes, incluindo análise de malware e parceiros. Os dados DNS históricos são indexados, tornando-os pesquisáveis para analistas de segurança, manipuladores de incidentes ou pesquisadores.

## Características

- **Consultas de domínio**: Analisa domínios para encontrar registros DNS históricos
- **Consultas de IP**: Encontra domínios que resolveram para um endereço IP específico
- **Consultas de URL**: Extrai o domínio de uma URL e consulta os registros DNS históricos
- **Filtragem por tipo RR**: Suporte para filtrar por tipos específicos de registros DNS
- **Paginação**: Suporte para paginação de resultados grandes
- **Autenticação**: Requer credenciais CIRCL Passive DNS

## Configuração

### Credenciais

O analyzer requer credenciais CIRCL Passive DNS configuradas no `WorkerConfig.secrets`:

```python
from sentineliqsdk import WorkerInput, WorkerConfig

secrets = {
    "circl_passivedns": {
        "username": "seu_usuario",
        "password": "sua_senha"
    }
}

input_data = WorkerInput(
    data_type="domain",
    data="example.com",
    config=WorkerConfig(secrets=secrets)
)
```

### Proxy

O analyzer respeita configurações de proxy definidas em `WorkerConfig.proxy`:

```python
from sentineliqsdk import WorkerInput, WorkerConfig, ProxyConfig

input_data = WorkerInput(
    data_type="domain",
    data="example.com",
    config=WorkerConfig(
        proxy=ProxyConfig(
            http="http://proxy:8080",
            https="https://proxy:8080"
        )
    )
)
```

## Uso Programático

### Exemplo Básico

```python
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.circl_passivedns import CirclPassivednsAnalyzer

# Configurar credenciais
secrets = {
    "circl_passivedns": {
        "username": "seu_usuario",
        "password": "sua_senha"
    }
}

# Criar dados de entrada
input_data = WorkerInput(
    data_type="domain",
    data="example.com",
    tlp=2,
    pap=2,
    config=WorkerConfig(secrets=secrets)
)

# Executar análise
analyzer = CirclPassivednsAnalyzer(input_data)
report = analyzer.execute()

# Acessar resultados
print(f"Verdict: {report.full_report['verdict']}")
print(f"Resultados: {len(report.full_report['details']['results'])}")
```

### Análise de Domínio

```python
secrets = {"circl_passivedns": {"username": "user", "password": "pass"}}
input_data = WorkerInput(
    data_type="domain", 
    data="malicious-domain.com",
    config=WorkerConfig(secrets=secrets)
)
analyzer = CirclPassivednsAnalyzer(input_data)
report = analyzer.execute()

# Verificar resultados
details = report.full_report['details']
print(f"Encontrados {details['result_count']} registros DNS")
for result in details['results'][:5]:  # Primeiros 5 resultados
    print(f"Tipo: {result['rrtype']}, Nome: {result['rrname']}")
```

### Análise de IP

```python
secrets = {"circl_passivedns": {"username": "user", "password": "pass"}}
input_data = WorkerInput(
    data_type="ip", 
    data="8.8.8.8",
    config=WorkerConfig(secrets=secrets)
)
analyzer = CirclPassivednsAnalyzer(input_data)
report = analyzer.execute()

# Verificar domínios que resolveram para este IP
details = report.full_report['details']
for result in details['results']:
    if result['rrtype'] == 'A':
        print(f"Domínio: {result['rdata']}")
```

### Análise de URL

```python
secrets = {"circl_passivedns": {"username": "user", "password": "pass"}}
input_data = WorkerInput(
    data_type="url", 
    data="https://suspicious-site.com/path/to/page",
    config=WorkerConfig(secrets=secrets)
)
analyzer = CirclPassivednsAnalyzer(input_data)
report = analyzer.execute()

# O analyzer extrai automaticamente o domínio da URL
details = report.full_report['details']
print(f"Domínio extraído: {details['query']}")
print(f"URL original: {details['original_url']}")
```

## Estrutura de Resposta

### AnalyzerReport

O analyzer retorna um `AnalyzerReport` com a seguinte estrutura:

```python
{
    "success": True,
    "summary": {},
    "artifacts": [],
    "operations": [],
    "full_report": {
        "observable": "example.com",
        "verdict": "safe|suspicious|info",
        "taxonomy": [
            {
                "level": "safe",
                "namespace": "CIRCL",
                "predicate": "PassiveDNS",
                "value": "5 records"
            }
        ],
        "source": "circl_passivedns",
        "data_type": "domain",
        "details": {
            "query": "example.com",
            "query_type": "domain",
            "results": [...],
            "result_count": 5
        },
        "metadata": {...}
    }
}
```

### Estrutura dos Resultados DNS

Cada resultado DNS contém:

```python
{
    "rrtype": "A",           # Tipo de registro DNS
    "rrname": "1.2.3.4",     # Nome do registro
    "rdata": "example.com",  # Dados do registro
    "count": "19",           # Número de ocorrências
    "time_first": "2023-10-01 12:00:00",  # Primeira vez visto
    "time_last": "2023-10-15 18:30:00"    # Última vez visto
}
```

## Tipos de Dados Suportados

- **domain**: Domínios para consulta DNS histórica
- **ip**: Endereços IP para encontrar domínios associados
- **url**: URLs (o domínio é extraído automaticamente)

## Verdicts

O analyzer determina o verdict baseado no número de registros encontrados:

- **info**: Nenhum registro histórico encontrado
- **safe**: 1-5 registros (provavelmente legítimo)
- **suspicious**: Mais de 5 registros (vale investigar)

## Tratamento de Erros

### Erros de Autenticação

```python
# Erro 401: Credenciais inválidas
# Erro 403: Acesso negado
```

### Erros de Formato

```python
# Domínio com '/' - use data_type="url" em vez de "domain"
# URL inválida - não é possível extrair domínio
```

### Erros de Conexão

```python
# Timeout ou erro de rede
# Serviço indisponível
```

## Exemplo Completo

```python
#!/usr/bin/env python3
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.circl_passivedns import CirclPassivednsAnalyzer

def analyze_domain(domain: str):
    """Analisa um domínio usando CIRCL Passive DNS."""
    # Configurar credenciais
    secrets = {
        "circl_passivedns": {
            "username": "seu_usuario",
            "password": "sua_senha"
        }
    }
    
    input_data = WorkerInput(
        data_type="domain", 
        data=domain,
        config=WorkerConfig(secrets=secrets)
    )
    analyzer = CirclPassivednsAnalyzer(input_data)
    report = analyzer.execute()
    
    details = report.full_report['details']
    print(f"Domínio: {domain}")
    print(f"Verdict: {report.full_report['verdict']}")
    print(f"Registros encontrados: {details['result_count']}")
    
    # Mostrar tipos de registro únicos
    rrtype_counts = {}
    for result in details['results']:
        rrtype = result['rrtype']
        rrtype_counts[rrtype] = rrtype_counts.get(rrtype, 0) + 1
    
    print("Tipos de registro:")
    for rrtype, count in sorted(rrtype_counts.items()):
        print(f"  {rrtype}: {count} registros")
    
    return report

# Exemplo de uso
if __name__ == "__main__":
    report = analyze_domain("example.com")
```

## Limitações

- Requer credenciais CIRCL Passive DNS válidas
- Acesso restrito a parceiros confiáveis
- Alguns domínios podem ter muitos registros (requer paginação)
- Não suporta consultas CIDR

## Referências

- [CIRCL Passive DNS Documentation](https://www.circl.lu/services/passive-dns/)
- [Passive DNS - Common Output Format](https://datatracker.ietf.org/doc/draft-dulaunoy-dnsop-passive-dns-cof/)
- [PyPDNS Library](https://github.com/CIRCL/PyPDNS)
