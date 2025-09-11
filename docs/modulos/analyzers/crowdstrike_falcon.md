# CrowdStrike Falcon Analyzer

O analisador CrowdStrike Falcon fornece análise abrangente de dispositivos, alertas, vulnerabilidades e arquivos usando a API do CrowdStrike Falcon.

## Funcionalidades

- **Análise de Hostname**: Obtém detalhes do dispositivo, alertas e vulnerabilidades
- **Análise de Arquivo**: Upload e análise de arquivos no sandbox FalconX
- **Detecção de Ameaças**: Identifica dispositivos comprometidos e arquivos maliciosos
- **Análise de Vulnerabilidades**: Lista vulnerabilidades conhecidas em dispositivos

## Configuração

### Credenciais (Obrigatórias)

Configure as credenciais do CrowdStrike Falcon em `WorkerConfig.secrets`:

```python
secrets = {
    "crowdstrike_falcon": {
        "client_id": "sua_client_id_aqui",
        "client_secret": "seu_client_secret_aqui"
    }
}
```

### Configurações Opcionais

As configurações específicas do CrowdStrike Falcon são definidas diretamente no analisador e podem ser personalizadas:

```python
config = WorkerConfig(
    # Configurações básicas
    check_tlp=True,
    max_tlp=2,
    check_pap=True,
    max_pap=2,
    auto_extract=True,
    secrets=secrets
)

# Configurações específicas do CrowdStrike (valores padrão):
# - base_url: "https://api.crowdstrike.com"
# - environment: 160 (sandbox environment)
# - days_before: 7 (dias para buscar alertas)
# - network_settings: "default"
# - action_script: "default"
# - alert_fields: campos específicos para alertas
# - vuln_fields: campos específicos para vulnerabilidades
```

## Uso Programático

### Análise de Hostname

```python
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.crowdstrike_falcon import CrowdStrikeFalconAnalyzer

# Configurar credenciais
secrets = {
    "crowdstrike_falcon": {
        "client_id": "sua_client_id_aqui",
        "client_secret": "seu_client_secret_aqui"
    }
}

config = WorkerConfig(
    check_tlp=True,
    max_tlp=2,
    check_pap=True,
    max_pap=2,
    auto_extract=True,
    crowdstrike_falcon_days_before=7,
    secrets=secrets
)

# Criar entrada para hostname
input_data = WorkerInput(
    data_type="hostname",
    data="example.com",
    tlp=2,
    pap=2,
    config=config
)

# Executar análise
analyzer = CrowdStrikeFalconAnalyzer(input_data)
report = analyzer.execute()

# Acessar resultados
print(f"Dispositivo encontrado: {report.full_report.get('device_details', {}).get('hostname')}")
print(f"Alertas encontrados: {len(report.full_report.get('alerts', []))}")
print(f"Vulnerabilidades encontradas: {len(report.full_report.get('vulnerabilities', []))}")
```

### Análise de Arquivo

```python
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.crowdstrike_falcon import CrowdStrikeFalconAnalyzer

# Configurar credenciais
secrets = {
    "crowdstrike_falcon": {
        "client_id": "sua_client_id_aqui",
        "client_secret": "seu_client_secret_aqui"
    }
}

config = WorkerConfig(
    check_tlp=True,
    max_tlp=2,
    check_pap=True,
    max_pap=2,
    auto_extract=True,
    crowdstrike_falcon_environment=160,
    crowdstrike_falcon_network_settings="default",
    crowdstrike_falcon_action_script="default",
    secrets=secrets
)

# Criar entrada para arquivo
input_data = WorkerInput(
    data_type="file",
    data="/caminho/para/arquivo.exe",
    filename="arquivo.exe",
    tlp=2,
    pap=2,
    config=config
)

# Executar análise
analyzer = CrowdStrikeFalconAnalyzer(input_data)
report = analyzer.execute()

# Acessar resultados
print(f"Tipo de análise: {report.full_report.get('analysis_type')}")
print(f"Status: {report.full_report.get('status')}")
print(f"Veredicto: {report.full_report.get('verdict')}")
```

## Tipos de Dados Suportados

- **hostname**: Análise de dispositivos, alertas e vulnerabilidades
- **file**: Análise de arquivos no sandbox FalconX

## Estrutura da Resposta

### Análise de Hostname

```json
{
  "success": true,
  "summary": {},
  "artifacts": [],
  "operations": [],
  "full_report": {
    "observable": "example.com",
    "data_type": "hostname",
    "analysis_type": "hostname",
    "device_id": "device123",
    "device_details": {
      "device_id": "device123",
      "hostname": "example.com",
      "external_ip": "1.2.3.4",
      "os_version": "Windows 10",
      "last_login_user": "admin"
    },
    "alerts": [
      {
        "device_id": "device123",
        "severity": 50,
        "detection_id": "det123",
        "created_timestamp": "2024-01-01T00:00:00Z"
      }
    ],
    "vulnerabilities": [
      {
        "id": "vuln123",
        "cve": {
          "base_score": 7.5
        },
        "apps": [
          {
            "product_name_normalized": "test_app"
          }
        ]
      }
    ],
    "metadata": {
      "name": "CrowdStrike Falcon Analyzer",
      "description": "Analyzes devices, alerts, vulnerabilities, and files using CrowdStrike Falcon API",
      "version_stage": "TESTING"
    }
  }
}
```

### Análise de Arquivo

```json
{
  "success": true,
  "summary": {},
  "artifacts": [],
  "operations": [],
  "full_report": {
    "observable": "/caminho/para/arquivo.exe",
    "data_type": "file",
    "analysis_type": "sandbox",
    "submit_id": "submit123",
    "status": "completed",
    "verdict": "malicious",
    "results": {
      "resources": [
        {
          "verdict": "malicious",
          "threat_score": 95,
          "threat_indicators": ["trojan", "backdoor"]
        }
      ]
    },
    "metadata": {
      "name": "CrowdStrike Falcon Analyzer",
      "description": "Analyzes devices, alerts, vulnerabilities, and files using CrowdStrike Falcon API",
      "version_stage": "TESTING"
    }
  }
}
```

## Níveis de Taxonomia

O analisador gera entradas de taxonomia baseadas nos resultados:

- **safe**: Arquivo/dispositivo seguro
- **suspicious**: Arquivo/dispositivo suspeito
- **malicious**: Arquivo/dispositivo malicioso
- **info**: Informações gerais

## Tratamento de Erros

O analisador trata os seguintes erros:

- **Credenciais ausentes**: Erro se `client_id` ou `client_secret` não estiverem configurados
- **Tipo de dados não suportado**: Erro para tipos diferentes de `hostname` e `file`
- **Arquivo não encontrado**: Erro se o arquivo especificado não existir
- **Falha na API**: Erro se a API do CrowdStrike retornar erro
- **Dispositivo não encontrado**: Erro se nenhum dispositivo for encontrado para o hostname

## Dependências

- **falconpy**: Biblioteca oficial do CrowdStrike Falcon
- **Instalação**: `pip install falconpy`

## Exemplo de Uso Completo

```python
#!/usr/bin/env python3
import json
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.crowdstrike_falcon import CrowdStrikeFalconAnalyzer

def main():
    # Configurar credenciais e configurações
    secrets = {
        "crowdstrike_falcon": {
            "client_id": "sua_client_id_aqui",
            "client_secret": "seu_client_secret_aqui"
        }
    }
    
    config = WorkerConfig(
        check_tlp=True,
        max_tlp=2,
        check_pap=True,
        max_pap=2,
        auto_extract=True,
        crowdstrike_falcon_days_before=7,
        secrets=secrets
    )
    
    # Análise de hostname
    hostname_input = WorkerInput(
        data_type="hostname",
        data="example.com",
        tlp=2,
        pap=2,
        config=config
    )
    
    analyzer = CrowdStrikeFalconAnalyzer(hostname_input)
    report = analyzer.execute()
    
    # Imprimir resultado
    print(json.dumps(report.full_report, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
```

## Notas de Segurança

- **Credenciais**: Sempre use `WorkerConfig.secrets` para credenciais
- **TLP/PAP**: Configure adequadamente os níveis de TLP e PAP
- **Arquivos**: A análise de arquivos requer permissões adequadas
- **Rede**: Configure proxies se necessário via `WorkerConfig.proxy`

## Limitações

- Requer credenciais válidas do CrowdStrike Falcon
- Análise de arquivos pode demorar vários minutos
- Algumas funcionalidades podem requerer licenças específicas do CrowdStrike
- Rate limiting da API pode afetar análises em lote
