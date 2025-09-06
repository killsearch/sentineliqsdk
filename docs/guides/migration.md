# Guia de Migração

Este guia detalha como migrar de versões anteriores do SentinelIQ SDK e de outras ferramentas de análise de segurança para a versão atual.

## Migração de Versões Anteriores

### Migração da v0.1.x para v0.2.x

#### Mudanças na API Principal

**Antes (v0.1.x):**
```python
from sentineliqsdk.analyzer import Analyzer
from sentineliqsdk.responder import Responder
from sentineliqsdk.worker import Worker

class MyAnalyzer(Analyzer):
    def run(self):
        data = self.getData()  # Método antigo
        result = self.analyze(data)
        self.report(result)
```

**Depois (v0.2.x):**
```python
from sentineliqsdk import Analyzer, WorkerInput

class MyAnalyzer(Analyzer):
    def run(self):
        data = self.get_data()  # Método novo
        result = self.analyze(data)
        self.report(result)
```

#### Mudanças nos Imports

**Antes:**
```python
from sentineliqsdk.analyzer import Analyzer
from sentineliqsdk.responder import Responder
from sentineliqsdk.worker import Worker
from sentineliqsdk.extractor import Extractor
```

**Depois:**
```python
from sentineliqsdk import Analyzer, Responder, Worker, Extractor
```

#### Mudanças nos Métodos

| Método Antigo | Método Novo | Notas |
|---------------|-------------|-------|
| `getData()` | `get_data()` | Método principal para obter dados |
| `getParam()` | `get_param()` | Acesso a parâmetros |
| `getEnv()` | `get_env()` | Acesso a variáveis de ambiente |
| `checkTlp()` | Automático | TLP/PAP verificados automaticamente |
| `checkPap()` | Automático | TLP/PAP verificados automaticamente |

#### Migração de Configuração

**Antes:**
```python
config = {
    "checkTlp": True,
    "maxTlp": 2,
    "autoExtractArtifacts": True
}
```

**Depois:**
```python
from sentineliqsdk import WorkerConfig

config = WorkerConfig(
    check_tlp=True,
    max_tlp=2,
    auto_extract=True  # Renomeado de autoExtractArtifacts
)
```

### Migração de Dicionários para Dataclasses

#### Input Data

**Antes (Dicionários):**
```python
input_data = {
    "dataType": "ip",
    "data": "1.2.3.4",
    "tlp": 2,
    "pap": 2,
    "config": {
        "check_tlp": True,
        "max_tlp": 2
    }
}

analyzer = MyAnalyzer(input_data)
```

**Depois (Dataclasses - Recomendado):**
```python
from sentineliqsdk import WorkerInput, WorkerConfig

input_data = WorkerInput(
    data_type="ip",
    data="1.2.3.4",
    tlp=2,
    pap=2,
    config=WorkerConfig(
        check_tlp=True,
        max_tlp=2
    )
)

analyzer = MyAnalyzer(input_data)
```

#### Output Data

**Antes:**
```python
def report(self, data):
    result = {
        "success": True,
        "summary": self.summary(data),
        "artifacts": self.artifacts(data),
        "operations": self.operations(data),
        "full": data
    }
    print(json.dumps(result))
```

**Depois:**
```python
from sentineliqsdk import AnalyzerReport

def report(self, data):
    result = AnalyzerReport(
        success=True,
        summary=self.summary(data),
        artifacts=self.artifacts(data),
        operations=self.operations(data),
        full=data
    )
    print(json.dumps(result.to_dict()))
```

## Migração de Outras Ferramentas

### Migração do MISP

#### Estrutura de Dados MISP

**Antes (MISP):**
```python
import pymisp

misp = PyMISP('https://misp.example.com', 'your_api_key')
events = misp.search(controller='events', published=True)

for event in events:
    for attribute in event['Event']['Attribute']:
        if attribute['type'] == 'ip-dst':
            # Processar IP
            pass
```

**Depois (SentinelIQ SDK):**
```python
from sentineliqsdk import Analyzer, WorkerInput

class MispAnalyzer(Analyzer):
    def run(self):
        # Dados já vêm estruturados do SentinelIQ
        observable = self.get_data()
        data_type = self.get_param("data_type")
        
        # Processar observável
        result = self.analyze_observable(observable, data_type)
        self.report(result)
```

### Migração do VirusTotal

#### Integração VirusTotal

**Antes (VirusTotal API direta):**
```python
import requests

def check_virustotal(ip):
    url = f"https://www.virustotal.com/vtapi/v2/ip-address/report"
    params = {'apikey': API_KEY, 'ip': ip}
    response = requests.get(url, params=params)
    return response.json()
```

**Depois (SentinelIQ SDK):**
```python
from sentineliqsdk import Analyzer, WorkerInput

class VirusTotalAnalyzer(Analyzer):
    def run(self):
        observable = self.get_data()
        
        # Configuração automática de proxy
        vt_result = self.query_virustotal(observable)
        
        result = {
            "observable": observable,
            "virustotal": vt_result,
            "verdict": self.determine_verdict(vt_result)
        }
        
        self.report(result)
    
    def query_virustotal(self, observable):
        # Lógica de consulta VirusTotal
        pass
```

### Migração do YARA

#### Regras YARA

**Antes (YARA direto):**
```python
import yara

rules = yara.compile('malware.yar')
matches = rules.match('suspicious_file.exe')

for match in matches:
    print(f"Rule: {match.rule}")
    print(f"Tags: {match.tags}")
```

**Depois (SentinelIQ SDK):**
```python
from sentineliqsdk import Analyzer, WorkerInput

class YaraAnalyzer(Analyzer):
    def run(self):
        file_path = self.get_data()  # Para dataType="file"
        
        # Compilar regras YARA
        rules = self.compile_yara_rules()
        
        # Executar análise
        matches = rules.match(file_path)
        
        result = {
            "file": file_path,
            "yara_matches": [self.format_match(m) for m in matches],
            "verdict": "malicious" if matches else "clean"
        }
        
        self.report(result)
```

## Migração de Scripts Personalizados

### Scripts de Análise Simples

#### Script Antigo

```python
#!/usr/bin/env python3
import sys
import json
import requests

def analyze_ip(ip):
    # Lógica de análise
    result = {
        "ip": ip,
        "verdict": "safe",
        "confidence": 0.8
    }
    return result

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python analyzer.py <ip>")
        sys.exit(1)
    
    ip = sys.argv[1]
    result = analyze_ip(ip)
    print(json.dumps(result))
```

#### Script Migrado

```python
#!/usr/bin/env python3
from __future__ import annotations
from sentineliqsdk import Analyzer, WorkerInput

class IpAnalyzer(Analyzer):
    def run(self):
        ip = self.get_data()
        
        # Lógica de análise (mesma)
        result = {
            "ip": ip,
            "verdict": "safe",
            "confidence": 0.8
        }
        
        self.report(result)

if __name__ == "__main__":
    # Suporte a job directory e STDIN
    import sys
    
    if len(sys.argv) > 1:
        # Modo job directory
        job_dir = sys.argv[1]
        input_data = WorkerInput.from_job_directory(job_dir)
    else:
        # Modo STDIN
        import json
        data = json.loads(sys.stdin.read())
        input_data = WorkerInput.from_dict(data)
    
    analyzer = IpAnalyzer(input_data)
    analyzer.run()
```

### Scripts com Configuração Complexa

#### Script Antigo com Configuração

```python
import os
import json
from typing import Dict, Any

class ConfigurableAnalyzer:
    def __init__(self, config_file: str):
        with open(config_file, 'r') as f:
            self.config = json.load(f)
        
        self.api_key = os.getenv('API_KEY')
        self.proxy = self.config.get('proxy')
        
        if self.proxy:
            os.environ['HTTP_PROXY'] = self.proxy['http']
            os.environ['HTTPS_PROXY'] = self.proxy['https']
    
    def analyze(self, data: str) -> Dict[str, Any]:
        # Lógica de análise
        pass
```

#### Script Migrado

```python
from __future__ import annotations
from sentineliqsdk import Analyzer, WorkerInput, WorkerConfig, ProxyConfig

class ConfigurableAnalyzer(Analyzer):
    def __init__(self, input_data: WorkerInput | Dict[str, Any]):
        super().__init__(input_data)
        
        # Configuração automática de proxy
        # TLP/PAP verificados automaticamente
        # Acesso a parâmetros via get_param()
    
    def run(self):
        data = self.get_data()
        api_key = self.get_env("API_KEY")
        
        # Lógica de análise
        result = self.analyze_data(data, api_key)
        self.report(result)
```

## Migração de Workflows

### Pipeline de Análise

#### Pipeline Antigo

```python
# pipeline.py
import subprocess
import json

def run_analysis_pipeline(observable):
    # Etapa 1: Análise de reputação
    result1 = subprocess.run(['python', 'reputation_analyzer.py', observable], 
                           capture_output=True, text=True)
    
    # Etapa 2: Análise de malware
    result2 = subprocess.run(['python', 'malware_analyzer.py', observable], 
                           capture_output=True, text=True)
    
    # Etapa 3: Correlação
    result3 = subprocess.run(['python', 'correlation_analyzer.py', observable], 
                           capture_output=True, text=True)
    
    # Combinar resultados
    combined = {
        "reputation": json.loads(result1.stdout),
        "malware": json.loads(result2.stdout),
        "correlation": json.loads(result3.stdout)
    }
    
    return combined
```

#### Pipeline Migrado

```python
# pipeline.py
from __future__ import annotations
from sentineliqsdk import Analyzer, WorkerInput
from typing import Dict, Any

class PipelineAnalyzer(Analyzer):
    def run(self):
        observable = self.get_data()
        
        # Executar todas as análises
        reputation_result = self.analyze_reputation(observable)
        malware_result = self.analyze_malware(observable)
        correlation_result = self.analyze_correlation(observable)
        
        # Combinar resultados
        combined_result = {
            "observable": observable,
            "reputation": reputation_result,
            "malware": malware_result,
            "correlation": correlation_result,
            "final_verdict": self.determine_final_verdict(
                reputation_result, malware_result, correlation_result
            )
        }
        
        self.report(combined_result)
    
    def analyze_reputation(self, observable: str) -> Dict[str, Any]:
        # Lógica de análise de reputação
        pass
    
    def analyze_malware(self, observable: str) -> Dict[str, Any]:
        # Lógica de análise de malware
        pass
    
    def analyze_correlation(self, observable: str) -> Dict[str, Any]:
        # Lógica de correlação
        pass
```

## Migração de Testes

### Testes Unitários

#### Testes Antigos

```python
import unittest
from my_analyzer import MyAnalyzer

class TestMyAnalyzer(unittest.TestCase):
    def test_analyze_ip(self):
        analyzer = MyAnalyzer()
        result = analyzer.analyze("1.2.3.4")
        self.assertEqual(result["verdict"], "safe")
```

#### Testes Migrados

```python
import unittest
from sentineliqsdk import Analyzer, WorkerInput

class TestMyAnalyzer(unittest.TestCase):
    def test_analyze_ip(self):
        input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        analyzer = MyAnalyzer(input_data)
        
        # Capturar output
        import io
        import sys
        from contextlib import redirect_stdout
        
        output = io.StringIO()
        with redirect_stdout(output):
            analyzer.run()
        
        result = json.loads(output.getvalue())
        self.assertEqual(result["full"]["verdict"], "safe")
```

### Testes de Integração

#### Testes Antigos

```python
def test_integration():
    # Criar arquivo de entrada
    with open('/tmp/input.json', 'w') as f:
        json.dump({"dataType": "ip", "data": "1.2.3.4"}, f)
    
    # Executar analisador
    result = subprocess.run(['python', 'my_analyzer.py', '/tmp'], 
                          capture_output=True, text=True)
    
    # Verificar resultado
    assert result.returncode == 0
    output = json.loads(result.stdout)
    assert output["success"] == True
```

#### Testes Migrados

```python
def test_integration():
    # Criar job directory
    job_dir = "/tmp/test_job"
    os.makedirs(f"{job_dir}/input", exist_ok=True)
    os.makedirs(f"{job_dir}/output", exist_ok=True)
    
    # Criar arquivo de entrada
    input_data = WorkerInput(data_type="ip", data="1.2.3.4")
    with open(f"{job_dir}/input/input.json", 'w') as f:
        json.dump(input_data.to_dict(), f)
    
    # Executar analisador
    result = subprocess.run(['python', 'my_analyzer.py', job_dir], 
                          capture_output=True, text=True)
    
    # Verificar resultado
    assert result.returncode == 0
    output = json.loads(result.stdout)
    assert output["success"] == True
```

## Checklist de Migração

### Pré-Migração

- [ ] Fazer backup do código atual
- [ ] Documentar dependências existentes
- [ ] Identificar funcionalidades customizadas
- [ ] Listar integrações externas

### Durante a Migração

- [ ] Atualizar imports para nova estrutura
- [ ] Migrar métodos antigos para novos
- [ ] Converter dicionários para dataclasses
- [ ] Atualizar configurações
- [ ] Migrar testes existentes

### Pós-Migração

- [ ] Executar testes unitários
- [ ] Executar testes de integração
- [ ] Validar funcionalidades
- [ ] Testar com dados reais
- [ ] Documentar mudanças

## Problemas Comuns e Soluções

### Problema: Erro de Import

**Erro:**
```
ModuleNotFoundError: No module named 'sentineliqsdk.analyzer'
```

**Solução:**
```python
# Antes
from sentineliqsdk.analyzer import Analyzer

# Depois
from sentineliqsdk import Analyzer
```

### Problema: Método Não Encontrado

**Erro:**
```
AttributeError: 'Analyzer' object has no attribute 'getData'
```

**Solução:**
```python
# Antes
data = self.getData()

# Depois
data = self.get_data()
```

### Problema: Configuração de Proxy

**Antes:**
```python
if config.get('proxy'):
    os.environ['HTTP_PROXY'] = config['proxy']['http']
    os.environ['HTTPS_PROXY'] = config['proxy']['https']
```

**Depois:**
```python
# Configuração automática via WorkerConfig
config = WorkerConfig(
    proxy=ProxyConfig(
        http="http://proxy:8080",
        https="https://proxy:8080"
    )
)
```

### Problema: Verificação TLP/PAP

**Antes:**
```python
if not self.checkTlp(data.get('tlp'), config.get('maxTlp')):
    self.error("TLP too high")
```

**Depois:**
```python
# Verificação automática - não é necessário código adicional
```

## Recursos de Apoio

### Documentação

- [Guia do Agente](guide.md) - Documentação completa da API
- [Exemplos](examples/) - Exemplos práticos de uso
- [Referência da API](reference/) - Documentação detalhada

### Ferramentas

- `sentineliqsdk-migrate` - Ferramenta de migração automática (futuro)
- Validador de configuração
- Testes de compatibilidade

### Comunidade

- GitHub Issues - Reportar problemas
- Discussões - Fazer perguntas
- Pull Requests - Contribuir melhorias

## Conclusão

A migração para o SentinelIQ SDK v0.2.x oferece benefícios significativos em termos de simplicidade, type safety e funcionalidades avançadas. Este guia deve ajudar a tornar o processo de migração o mais suave possível.

Para dúvidas específicas ou problemas não cobertos neste guia, consulte a documentação completa ou entre em contato com a comunidade.
