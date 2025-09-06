# Melhores Práticas

Este guia apresenta as melhores práticas para desenvolver, testar e manter analisadores e respondedores usando o SentinelIQ SDK.

## Desenvolvimento de Analisadores

### Estrutura de Código

#### Organização de Classes

```python
from __future__ import annotations
from typing import Dict, Any, List, Optional
from sentineliqsdk import Analyzer, WorkerInput

class ReputationAnalyzer(Analyzer):
    """
    Analisador de reputação para IPs e domínios.
    
    Este analisador consulta múltiplas fontes de threat intelligence
    para determinar a reputação de um observável.
    """
    
    def __init__(self, input_data: WorkerInput | Dict[str, Any]):
        super().__init__(input_data)
        self._initialize_config()
        self._setup_http_client()
    
    def run(self) -> None:
        """Método principal de execução."""
        try:
            observable = self.get_data()
            result = self._analyze_observable(observable)
            self.report(result)
        except Exception as e:
            self._handle_error(e)
    
    def _initialize_config(self) -> None:
        """Inicializa configurações específicas do analisador."""
        self.api_key = self.get_env("REPUTATION_API_KEY")
        self.timeout = self.get_param("timeout", 30)
        self.max_retries = self.get_param("max_retries", 3)
    
    def _setup_http_client(self) -> None:
        """Configura cliente HTTP com retry e timeout."""
        import requests
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        
        self.session = requests.Session()
        
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
    
    def _analyze_observable(self, observable: str) -> Dict[str, Any]:
        """Analisa um observável específico."""
        # Implementação da análise
        pass
    
    def _handle_error(self, error: Exception) -> None:
        """Trata erros de forma consistente."""
        error_msg = f"Erro na análise: {str(error)}"
        self.error(error_msg)
```

#### Tratamento de Erros

```python
class RobustAnalyzer(Analyzer):
    def run(self) -> None:
        try:
            self._validate_input()
            result = self._perform_analysis()
            self.report(result)
        except ValidationError as e:
            self.error(f"Erro de validação: {e}")
        except NetworkError as e:
            self.error(f"Erro de rede: {e}")
        except AnalysisError as e:
            self.error(f"Erro de análise: {e}")
        except Exception as e:
            self.error(f"Erro inesperado: {e}")
    
    def _validate_input(self) -> None:
        """Valida entrada antes da análise."""
        data = self.get_data()
        if not data:
            raise ValidationError("Dados de entrada vazios")
        
        if not isinstance(data, str):
            raise ValidationError("Tipo de dados inválido")
    
    def _perform_analysis(self) -> Dict[str, Any]:
        """Executa a análise principal."""
        try:
            # Lógica de análise
            return {"verdict": "safe"}
        except Exception as e:
            raise AnalysisError(f"Falha na análise: {e}")
```

### Configuração e Parâmetros

#### Uso de Configurações

```python
class ConfigurableAnalyzer(Analyzer):
    def __init__(self, input_data: WorkerInput | Dict[str, Any]):
        super().__init__(input_data)
        self._load_configuration()
    
    def _load_configuration(self) -> None:
        """Carrega configurações do analisador."""
        # Configurações obrigatórias
        self.api_key = self.get_env("API_KEY", message="API_KEY é obrigatória")
        
        # Configurações opcionais com valores padrão
        self.timeout = self.get_param("timeout", 30)
        self.retry_count = self.get_param("retry_count", 3)
        self.debug_mode = self.get_param("debug", False)
        
        # Configurações de threshold
        self.malicious_threshold = self.get_param("malicious_threshold", 0.8)
        self.suspicious_threshold = self.get_param("suspicious_threshold", 0.5)
        
        # Configurações de cache
        self.cache_enabled = self.get_param("cache_enabled", True)
        self.cache_ttl = self.get_param("cache_ttl", 3600)
```

#### Validação de Configuração

```python
def _validate_configuration(self) -> None:
    """Valida configurações do analisador."""
    if not self.api_key:
        raise ConfigurationError("API_KEY não configurada")
    
    if self.timeout <= 0:
        raise ConfigurationError("Timeout deve ser positivo")
    
    if not 0 <= self.malicious_threshold <= 1:
        raise ConfigurationError("Threshold malicioso deve estar entre 0 e 1")
    
    if not 0 <= self.suspicious_threshold <= 1:
        raise ConfigurationError("Threshold suspeito deve estar entre 0 e 1")
    
    if self.suspicious_threshold >= self.malicious_threshold:
        raise ConfigurationError("Threshold suspeito deve ser menor que malicioso")
```

### Logging e Debugging

#### Sistema de Logging

```python
import logging
from typing import Optional

class LoggingAnalyzer(Analyzer):
    def __init__(self, input_data: WorkerInput | Dict[str, Any]):
        super().__init__(input_data)
        self._setup_logging()
    
    def _setup_logging(self) -> None:
        """Configura sistema de logging."""
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Configurar nível de log baseado no parâmetro debug
        debug_mode = self.get_param("debug", False)
        level = logging.DEBUG if debug_mode else logging.INFO
        self.logger.setLevel(level)
        
        # Configurar handler se não existir
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
    
    def run(self) -> None:
        """Execução com logging detalhado."""
        self.logger.info("Iniciando análise")
        
        try:
            observable = self.get_data()
            self.logger.debug(f"Analisando observável: {observable}")
            
            result = self._analyze_observable(observable)
            self.logger.info(f"Análise concluída: {result.get('verdict')}")
            
            self.report(result)
        except Exception as e:
            self.logger.error(f"Erro na análise: {e}", exc_info=True)
            raise
```

#### Debugging Avançado

```python
class DebugAnalyzer(Analyzer):
    def run(self) -> None:
        debug_mode = self.get_param("debug", False)
        
        if debug_mode:
            self._print_debug_info()
        
        # Lógica de análise
        result = self._perform_analysis()
        
        if debug_mode:
            self._print_debug_result(result)
        
        self.report(result)
    
    def _print_debug_info(self) -> None:
        """Imprime informações de debug."""
        print("=== DEBUG INFO ===")
        print(f"Observável: {self.get_data()}")
        print(f"Tipo de dados: {self.get_param('data_type')}")
        print(f"TLP: {self.get_param('tlp')}")
        print(f"PAP: {self.get_param('pap')}")
        print("==================")
    
    def _print_debug_result(self, result: Dict[str, Any]) -> None:
        """Imprime resultado de debug."""
        print("=== DEBUG RESULT ===")
        print(f"Veredito: {result.get('verdict')}")
        print(f"Confiança: {result.get('confidence')}")
        print(f"Fontes consultadas: {result.get('sources_consulted', 0)}")
        print("====================")
```

## Desenvolvimento de Respondedores

### Estrutura de Resposta

#### Respondedor Robusto

```python
from __future__ import annotations
from typing import Dict, Any, List
from sentineliqsdk import Responder, WorkerInput

class SecurityResponder(Responder):
    """
    Respondedor de segurança para automação de resposta.
    
    Este respondedor executa ações de segurança baseadas
    no tipo e severidade do incidente.
    """
    
    def __init__(self, input_data: WorkerInput | Dict[str, Any]):
        super().__init__(input_data)
        self._initialize_actions()
    
    def run(self) -> None:
        """Executa resposta de segurança."""
        try:
            incident_data = self.get_data()
            response_plan = self._create_response_plan(incident_data)
            execution_result = self._execute_response(response_plan)
            self.report(execution_result)
        except Exception as e:
            self._handle_error(e)
    
    def _initialize_actions(self) -> None:
        """Inicializa ações disponíveis."""
        self.actions = {
            "block_ip": self._block_ip,
            "quarantine_file": self._quarantine_file,
            "disable_user": self._disable_user,
            "notify_security": self._notify_security
        }
    
    def _create_response_plan(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Cria plano de resposta baseado no incidente."""
        incident_type = incident_data.get("type")
        severity = incident_data.get("severity")
        
        plan = {
            "incident_id": incident_data.get("id"),
            "actions": [],
            "priority": self._calculate_priority(severity),
            "estimated_duration": "Unknown"
        }
        
        # Adicionar ações baseadas no tipo de incidente
        if incident_type == "malware":
            plan["actions"].extend([
                {"action": "quarantine_file", "target": incident_data.get("file_path")},
                {"action": "block_ip", "target": incident_data.get("source_ip")}
            ])
        elif incident_type == "intrusion":
            plan["actions"].extend([
                {"action": "block_ip", "target": incident_data.get("source_ip")},
                {"action": "disable_user", "target": incident_data.get("username")}
            ])
        
        return plan
    
    def _execute_response(self, plan: Dict[str, Any]) -> Dict[str, Any]:
        """Executa plano de resposta."""
        results = []
        
        for action_item in plan["actions"]:
            action = action_item["action"]
            target = action_item["target"]
            
            if action in self.actions:
                try:
                    result = self.actions[action](target)
                    results.append({
                        "action": action,
                        "target": target,
                        "success": True,
                        "result": result
                    })
                except Exception as e:
                    results.append({
                        "action": action,
                        "target": target,
                        "success": False,
                        "error": str(e)
                    })
            else:
                results.append({
                    "action": action,
                    "target": target,
                    "success": False,
                    "error": "Ação não suportada"
                })
        
        return {
            "plan": plan,
            "execution_results": results,
            "success_rate": self._calculate_success_rate(results)
        }
```

### Validação e Segurança

#### Validação de Entrada

```python
class SecureResponder(Responder):
    def run(self) -> None:
        # Validar entrada antes de executar
        if not self._validate_input():
            self.error("Entrada inválida para respondedor")
        
        # Executar resposta
        result = self._execute_secure_response()
        self.report(result)
    
    def _validate_input(self) -> bool:
        """Valida entrada do respondedor."""
        data = self.get_data()
        
        # Verificar campos obrigatórios
        required_fields = ["incident_id", "type", "severity"]
        if not all(field in data for field in required_fields):
            return False
        
        # Validar severidade
        valid_severities = ["low", "medium", "high", "critical"]
        if data.get("severity") not in valid_severities:
            return False
        
        # Validar TLP/PAP se configurado
        if self.get_param("check_tlp", False):
            tlp = data.get("tlp", 0)
            max_tlp = self.get_param("max_tlp", 2)
            if tlp > max_tlp:
                return False
        
        return True
```

#### Controle de Acesso

```python
class AccessControlledResponder(Responder):
    def __init__(self, input_data: WorkerInput | Dict[str, Any]):
        super().__init__(input_data)
        self._load_permissions()
    
    def _load_permissions(self) -> None:
        """Carrega permissões do respondedor."""
        self.permissions = self.get_param("permissions", [])
        self.require_approval = self.get_param("require_approval", True)
    
    def run(self) -> None:
        # Verificar permissões
        if not self._check_permissions():
            self.error("Permissões insuficientes para executar resposta")
        
        # Verificar aprovação se necessário
        if self.require_approval and not self._check_approval():
            self.error("Aprovação necessária para executar resposta")
        
        # Executar resposta
        result = self._execute_response()
        self.report(result)
    
    def _check_permissions(self) -> bool:
        """Verifica se o respondedor tem permissões necessárias."""
        required_permissions = ["execute_response", "modify_security"]
        return all(perm in self.permissions for perm in required_permissions)
    
    def _check_approval(self) -> bool:
        """Verifica se a resposta foi aprovada."""
        # Implementar lógica de aprovação
        return True
```

## Testes

### Testes Unitários

#### Estrutura de Testes

```python
import unittest
import json
from unittest.mock import Mock, patch
from sentineliqsdk import WorkerInput, WorkerConfig

class TestReputationAnalyzer(unittest.TestCase):
    def setUp(self):
        """Configuração para cada teste."""
        self.input_data = WorkerInput(
            data_type="ip",
            data="1.2.3.4",
            config=WorkerConfig(auto_extract=True)
        )
        self.analyzer = ReputationAnalyzer(self.input_data)
    
    def test_analyze_safe_ip(self):
        """Testa análise de IP seguro."""
        with patch.object(self.analyzer, '_query_reputation_sources') as mock_query:
            mock_query.return_value = {"verdict": "safe", "confidence": 0.9}
            
            result = self.analyzer._analyze_observable("8.8.8.8")
            
            self.assertEqual(result["verdict"], "safe")
            self.assertEqual(result["confidence"], 0.9)
    
    def test_analyze_malicious_ip(self):
        """Testa análise de IP malicioso."""
        with patch.object(self.analyzer, '_query_reputation_sources') as mock_query:
            mock_query.return_value = {"verdict": "malicious", "confidence": 0.95}
            
            result = self.analyzer._analyze_observable("1.2.3.4")
            
            self.assertEqual(result["verdict"], "malicious")
            self.assertEqual(result["confidence"], 0.95)
    
    def test_handle_network_error(self):
        """Testa tratamento de erro de rede."""
        with patch.object(self.analyzer, '_query_reputation_sources') as mock_query:
            mock_query.side_effect = NetworkError("Connection failed")
            
            with self.assertRaises(NetworkError):
                self.analyzer._analyze_observable("8.8.8.8")
    
    def test_configuration_validation(self):
        """Testa validação de configuração."""
        # Teste com configuração válida
        self.assertTrue(self.analyzer._validate_configuration())
        
        # Teste com configuração inválida
        self.analyzer.api_key = None
        with self.assertRaises(ConfigurationError):
            self.analyzer._validate_configuration()
```

#### Testes de Integração

```python
class TestAnalyzerIntegration(unittest.TestCase):
    def test_full_analysis_workflow(self):
        """Testa workflow completo de análise."""
        # Criar dados de entrada
        input_data = {
            "dataType": "ip",
            "data": "1.2.3.4",
            "tlp": 2,
            "pap": 2,
            "config": {
                "auto_extract": True,
                "timeout": 30
            }
        }
        
        # Executar analisador
        analyzer = ReputationAnalyzer(input_data)
        
        # Capturar output
        import io
        import sys
        from contextlib import redirect_stdout
        
        output = io.StringIO()
        with redirect_stdout(output):
            analyzer.run()
        
        # Verificar resultado
        result = json.loads(output.getvalue())
        self.assertTrue(result["success"])
        self.assertIn("full", result)
        self.assertIn("verdict", result["full"])
```

### Testes de Performance

#### Benchmark de Performance

```python
import time
import statistics
from typing import List

class PerformanceTest(unittest.TestCase):
    def test_analysis_performance(self):
        """Testa performance da análise."""
        test_cases = [
            "8.8.8.8",
            "1.1.1.1", 
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1"
        ]
        
        execution_times = []
        
        for test_case in test_cases:
            input_data = WorkerInput(data_type="ip", data=test_case)
            analyzer = ReputationAnalyzer(input_data)
            
            start_time = time.time()
            analyzer._analyze_observable(test_case)
            end_time = time.time()
            
            execution_times.append(end_time - start_time)
        
        # Verificar que o tempo médio está dentro do limite
        avg_time = statistics.mean(execution_times)
        max_time = max(execution_times)
        
        self.assertLess(avg_time, 5.0, "Tempo médio de análise muito alto")
        self.assertLess(max_time, 10.0, "Tempo máximo de análise muito alto")
```

## Documentação

### Documentação de Código

#### Docstrings Completas

```python
class ThreatIntelligenceAnalyzer(Analyzer):
    """
    Analisador de Threat Intelligence para múltiplas fontes.
    
    Este analisador consulta diversas fontes de threat intelligence
    para determinar a reputação e classificação de observáveis.
    
    Attributes:
        api_keys (Dict[str, str]): Chaves de API para diferentes fontes
        timeout (int): Timeout para requisições HTTP
        retry_count (int): Número de tentativas em caso de falha
    
    Example:
        >>> input_data = WorkerInput(data_type="ip", data="1.2.3.4")
        >>> analyzer = ThreatIntelligenceAnalyzer(input_data)
        >>> analyzer.run()
    """
    
    def __init__(self, input_data: WorkerInput | Dict[str, Any]):
        """
        Inicializa o analisador de threat intelligence.
        
        Args:
            input_data: Dados de entrada do analisador
            
        Raises:
            ConfigurationError: Se configurações obrigatórias estão ausentes
        """
        super().__init__(input_data)
        self._load_api_keys()
    
    def _query_virustotal(self, observable: str) -> Optional[Dict[str, Any]]:
        """
        Consulta VirusTotal para um observável.
        
        Args:
            observable: IP, domínio ou hash para consultar
            
        Returns:
            Dicionário com resultado da consulta ou None se falhar
            
        Raises:
            NetworkError: Se houver erro de rede
            APIError: Se houver erro na API do VirusTotal
        """
        pass
```

#### Documentação de Configuração

```python
# config_example.json
{
    "timeout": 30,
    "retry_count": 3,
    "api_keys": {
        "virustotal": "your_virustotal_api_key",
        "abuseipdb": "your_abuseipdb_api_key"
    },
    "thresholds": {
        "malicious": 0.8,
        "suspicious": 0.5
    },
    "cache": {
        "enabled": true,
        "ttl": 3600
    }
}
```

### Documentação de API

#### Exemplos de Uso

```python
# Exemplo 1: Análise básica de IP
from sentineliqsdk import Analyzer, WorkerInput

input_data = WorkerInput(data_type="ip", data="1.2.3.4")
analyzer = ReputationAnalyzer(input_data)
analyzer.run()

# Exemplo 2: Análise com configuração personalizada
from sentineliqsdk import WorkerInput, WorkerConfig

config = WorkerConfig(
    timeout=60,
    auto_extract=True,
    check_tlp=True,
    max_tlp=3
)

input_data = WorkerInput(
    data_type="domain",
    data="malicious.example.com",
    config=config
)

analyzer = ReputationAnalyzer(input_data)
analyzer.run()

# Exemplo 3: Análise em lote
observables = ["1.2.3.4", "8.8.8.8", "5.6.7.8"]

for obs in observables:
    input_data = WorkerInput(data_type="ip", data=obs)
    analyzer = ReputationAnalyzer(input_data)
    analyzer.run()
```

## Deploy e Produção

### Configuração de Produção

#### Variáveis de Ambiente

```bash
# .env.production
SENTINELIQ_DEBUG=false
SENTINELIQ_LOG_LEVEL=INFO
SENTINELIQ_TIMEOUT=30
SENTINELIQ_RETRY_COUNT=3

# API Keys
VIRUSTOTAL_API_KEY=your_api_key_here
ABUSEIPDB_API_KEY=your_api_key_here

# Proxy Configuration
HTTP_PROXY=http://proxy.company.com:8080
HTTPS_PROXY=https://proxy.company.com:8080
NO_PROXY=localhost,127.0.0.1
```

#### Configuração de Logging

```python
# logging_config.py
import logging
import logging.handlers
from pathlib import Path

def setup_production_logging():
    """Configura logging para produção."""
    log_dir = Path("/var/log/sentineliq")
    log_dir.mkdir(exist_ok=True)
    
    # Configurar logger principal
    logger = logging.getLogger("sentineliq")
    logger.setLevel(logging.INFO)
    
    # Handler para arquivo com rotação
    file_handler = logging.handlers.RotatingFileHandler(
        log_dir / "analyzers.log",
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    
    # Handler para console
    console_handler = logging.StreamHandler()
    
    # Formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger
```

### Monitoramento

#### Métricas de Performance

```python
import time
import psutil
from typing import Dict, Any

class MetricsCollector:
    """Coletor de métricas para analisadores."""
    
    def __init__(self):
        self.metrics = {}
    
    def start_analysis(self, observable: str) -> None:
        """Inicia coleta de métricas para uma análise."""
        self.metrics[observable] = {
            "start_time": time.time(),
            "start_memory": psutil.Process().memory_info().rss,
            "start_cpu": psutil.Process().cpu_percent()
        }
    
    def end_analysis(self, observable: str, success: bool) -> Dict[str, Any]:
        """Finaliza coleta de métricas."""
        if observable not in self.metrics:
            return {}
        
        start_metrics = self.metrics[observable]
        end_time = time.time()
        
        metrics = {
            "observable": observable,
            "execution_time": end_time - start_metrics["start_time"],
            "memory_used": psutil.Process().memory_info().rss - start_metrics["start_memory"],
            "cpu_used": psutil.Process().cpu_percent() - start_metrics["start_cpu"],
            "success": success,
            "timestamp": end_time
        }
        
        del self.metrics[observable]
        return metrics
```

#### Health Checks

```python
class HealthChecker:
    """Verificador de saúde para analisadores."""
    
    def __init__(self, analyzer_class):
        self.analyzer_class = analyzer_class
    
    def check_health(self) -> Dict[str, Any]:
        """Verifica saúde do analisador."""
        health_status = {
            "status": "healthy",
            "checks": {},
            "timestamp": time.time()
        }
        
        # Verificar dependências
        health_status["checks"]["dependencies"] = self._check_dependencies()
        
        # Verificar conectividade
        health_status["checks"]["connectivity"] = self._check_connectivity()
        
        # Verificar configuração
        health_status["checks"]["configuration"] = self._check_configuration()
        
        # Determinar status geral
        if not all(health_status["checks"].values()):
            health_status["status"] = "unhealthy"
        
        return health_status
    
    def _check_dependencies(self) -> bool:
        """Verifica dependências do analisador."""
        try:
            import requests
            import json
            return True
        except ImportError:
            return False
    
    def _check_connectivity(self) -> bool:
        """Verifica conectividade de rede."""
        try:
            import requests
            response = requests.get("https://httpbin.org/status/200", timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def _check_configuration(self) -> bool:
        """Verifica configuração do analisador."""
        try:
            # Teste básico de configuração
            test_input = WorkerInput(data_type="ip", data="8.8.8.8")
            analyzer = self.analyzer_class(test_input)
            return True
        except:
            return False
```

## Segurança

### Boas Práticas de Segurança

#### Tratamento de Dados Sensíveis

```python
import re
from typing import Any, Dict

class SecureAnalyzer(Analyzer):
    """Analisador com práticas de segurança."""
    
    def __init__(self, input_data: WorkerInput | Dict[str, Any]):
        super().__init__(input_data)
        self._setup_security()
    
    def _setup_security(self) -> None:
        """Configura medidas de segurança."""
        self.sensitive_patterns = [
            r'password\s*=\s*["\']?([^"\'\s]+)',
            r'api[_-]?key\s*=\s*["\']?([^"\'\s]+)',
            r'token\s*=\s*["\']?([^"\'\s]+)'
        ]
    
    def _sanitize_output(self, data: Any) -> Any:
        """Remove dados sensíveis do output."""
        if isinstance(data, dict):
            return {k: self._sanitize_output(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._sanitize_output(item) for item in data]
        elif isinstance(data, str):
            return self._sanitize_string(data)
        else:
            return data
    
    def _sanitize_string(self, text: str) -> str:
        """Remove informações sensíveis de strings."""
        for pattern in self.sensitive_patterns:
            text = re.sub(pattern, r'\1=***REMOVED***', text, flags=re.IGNORECASE)
        return text
    
    def report(self, data: Dict[str, Any]) -> None:
        """Reporta dados sanitizados."""
        sanitized_data = self._sanitize_output(data)
        super().report(sanitized_data)
```

#### Validação de Entrada

```python
import ipaddress
import re
from urllib.parse import urlparse

class InputValidator:
    """Validador de entrada para analisadores."""
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """Valida endereço IP."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_domain(domain: str) -> bool:
        """Valida domínio."""
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(pattern, domain))
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """Valida URL."""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    @staticmethod
    def validate_hash(hash_value: str) -> bool:
        """Valida hash."""
        hash_patterns = {
            32: r'^[a-fA-F0-9]{32}$',  # MD5
            40: r'^[a-fA-F0-9]{40}$',  # SHA1
            64: r'^[a-fA-F0-9]{64}$'   # SHA256
        }
        
        length = len(hash_value)
        if length in hash_patterns:
            return bool(re.match(hash_patterns[length], hash_value))
        
        return False
```

## Conclusão

Seguir estas melhores práticas ajudará a criar analisadores e respondedores robustos, seguros e maintíveis. Lembre-se de:

1. **Sempre validar entrada** antes de processar
2. **Tratar erros** de forma consistente
3. **Documentar código** adequadamente
4. **Testar** extensivamente
5. **Monitorar** em produção
6. **Manter segurança** em mente

Para mais informações, consulte a documentação completa do SDK e os exemplos fornecidos.
