# Recursos Avançados

Este guia cobre recursos avançados do SentinelIQ SDK, incluindo processamento em lote, configurações personalizadas, e integração com sistemas externos.

## Processamento em Lote

### Processando Múltiplos Observáveis

```python
from __future__ import annotations
from typing import List, Dict, Any
from sentineliqsdk import Analyzer, WorkerInput, WorkerConfig

class BatchAnalyzer(Analyzer):
    """Analisador que processa múltiplos observáveis em lote."""
    
    def __init__(self, input_data: WorkerInput | Dict[str, Any]):
        super().__init__(input_data)
        self.batch_results = []
    
    def run(self) -> None:
        # Obter lista de observáveis do input
        observables = self.get_param("observables", [])
        
        if not observables:
            self.error("Nenhum observável fornecido para processamento em lote")
        
        # Processar cada observável
        for obs_data in observables:
            result = self._analyze_single(obs_data)
            self.batch_results.append(result)
        
        # Relatório consolidado
        self.report({
            "batch_size": len(observables),
            "results": self.batch_results,
            "summary": self._generate_summary()
        })
    
    def _analyze_single(self, obs_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analisa um único observável."""
        data_type = obs_data.get("dataType")
        data = obs_data.get("data")
        
        # Lógica de análise específica
        verdict = self._determine_verdict(data_type, data)
        
        return {
            "observable": data,
            "data_type": data_type,
            "verdict": verdict,
            "confidence": self._calculate_confidence(verdict)
        }
    
    def _determine_verdict(self, data_type: str, data: str) -> str:
        """Determina o veredito baseado no tipo e dados."""
        if data_type == "ip":
            return "malicious" if data.startswith("192.168.") else "safe"
        elif data_type == "domain":
            return "suspicious" if "malware" in data.lower() else "safe"
        else:
            return "safe"
    
    def _calculate_confidence(self, verdict: str) -> float:
        """Calcula a confiança do veredito."""
        confidence_map = {
            "malicious": 0.9,
            "suspicious": 0.7,
            "safe": 0.8
        }
        return confidence_map.get(verdict, 0.5)
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Gera resumo do processamento em lote."""
        verdicts = [r["verdict"] for r in self.batch_results]
        return {
            "total_processed": len(self.batch_results),
            "malicious_count": verdicts.count("malicious"),
            "suspicious_count": verdicts.count("suspicious"),
            "safe_count": verdicts.count("safe"),
            "average_confidence": sum(r["confidence"] for r in self.batch_results) / len(self.batch_results)
        }

# Exemplo de uso
if __name__ == "__main__":
    batch_input = {
        "dataType": "batch",
        "observables": [
            {"dataType": "ip", "data": "192.168.1.1"},
            {"dataType": "domain", "data": "malware.example.com"},
            {"dataType": "ip", "data": "8.8.8.8"}
        ],
        "config": {"auto_extract": True}
    }
    
    analyzer = BatchAnalyzer(batch_input)
    analyzer.run()
```

## Configurações Personalizadas

### Configuração Avançada de Proxy

```python
from sentineliqsdk import WorkerInput, WorkerConfig, ProxyConfig

# Configuração de proxy com autenticação
proxy_config = ProxyConfig(
    http="http://user:pass@proxy.company.com:8080",
    https="https://user:pass@proxy.company.com:8080",
    no_proxy="localhost,127.0.0.1,.local"
)

# Configuração de worker com proxy
config = WorkerConfig(
    check_tlp=True,
    max_tlp=3,
    check_pap=True,
    max_pap=3,
    auto_extract=True,
    proxy=proxy_config
)

input_data = WorkerInput(
    data_type="ip",
    data="1.2.3.4",
    tlp=2,
    pap=2,
    config=config
)
```

### Configuração de Timeout e Retry

```python
from __future__ import annotations
import time
from typing import Optional
from sentineliqsdk import Analyzer, WorkerInput

class ResilientAnalyzer(Analyzer):
    """Analisador com retry e timeout personalizados."""
    
    def __init__(self, input_data: WorkerInput | Dict[str, Any]):
        super().__init__(input_data)
        self.max_retries = self.get_param("max_retries", 3)
        self.timeout = self.get_param("timeout", 30)
        self.retry_delay = self.get_param("retry_delay", 1)
    
    def run(self) -> None:
        observable = self.get_data()
        
        # Tentar análise com retry
        result = self._analyze_with_retry(observable)
        
        self.report({
            "observable": observable,
            "result": result,
            "retry_count": result.get("retry_count", 0)
        })
    
    def _analyze_with_retry(self, observable: str) -> Dict[str, Any]:
        """Executa análise com retry em caso de falha."""
        last_error = None
        
        for attempt in range(self.max_retries + 1):
            try:
                result = self._perform_analysis(observable)
                result["retry_count"] = attempt
                return result
            except Exception as e:
                last_error = e
                if attempt < self.max_retries:
                    time.sleep(self.retry_delay * (2 ** attempt))  # Backoff exponencial
                    continue
                else:
                    break
        
        # Se chegou aqui, todas as tentativas falharam
        return {
            "error": str(last_error),
            "retry_count": self.max_retries,
            "success": False
        }
    
    def _perform_analysis(self, observable: str) -> Dict[str, Any]:
        """Executa a análise real (simulada aqui)."""
        # Simular análise que pode falhar
        import random
        if random.random() < 0.3:  # 30% de chance de falha
            raise Exception("Análise falhou temporariamente")
        
        return {
            "verdict": "safe" if observable != "1.2.3.4" else "malicious",
            "confidence": 0.8,
            "success": True
        }
```

## Integração com APIs Externas

### Integração com Threat Intelligence

```python
from __future__ import annotations
import requests
from typing import Dict, Any, Optional
from sentineliqsdk import Analyzer, WorkerInput

class ThreatIntelAnalyzer(Analyzer):
    """Analisador que integra com APIs de threat intelligence."""
    
    def __init__(self, input_data: WorkerInput | Dict[str, Any]):
        super().__init__(input_data)
        self.api_key = self.get_env("THREAT_INTEL_API_KEY")
        self.api_base_url = self.get_param("api_base_url", "https://api.threatintel.com")
        self.timeout = self.get_param("timeout", 10)
    
    def run(self) -> None:
        observable = self.get_data()
        
        if not self.api_key:
            self.error("API key não configurada para threat intelligence")
        
        # Consultar múltiplas fontes
        results = {
            "observable": observable,
            "sources": {}
        }
        
        # VirusTotal
        vt_result = self._query_virustotal(observable)
        if vt_result:
            results["sources"]["virustotal"] = vt_result
        
        # AbuseIPDB
        abuse_result = self._query_abuseipdb(observable)
        if abuse_result:
            results["sources"]["abuseipdb"] = abuse_result
        
        # Determinar veredito consolidado
        verdict = self._consolidate_verdict(results["sources"])
        results["verdict"] = verdict
        
        self.report(results)
    
    def _query_virustotal(self, observable: str) -> Optional[Dict[str, Any]]:
        """Consulta VirusTotal API."""
        try:
            headers = {"X-Apikey": self.api_key}
            url = f"{self.api_base_url}/vt/v2/ip-address/report"
            
            response = requests.get(
                url,
                params={"ip": observable},
                headers=headers,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            data = response.json()
            return {
                "malicious_detections": data.get("positives", 0),
                "total_scans": data.get("total", 0),
                "last_scan": data.get("scan_date"),
                "categories": data.get("categories", {})
            }
        except Exception as e:
            self.get_param("debug", False) and print(f"Erro VirusTotal: {e}")
            return None
    
    def _query_abuseipdb(self, observable: str) -> Optional[Dict[str, Any]]:
        """Consulta AbuseIPDB API."""
        try:
            headers = {"Key": self.api_key}
            url = f"{self.api_base_url}/abuseipdb/v2/check"
            
            response = requests.get(
                url,
                params={"ipAddress": observable, "maxAgeInDays": 90},
                headers=headers,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            data = response.json()
            return {
                "abuse_confidence": data.get("data", {}).get("abuseConfidencePercentage", 0),
                "country": data.get("data", {}).get("countryCode"),
                "usage_type": data.get("data", {}).get("usageType"),
                "last_reported": data.get("data", {}).get("lastReportedAt")
            }
        except Exception as e:
            self.get_param("debug", False) and print(f"Erro AbuseIPDB: {e}")
            return None
    
    def _consolidate_verdict(self, sources: Dict[str, Any]) -> str:
        """Consolida vereditos de múltiplas fontes."""
        malicious_score = 0
        total_sources = 0
        
        # VirusTotal
        if "virustotal" in sources:
            vt = sources["virustotal"]
            if vt["total_scans"] > 0:
                malicious_score += (vt["malicious_detections"] / vt["total_scans"]) * 100
                total_sources += 1
        
        # AbuseIPDB
        if "abuseipdb" in sources:
            abuse = sources["abuseipdb"]
            malicious_score += abuse["abuse_confidence"]
            total_sources += 1
        
        if total_sources == 0:
            return "unknown"
        
        avg_score = malicious_score / total_sources
        
        if avg_score >= 70:
            return "malicious"
        elif avg_score >= 30:
            return "suspicious"
        else:
            return "safe"
```

## Processamento Assíncrono

### Análise Assíncrona com asyncio

```python
from __future__ import annotations
import asyncio
import aiohttp
from typing import List, Dict, Any
from sentineliqsdk import Analyzer, WorkerInput

class AsyncAnalyzer(Analyzer):
    """Analisador que executa consultas assíncronas."""
    
    def __init__(self, input_data: WorkerInput | Dict[str, Any]):
        super().__init__(input_data)
        self.session = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    def run(self) -> None:
        """Executa análise assíncrona."""
        asyncio.run(self._async_run())
    
    async def _async_run(self) -> None:
        """Lógica principal assíncrona."""
        async with self:
            observable = self.get_data()
            
            # Executar múltiplas consultas em paralelo
            tasks = [
                self._query_source_1(observable),
                self._query_source_2(observable),
                self._query_source_3(observable)
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Processar resultados
            processed_results = []
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    processed_results.append({
                        "source": f"source_{i+1}",
                        "error": str(result),
                        "success": False
                    })
                else:
                    processed_results.append({
                        "source": f"source_{i+1}",
                        "result": result,
                        "success": True
                    })
            
            self.report({
                "observable": observable,
                "results": processed_results,
                "summary": self._summarize_results(processed_results)
            })
    
    async def _query_source_1(self, observable: str) -> Dict[str, Any]:
        """Consulta fonte 1."""
        # Simular consulta assíncrona
        await asyncio.sleep(0.5)
        return {"verdict": "safe", "confidence": 0.8}
    
    async def _query_source_2(self, observable: str) -> Dict[str, Any]:
        """Consulta fonte 2."""
        # Simular consulta assíncrona
        await asyncio.sleep(0.3)
        return {"verdict": "suspicious", "confidence": 0.6}
    
    async def _query_source_3(self, observable: str) -> Dict[str, Any]:
        """Consulta fonte 3."""
        # Simular consulta assíncrona
        await asyncio.sleep(0.7)
        return {"verdict": "safe", "confidence": 0.9}
    
    def _summarize_results(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Resume os resultados das consultas."""
        successful = [r for r in results if r["success"]]
        verdicts = [r["result"]["verdict"] for r in successful if "result" in r]
        
        return {
            "total_queries": len(results),
            "successful_queries": len(successful),
            "verdict_distribution": {
                "safe": verdicts.count("safe"),
                "suspicious": verdicts.count("suspicious"),
                "malicious": verdicts.count("malicious")
            }
        }
```

## Cache e Otimização

### Sistema de Cache Inteligente

```python
from __future__ import annotations
import json
import hashlib
import time
from typing import Dict, Any, Optional
from sentineliqsdk import Analyzer, WorkerInput

class CachedAnalyzer(Analyzer):
    """Analisador com sistema de cache para otimizar consultas repetidas."""
    
    def __init__(self, input_data: WorkerInput | Dict[str, Any]):
        super().__init__(input_data)
        self.cache_ttl = self.get_param("cache_ttl", 3600)  # 1 hora
        self.cache_file = self.get_param("cache_file", "/tmp/analyzer_cache.json")
        self.cache = self._load_cache()
    
    def run(self) -> None:
        observable = self.get_data()
        
        # Verificar cache primeiro
        cached_result = self._get_cached_result(observable)
        if cached_result:
            self.report({
                "observable": observable,
                "result": cached_result,
                "cached": True,
                "cache_age": cached_result.get("cache_age", 0)
            })
            return
        
        # Executar análise se não estiver em cache
        result = self._perform_analysis(observable)
        result["cached"] = False
        result["timestamp"] = time.time()
        
        # Salvar no cache
        self._cache_result(observable, result)
        
        self.report({
            "observable": observable,
            "result": result
        })
    
    def _load_cache(self) -> Dict[str, Any]:
        """Carrega cache do arquivo."""
        try:
            with open(self.cache_file, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}
    
    def _save_cache(self) -> None:
        """Salva cache no arquivo."""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f)
        except Exception as e:
            print(f"Erro ao salvar cache: {e}")
    
    def _get_cache_key(self, observable: str) -> str:
        """Gera chave única para o cache."""
        return hashlib.md5(observable.encode()).hexdigest()
    
    def _get_cached_result(self, observable: str) -> Optional[Dict[str, Any]]:
        """Recupera resultado do cache se ainda válido."""
        cache_key = self._get_cache_key(observable)
        
        if cache_key not in self.cache:
            return None
        
        cached_data = self.cache[cache_key]
        timestamp = cached_data.get("timestamp", 0)
        
        # Verificar se ainda é válido
        if time.time() - timestamp > self.cache_ttl:
            # Remover do cache se expirado
            del self.cache[cache_key]
            self._save_cache()
            return None
        
        # Calcular idade do cache
        cached_data["cache_age"] = int(time.time() - timestamp)
        return cached_data
    
    def _cache_result(self, observable: str, result: Dict[str, Any]) -> None:
        """Salva resultado no cache."""
        cache_key = self._get_cache_key(observable)
        self.cache[cache_key] = result
        self._save_cache()
    
    def _perform_analysis(self, observable: str) -> Dict[str, Any]:
        """Executa análise real (simulada aqui)."""
        # Simular análise demorada
        time.sleep(1)
        
        return {
            "verdict": "malicious" if observable == "1.2.3.4" else "safe",
            "confidence": 0.85,
            "analysis_time": 1.0
        }
```

## Monitoramento e Métricas

### Sistema de Métricas Personalizado

```python
from __future__ import annotations
import time
import psutil
from typing import Dict, Any
from sentineliqsdk import Analyzer, WorkerInput

class MetricsAnalyzer(Analyzer):
    """Analisador com coleta de métricas detalhadas."""
    
    def __init__(self, input_data: WorkerInput | Dict[str, Any]):
        super().__init__(input_data)
        self.start_time = time.time()
        self.metrics = {
            "performance": {},
            "system": {},
            "analysis": {}
        }
    
    def run(self) -> None:
        observable = self.get_data()
        
        # Coletar métricas do sistema
        self._collect_system_metrics()
        
        # Executar análise com medição de performance
        analysis_start = time.time()
        result = self._perform_analysis(observable)
        analysis_time = time.time() - analysis_start
        
        # Coletar métricas de performance
        self._collect_performance_metrics(analysis_time)
        
        # Coletar métricas de análise
        self._collect_analysis_metrics(result)
        
        self.report({
            "observable": observable,
            "result": result,
            "metrics": self.metrics
        })
    
    def _collect_system_metrics(self) -> None:
        """Coleta métricas do sistema."""
        self.metrics["system"] = {
            "cpu_percent": psutil.cpu_percent(),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_usage": psutil.disk_usage('/').percent,
            "load_average": psutil.getloadavg()[0] if hasattr(psutil, 'getloadavg') else None
        }
    
    def _collect_performance_metrics(self, analysis_time: float) -> None:
        """Coleta métricas de performance."""
        total_time = time.time() - self.start_time
        
        self.metrics["performance"] = {
            "analysis_time": analysis_time,
            "total_time": total_time,
            "overhead_time": total_time - analysis_time,
            "efficiency": analysis_time / total_time if total_time > 0 else 0
        }
    
    def _collect_analysis_metrics(self, result: Dict[str, Any]) -> None:
        """Coleta métricas específicas da análise."""
        self.metrics["analysis"] = {
            "verdict": result.get("verdict"),
            "confidence": result.get("confidence", 0),
            "sources_consulted": result.get("sources_consulted", 0),
            "cache_hit": result.get("cached", False)
        }
    
    def _perform_analysis(self, observable: str) -> Dict[str, Any]:
        """Executa análise com coleta de métricas."""
        # Simular consulta a múltiplas fontes
        sources_consulted = 0
        
        # Fonte 1
        time.sleep(0.1)
        sources_consulted += 1
        
        # Fonte 2
        time.sleep(0.2)
        sources_consulted += 1
        
        # Fonte 3
        time.sleep(0.1)
        sources_consulted += 1
        
        return {
            "verdict": "malicious" if observable == "1.2.3.4" else "safe",
            "confidence": 0.9,
            "sources_consulted": sources_consulted
        }
```

## Conclusão

Estes recursos avançados permitem criar analisadores mais robustos, eficientes e integrados com sistemas externos. Use-os conforme necessário para atender aos requisitos específicos do seu ambiente de segurança.
