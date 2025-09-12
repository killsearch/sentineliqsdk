# Threat Intelligence Guide

## Visão Geral

Este guia aborda as melhores práticas para desenvolvimento de analyzers de threat intelligence no SentinelIQ SDK, incluindo integração com fontes de TI, análise de IOCs e construção de relatórios enriquecidos.

## Fundamentos de Threat Intelligence

### Tipos de Indicadores

#### Indicadores de Rede
- **IPs**: Endereços IPv4/IPv6 maliciosos
- **Domínios**: Domínios de comando e controle
- **URLs**: Links maliciosos e phishing
- **Certificados**: Certificados SSL suspeitos

#### Indicadores de Arquivo
- **Hashes**: MD5, SHA-1, SHA-256 de malware
- **Nomes**: Nomes de arquivos maliciosos
- **Caminhos**: Localizações típicas de malware

#### Indicadores de Email
- **Remetentes**: Endereços de email maliciosos
- **Assuntos**: Padrões de assunto de phishing
- **Anexos**: Tipos de arquivo perigosos

### Níveis de Confiança

```python
CONFIDENCE_LEVELS = {
    "high": 85,      # Alta confiança (>85%)
    "medium": 60,    # Média confiança (60-85%)
    "low": 30,       # Baixa confiança (30-60%)
    "unknown": 0     # Confiança desconhecida (<30%)
}
```

## Estrutura de Analyzer de TI

### Template Base

```python
from sentineliqsdk import Analyzer, WorkerInput, WorkerConfig
from sentineliqsdk.models import AnalyzerReport, ModuleMetadata
import requests
from datetime import datetime, timedelta

class ThreatIntelAnalyzer(Analyzer):
    METADATA = ModuleMetadata(
        name="Threat Intel Analyzer",
        description="Análise de threat intelligence",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="threat-intel",
        doc_pattern="Página de módulo MkDocs; uso programático",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/analyzers/threat_intel/",
        version_stage="TESTING",
    )

    def execute(self) -> AnalyzerReport:
        observable = self.get_data()
        
        # Obter configurações
        api_key = self.get_secret("threat_intel.api_key", "API key obrigatória")
        timeout = self.get_config("threat_intel.timeout", 30)
        
        # Análise de threat intelligence
        ti_result = self.analyze_threat_intel(observable, api_key, timeout)
        
        # Determinar veredito
        verdict = self.determine_verdict(ti_result)
        
        # Construir taxonomia
        taxonomy = self.build_taxonomy(
            level=verdict,
            namespace="threat-intel",
            predicate=ti_result.get("category", "reputation"),
            value=str(observable)
        )
        
        full_report = {
            "observable": observable,
            "verdict": verdict,
            "taxonomy": [taxonomy.to_dict()],
            "threat_intel": ti_result,
            "metadata": self.METADATA.to_dict()
        }
        
        return self.report(full_report)
    
    def analyze_threat_intel(self, observable: str, api_key: str, timeout: int) -> dict:
        """Realiza análise de threat intelligence."""
        # Implementar lógica específica
        pass
    
    def determine_verdict(self, ti_result: dict) -> str:
        """Determina veredito baseado nos resultados de TI."""
        confidence = ti_result.get("confidence", 0)
        threat_score = ti_result.get("threat_score", 0)
        
        if confidence >= 85 and threat_score >= 80:
            return "malicious"
        elif confidence >= 60 and threat_score >= 50:
            return "suspicious"
        elif confidence >= 30:
            return "safe"
        else:
            return "info"
```

## Integração com Fontes de TI

### VirusTotal Integration

```python
class VirusTotalAnalyzer(Analyzer):
    BASE_URL = "https://www.virustotal.com/vtapi/v2"
    
    def analyze_ip(self, ip: str) -> dict:
        """Analisa IP no VirusTotal."""
        api_key = self.get_secret("virustotal.api_key")
        
        url = f"{self.BASE_URL}/ip-address/report"
        params = {
            "apikey": api_key,
            "ip": ip
        }
        
        response = requests.get(url, params=params)
        data = response.json()
        
        if data["response_code"] == 1:
            detected_urls = data.get("detected_urls", [])
            detected_samples = data.get("detected_downloaded_samples", [])
            
            threat_score = min(100, len(detected_urls) * 10 + len(detected_samples) * 5)
            
            return {
                "source": "virustotal",
                "threat_score": threat_score,
                "confidence": 90 if threat_score > 0 else 70,
                "category": "malware" if threat_score > 50 else "reputation",
                "details": {
                    "detected_urls": len(detected_urls),
                    "detected_samples": len(detected_samples),
                    "country": data.get("country"),
                    "asn": data.get("asn")
                }
            }
        
        return {
            "source": "virustotal",
            "threat_score": 0,
            "confidence": 30,
            "message": "IP não encontrado"
        }
    
    def analyze_domain(self, domain: str) -> dict:
        """Analisa domínio no VirusTotal."""
        api_key = self.get_secret("virustotal.api_key")
        
        url = f"{self.BASE_URL}/domain/report"
        params = {
            "apikey": api_key,
            "domain": domain
        }
        
        response = requests.get(url, params=params)
        data = response.json()
        
        if data["response_code"] == 1:
            detected_urls = data.get("detected_urls", [])
            categories = data.get("categories", [])
            
            # Calcular score baseado em detecções
            threat_score = len(detected_urls) * 15
            
            # Ajustar baseado em categorias
            malicious_categories = ["malware", "phishing", "suspicious"]
            if any(cat in malicious_categories for cat in categories):
                threat_score += 30
            
            return {
                "source": "virustotal",
                "threat_score": min(100, threat_score),
                "confidence": 85,
                "category": "phishing" if "phishing" in categories else "malware",
                "details": {
                    "detected_urls": len(detected_urls),
                    "categories": categories,
                    "whois_date": data.get("whois_timestamp")
                }
            }
```

### AbuseIPDB Integration

```python
class AbuseIPDBAnalyzer(Analyzer):
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    
    def analyze_ip(self, ip: str) -> dict:
        """Analisa IP no AbuseIPDB."""
        api_key = self.get_secret("abuseipdb.api_key")
        
        headers = {
            "Key": api_key,
            "Accept": "application/json"
        }
        
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": ""
        }
        
        response = requests.get(
            f"{self.BASE_URL}/check",
            headers=headers,
            params=params
        )
        
        data = response.json()["data"]
        
        abuse_confidence = data.get("abuseConfidencePercentage", 0)
        usage_type = data.get("usageType", "unknown")
        
        return {
            "source": "abuseipdb",
            "threat_score": abuse_confidence,
            "confidence": 90 if abuse_confidence > 0 else 60,
            "category": "abuse",
            "details": {
                "abuse_confidence": abuse_confidence,
                "usage_type": usage_type,
                "country_code": data.get("countryCode"),
                "isp": data.get("isp"),
                "total_reports": data.get("totalReports", 0)
            }
        }
```

### Shodan Integration

```python
class ShodanAnalyzer(Analyzer):
    BASE_URL = "https://api.shodan.io"
    
    def analyze_ip(self, ip: str) -> dict:
        """Analisa IP no Shodan."""
        api_key = self.get_secret("shodan.api_key")
        
        url = f"{self.BASE_URL}/shodan/host/{ip}"
        params = {"key": api_key}
        
        try:
            response = requests.get(url, params=params)
            data = response.json()
            
            # Analisar serviços expostos
            ports = data.get("ports", [])
            vulns = data.get("vulns", [])
            
            # Calcular score de risco
            risk_score = 0
            
            # Portas de alto risco
            high_risk_ports = [22, 23, 135, 139, 445, 1433, 3389]
            risk_score += len([p for p in ports if p in high_risk_ports]) * 10
            
            # Vulnerabilidades
            risk_score += len(vulns) * 20
            
            return {
                "source": "shodan",
                "threat_score": min(100, risk_score),
                "confidence": 80,
                "category": "infrastructure",
                "details": {
                    "ports": ports,
                    "vulnerabilities": len(vulns),
                    "organization": data.get("org"),
                    "country": data.get("country_name"),
                    "last_update": data.get("last_update")
                }
            }
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                return {
                    "source": "shodan",
                    "threat_score": 0,
                    "confidence": 50,
                    "message": "IP não encontrado"
                }
            raise
```

## Análise Multi-Fonte

### Agregação de Resultados

```python
class MultiSourceTIAnalyzer(Analyzer):
    def execute(self) -> AnalyzerReport:
        observable = self.get_data()
        
        # Coletar dados de múltiplas fontes
        sources_results = self.collect_from_sources(observable)
        
        # Agregar resultados
        aggregated = self.aggregate_results(sources_results)
        
        # Determinar veredito final
        final_verdict = self.determine_consensus_verdict(aggregated)
        
        # Construir taxonomias múltiplas
        taxonomies = self.build_multiple_taxonomies(observable, aggregated)
        
        full_report = {
            "observable": observable,
            "verdict": final_verdict,
            "taxonomy": [t.to_dict() for t in taxonomies],
            "sources": sources_results,
            "aggregated": aggregated,
            "metadata": self.METADATA.to_dict()
        }
        
        return self.report(full_report)
    
    def collect_from_sources(self, observable: str) -> dict:
        """Coleta dados de múltiplas fontes."""
        results = {}
        
        # Lista de fontes configuradas
        sources = [
            ("virustotal", self.check_virustotal),
            ("abuseipdb", self.check_abuseipdb),
            ("shodan", self.check_shodan),
            ("otx", self.check_alienvault_otx)
        ]
        
        for source_name, check_function in sources:
            try:
                if self.is_source_enabled(source_name):
                    results[source_name] = check_function(observable)
            except Exception as e:
                self.logger.warning(f"Erro em {source_name}: {e}")
                results[source_name] = {"error": str(e)}
        
        return results
    
    def aggregate_results(self, sources_results: dict) -> dict:
        """Agrega resultados de múltiplas fontes."""
        threat_scores = []
        confidences = []
        categories = []
        
        for source, result in sources_results.items():
            if "error" not in result:
                threat_scores.append(result.get("threat_score", 0))
                confidences.append(result.get("confidence", 0))
                if "category" in result:
                    categories.append(result["category"])
        
        # Calcular médias ponderadas
        avg_threat_score = sum(threat_scores) / len(threat_scores) if threat_scores else 0
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0
        
        # Categoria mais comum
        most_common_category = max(set(categories), key=categories.count) if categories else "unknown"
        
        return {
            "average_threat_score": avg_threat_score,
            "average_confidence": avg_confidence,
            "most_common_category": most_common_category,
            "sources_count": len([r for r in sources_results.values() if "error" not in r]),
            "consensus_level": self.calculate_consensus(sources_results)
        }
    
    def determine_consensus_verdict(self, aggregated: dict) -> str:
        """Determina veredito baseado em consenso."""
        threat_score = aggregated["average_threat_score"]
        confidence = aggregated["average_confidence"]
        consensus = aggregated["consensus_level"]
        
        # Ajustar thresholds baseado no consenso
        if consensus >= 0.8:  # Alto consenso
            if threat_score >= 70:
                return "malicious"
            elif threat_score >= 40:
                return "suspicious"
            else:
                return "safe"
        elif consensus >= 0.5:  # Consenso médio
            if threat_score >= 80:
                return "malicious"
            elif threat_score >= 60:
                return "suspicious"
            else:
                return "info"
        else:  # Baixo consenso
            if threat_score >= 90:
                return "suspicious"  # Mais conservador
            else:
                return "info"
    
    def calculate_consensus(self, sources_results: dict) -> float:
        """Calcula nível de consenso entre fontes."""
        verdicts = []
        
        for result in sources_results.values():
            if "error" not in result:
                threat_score = result.get("threat_score", 0)
                if threat_score >= 70:
                    verdicts.append("malicious")
                elif threat_score >= 40:
                    verdicts.append("suspicious")
                else:
                    verdicts.append("safe")
        
        if not verdicts:
            return 0.0
        
        # Calcular consenso como proporção do veredito mais comum
        most_common = max(set(verdicts), key=verdicts.count)
        consensus = verdicts.count(most_common) / len(verdicts)
        
        return consensus
```

## Enriquecimento de Dados

### Contexto Geográfico

```python
def add_geolocation_context(self, ip: str, result: dict) -> dict:
    """Adiciona contexto geográfico."""
    try:
        # Usar serviço de geolocalização
        geo_data = self.get_geolocation(ip)
        
        result["geolocation"] = {
            "country": geo_data.get("country"),
            "region": geo_data.get("region"),
            "city": geo_data.get("city"),
            "coordinates": {
                "lat": geo_data.get("latitude"),
                "lon": geo_data.get("longitude")
            }
        }
        
        # Ajustar score baseado em país de risco
        high_risk_countries = ["CN", "RU", "KP", "IR"]
        if geo_data.get("country_code") in high_risk_countries:
            result["threat_score"] = min(100, result.get("threat_score", 0) + 10)
            result["risk_factors"] = result.get("risk_factors", []) + ["high_risk_country"]
        
    except Exception as e:
        self.logger.warning(f"Erro ao obter geolocalização: {e}")
    
    return result
```

### Contexto Temporal

```python
def add_temporal_context(self, result: dict) -> dict:
    """Adiciona contexto temporal."""
    now = datetime.utcnow()
    
    # Verificar se há dados recentes
    last_seen = result.get("last_seen")
    if last_seen:
        last_seen_dt = datetime.fromisoformat(last_seen)
        days_ago = (now - last_seen_dt).days
        
        result["temporal_context"] = {
            "last_seen_days_ago": days_ago,
            "recency_score": max(0, 100 - days_ago * 2)  # Decai 2 pontos por dia
        }
        
        # Ajustar threat score baseado na recência
        if days_ago <= 7:
            result["threat_score"] = min(100, result.get("threat_score", 0) + 15)
        elif days_ago <= 30:
            result["threat_score"] = min(100, result.get("threat_score", 0) + 5)
    
    return result
```

## Tratamento de Rate Limits

### Implementação de Backoff

```python
import time
from functools import wraps

def rate_limit_handler(max_retries=3, backoff_factor=2):
    """Decorator para lidar com rate limits."""
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(self, *args, **kwargs)
                except requests.exceptions.HTTPError as e:
                    if e.response.status_code == 429:  # Rate limit
                        if attempt < max_retries - 1:
                            wait_time = backoff_factor ** attempt
                            self.logger.warning(f"Rate limit hit, waiting {wait_time}s")
                            time.sleep(wait_time)
                            continue
                    raise
            return None
        return wrapper
    return decorator

class RateLimitedAnalyzer(Analyzer):
    @rate_limit_handler(max_retries=3)
    def call_external_api(self, endpoint: str, params: dict) -> dict:
        """Chama API externa com tratamento de rate limit."""
        response = requests.get(endpoint, params=params)
        response.raise_for_status()
        return response.json()
```

## Cache e Performance

### Cache de Resultados

```python
import redis
from datetime import timedelta
import json

class CachedTIAnalyzer(Analyzer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cache = redis.Redis(
            host=self.get_config("cache.host", "localhost"),
            port=self.get_config("cache.port", 6379),
            decode_responses=True
        )
        self.cache_ttl = self.get_config("cache.ttl", 3600)  # 1 hora
    
    def get_cached_result(self, observable: str, source: str) -> dict:
        """Obtém resultado do cache."""
        cache_key = f"ti:{source}:{observable}"
        cached = self.cache.get(cache_key)
        
        if cached:
            return json.loads(cached)
        return None
    
    def cache_result(self, observable: str, source: str, result: dict):
        """Armazena resultado no cache."""
        cache_key = f"ti:{source}:{observable}"
        self.cache.setex(
            cache_key,
            self.cache_ttl,
            json.dumps(result)
        )
    
    def analyze_with_cache(self, observable: str, source: str, analyze_func) -> dict:
        """Analisa com cache."""
        # Tentar cache primeiro
        cached_result = self.get_cached_result(observable, source)
        if cached_result:
            self.logger.debug(f"Cache hit for {source}:{observable}")
            return cached_result
        
        # Executar análise
        result = analyze_func(observable)
        
        # Armazenar no cache
        self.cache_result(observable, source, result)
        
        return result
```

## Veja Também

- [Building Analyzers](../tutorials/building-analyzers.md)
- [Hash Analysis](hash-analysis.md)
- [Taxonomy](../core/taxonomy.md)
- [WorkerConfig](../core/worker-config.md)
- [Examples](../examples/threat-intelligence.md)