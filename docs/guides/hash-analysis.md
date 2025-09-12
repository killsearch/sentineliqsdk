# Hash Analysis Guide

## Visão Geral

Este guia aborda as melhores práticas para análise de hashes no SentinelIQ SDK, incluindo tipos de hash suportados, técnicas de análise e integração com serviços de threat intelligence.

## Tipos de Hash Suportados

### Hashes Criptográficos

#### MD5
- **Tamanho**: 32 caracteres hexadecimais
- **Uso**: Identificação rápida de arquivos
- **Limitações**: Vulnerável a colisões
- **Exemplo**: `d41d8cd98f00b204e9800998ecf8427e`

#### SHA-1
- **Tamanho**: 40 caracteres hexadecimais
- **Uso**: Identificação mais segura que MD5
- **Limitações**: Considerado obsoleto para segurança
- **Exemplo**: `da39a3ee5e6b4b0d3255bfef95601890afd80709`

#### SHA-256
- **Tamanho**: 64 caracteres hexadecimais
- **Uso**: Padrão atual para identificação segura
- **Vantagens**: Resistente a colisões
- **Exemplo**: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`

### Hashes Especializados

#### SSDEEP (Fuzzy Hash)
- **Uso**: Detecção de similaridade entre arquivos
- **Vantagens**: Identifica variantes de malware
- **Exemplo**: `3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C`

#### TLSH (Trend Locality Sensitive Hash)
- **Uso**: Análise de similaridade robusta
- **Vantagens**: Resistente a pequenas modificações
- **Exemplo**: `6FF02BEF718027B0160B4391212923ED7F6A463D563B1549B86CF62973B197AD2731F8`

## Detecção Automática de Hashes

### Extrator de Hash

O SentinelIQ SDK detecta automaticamente hashes em dados de entrada:

```python
from sentineliqsdk.extractors import Extractor

# Extração automática
text = "Arquivo suspeito: d41d8cd98f00b204e9800998ecf8427e"
extracted = Extractor.extract(text)

# Resultado
# {
#     "hash": ["d41d8cd98f00b204e9800998ecf8427e"]
# }
```

### Padrões de Detecção

```python
# Padrões regex para diferentes tipos de hash
HASH_PATTERNS = {
    "md5": r"\b[a-fA-F0-9]{32}\b",
    "sha1": r"\b[a-fA-F0-9]{40}\b", 
    "sha256": r"\b[a-fA-F0-9]{64}\b",
    "ssdeep": r"\b\d+:[A-Za-z0-9+/]+:[A-Za-z0-9+/]+\b"
}
```

## Desenvolvimento de Hash Analyzers

### Estrutura Básica

```python
from sentineliqsdk import Analyzer, WorkerInput, WorkerConfig
from sentineliqsdk.models import AnalyzerReport, ModuleMetadata
import hashlib

class HashAnalyzer(Analyzer):
    METADATA = ModuleMetadata(
        name="Hash Analyzer",
        description="Análise de hashes de arquivos",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="threat-intel",
        doc_pattern="Página de módulo MkDocs; uso programático",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/analyzers/hash/",
        version_stage="TESTING",
    )

    def execute(self) -> AnalyzerReport:
        hash_value = self.get_data()
        
        # Identificar tipo de hash
        hash_type = self.identify_hash_type(hash_value)
        
        # Análise específica por tipo
        result = self.analyze_hash(hash_value, hash_type)
        
        # Construir taxonomia
        taxonomy = self.build_taxonomy(
            level=result["verdict"],
            namespace="file",
            predicate="hash",
            value=hash_value
        )
        
        full_report = {
            "observable": hash_value,
            "hash_type": hash_type,
            "verdict": result["verdict"],
            "taxonomy": [taxonomy.to_dict()],
            "analysis": result["details"],
            "metadata": self.METADATA.to_dict()
        }
        
        return self.report(full_report)
    
    def identify_hash_type(self, hash_value: str) -> str:
        """Identifica o tipo de hash baseado no comprimento."""
        length = len(hash_value)
        
        if length == 32:
            return "md5"
        elif length == 40:
            return "sha1"
        elif length == 64:
            return "sha256"
        else:
            return "unknown"
    
    def analyze_hash(self, hash_value: str, hash_type: str) -> dict:
        """Realiza análise do hash."""
        # Implementar lógica de análise específica
        pass
```

### Validação de Hashes

```python
def validate_hash(self, hash_value: str, hash_type: str) -> bool:
    """Valida formato do hash."""
    import re
    
    patterns = {
        "md5": r"^[a-fA-F0-9]{32}$",
        "sha1": r"^[a-fA-F0-9]{40}$",
        "sha256": r"^[a-fA-F0-9]{64}$"
    }
    
    if hash_type not in patterns:
        return False
    
    return bool(re.match(patterns[hash_type], hash_value))

def normalize_hash(self, hash_value: str) -> str:
    """Normaliza hash para lowercase."""
    return hash_value.lower().strip()
```

## Integração com Serviços de TI

### VirusTotal Integration

```python
class VirusTotalHashAnalyzer(Analyzer):
    def analyze_hash(self, hash_value: str) -> dict:
        api_key = self.get_secret("virustotal.api_key", "VirusTotal API key obrigatória")
        
        url = f"https://www.virustotal.com/vtapi/v2/file/report"
        params = {
            "apikey": api_key,
            "resource": hash_value
        }
        
        response = requests.get(url, params=params)
        data = response.json()
        
        if data["response_code"] == 1:
            positives = data["positives"]
            total = data["total"]
            
            if positives > 0:
                verdict = "malicious"
            else:
                verdict = "safe"
            
            return {
                "verdict": verdict,
                "details": {
                    "positives": positives,
                    "total": total,
                    "scan_date": data["scan_date"],
                    "permalink": data["permalink"]
                }
            }
        else:
            return {
                "verdict": "info",
                "details": {"message": "Hash não encontrado"}
            }
```

### Hybrid Analysis Integration

```python
class HybridAnalysisHashAnalyzer(Analyzer):
    def analyze_hash(self, hash_value: str) -> dict:
        api_key = self.get_secret("hybrid_analysis.api_key")
        
        headers = {
            "api-key": api_key,
            "user-agent": "SentinelIQ SDK"
        }
        
        url = f"https://www.hybrid-analysis.com/api/v2/search/hash"
        data = {"hash": hash_value}
        
        response = requests.post(url, headers=headers, data=data)
        results = response.json()
        
        if results:
            # Processar resultados
            threat_score = max([r.get("threat_score", 0) for r in results])
            
            if threat_score >= 70:
                verdict = "malicious"
            elif threat_score >= 30:
                verdict = "suspicious"
            else:
                verdict = "safe"
            
            return {
                "verdict": verdict,
                "details": {
                    "threat_score": threat_score,
                    "submissions": len(results)
                }
            }
```

## Análise de Similaridade

### SSDEEP Comparison

```python
import ssdeep

class SSDeepAnalyzer(Analyzer):
    def compare_hashes(self, hash1: str, hash2: str) -> int:
        """Compara dois hashes SSDEEP."""
        try:
            return ssdeep.compare(hash1, hash2)
        except Exception:
            return 0
    
    def find_similar_samples(self, target_hash: str, known_hashes: list) -> list:
        """Encontra amostras similares."""
        similarities = []
        
        for known_hash in known_hashes:
            similarity = self.compare_hashes(target_hash, known_hash)
            if similarity > 50:  # Threshold de similaridade
                similarities.append({
                    "hash": known_hash,
                    "similarity": similarity
                })
        
        return sorted(similarities, key=lambda x: x["similarity"], reverse=True)
```

### TLSH Analysis

```python
import tlsh

class TLSHAnalyzer(Analyzer):
    def calculate_distance(self, hash1: str, hash2: str) -> int:
        """Calcula distância entre hashes TLSH."""
        try:
            return tlsh.diff(hash1, hash2)
        except Exception:
            return 999  # Máxima distância em caso de erro
    
    def is_similar(self, hash1: str, hash2: str, threshold: int = 100) -> bool:
        """Verifica se dois hashes são similares."""
        distance = self.calculate_distance(hash1, hash2)
        return distance <= threshold
```

## Caching e Performance

### Cache de Resultados

```python
import hashlib
from functools import lru_cache

class CachedHashAnalyzer(Analyzer):
    @lru_cache(maxsize=1000)
    def analyze_hash_cached(self, hash_value: str) -> dict:
        """Análise com cache para melhor performance."""
        return self.analyze_hash_internal(hash_value)
    
    def analyze_hash_internal(self, hash_value: str) -> dict:
        """Implementação real da análise."""
        # Lógica de análise aqui
        pass
```

### Batch Processing

```python
class BatchHashAnalyzer(Analyzer):
    def analyze_multiple_hashes(self, hashes: list) -> dict:
        """Analisa múltiplos hashes em batch."""
        results = {}
        
        # Processar em lotes para APIs que suportam
        batch_size = 25
        for i in range(0, len(hashes), batch_size):
            batch = hashes[i:i + batch_size]
            batch_results = self.process_hash_batch(batch)
            results.update(batch_results)
        
        return results
    
    def process_hash_batch(self, hash_batch: list) -> dict:
        """Processa um lote de hashes."""
        # Implementar chamada batch para API
        pass
```

## Tratamento de Erros

### Validação e Sanitização

```python
def sanitize_hash(self, hash_value: str) -> str:
    """Sanitiza e valida hash de entrada."""
    # Remover espaços e caracteres especiais
    cleaned = re.sub(r'[^a-fA-F0-9]', '', hash_value)
    
    # Converter para lowercase
    cleaned = cleaned.lower()
    
    # Validar comprimento
    valid_lengths = [32, 40, 64]  # MD5, SHA1, SHA256
    if len(cleaned) not in valid_lengths:
        raise ValueError(f"Hash inválido: comprimento {len(cleaned)}")
    
    return cleaned

def handle_api_errors(self, response) -> dict:
    """Trata erros de API de forma consistente."""
    if response.status_code == 429:
        # Rate limit
        return {"verdict": "info", "error": "Rate limit excedido"}
    elif response.status_code == 404:
        # Hash não encontrado
        return {"verdict": "info", "message": "Hash não encontrado"}
    elif response.status_code >= 500:
        # Erro do servidor
        return {"verdict": "info", "error": "Erro no serviço externo"}
    else:
        response.raise_for_status()
```

## Exemplo Completo

```python
from sentineliqsdk import Analyzer
from sentineliqsdk.models import AnalyzerReport, ModuleMetadata
import requests
import re

class ComprehensiveHashAnalyzer(Analyzer):
    METADATA = ModuleMetadata(
        name="Comprehensive Hash Analyzer",
        description="Análise completa de hashes com múltiplas fontes",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="threat-intel",
        doc_pattern="Página de módulo MkDocs; uso programático",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/analyzers/hash/",
        version_stage="STABLE",
    )

    def execute(self) -> AnalyzerReport:
        hash_value = self.get_data()
        
        try:
            # Sanitizar e validar hash
            clean_hash = self.sanitize_hash(hash_value)
            hash_type = self.identify_hash_type(clean_hash)
            
            # Análise multi-fonte
            results = self.multi_source_analysis(clean_hash)
            
            # Determinar veredito final
            final_verdict = self.determine_final_verdict(results)
            
            # Construir taxonomia
            taxonomy = self.build_taxonomy(
                level=final_verdict,
                namespace="file",
                predicate="hash",
                value=clean_hash
            )
            
            full_report = {
                "observable": clean_hash,
                "hash_type": hash_type,
                "verdict": final_verdict,
                "taxonomy": [taxonomy.to_dict()],
                "sources": results,
                "metadata": self.METADATA.to_dict()
            }
            
            return self.report(full_report)
            
        except Exception as e:
            self.logger.error(f"Erro na análise de hash: {e}")
            return self.report({
                "observable": hash_value,
                "verdict": "info",
                "error": str(e),
                "metadata": self.METADATA.to_dict()
            })
    
    def multi_source_analysis(self, hash_value: str) -> dict:
        """Análise usando múltiplas fontes."""
        results = {}
        
        # VirusTotal
        try:
            results["virustotal"] = self.check_virustotal(hash_value)
        except Exception as e:
            results["virustotal"] = {"error": str(e)}
        
        # Outras fontes...
        
        return results
    
    def determine_final_verdict(self, results: dict) -> str:
        """Determina veredito final baseado em múltiplas fontes."""
        verdicts = []
        
        for source, result in results.items():
            if "verdict" in result:
                verdicts.append(result["verdict"])
        
        # Lógica de consenso
        if "malicious" in verdicts:
            return "malicious"
        elif "suspicious" in verdicts:
            return "suspicious"
        elif "safe" in verdicts:
            return "safe"
        else:
            return "info"
```

## Veja Também

- [Building Analyzers](../tutorials/building-analyzers.md)
- [Taxonomy](../core/taxonomy.md)
- [File Processing](../tutorials/file-processing.md)
- [Threat Intelligence](threat-intelligence.md)