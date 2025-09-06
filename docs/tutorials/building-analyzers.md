---
title: Building Analyzers
---

# Building Analyzers

This comprehensive guide covers everything you need to know about building sophisticated analyzers with the SentinelIQ SDK. From basic concepts to advanced patterns, you'll learn how to create production-ready analyzers.

## Table of Contents

- [Analyzer Fundamentals](#analyzer-fundamentals)
- [Input Handling](#input-handling)
- [Analysis Patterns](#analysis-patterns)
- [Output Formatting](#output-formatting)
- [Error Handling](#error-handling)
- [Performance Optimization](#performance-optimization)
- [Testing Strategies](#testing-strategies)
- [Advanced Features](#advanced-features)

## Analyzer Fundamentals

### What is an Analyzer?

An analyzer is a specialized worker that examines observables (IPs, URLs, files, etc.) and provides intelligence about their nature, threat level, and characteristics. Analyzers are the core of threat intelligence and security analysis.

### Key Characteristics

- **Input**: Observables (IPs, URLs, domains, files, hashes)
- **Output**: Structured analysis reports with verdicts, taxonomy, and artifacts
- **Purpose**: Intelligence gathering and threat assessment
- **Auto-extraction**: Automatically finds additional IOCs in reports

### Basic Structure

```python
from sentineliqsdk import Analyzer

class MyAnalyzer(Analyzer):
    def run(self) -> None:
        # 1. Get input data
        observable = self.get_data()
        
        # 2. Perform analysis
        result = self._analyze(observable)
        
        # 3. Build report
        report = self._build_report(observable, result)
        
        # 4. Output results
        self.report(report)
```

## Input Handling

### Supported Data Types

The SDK supports various observable types:

```python
# IP addresses
input_data = {"dataType": "ip", "data": "192.168.1.1"}

# URLs
input_data = {"dataType": "url", "data": "https://example.com"}

# Domains
input_data = {"dataType": "domain", "data": "example.com"}

# File hashes
input_data = {"dataType": "hash", "data": "a1b2c3d4e5f6..."}

# Files
input_data = {"dataType": "file", "filename": "malware.exe"}
```

### Handling Different Input Types

```python
def run(self) -> None:
    observable = self.get_data()
    data_type = self.data_type
    
    if data_type == "ip":
        result = self._analyze_ip(observable)
    elif data_type == "url":
        result = self._analyze_url(observable)
    elif data_type == "file":
        file_path = self.get_param("file")
        result = self._analyze_file(file_path)
    else:
        self.error(f"Unsupported data type: {data_type}")
    
    self.report(result)
```

### File Processing

For file-based analysis:

```python
def run(self) -> None:
    if self.data_type == "file":
        # Get file path
        file_path = self.get_param("file")
        
        # Validate file exists
        if not os.path.exists(file_path):
            self.error(f"File not found: {file_path}")
        
        # Analyze file
        result = self._analyze_file(file_path)
    else:
        # Analyze direct input
        observable = self.get_data()
        result = self._analyze_observable(observable)
    
    self.report(result)
```

## Analysis Patterns

### 1. Reputation-Based Analysis

Check against known threat intelligence:

```python
def _analyze_reputation(self, observable: str) -> dict:
    """Analyze observable against reputation databases."""
    # Load threat intelligence
    blacklist = self._load_blacklist()
    whitelist = self._load_whitelist()
    
    if observable in blacklist:
        return {
            "verdict": "malicious",
            "confidence": "high",
            "source": "blacklist"
        }
    elif observable in whitelist:
        return {
            "verdict": "safe",
            "confidence": "high",
            "source": "whitelist"
        }
    else:
        return {
            "verdict": "unknown",
            "confidence": "low",
            "source": "none"
        }
```

### 2. Behavioral Analysis

Analyze patterns and behaviors:

```python
def _analyze_behavior(self, observable: str) -> dict:
    """Analyze behavioral patterns."""
    patterns = {
        "suspicious_domain": self._check_domain_patterns(observable),
        "recent_registration": self._check_registration_date(observable),
        "dga_likelihood": self._check_dga_patterns(observable),
        "typosquatting": self._check_typosquatting(observable)
    }
    
    # Calculate behavioral score
    suspicious_count = sum(patterns.values())
    if suspicious_count >= 3:
        verdict = "suspicious"
    elif suspicious_count >= 1:
        verdict = "unknown"
    else:
        verdict = "safe"
    
    return {
        "verdict": verdict,
        "patterns": patterns,
        "behavioral_score": suspicious_count / len(patterns)
    }
```

### 3. Multi-Source Analysis

Combine multiple analysis sources:

```python
def _analyze_multi_source(self, observable: str) -> dict:
    """Combine multiple analysis sources."""
    sources = {
        "reputation": self._analyze_reputation(observable),
        "behavior": self._analyze_behavior(observable),
        "network": self._analyze_network(observable),
        "temporal": self._analyze_temporal(observable)
    }
    
    # Weighted scoring
    weights = {
        "reputation": 0.4,
        "behavior": 0.3,
        "network": 0.2,
        "temporal": 0.1
    }
    
    # Calculate final verdict
    total_score = sum(
        self._verdict_to_score(source["verdict"]) * weights[name]
        for name, source in sources.items()
    )
    
    if total_score >= 0.7:
        verdict = "malicious"
    elif total_score >= 0.4:
        verdict = "suspicious"
    else:
        verdict = "safe"
    
    return {
        "verdict": verdict,
        "confidence": self._calculate_confidence(sources),
        "sources": sources,
        "total_score": total_score
    }
```

## Output Formatting

### Building Taxonomy

Create structured classification:

```python
def _build_taxonomy(self, analysis: dict) -> list[dict]:
    """Build taxonomy entries from analysis."""
    taxonomy = []
    
    # Main verdict
    taxonomy.append(
        self.build_taxonomy(
            level=analysis["verdict"],
            namespace="reputation",
            predicate="overall",
            value=analysis["confidence"]
        )
    )
    
    # Specific findings
    if analysis.get("malware_family"):
        taxonomy.append(
            self.build_taxonomy(
                level="malicious",
                namespace="malware",
                predicate="family",
                value=analysis["malware_family"]
            )
        )
    
    # Risk indicators
    if analysis.get("risk_indicators"):
        for indicator in analysis["risk_indicators"]:
            taxonomy.append(
                self.build_taxonomy(
                    level="info",
                    namespace="indicators",
                    predicate=indicator["type"],
                    value=indicator["value"]
                )
            )
    
    return taxonomy
```

### Creating Artifacts

Extract additional IOCs:

```python
def _build_artifacts(self, analysis: dict) -> list[dict]:
    """Build artifacts from analysis results."""
    artifacts = []
    
    # Extract IPs
    if analysis.get("related_ips"):
        for ip in analysis["related_ips"]:
            artifacts.append(
                self.build_artifact("ip", ip, tlp=2, extra={
                    "relationship": "related",
                    "confidence": "medium"
                })
            )
    
    # Extract domains
    if analysis.get("related_domains"):
        for domain in analysis["related_domains"]:
            artifacts.append(
                self.build_artifact("domain", domain, tlp=2, extra={
                    "relationship": "related",
                    "confidence": "medium"
                })
            )
    
    # Extract files
    if analysis.get("dropped_files"):
        for file_info in analysis["dropped_files"]:
            artifacts.append(
                self.build_artifact("file", file_info["path"], tlp=2, extra={
                    "hash": file_info["hash"],
                    "size": file_info["size"]
                })
            )
    
    return artifacts
```

### Defining Operations

Specify follow-up actions:

```python
def operations(self, raw: Any) -> list[dict]:
    """Define follow-up operations based on analysis."""
    operations = []
    
    if raw.get("verdict") == "malicious":
        # High priority hunt
        operations.append(
            self.build_operation(
                "hunt",
                query=f"observable:{raw['observable']}",
                priority="high",
                description="Hunt for related activity"
            )
        )
        
        # Enrich with threat intel
        operations.append(
            self.build_operation(
                "enrich",
                service="threat_intelligence",
                target=raw["observable"],
                priority="high"
            )
        )
    
    elif raw.get("verdict") == "suspicious":
        # Medium priority investigation
        operations.append(
            self.build_operation(
                "investigate",
                target=raw["observable"],
                priority="medium"
            )
        )
    
    # Always add monitoring for unknown verdicts
    if raw.get("verdict") == "unknown":
        operations.append(
            self.build_operation(
                "monitor",
                target=raw["observable"],
                duration="24h"
            )
        )
    
    return operations
```

## Error Handling

### Comprehensive Error Handling

```python
def run(self) -> None:
    """Main analysis with comprehensive error handling."""
    try:
        # Validate input
        self._validate_input()
        
        # Perform analysis
        result = self._perform_analysis()
        
        # Validate result
        self._validate_result(result)
        
        # Output result
        self.report(result)
        
    except ValidationError as e:
        self.error(f"Input validation failed: {str(e)}")
    except AnalysisError as e:
        self.error(f"Analysis failed: {str(e)}")
    except Exception as e:
        self.error(f"Unexpected error: {str(e)}")

def _validate_input(self) -> None:
    """Validate input data."""
    observable = self.get_data()
    
    if not observable:
        raise ValidationError("No observable provided")
    
    if self.data_type == "ip" and not self._is_valid_ip(observable):
        raise ValidationError(f"Invalid IP address: {observable}")
    
    if self.data_type == "url" and not self._is_valid_url(observable):
        raise ValidationError(f"Invalid URL: {observable}")

def _validate_result(self, result: dict) -> None:
    """Validate analysis result."""
    required_fields = ["verdict", "confidence", "observable"]
    
    for field in required_fields:
        if field not in result:
            raise AnalysisError(f"Missing required field: {field}")
    
    if result["verdict"] not in ["safe", "suspicious", "malicious", "unknown"]:
        raise AnalysisError(f"Invalid verdict: {result['verdict']}")
```

### Graceful Degradation

```python
def _analyze_with_fallback(self, observable: str) -> dict:
    """Analyze with fallback mechanisms."""
    try:
        # Try primary analysis method
        return self._primary_analysis(observable)
    except PrimaryAnalysisError:
        try:
            # Fallback to secondary method
            return self._secondary_analysis(observable)
        except SecondaryAnalysisError:
            # Final fallback
            return self._basic_analysis(observable)
```

## Performance Optimization

### Caching

Implement caching for expensive operations:

```python
import functools
from typing import Dict, Any

class CachedAnalyzer(Analyzer):
    def __init__(self, input_data):
        super().__init__(input_data)
        self._cache: Dict[str, Any] = {}
    
    @functools.lru_cache(maxsize=1000)
    def _expensive_analysis(self, observable: str) -> dict:
        """Cached expensive analysis operation."""
        # Expensive computation here
        return {"result": "analysis"}
    
    def _load_threat_intel(self) -> set[str]:
        """Load threat intelligence with caching."""
        cache_key = "threat_intel"
        
        if cache_key not in self._cache:
            # Load from database/API
            self._cache[cache_key] = self._fetch_threat_intel()
        
        return self._cache[cache_key]
```

### Async Operations

For I/O-bound operations:

```python
import asyncio
import aiohttp

class AsyncAnalyzer(Analyzer):
    async def _analyze_async(self, observable: str) -> dict:
        """Perform async analysis."""
        async with aiohttp.ClientSession() as session:
            tasks = [
                self._check_reputation_async(session, observable),
                self._check_behavior_async(session, observable),
                self._check_network_async(session, observable)
            ]
            
            results = await asyncio.gather(*tasks)
            return self._combine_results(results)
    
    def run(self) -> None:
        """Run async analysis."""
        observable = self.get_data()
        result = asyncio.run(self._analyze_async(observable))
        self.report(result)
```

### Batch Processing

Process multiple observables efficiently:

```python
def _analyze_batch(self, observables: list[str]) -> list[dict]:
    """Analyze multiple observables efficiently."""
    # Group by type for efficient processing
    grouped = self._group_by_type(observables)
    
    results = []
    for data_type, items in grouped.items():
        if data_type == "ip":
            batch_results = self._analyze_ip_batch(items)
        elif data_type == "url":
            batch_results = self._analyze_url_batch(items)
        else:
            batch_results = [self._analyze_single(item) for item in items]
        
        results.extend(batch_results)
    
    return results
```

## Testing Strategies

### Unit Testing

```python
import pytest
from unittest.mock import Mock, patch

class TestMyAnalyzer:
    def test_malicious_ip_analysis(self):
        """Test analysis of malicious IP."""
        input_data = {
            "dataType": "ip",
            "data": "1.2.3.4",
            "tlp": 2,
            "pap": 2
        }
        
        analyzer = MyAnalyzer(input_data)
        
        with patch.object(analyzer, '_load_threat_intel') as mock_load:
            mock_load.return_value = {"1.2.3.4"}
            
            result = analyzer._analyze_reputation("1.2.3.4")
            
            assert result["verdict"] == "malicious"
            assert result["confidence"] == "high"
    
    def test_safe_ip_analysis(self):
        """Test analysis of safe IP."""
        input_data = {
            "dataType": "ip",
            "data": "8.8.8.8",
            "tlp": 2,
            "pap": 2
        }
        
        analyzer = MyAnalyzer(input_data)
        
        with patch.object(analyzer, '_load_threat_intel') as mock_load:
            mock_load.return_value = set()
            
            result = analyzer._analyze_reputation("8.8.8.8")
            
            assert result["verdict"] == "unknown"
            assert result["confidence"] == "low"
    
    def test_error_handling(self):
        """Test error handling."""
        input_data = {
            "dataType": "ip",
            "data": "",
            "tlp": 2,
            "pap": 2
        }
        
        analyzer = MyAnalyzer(input_data)
        
        with pytest.raises(ValidationError):
            analyzer._validate_input()
```

### Integration Testing

```python
def test_full_analysis_workflow(self):
    """Test complete analysis workflow."""
    input_data = {
        "dataType": "url",
        "data": "https://malicious.com",
        "tlp": 2,
        "pap": 2,
        "config": {"auto_extract": True}
    }
    
    analyzer = MyAnalyzer(input_data)
    
    # Mock external dependencies
    with patch.object(analyzer, '_load_threat_intel') as mock_load:
        mock_load.return_value = {"malicious.com"}
        
        # Run analysis
        result = analyzer.report({
            "observable": "https://malicious.com",
            "verdict": "malicious",
            "confidence": "high"
        })
        
        # Verify output structure
        assert result["success"] is True
        assert result["full"]["verdict"] == "malicious"
        assert len(result["operations"]) > 0
```

### Performance Testing

```python
import time

def test_analysis_performance(self):
    """Test analysis performance."""
    input_data = {
        "dataType": "ip",
        "data": "1.2.3.4",
        "tlp": 2,
        "pap": 2
    }
    
    analyzer = MyAnalyzer(input_data)
    
    start_time = time.time()
    result = analyzer._analyze_reputation("1.2.3.4")
    end_time = time.time()
    
    # Should complete within 1 second
    assert (end_time - start_time) < 1.0
    assert result["verdict"] in ["safe", "suspicious", "malicious", "unknown"]
```

## Advanced Features

### Configuration Management

```python
def run(self) -> None:
    """Main analysis with configuration support."""
    # Get configuration
    config = self._get_analysis_config()
    
    # Adjust analysis based on configuration
    if config["strict_mode"]:
        result = self._strict_analysis()
    else:
        result = self._standard_analysis()
    
    # Apply confidence thresholds
    if result["confidence_score"] < config["min_confidence"]:
        result["verdict"] = "unknown"
    
    self.report(result)

def _get_analysis_config(self) -> dict:
    """Get analysis configuration."""
    return {
        "strict_mode": self.get_param("config.strict_mode", default=False),
        "min_confidence": self.get_param("config.min_confidence", default=0.7),
        "enable_behavioral": self.get_param("config.enable_behavioral", default=True),
        "enable_network": self.get_param("config.enable_network", default=True),
        "custom_rules": self.get_param("config.custom_rules", default=[])
    }
```

### Plugin Architecture

```python
class PluginAnalyzer(Analyzer):
    def __init__(self, input_data):
        super().__init__(input_data)
        self.plugins = self._load_plugins()
    
    def _load_plugins(self) -> list:
        """Load analysis plugins."""
        plugins = []
        
        # Load built-in plugins
        plugins.append(ReputationPlugin())
        plugins.append(BehavioralPlugin())
        
        # Load custom plugins
        custom_plugins = self.get_param("config.plugins", default=[])
        for plugin_config in custom_plugins:
            plugin = self._instantiate_plugin(plugin_config)
            plugins.append(plugin)
        
        return plugins
    
    def _analyze_with_plugins(self, observable: str) -> dict:
        """Analyze using all loaded plugins."""
        results = []
        
        for plugin in self.plugins:
            try:
                result = plugin.analyze(observable)
                results.append(result)
            except Exception as e:
                # Log error but continue with other plugins
                print(f"Plugin {plugin.name} failed: {e}")
        
        return self._combine_plugin_results(results)
```

### Metrics and Monitoring

```python
import time
from collections import defaultdict

class MetricsAnalyzer(Analyzer):
    def __init__(self, input_data):
        super().__init__(input_data)
        self.metrics = defaultdict(int)
        self.start_time = None
    
    def run(self) -> None:
        """Run analysis with metrics collection."""
        self.start_time = time.time()
        
        try:
            result = self._perform_analysis()
            self.metrics["successful_analyses"] += 1
        except Exception as e:
            self.metrics["failed_analyses"] += 1
            raise
        finally:
            self.metrics["total_analyses"] += 1
            self.metrics["analysis_time"] = time.time() - self.start_time
        
        self.report(result)
    
    def _perform_analysis(self) -> dict:
        """Perform analysis with timing."""
        start = time.time()
        
        # Analysis logic here
        result = {"verdict": "safe"}
        
        self.metrics["analysis_duration"] = time.time() - start
        return result
```

## Best Practices Summary

1. **Input Validation**: Always validate input data
2. **Error Handling**: Implement comprehensive error handling
3. **Configuration**: Support configuration parameters
4. **Testing**: Write comprehensive tests
5. **Performance**: Optimize for your use case
6. **Documentation**: Document your analyzer thoroughly
7. **Monitoring**: Add metrics and logging
8. **Security**: Handle sensitive data appropriately

## Next Steps

- [Building Responders](../tutorials/building-responders.md) - Learn about responders
- [File Processing](../tutorials/file-processing.md) - Advanced file analysis
- [Advanced Features](../tutorials/advanced-features.md) - Advanced techniques
- [Examples](../examples/threat-intelligence.md) - Real-world examples
