---
title: Threat Intelligence Analyzer
---

# Threat Intelligence Analyzer

This example demonstrates how to build a comprehensive threat intelligence analyzer that integrates with multiple data sources and provides detailed threat assessment.

## Overview

The Threat Intelligence Analyzer combines multiple threat intelligence sources to provide comprehensive analysis of observables. It demonstrates:

- Integration with external APIs
- Multi-source threat intelligence
- Confidence scoring
- Taxonomy classification
- Artifact extraction
- Error handling and retry logic

## Implementation

```python
# threat_intelligence_analyzer.py
from __future__ import annotations

import asyncio
import aiohttp
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from sentineliqsdk import Analyzer, runner


@dataclass
class ThreatIntelligenceSource:
    """Configuration for a threat intelligence source."""
    name: str
    api_url: str
    api_key: str
    timeout: int = 30
    retry_attempts: int = 3
    weight: float = 1.0


class ThreatIntelligenceAnalyzer(Analyzer):
    """Comprehensive threat intelligence analyzer."""
    
    def __init__(self, input_data):
        super().__init__(input_data)
        self.sources = self._load_threat_intel_sources()
        self.cache = {}
        self.cache_ttl = 3600  # 1 hour
    
    def _load_threat_intel_sources(self) -> List[ThreatIntelligenceSource]:
        """Load threat intelligence source configurations."""
        sources = []
        
        # VirusTotal
        vt_api_key = self.get_param("config.virustotal_api_key")
        if vt_api_key:
            sources.append(ThreatIntelligenceSource(
                name="virustotal",
                api_url="https://www.virustotal.com/vtapi/v2",
                api_key=vt_api_key,
                weight=0.3
            ))
        
        # AbuseIPDB
        abuse_api_key = self.get_param("config.abuseipdb_api_key")
        if abuse_api_key:
            sources.append(ThreatIntelligenceSource(
                name="abuseipdb",
                api_url="https://api.abuseipdb.com/api/v2",
                api_key=abuse_api_key,
                weight=0.25
            ))
        
        # Shodan
        shodan_api_key = self.get_param("config.shodan_api_key")
        if shodan_api_key:
            sources.append(ThreatIntelligenceSource(
                name="shodan",
                api_url="https://api.shodan.io",
                api_key=shodan_api_key,
                weight=0.2
            ))
        
        # Custom internal source
        internal_api_key = self.get_param("config.internal_api_key")
        if internal_api_key:
            sources.append(ThreatIntelligenceSource(
                name="internal",
                api_url=self.get_param("config.internal_api_url"),
                api_key=internal_api_key,
                weight=0.25
            ))
        
        return sources
    
    def run(self) -> None:
        """Main analysis logic."""
        observable = self.get_data()
        data_type = self.data_type
        
        # Validate observable
        if not self._validate_observable(observable, data_type):
            self.error(f"Invalid {data_type}: {observable}")
        
        # Check cache first
        cache_key = f"{data_type}:{observable}"
        if self._is_cached(cache_key):
            cached_result = self.cache[cache_key]
            self.report(cached_result)
            return
        
        # Perform threat intelligence analysis
        try:
            analysis_result = asyncio.run(self._analyze_threat_intelligence(observable, data_type))
            
            # Cache the result
            self._cache_result(cache_key, analysis_result)
            
            # Report the result
            self.report(analysis_result)
            
        except Exception as e:
            self.error(f"Threat intelligence analysis failed: {str(e)}")
    
    def _validate_observable(self, observable: str, data_type: str) -> bool:
        """Validate the observable based on its type."""
        if data_type == "ip":
            return self._is_valid_ip(observable)
        elif data_type == "domain":
            return self._is_valid_domain(observable)
        elif data_type == "url":
            return self._is_valid_url(observable)
        elif data_type == "hash":
            return self._is_valid_hash(observable)
        else:
            return True  # Assume valid for other types
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format."""
        import ipaddress
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain format."""
        import re
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(pattern, domain))
    
    def _is_valid_url(self, url: str) -> bool:
        """Validate URL format."""
        from urllib.parse import urlparse
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    def _is_valid_hash(self, hash_str: str) -> bool:
        """Validate hash format."""
        import re
        # Check for MD5, SHA1, or SHA256
        if re.match(r'^[a-fA-F0-9]{32}$', hash_str):  # MD5
            return True
        elif re.match(r'^[a-fA-F0-9]{40}$', hash_str):  # SHA1
            return True
        elif re.match(r'^[a-fA-F0-9]{64}$', hash_str):  # SHA256
            return True
        return False
    
    async def _analyze_threat_intelligence(self, observable: str, data_type: str) -> Dict[str, Any]:
        """Perform threat intelligence analysis using multiple sources."""
        # Create analysis tasks for each source
        tasks = []
        for source in self.sources:
            task = self._query_threat_intel_source(source, observable, data_type)
            tasks.append(task)
        
        # Execute all queries in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        source_results = {}
        for i, result in enumerate(results):
            source_name = self.sources[i].name
            if isinstance(result, Exception):
                source_results[source_name] = {
                    "error": str(result),
                    "status": "failed"
                }
            else:
                source_results[source_name] = result
        
        # Combine results and determine final verdict
        combined_analysis = self._combine_threat_intel_results(observable, data_type, source_results)
        
        return combined_analysis
    
    async def _query_threat_intel_source(self, source: ThreatIntelligenceSource, observable: str, data_type: str) -> Dict[str, Any]:
        """Query a specific threat intelligence source."""
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=source.timeout)) as session:
            for attempt in range(source.retry_attempts):
                try:
                    if source.name == "virustotal":
                        return await self._query_virustotal(session, source, observable, data_type)
                    elif source.name == "abuseipdb":
                        return await self._query_abuseipdb(session, source, observable, data_type)
                    elif source.name == "shodan":
                        return await self._query_shodan(session, source, observable, data_type)
                    elif source.name == "internal":
                        return await self._query_internal(session, source, observable, data_type)
                    else:
                        return {"error": f"Unknown source: {source.name}", "status": "failed"}
                
                except asyncio.TimeoutError:
                    if attempt == source.retry_attempts - 1:
                        return {"error": "Timeout", "status": "failed"}
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                
                except Exception as e:
                    if attempt == source.retry_attempts - 1:
                        return {"error": str(e), "status": "failed"}
                    await asyncio.sleep(2 ** attempt)
    
    async def _query_virustotal(self, session: aiohttp.ClientSession, source: ThreatIntelligenceSource, observable: str, data_type: str) -> Dict[str, Any]:
        """Query VirusTotal API."""
        if data_type == "ip":
            url = f"{source.api_url}/ip-address/report"
            params = {"apikey": source.api_key, "ip": observable}
        elif data_type == "domain":
            url = f"{source.api_url}/domain/report"
            params = {"apikey": source.api_key, "domain": observable}
        elif data_type == "url":
            url = f"{source.api_url}/url/report"
            params = {"apikey": source.api_key, "resource": observable}
        elif data_type == "hash":
            url = f"{source.api_url}/file/report"
            params = {"apikey": source.api_key, "resource": observable}
        else:
            return {"error": f"Unsupported data type for VirusTotal: {data_type}", "status": "failed"}
        
        async with session.get(url, params=params) as response:
            if response.status == 200:
                data = await response.json()
                return self._parse_virustotal_response(data, data_type)
            else:
                return {"error": f"HTTP {response.status}", "status": "failed"}
    
    def _parse_virustotal_response(self, data: Dict[str, Any], data_type: str) -> Dict[str, Any]:
        """Parse VirusTotal API response."""
        if data.get("response_code") != 1:
            return {"error": "Not found in VirusTotal", "status": "not_found"}
        
        scans = data.get("scans", {})
        positives = data.get("positives", 0)
        total = data.get("total", 0)
        
        # Calculate detection ratio
        detection_ratio = positives / total if total > 0 else 0
        
        # Determine verdict based on detection ratio
        if detection_ratio >= 0.5:
            verdict = "malicious"
            confidence = "high"
        elif detection_ratio >= 0.1:
            verdict = "suspicious"
            confidence = "medium"
        else:
            verdict = "safe"
            confidence = "high"
        
        # Extract detection details
        detections = []
        for engine, result in scans.items():
            if result.get("detected"):
                detections.append({
                    "engine": engine,
                    "result": result.get("result", "Unknown"),
                    "version": result.get("version", "Unknown"),
                    "update": result.get("update", "Unknown")
                })
        
        return {
            "status": "success",
            "verdict": verdict,
            "confidence": confidence,
            "detection_ratio": detection_ratio,
            "positives": positives,
            "total": total,
            "detections": detections,
            "scan_date": data.get("scan_date"),
            "permalink": data.get("permalink")
        }
    
    async def _query_abuseipdb(self, session: aiohttp.ClientSession, source: ThreatIntelligenceSource, observable: str, data_type: str) -> Dict[str, Any]:
        """Query AbuseIPDB API."""
        if data_type != "ip":
            return {"error": f"AbuseIPDB only supports IP addresses, got: {data_type}", "status": "failed"}
        
        url = f"{source.api_url}/check"
        params = {
            "ipAddress": observable,
            "maxAgeInDays": 90,
            "verbose": ""
        }
        headers = {
            "Key": source.api_key,
            "Accept": "application/json"
        }
        
        async with session.get(url, params=params, headers=headers) as response:
            if response.status == 200:
                data = await response.json()
                return self._parse_abuseipdb_response(data)
            else:
                return {"error": f"HTTP {response.status}", "status": "failed"}
    
    def _parse_abuseipdb_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse AbuseIPDB API response."""
        if "data" not in data:
            return {"error": "Invalid response format", "status": "failed"}
        
        abuse_data = data["data"]
        abuse_confidence = abuse_data.get("abuseConfidencePercentage", 0)
        is_public = abuse_data.get("isPublic", False)
        is_whitelisted = abuse_data.get("isWhitelisted", False)
        usage_type = abuse_data.get("usageType", "Unknown")
        country_code = abuse_data.get("countryCode", "Unknown")
        
        # Determine verdict based on abuse confidence
        if is_whitelisted:
            verdict = "safe"
            confidence = "high"
        elif abuse_confidence >= 75:
            verdict = "malicious"
            confidence = "high"
        elif abuse_confidence >= 25:
            verdict = "suspicious"
            confidence = "medium"
        else:
            verdict = "safe"
            confidence = "low"
        
        return {
            "status": "success",
            "verdict": verdict,
            "confidence": confidence,
            "abuse_confidence": abuse_confidence,
            "is_public": is_public,
            "is_whitelisted": is_whitelisted,
            "usage_type": usage_type,
            "country_code": country_code,
            "total_reports": abuse_data.get("totalReports", 0),
            "distinct_users": abuse_data.get("numDistinctUsers", 0)
        }
    
    async def _query_shodan(self, session: aiohttp.ClientSession, source: ThreatIntelligenceSource, observable: str, data_type: str) -> Dict[str, Any]:
        """Query Shodan API."""
        if data_type not in ["ip", "domain"]:
            return {"error": f"Shodan only supports IP addresses and domains, got: {data_type}", "status": "failed"}
        
        url = f"{source.api_url}/shodan/host/{observable}"
        params = {"key": source.api_key}
        
        async with session.get(url, params=params) as response:
            if response.status == 200:
                data = await response.json()
                return self._parse_shodan_response(data, data_type)
            elif response.status == 404:
                return {"error": "Not found in Shodan", "status": "not_found"}
            else:
                return {"error": f"HTTP {response.status}", "status": "failed"}
    
    def _parse_shodan_response(self, data: Dict[str, Any], data_type: str) -> Dict[str, Any]:
        """Parse Shodan API response."""
        ip = data.get("ip_str", "Unknown")
        country = data.get("country_name", "Unknown")
        city = data.get("city", "Unknown")
        org = data.get("org", "Unknown")
        os = data.get("os", "Unknown")
        ports = data.get("ports", [])
        vulns = data.get("vulns", [])
        
        # Determine verdict based on vulnerabilities and open ports
        risk_score = 0
        if vulns:
            risk_score += len(vulns) * 2
        if len(ports) > 10:
            risk_score += 1
        if any(port in ports for port in [22, 23, 3389, 5900]):  # Common admin ports
            risk_score += 1
        
        if risk_score >= 5:
            verdict = "suspicious"
            confidence = "high"
        elif risk_score >= 2:
            verdict = "suspicious"
            confidence = "medium"
        else:
            verdict = "safe"
            confidence = "low"
        
        return {
            "status": "success",
            "verdict": verdict,
            "confidence": confidence,
            "ip": ip,
            "country": country,
            "city": city,
            "organization": org,
            "operating_system": os,
            "open_ports": ports,
            "vulnerabilities": vulns,
            "risk_score": risk_score
        }
    
    async def _query_internal(self, session: aiohttp.ClientSession, source: ThreatIntelligenceSource, observable: str, data_type: str) -> Dict[str, Any]:
        """Query internal threat intelligence source."""
        url = f"{source.api_url}/threat-intel/check"
        payload = {
            "observable": observable,
            "data_type": data_type
        }
        headers = {
            "Authorization": f"Bearer {source.api_key}",
            "Content-Type": "application/json"
        }
        
        async with session.post(url, json=payload, headers=headers) as response:
            if response.status == 200:
                data = await response.json()
                return {
                    "status": "success",
                    "verdict": data.get("verdict", "unknown"),
                    "confidence": data.get("confidence", "low"),
                    "source": "internal",
                    "details": data.get("details", {})
                }
            else:
                return {"error": f"HTTP {response.status}", "status": "failed"}
    
    def _combine_threat_intel_results(self, observable: str, data_type: str, source_results: Dict[str, Any]) -> Dict[str, Any]:
        """Combine results from multiple threat intelligence sources."""
        # Calculate weighted scores
        total_weight = 0
        weighted_score = 0
        successful_sources = 0
        all_verdicts = []
        all_confidences = []
        
        for source_name, result in source_results.items():
            if result.get("status") == "success":
                source_weight = next((s.weight for s in self.sources if s.name == source_name), 1.0)
                total_weight += source_weight
                successful_sources += 1
                
                # Convert verdict to numeric score
                verdict_score = self._verdict_to_score(result.get("verdict", "unknown"))
                weighted_score += verdict_score * source_weight
                
                all_verdicts.append(result.get("verdict", "unknown"))
                all_confidences.append(result.get("confidence", "low"))
        
        # Calculate final verdict
        if successful_sources == 0:
            final_verdict = "unknown"
            final_confidence = "low"
        else:
            average_score = weighted_score / total_weight if total_weight > 0 else 0
            final_verdict = self._score_to_verdict(average_score)
            final_confidence = self._calculate_confidence(all_confidences)
        
        # Build comprehensive report
        report = {
            "observable": observable,
            "data_type": data_type,
            "verdict": final_verdict,
            "confidence": final_confidence,
            "analysis_timestamp": datetime.utcnow().isoformat() + "Z",
            "sources_queried": len(self.sources),
            "sources_successful": successful_sources,
            "source_results": source_results,
            "taxonomy": self._build_taxonomy(final_verdict, final_confidence, source_results),
            "artifacts": self._extract_artifacts(observable, data_type, source_results),
            "operations": self._build_operations(final_verdict, observable, data_type)
        }
        
        return report
    
    def _verdict_to_score(self, verdict: str) -> float:
        """Convert verdict to numeric score."""
        verdict_scores = {
            "malicious": 1.0,
            "suspicious": 0.5,
            "safe": 0.0,
            "unknown": 0.25
        }
        return verdict_scores.get(verdict, 0.25)
    
    def _score_to_verdict(self, score: float) -> str:
        """Convert numeric score to verdict."""
        if score >= 0.7:
            return "malicious"
        elif score >= 0.4:
            return "suspicious"
        elif score >= 0.1:
            return "safe"
        else:
            return "unknown"
    
    def _calculate_confidence(self, confidences: List[str]) -> str:
        """Calculate overall confidence from individual confidences."""
        confidence_scores = {
            "high": 3,
            "medium": 2,
            "low": 1
        }
        
        if not confidences:
            return "low"
        
        total_score = sum(confidence_scores.get(c, 1) for c in confidences)
        average_score = total_score / len(confidences)
        
        if average_score >= 2.5:
            return "high"
        elif average_score >= 1.5:
            return "medium"
        else:
            return "low"
    
    def _build_taxonomy(self, verdict: str, confidence: str, source_results: Dict[str, Any]) -> List[Dict[str, str]]:
        """Build taxonomy entries from analysis results."""
        taxonomy = []
        
        # Main verdict taxonomy
        taxonomy.append(
            self.build_taxonomy(
                level=verdict,
                namespace="threat_intelligence",
                predicate="overall",
                value=confidence
            )
        )
        
        # Source-specific taxonomy
        for source_name, result in source_results.items():
            if result.get("status") == "success":
                source_verdict = result.get("verdict", "unknown")
                source_confidence = result.get("confidence", "low")
                
                taxonomy.append(
                    self.build_taxonomy(
                        level=source_verdict,
                        namespace="threat_intelligence",
                        predicate=source_name,
                        value=source_confidence
                    )
                )
        
        return taxonomy
    
    def _extract_artifacts(self, observable: str, data_type: str, source_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract additional artifacts from analysis results."""
        artifacts = []
        
        for source_name, result in source_results.items():
            if result.get("status") == "success":
                # Extract related IPs
                if "related_ips" in result:
                    for ip in result["related_ips"]:
                        artifacts.append(
                            self.build_artifact("ip", ip, tlp=2, extra={
                                "source": source_name,
                                "relationship": "related"
                            })
                        )
                
                # Extract related domains
                if "related_domains" in result:
                    for domain in result["related_domains"]:
                        artifacts.append(
                            self.build_artifact("domain", domain, tlp=2, extra={
                                "source": source_name,
                                "relationship": "related"
                            })
                        )
                
                # Extract vulnerabilities
                if "vulnerabilities" in result:
                    for vuln in result["vulnerabilities"]:
                        artifacts.append(
                            self.build_artifact("vulnerability", vuln, tlp=2, extra={
                                "source": source_name,
                                "type": "cve"
                            })
                        )
        
        return artifacts
    
    def _build_operations(self, verdict: str, observable: str, data_type: str) -> List[Dict[str, Any]]:
        """Build follow-up operations based on analysis results."""
        operations = []
        
        if verdict == "malicious":
            # High priority operations for malicious observables
            operations.append(
                self.build_operation(
                    "hunt",
                    query=f"{data_type}:{observable}",
                    priority="high",
                    description="Hunt for related malicious activity"
                )
            )
            
            operations.append(
                self.build_operation(
                    "block",
                    target=observable,
                    priority="high",
                    description="Block malicious observable"
                )
            )
            
            operations.append(
                self.build_operation(
                    "alert",
                    severity="high",
                    target=observable,
                    description="Send high priority alert"
                )
            )
        
        elif verdict == "suspicious":
            # Medium priority operations for suspicious observables
            operations.append(
                self.build_operation(
                    "investigate",
                    target=observable,
                    priority="medium",
                    description="Investigate suspicious observable"
                )
            )
            
            operations.append(
                self.build_operation(
                    "monitor",
                    target=observable,
                    duration="24h",
                    description="Monitor suspicious observable"
                )
            )
        
        # Always add enrichment operation
        operations.append(
            self.build_operation(
                "enrich",
                service="threat_intelligence",
                target=observable,
                description="Enrich with additional threat intelligence"
            )
        )
        
        return operations
    
    def _is_cached(self, cache_key: str) -> bool:
        """Check if result is cached and not expired."""
        if cache_key not in self.cache:
            return False
        
        cached_time = self.cache[cache_key].get("cached_at", 0)
        return time.time() - cached_time < self.cache_ttl
    
    def _cache_result(self, cache_key: str, result: Dict[str, Any]) -> None:
        """Cache analysis result."""
        result["cached_at"] = time.time()
        self.cache[cache_key] = result


if __name__ == "__main__":
    # Example usage
    input_data = {
        "dataType": "ip",
        "data": "1.2.3.4",
        "tlp": 2,
        "pap": 2,
        "config": {
            "virustotal_api_key": "your_vt_api_key",
            "abuseipdb_api_key": "your_abuseipdb_api_key",
            "shodan_api_key": "your_shodan_api_key",
            "internal_api_key": "your_internal_api_key",
            "internal_api_url": "https://internal-api.company.com",
            "auto_extract": True
        }
    }
    
    analyzer = ThreatIntelligenceAnalyzer(input_data)
    analyzer.run()
```

## Configuration

### Environment Variables

Set the following environment variables or include them in your input configuration:

```bash
export VIRUSTOTAL_API_KEY="your_virustotal_api_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_api_key"
export SHODAN_API_KEY="your_shodan_api_key"
export INTERNAL_API_KEY="your_internal_api_key"
export INTERNAL_API_URL="https://internal-api.company.com"
```

### Input Configuration

```json
{
  "dataType": "ip",
  "data": "1.2.3.4",
  "tlp": 2,
  "pap": 2,
  "config": {
    "virustotal_api_key": "your_vt_api_key",
    "abuseipdb_api_key": "your_abuseipdb_api_key",
    "shodan_api_key": "your_shodan_api_key",
    "internal_api_key": "your_internal_api_key",
    "internal_api_url": "https://internal-api.company.com",
    "auto_extract": true
  }
}
```

## Output Example

```json
{
  "success": true,
  "summary": {
    "verdict": "malicious",
    "confidence": "high",
    "sources_queried": 4,
    "sources_successful": 3
  },
  "artifacts": [
    {
      "dataType": "ip",
      "data": "5.6.7.8",
      "tlp": 2,
      "extra": {
        "source": "virustotal",
        "relationship": "related"
      }
    }
  ],
  "operations": [
    {
      "operation_type": "hunt",
      "parameters": {
        "query": "ip:1.2.3.4",
        "priority": "high",
        "description": "Hunt for related malicious activity"
      }
    },
    {
      "operation_type": "block",
      "parameters": {
        "target": "1.2.3.4",
        "priority": "high",
        "description": "Block malicious observable"
      }
    }
  ],
  "full": {
    "observable": "1.2.3.4",
    "data_type": "ip",
    "verdict": "malicious",
    "confidence": "high",
    "analysis_timestamp": "2024-01-01T12:00:00Z",
    "sources_queried": 4,
    "sources_successful": 3,
    "source_results": {
      "virustotal": {
        "status": "success",
        "verdict": "malicious",
        "confidence": "high",
        "detection_ratio": 0.75,
        "positives": 30,
        "total": 40
      },
      "abuseipdb": {
        "status": "success",
        "verdict": "malicious",
        "confidence": "high",
        "abuse_confidence": 85
      },
      "shodan": {
        "status": "success",
        "verdict": "suspicious",
        "confidence": "medium",
        "open_ports": [22, 80, 443, 3389],
        "vulnerabilities": ["CVE-2021-1234"]
      }
    },
    "taxonomy": [
      {
        "level": "malicious",
        "namespace": "threat_intelligence",
        "predicate": "overall",
        "value": "high"
      }
    ]
  }
}
```

## Features Demonstrated

1. **Multi-Source Integration**: Combines multiple threat intelligence sources
2. **Async Processing**: Uses asyncio for parallel API calls
3. **Error Handling**: Comprehensive error handling with retry logic
4. **Caching**: Implements result caching to avoid duplicate API calls
5. **Weighted Scoring**: Uses weighted scores to combine results
6. **Artifact Extraction**: Extracts additional IOCs from analysis results
7. **Operation Generation**: Creates follow-up operations based on verdicts
8. **Taxonomy Classification**: Builds comprehensive taxonomy entries

## Best Practices

1. **API Rate Limiting**: Implement rate limiting for external APIs
2. **Error Handling**: Handle API failures gracefully
3. **Caching**: Cache results to reduce API calls
4. **Configuration**: Use environment variables for sensitive data
5. **Logging**: Add comprehensive logging for debugging
6. **Testing**: Write tests for all API integrations
7. **Monitoring**: Monitor API usage and costs

## Next Steps

- [Malware Analysis Example](malware-analysis.md) - Advanced file analysis
- [Network Monitoring Example](network-monitoring.md) - Network security monitoring
- [Incident Response Example](incident-response.md) - Automated response workflows
