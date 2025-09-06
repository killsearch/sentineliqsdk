---
title: Your First Analyzer
---

# Your First Analyzer

This tutorial will guide you through building a complete, production-ready analyzer step by step. We'll create a URL reputation analyzer that checks URLs against multiple threat intelligence sources.

## What We'll Build

A URL reputation analyzer that:
- Checks URLs against known malicious domains
- Performs basic URL validation
- Extracts additional IOCs from the analysis
- Provides detailed taxonomy and confidence scoring
- Handles errors gracefully

## Step 1: Project Setup

Create a new directory for your analyzer:

```bash
mkdir url-reputation-analyzer
cd url-reputation-analyzer
```

Create a virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

Install the SDK:

```bash
pip install sentineliqsdk
```

## Step 2: Basic Analyzer Structure

Create `url_analyzer.py`:

```python
# url_analyzer.py
from __future__ import annotations

import json
from datetime import datetime
from urllib.parse import urlparse

from sentineliqsdk import Analyzer, runner


class URLReputationAnalyzer(Analyzer):
    """URL reputation analyzer with threat intelligence integration."""
    
    def __init__(self, input_data):
        super().__init__(input_data)
        # Initialize threat intelligence sources
        self.malicious_domains = self._load_threat_intel()
    
    def _load_threat_intel(self) -> set[str]:
        """Load known malicious domains."""
        # In production, this would load from a database or API
        return {
            "malicious-example.com",
            "phishing-site.net",
            "malware-distribution.org",
            "suspicious-domain.info"
        }
    
    def run(self) -> None:
        """Main analysis logic."""
        url = self.get_data()
        
        # Validate URL format
        if not self._is_valid_url(url):
            self.error("Invalid URL format provided")
        
        # Extract domain for analysis
        domain = self._extract_domain(url)
        
        # Perform reputation analysis
        analysis = self._analyze_url_reputation(url, domain)
        
        # Build comprehensive report
        report = self._build_report(url, domain, analysis)
        
        # Output the report
        self.report(report)
    
    def _is_valid_url(self, url: str) -> bool:
        """Validate URL format."""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        return urlparse(url).netloc.lower()
    
    def _analyze_url_reputation(self, url: str, domain: str) -> dict:
        """Analyze URL reputation using multiple checks."""
        checks = {
            "domain_blacklist": domain in self.malicious_domains,
            "suspicious_tld": self._check_suspicious_tld(domain),
            "suspicious_path": self._check_suspicious_path(url),
            "short_url": self._is_short_url(url),
            "recent_registration": self._check_recent_registration(domain)
        }
        
        # Calculate overall verdict
        malicious_count = sum(checks.values())
        if malicious_count >= 3:
            verdict = "malicious"
            confidence = "high"
        elif malicious_count >= 1:
            verdict = "suspicious"
            confidence = "medium"
        else:
            verdict = "safe"
            confidence = "high"
        
        return {
            "verdict": verdict,
            "confidence": confidence,
            "checks": checks,
            "risk_score": malicious_count / len(checks)
        }
    
    def _check_suspicious_tld(self, domain: str) -> bool:
        """Check for suspicious top-level domains."""
        suspicious_tlds = {".tk", ".ml", ".ga", ".cf", ".click", ".download"}
        return any(domain.endswith(tld) for tld in suspicious_tlds)
    
    def _check_suspicious_path(self, url: str) -> bool:
        """Check for suspicious URL paths."""
        suspicious_patterns = [
            "/download/",
            "/malware/",
            "/virus/",
            "/phishing/",
            "/scam/"
        ]
        return any(pattern in url.lower() for pattern in suspicious_patterns)
    
    def _is_short_url(self, url: str) -> bool:
        """Check if URL is a short URL service."""
        short_url_domains = {
            "bit.ly", "tinyurl.com", "short.link", "t.co",
            "goo.gl", "ow.ly", "is.gd"
        }
        domain = self._extract_domain(url)
        return domain in short_url_domains
    
    def _check_recent_registration(self, domain: str) -> bool:
        """Simulate recent domain registration check."""
        # In production, this would check WHOIS data
        # For demo, assume domains with numbers are recently registered
        return any(char.isdigit() for char in domain)
    
    def _build_report(self, url: str, domain: str, analysis: dict) -> dict:
        """Build comprehensive analysis report."""
        # Build taxonomy entries
        taxonomy = [
            self.build_taxonomy(
                level=analysis["verdict"],
                namespace="reputation",
                predicate="url_analysis",
                value=analysis["confidence"]
            ),
            self.build_taxonomy(
                level="info",
                namespace="analysis",
                predicate="risk_score",
                value=str(analysis["risk_score"])
            )
        ]
        
        # Add additional taxonomy for specific checks
        for check_name, result in analysis["checks"].items():
            if result:
                taxonomy.append(
                    self.build_taxonomy(
                        level="info",
                        namespace="checks",
                        predicate=check_name,
                        value="true"
                    )
                )
        
        # Build artifacts (additional IOCs found)
        artifacts = []
        if analysis["checks"]["short_url"]:
            artifacts.append(
                self.build_artifact("url", url, tlp=2, extra={"type": "short_url"})
            )
        
        # Create operations for follow-up actions
        operations = []
        if analysis["verdict"] in ["malicious", "suspicious"]:
            operations.append(
                self.build_operation(
                    "hunt",
                    query=f"url:{url}",
                    priority="high" if analysis["verdict"] == "malicious" else "medium"
                )
            )
            operations.append(
                self.build_operation(
                    "enrich",
                    service="threat_intel",
                    target=domain
                )
            )
        
        return {
            "observable": url,
            "domain": domain,
            "verdict": analysis["verdict"],
            "confidence": analysis["confidence"],
            "risk_score": analysis["risk_score"],
            "analysis_details": analysis["checks"],
            "taxonomy": taxonomy,
            "artifacts": artifacts,
            "operations": operations,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "analyzer_version": "1.0.0"
        }


if __name__ == "__main__":
    # Test with sample data
    test_cases = [
        {
            "dataType": "url",
            "data": "https://malicious-example.com/phishing",
            "tlp": 2,
            "pap": 2,
            "config": {"auto_extract": True}
        },
        {
            "dataType": "url", 
            "data": "https://google.com",
            "tlp": 2,
            "pap": 2,
            "config": {"auto_extract": True}
        }
    ]
    
    for i, input_data in enumerate(test_cases, 1):
        print(f"\n--- Test Case {i} ---")
        analyzer = URLReputationAnalyzer(input_data)
        analyzer.run()
```

## Step 3: Test Your Analyzer

Run the analyzer with different test cases:

```bash
python url_analyzer.py
```

You should see output like:

```json
{
  "success": true,
  "summary": {},
  "artifacts": [
    {
      "dataType": "url",
      "data": "https://malicious-example.com/phishing",
      "tlp": 2,
      "extra": {"type": "short_url"}
    }
  ],
  "operations": [
    {
      "operation_type": "hunt",
      "parameters": {
        "query": "url:https://malicious-example.com/phishing",
        "priority": "high"
      }
    }
  ],
  "full": {
    "observable": "https://malicious-example.com/phishing",
    "domain": "malicious-example.com",
    "verdict": "malicious",
    "confidence": "high",
    "risk_score": 0.6,
    "analysis_details": {
      "domain_blacklist": true,
      "suspicious_tld": false,
      "suspicious_path": true,
      "short_url": false,
      "recent_registration": false
    },
    "taxonomy": [
      {
        "level": "malicious",
        "namespace": "reputation",
        "predicate": "url_analysis",
        "value": "high"
      }
    ],
    "timestamp": "2024-01-01T00:00:00Z",
    "analyzer_version": "1.0.0"
  }
}
```

## Step 4: Add Configuration Support

Enhance your analyzer to use configuration parameters:

```python
def run(self) -> None:
    """Main analysis logic with configuration support."""
    url = self.get_data()
    
    # Get configuration parameters
    strict_mode = self.get_param("config.strict_mode", default=False)
    custom_blacklist = self.get_param("config.custom_blacklist", default=[])
    
    # Add custom domains to blacklist
    if custom_blacklist:
        self.malicious_domains.update(custom_blacklist)
    
    # Adjust analysis based on strict mode
    if strict_mode:
        # More aggressive detection
        analysis = self._analyze_url_reputation_strict(url, domain)
    else:
        analysis = self._analyze_url_reputation(url, domain)
    
    # Rest of the logic...
```

## Step 5: Add Error Handling

Improve error handling and logging:

```python
def run(self) -> None:
    """Main analysis logic with comprehensive error handling."""
    try:
        url = self.get_data()
        
        if not url:
            self.error("No URL provided for analysis")
        
        # Validate URL format
        if not self._is_valid_url(url):
            self.error(f"Invalid URL format: {url}")
        
        # Perform analysis
        domain = self._extract_domain(url)
        analysis = self._analyze_url_reputation(url, domain)
        
        # Build and output report
        report = self._build_report(url, domain, analysis)
        self.report(report)
        
    except Exception as e:
        self.error(f"Analysis failed: {str(e)}")
```

## Step 6: Add File Support

Handle file-based input:

```python
def get_data(self) -> str:
    """Get URL data, handling both direct input and file input."""
    if self.data_type == "file":
        # Read URL from file
        file_path = self.get_param("file")
        try:
            with open(file_path, 'r') as f:
                return f.read().strip()
        except FileNotFoundError:
            self.error(f"File not found: {file_path}")
        except Exception as e:
            self.error(f"Error reading file: {str(e)}")
    else:
        # Direct URL input
        return super().get_data()
```

## Step 7: Create a Test Suite

Create `test_url_analyzer.py`:

```python
# test_url_analyzer.py
import pytest
from url_analyzer import URLReputationAnalyzer


def test_malicious_url():
    """Test analyzer with malicious URL."""
    input_data = {
        "dataType": "url",
        "data": "https://malicious-example.com/phishing",
        "tlp": 2,
        "pap": 2,
        "config": {"auto_extract": True}
    }
    
    analyzer = URLReputationAnalyzer(input_data)
    result = analyzer.report({
        "observable": "https://malicious-example.com/phishing",
        "verdict": "malicious",
        "confidence": "high"
    })
    
    assert result["success"] is True
    assert result["full"]["verdict"] == "malicious"


def test_safe_url():
    """Test analyzer with safe URL."""
    input_data = {
        "dataType": "url",
        "data": "https://google.com",
        "tlp": 2,
        "pap": 2,
        "config": {"auto_extract": True}
    }
    
    analyzer = URLReputationAnalyzer(input_data)
    result = analyzer.report({
        "observable": "https://google.com",
        "verdict": "safe",
        "confidence": "high"
    })
    
    assert result["success"] is True
    assert result["full"]["verdict"] == "safe"


if __name__ == "__main__":
    pytest.main([__file__])
```

Run tests:

```bash
pip install pytest
python -m pytest test_url_analyzer.py -v
```

## Step 8: Package Your Analyzer

Create `setup.py` for distribution:

```python
# setup.py
from setuptools import setup, find_packages

setup(
    name="url-reputation-analyzer",
    version="1.0.0",
    description="URL reputation analyzer for SentinelIQ",
    author="Your Name",
    author_email="your.email@example.com",
    packages=find_packages(),
    install_requires=[
        "sentineliqsdk>=0.1.2",
    ],
    python_requires=">=3.13",
    entry_points={
        "console_scripts": [
            "url-analyzer=url_analyzer:main",
        ],
    },
)
```

## Step 9: Deploy and Use

### Local Testing

```bash
# Test with different inputs
echo '{"dataType": "url", "data": "https://example.com"}' | python url_analyzer.py
```

### Integration with SentinelIQ

Your analyzer is now ready to be integrated with the SentinelIQ platform. The JSON output format is compatible with the platform's expectations.

## Best Practices Demonstrated

1. **Input Validation**: Always validate input data
2. **Error Handling**: Comprehensive error handling with meaningful messages
3. **Configuration**: Support for configuration parameters
4. **Taxonomy**: Proper taxonomy classification
5. **Artifacts**: Extract additional IOCs when found
6. **Operations**: Define follow-up actions
7. **Testing**: Comprehensive test coverage
8. **Documentation**: Clear code documentation

## Next Steps

Now that you have a complete analyzer:

1. **Add More Features**: Integrate with real threat intelligence APIs
2. **Improve Performance**: Add caching and async processing
3. **Add Logging**: Implement structured logging
4. **Create More Tests**: Add edge cases and error scenarios
5. **Deploy**: Package and deploy to your environment

## Resources

- [API Reference](../reference/api/analyzer.md) - Complete API documentation
- [Advanced Features](../tutorials/advanced-features.md) - Learn advanced techniques
- [Examples](../examples/threat-intelligence.md) - More real-world examples
- [Troubleshooting](../troubleshooting/common-issues.md) - Common issues and solutions

Congratulations! You've built your first production-ready analyzer. 🎉
