---
title: Quick Start
---

# Quick Start

Get up and running with SentinelIQ SDK in under 5 minutes. This guide will walk you through creating your first analyzer and responder.

## Prerequisites

- Python 3.13+ installed
- SentinelIQ SDK installed (see [Installation](installation.md))

## Your First Analyzer

Let's create a simple IP reputation analyzer that marks certain IPs as malicious:

```python
# threat_analyzer.py
from __future__ import annotations

from sentineliqsdk import Analyzer, runner


class ThreatAnalyzer(Analyzer):
    """Simple threat analyzer that checks IP reputation."""
    
    def run(self) -> None:
        # Get the observable data
        ip_address = self.get_data()
        
        # Simple threat detection logic
        malicious_ips = {
            "1.2.3.4",
            "5.6.7.8", 
            "192.168.1.100"
        }
        
        verdict = "malicious" if ip_address in malicious_ips else "safe"
        
        # Build taxonomy entry
        taxonomy = self.build_taxonomy(
            level=verdict,
            namespace="reputation",
            predicate="static",
            value="high" if verdict == "malicious" else "low"
        )
        
        # Create the analysis report
        report = {
            "observable": ip_address,
            "verdict": verdict,
            "confidence": "high" if verdict == "malicious" else "medium",
            "taxonomy": [taxonomy],
            "timestamp": "2024-01-01T00:00:00Z"
        }
        
        # Output the report
        self.report(report)


if __name__ == "__main__":
    # Test with sample data
    input_data = {
        "dataType": "ip",
        "data": "1.2.3.4",
        "tlp": 2,
        "pap": 2,
        "config": {
            "check_tlp": True,
            "max_tlp": 2,
            "auto_extract": True
        }
    }
    
    # Create and run analyzer
    analyzer = ThreatAnalyzer(input_data)
    analyzer.run()
```

## Your First Responder

Now let's create a simple responder that blocks malicious IPs:

```python
# block_responder.py
from __future__ import annotations

from sentineliqsdk import Responder, runner


class BlockResponder(Responder):
    """Simple responder that blocks malicious IPs."""
    
    def run(self) -> None:
        # Get the IP to block
        ip_address = self.get_data()
        
        # Simulate blocking action
        result = self._block_ip(ip_address)
        
        # Create response report
        report = {
            "action": "block",
            "target": ip_address,
            "status": "success" if result["blocked"] else "failed",
            "rule_id": result["rule_id"],
            "timestamp": result["timestamp"]
        }
        
        # Output the report
        self.report(report)
    
    def _block_ip(self, ip: str) -> dict:
        """Simulate IP blocking logic."""
        # In a real implementation, this would call your firewall API
        return {
            "blocked": True,
            "rule_id": f"block_{ip}_{hash(ip) % 10000}",
            "timestamp": "2024-01-01T00:00:00Z"
        }


if __name__ == "__main__":
    # Test with sample data
    input_data = {
        "dataType": "ip",
        "data": "1.2.3.4",
        "tlp": 2,
        "pap": 2
    }
    
    # Create and run responder
    responder = BlockResponder(input_data)
    responder.run()
```

## Running Your Code

### Method 1: Direct Execution

```bash
python threat_analyzer.py
python block_responder.py
```

### Method 2: Using the Runner

```python
# Using the runner helper
from sentineliqsdk import runner

if __name__ == "__main__":
    runner(ThreatAnalyzer)
    runner(BlockResponder)
```

### Method 3: Programmatic Usage

```python
# Use in your own code
from sentineliqsdk import ThreatAnalyzer

# Create input data
input_data = {
    "dataType": "ip",
    "data": "8.8.8.8",
    "tlp": 2,
    "pap": 2,
    "config": {"auto_extract": True}
}

# Create and run analyzer
analyzer = ThreatAnalyzer(input_data)
result = analyzer.report({
    "observable": "8.8.8.8",
    "verdict": "safe",
    "confidence": "high"
})

print(f"Analysis result: {result}")
```

## Understanding the Output

### Analyzer Output

Your analyzer will produce JSON output like this:

```json
{
  "success": true,
  "summary": {},
  "artifacts": [],
  "operations": [],
  "full": {
    "observable": "1.2.3.4",
    "verdict": "malicious",
    "confidence": "high",
    "taxonomy": [
      {
        "level": "malicious",
        "namespace": "reputation",
        "predicate": "static",
        "value": "high"
      }
    ],
    "timestamp": "2024-01-01T00:00:00Z"
  }
}
```

### Responder Output

Your responder will produce JSON output like this:

```json
{
  "success": true,
  "full": {
    "action": "block",
    "target": "1.2.3.4",
    "status": "success",
    "rule_id": "block_1.2.3.4_1234",
    "timestamp": "2024-01-01T00:00:00Z"
  },
  "operations": []
}
```

## Key Concepts

### Input Data Structure

All workers receive input in this format:

```json
{
  "dataType": "ip|url|domain|hash|file|...",
  "data": "observable_value",
  "tlp": 2,
  "pap": 2,
  "config": {
    "check_tlp": true,
    "max_tlp": 2,
    "auto_extract": true,
    "proxy": {
      "http": "http://proxy:8080",
      "https": "https://proxy:8080"
    }
  }
}
```

### TLP/PAP Enforcement

- **TLP (Traffic Light Protocol)**: Controls data sharing
- **PAP (Permissible Actions Protocol)**: Controls actions allowed
- Automatically enforced when configured

### Auto-Extraction

When enabled, the SDK automatically extracts IOCs from your reports:

```python
# This will automatically find IPs, URLs, domains, etc.
report = {
    "description": "Found malicious activity from 1.2.3.4",
    "urls": ["https://evil.com/malware.exe"],
    "domains": ["evil.com", "malicious.net"]
}
```

## Next Steps

Now that you have the basics:

1. **Explore Examples**: Check out [real-world examples](../examples/threat-intelligence.md)
2. **Learn Advanced Features**: Read about [file processing](../tutorials/file-processing.md)
3. **Build Complex Analyzers**: Follow the [building analyzers tutorial](../tutorials/building-analyzers.md)
4. **API Reference**: Dive into the [complete API documentation](../reference/api/worker.md)

## Common Patterns

### Error Handling

```python
def run(self) -> None:
    try:
        # Your analysis logic
        result = self._analyze()
        self.report(result)
    except Exception as e:
        self.error(f"Analysis failed: {str(e)}")
```

### Configuration Access

```python
def run(self) -> None:
    # Get configuration parameters
    api_key = self.get_param("config.api_key", message="API key required")
    timeout = self.get_param("config.timeout", default=30)
    
    # Use in your logic
    result = self._call_api(api_key, timeout)
```

### Environment Variables

```python
def run(self) -> None:
    # Access environment variables
    debug_mode = self.get_env("DEBUG", default="false")
    if debug_mode.lower() == "true":
        print("Debug mode enabled")
```

## Troubleshooting

If something doesn't work:

1. Check the [Common Issues](../troubleshooting/common-issues.md) guide
2. Verify your Python version: `python --version`
3. Ensure the SDK is installed: `python -c "import sentineliqsdk"`
4. Check the [FAQ](../troubleshooting/faq.md)

Ready to build something amazing? Let's move on to [Building Your First Analyzer](first-analyzer.md)!
