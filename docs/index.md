---
title: SentinelIQ SDK
---

# SentinelIQ SDK — Overview

The SentinelIQ SDK is a modern Python library designed to simplify the development of security analyzers and responders for the SentinelIQ platform. Built with Python 3.13+ and following SOLID principles, it provides a clean, opinionated API for building robust security automation tools.

## Key Features

### 🏗️ **Modular Architecture**
- **Worker**: Core base class with IO, configuration, and reporting capabilities
- **Analyzer**: Specialized for threat analysis with auto-extraction and taxonomy helpers
- **Responder**: Streamlined for automated response actions
- **Extractor**: IOC detection using Python standard library utilities

### 🔒 **Security-First Design**
- **TLP/PAP Enforcement**: Automatic Traffic Light Protocol and Permissible Actions Protocol validation
- **Secret Sanitization**: Automatic removal of sensitive data from error outputs
- **Proxy Support**: Built-in HTTP/HTTPS proxy configuration
- **Input Validation**: Robust parameter validation with clear error messages

### 🚀 **Developer Experience**
- **Modern Python**: Type hints, protocols, and Python 3.13+ features
- **Zero Dependencies**: Uses only Python standard library
- **Comprehensive Testing**: Full test coverage with pytest
- **Clear Documentation**: Detailed API reference and usage examples

## Quick Start

### Installation

```bash
pip install sentineliqsdk
```

### Basic Analyzer

```python
from __future__ import annotations

from sentineliqsdk import Analyzer, runner


class ThreatAnalyzer(Analyzer):
    def run(self) -> None:
        observable = self.get_data()
        
        # Your analysis logic here
        verdict = "malicious" if self._is_threat(observable) else "safe"
        
        self.report({
            "observable": observable,
            "verdict": verdict,
            "taxonomy": [
                self.build_taxonomy(
                    level=verdict,
                    namespace="threat_intel",
                    predicate="reputation",
                    value="high"
                )
            ]
        })
    
    def _is_threat(self, observable: str) -> bool:
        # Implement your threat detection logic
        return observable in ["malicious.example.com", "1.2.3.4"]


if __name__ == "__main__":
    runner(ThreatAnalyzer)
```

### Basic Responder

```python
from __future__ import annotations

from sentineliqsdk import Responder, runner


class BlockResponder(Responder):
    def run(self) -> None:
        target = self.get_data()
        
        # Your response logic here
        result = self._block_target(target)
        
        self.report({
            "action": "block",
            "target": target,
            "status": "success" if result else "failed"
        })
    
    def _block_target(self, target: str) -> bool:
        # Implement your blocking logic
        return True


if __name__ == "__main__":
    runner(BlockResponder)
```

## Core Components

### Worker
The foundation class providing:
- **Input/Output**: JSON-based job processing with STDIN and file support
- **Configuration**: Dotted notation parameter access (`config.api_key`)
- **Error Handling**: Structured error reporting with sanitization
- **TLP/PAP**: Automatic protocol enforcement
- **Operations**: Follow-up action definitions

### Analyzer
Extends Worker with analyzer-specific features:
- **File Handling**: Automatic file path resolution and copying
- **Auto-Extraction**: IOC detection from analysis results
- **Taxonomy**: Standardized threat classification
- **Artifacts**: Structured artifact generation
- **Envelope**: Rich output format with summary, artifacts, and operations

### Responder
Simplified Worker for response actions:
- **Streamlined Output**: Minimal response envelope
- **Action Focus**: Designed for automated responses
- **Status Reporting**: Clear success/failure indication

### Extractor
IOC detection using Python standard library:
- **IP Addresses**: IPv4 and IPv6 validation
- **URLs**: HTTP/HTTPS URL parsing
- **Domains**: Domain and FQDN detection
- **Hashes**: MD5, SHA1, SHA256 validation
- **Email**: Email address parsing
- **Registry**: Windows registry key detection
- **User Agents**: Browser user agent identification

## Input/Output Format

### Input (JSON)
```json
{
  "dataType": "ip",
  "data": "1.2.3.4",
  "tlp": 2,
  "pap": 2,
  "config": {
    "check_tlp": true,
    "max_tlp": 2,
    "auto_extract": true,
    "proxy": {
      "http": "http://proxy.example.com:8080"
    }
  }
}
```

### Analyzer Output (JSON)
```json
{
  "success": true,
  "summary": {
    "verdict": "malicious"
  },
  "artifacts": [
    {
      "dataType": "ip",
      "data": "5.6.7.8",
      "tlp": 2
    }
  ],
  "operations": [
    {
      "type": "hunt",
      "query": "ip:1.2.3.4"
    }
  ],
  "full": {
    "observable": "1.2.3.4",
    "verdict": "malicious",
    "taxonomy": [
      {
        "level": "malicious",
        "namespace": "threat_intel",
        "predicate": "reputation",
        "value": "high"
      }
    ]
  }
}
```

### Responder Output (JSON)
```json
{
  "success": true,
  "full": {
    "action": "block",
    "target": "1.2.3.4",
    "status": "success"
  },
  "operations": []
}
```

## Advanced Features

### Auto-Extraction
Automatically detect IOCs in analysis results:
```python
# Enabled by default, can be disabled with config.auto_extract: false
# Uses Extractor to find IPs, URLs, domains, etc. in your report
```

### File Handling
Seamless file processing:
```python
# For dataType == "file", get_param("file") returns absolute path
file_path = self.get_param("file")  # /job/input/malware.exe

# build_artifact("file", path) copies file to output directory
artifact = self.build_artifact("file", "/tmp/analysis.json")
```

### Operations
Define follow-up actions:
```python
def operations(self, raw):
    return [
        self.build_operation("hunt", query=f"ip:{self.get_data()}"),
        self.build_operation("enrich", service="threat_intel")
    ]
```

### Proxy Configuration
Automatic proxy setup:
```python
# Set in config.proxy.http/https, automatically exported to environment
# Works with requests, urllib, and other HTTP libraries
```

## Development

### Project Structure
```
src/sentineliqsdk/
├── __init__.py              # Public API exports
├── core/                    # Core functionality
│   ├── worker.py           # Base Worker class
│   ├── contracts.py        # Protocol definitions
│   ├── config/             # Configuration helpers
│   ├── io/                 # Input/Output utilities
│   └── runtime/            # Runtime helpers
├── analyzers/              # Analyzer implementation
│   └── base.py            # Analyzer base class
├── responders/             # Responder implementation
│   └── base.py            # Responder base class
└── extractors/             # IOC extraction
    └── regex.py           # Extractor implementation
```

### Testing
```bash
# Run tests with coverage
poe test

# Lint and type check
poe lint

# Build documentation
poe docs
```

### Contributing
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run `poe lint` and `poe test`
6. Submit a pull request

## Migration Guide

### From Legacy API
- **Imports**: Use `from sentineliqsdk import Analyzer` instead of `from sentineliqsdk.analyzer import Analyzer`
- **Methods**: Use `get_data()` instead of `getData()`, `get_param()` instead of `getParam()`
- **TLP/PAP**: Automatic enforcement, remove manual `checkTlp()` calls
- **Config**: Use `config.auto_extract` instead of `config.auto_extract_artifacts`

## Resources

- **📖 [Agent Guide](guide.md)**: Comprehensive usage guide with examples
- **📚 [API Reference](reference.md)**: Detailed API documentation
- **🐛 [Issues](https://github.com/killsearch/sentineliqsdk/issues)**: Bug reports and feature requests
- **📝 [Changelog](https://github.com/killsearch/sentineliqsdk/blob/main/CHANGELOG.md)**: Version history
- **🏠 [Repository](https://github.com/killsearch/sentineliqsdk)**: Source code and development

## License

This project is licensed under the terms specified in the repository.

---

*Built with ❤️ for the security community*
