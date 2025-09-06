---
title: API Reference
---

# API Reference

This section provides detailed documentation for all public classes, methods, and functions in the SentinelIQ SDK.

## Core Classes

### Worker

Base class for all SentinelIQ workers (analyzers and responders).

```python
class Worker(ABC):
    """Common functionality for analyzers and responders."""
    
    def __init__(
        self,
        job_directory: str | None = None,
        secret_phrases: tuple[str, ...] | None = None,
    ) -> None:
        """Initialize worker with job directory and secret phrases for sanitization."""
```

#### Methods

##### `get_param(name: str, default: Any | None = None, message: str | None = None) -> Any`

Access configuration parameters using dotted notation (e.g., `"config.api_key"`).

- **Parameters:**
  - `name`: Parameter name with dotted notation support
  - `default`: Default value if parameter not found
  - `message`: Error message to display if parameter is required but missing
- **Returns:** Parameter value or default
- **Raises:** Calls `error()` and exits if `message` provided and parameter missing

##### `get_env(key: str, default: Any | None = None, message: str | None = None) -> Any`

Access environment variables with optional error handling.

- **Parameters:**
  - `key`: Environment variable name
  - `default`: Default value if variable not found
  - `message`: Error message to display if variable is required but missing
- **Returns:** Environment variable value or default
- **Raises:** Calls `error()` and exits if `message` provided and variable missing

##### `get_data() -> Any`

Get the observable data from input. Overridden in subclasses.

- **Returns:** Observable value from input JSON
- **Raises:** Calls `error()` if data field is missing

##### `build_operation(op_type: str, **parameters: Any) -> dict[str, Any]`

Create an operation descriptor for follow-up actions.

- **Parameters:**
  - `op_type`: Operation type identifier
  - `**parameters`: Additional operation parameters
- **Returns:** Dictionary with operation type and parameters

##### `operations(raw: Any) -> list[dict[str, Any]]`

Hook method to return list of operations to execute after job completion.

- **Parameters:**
  - `raw`: Full report data
- **Returns:** List of operation dictionaries (default: empty list)

##### `summary(raw: Any) -> dict[str, Any]`

Hook method to return a summary for short reports.

- **Parameters:**
  - `raw`: Full report data
- **Returns:** Summary dictionary (default: empty dict)

##### `artifacts(raw: Any) -> list[dict[str, Any]]`

Hook method to return list of artifacts.

- **Parameters:**
  - `raw`: Full report data
- **Returns:** List of artifact dictionaries (default: empty list)

##### `report(output: dict[str, Any], ensure_ascii: bool = False) -> None`

Write output JSON to job directory or STDOUT.

- **Parameters:**
  - `output`: Output data dictionary
  - `ensure_ascii`: Force ASCII encoding (default: False)

##### `error(message: str, ensure_ascii: bool = False) -> NoReturn`

Write error JSON and exit with code 1.

- **Parameters:**
  - `message`: Error message
  - `ensure_ascii`: Force ASCII encoding (default: False)
- **Raises:** SystemExit(1)

##### `run() -> None`

Abstract method to implement main worker logic in subclasses.

### Analyzer

Base class for analyzers with auto-extraction and helper methods.

```python
class Analyzer(Worker):
    """Base class for analyzers with auto-extraction and helpers."""
    
    def __init__(self, job_directory: str | None = None, secret_phrases=None) -> None:
        """Initialize analyzer with auto-extraction enabled by default."""
```

#### Methods

##### `get_data() -> Any`

Get observable data, returning filename for file datatypes.

- **Returns:** Filename for `dataType == "file"`, otherwise the `data` field

##### `get_param(name: str, default: Any | None = None, message: str | None = None) -> Any`

Enhanced parameter access with file path resolution.

- **Special behavior:** When `name` is `"file"` and `dataType == "file"` in job directory mode, returns absolute path to input file if it exists
- **Parameters:** Same as `Worker.get_param()`
- **Returns:** Parameter value, with special file path resolution

##### `build_taxonomy(level: TaxonomyLevel, namespace: str, predicate: str, value: str) -> dict`

Create a normalized taxonomy entry for report metadata.

- **Parameters:**
  - `level`: Taxonomy level (`"info"`, `"safe"`, `"suspicious"`, `"malicious"`)
  - `namespace`: Taxonomy namespace
  - `predicate`: Taxonomy predicate
  - `value`: Taxonomy value
- **Returns:** Dictionary with taxonomy structure

##### `build_artifact(data_type: str, data: Any, **kwargs: Any) -> dict | None`

Build an artifact dictionary with file handling.

- **Parameters:**
  - `data_type`: Artifact data type
  - `data`: Artifact data value
  - `**kwargs`: Additional artifact fields
- **Returns:** Artifact dictionary or None (for file artifacts in STDIN mode)
- **Special behavior:** For `data_type == "file"`, copies file to output directory

##### `artifacts(raw: Any) -> list[dict]`

Auto-extract IOCs from full report when enabled.

- **Parameters:**
  - `raw`: Full report data
- **Returns:** List of extracted IOCs (when `auto_extract` is enabled)

##### `report(full_report: dict, ensure_ascii: bool = False) -> None`

Write analyzer output with SDK envelope.

- **Parameters:**
  - `full_report`: Full analysis report
  - `ensure_ascii`: Force ASCII encoding
- **Output format:** `{"success": true, "summary": ..., "artifacts": ..., "operations": ..., "full": ...}`

### Responder

Base class for responders with simplified output format.

```python
class Responder(Worker):
    """Base class for responders."""
    
    def __init__(self, job_directory: str | None = None, secret_phrases=None):
        """Initialize responder."""
```

#### Methods

##### `get_data() -> Any`

Get observable data from input.

- **Returns:** Data field from input JSON

##### `report(full_report, ensure_ascii: bool = False) -> None`

Write responder output with simplified envelope.

- **Parameters:**
  - `full_report`: Full response report
  - `ensure_ascii`: Force ASCII encoding
- **Output format:** `{"success": true, "full": full_report, "operations": [...]}`

### Extractor

IOC extractor using Python standard library helpers.

```python
class Extractor:
    """Detect IOC attribute types using stdlib-backed heuristics."""
    
    def __init__(self, ignore: str | None = None):
        """Initialize extractor with optional ignore string."""
```

#### Methods

##### `check_string(value: str) -> str`

Check if a string matches a known IOC type.

- **Parameters:**
  - `value`: String to test
- **Returns:** Data type name or empty string if no match

##### `check_iterable(iterable: Any) -> list[dict[str, str]]`

Extract IOCs from iterable data structures.

- **Parameters:**
  - `iterable`: List, dict, tuple, set, or string to search
- **Returns:** List of IOC dictionaries with `dataType` and `data` keys
- **Raises:** TypeError for unsupported types

##### `deduplicate(list_of_objects: list[dict[str, str]]) -> list[dict[str, str]]`

Remove duplicate IOCs from a list.

- **Parameters:**
  - `list_of_objects`: List of IOC dictionaries
- **Returns:** Deduplicated list

#### Supported IOC Types

The extractor recognizes the following IOC types:

- **`ip`**: IPv4 and IPv6 addresses (using `ipaddress.ip_address`)
- **`url`**: HTTP/HTTPS URLs (using `urllib.parse.urlparse`)
- **`domain`**: Two-part domain names (e.g., `example.com`)
- **`fqdn`**: Fully qualified domain names with 3+ labels
- **`hash`**: MD5 (32), SHA1 (40), or SHA256 (64) hexadecimal hashes
- **`mail`**: Email addresses (using `email.utils.parseaddr`)
- **`user-agent`**: User agent strings starting with `Mozilla/4.0` or `Mozilla/5.0`
- **`uri_path`**: Non-HTTP URI schemes (e.g., `ftp://`, `file://`)
- **`registry`**: Windows registry keys starting with `HKEY`, `HKLM`, etc.

## Utility Functions

### runner

Convenience function to instantiate and run a worker class.

```python
def runner(worker_cls: type[T]) -> None:
    """Instantiate and run a worker class with a ``run()`` method."""
```

- **Parameters:**
  - `worker_cls`: Worker class with a `run()` method
- **Usage:** `runner(MyAnalyzer)` or `runner(MyResponder)`

## Configuration

### TLP/PAP Enforcement

Workers automatically enforce TLP (Traffic Light Protocol) and PAP (Permissible Actions Protocol) limits when configured:

- **Enable:** Set `config.check_tlp: true` and/or `config.check_pap: true`
- **Limits:** Set `config.max_tlp` and/or `config.max_pap` values
- **Behavior:** Worker calls `error()` and exits if limits are exceeded

### Proxy Configuration

HTTP/HTTPS proxies can be configured via input JSON:

```json
{
  "config": {
    "proxy": {
      "http": "http://proxy.example.com:8080",
      "https": "https://proxy.example.com:8080"
    }
  }
}
```

These are automatically exported to environment variables `http_proxy` and `https_proxy`.

### Secret Sanitization

Error payloads automatically sanitize configuration keys containing sensitive terms:

- **Default terms:** `key`, `password`, `secret`, `token`
- **Customization:** Override via `secret_phrases` parameter in `Worker.__init__()`
- **Behavior:** Sensitive values are replaced with `"REMOVED"` in error outputs

## Error Handling

### Error Output Format

When a worker encounters an error, it outputs:

```json
{
  "success": false,
  "input": { /* sanitized input */ },
  "errorMessage": "Error description"
}
```

### Common Error Scenarios

- **Missing required parameters:** When `get_param()` or `get_env()` is called with a `message` parameter and the value is not found
- **TLP/PAP violations:** When configured limits are exceeded
- **File access errors:** When required files are not accessible
- **Invalid input format:** When input JSON cannot be parsed

## Examples

### Complete Analyzer Example

```python
from __future__ import annotations

from sentineliqsdk import Analyzer, runner


class ThreatIntelligenceAnalyzer(Analyzer):
    """Example analyzer with taxonomy and artifacts."""
    
    def run(self) -> None:
        observable = self.get_data()
        
        # Perform analysis
        verdict = self._analyze_threat(observable)
        
        # Build taxonomy
        taxonomy = [
            self.build_taxonomy(
                level=verdict["level"],
                namespace="threat_intel",
                predicate="reputation",
                value=verdict["confidence"]
            )
        ]
        
        # Build artifacts
        artifacts = []
        if verdict.get("related_ips"):
            for ip in verdict["related_ips"]:
                artifacts.append(self.build_artifact("ip", ip, tlp=2))
        
        # Create full report
        full_report = {
            "observable": observable,
            "verdict": verdict,
            "taxonomy": taxonomy,
            "related_indicators": verdict.get("indicators", [])
        }
        
        self.report(full_report)
    
    def _analyze_threat(self, observable: str) -> dict:
        """Mock threat analysis."""
        return {
            "level": "suspicious",
            "confidence": "medium",
            "related_ips": ["1.2.3.4", "5.6.7.8"],
            "indicators": ["malware", "c2"]
        }


if __name__ == "__main__":
    runner(ThreatIntelligenceAnalyzer)
```

### Complete Responder Example

```python
from __future__ import annotations

from sentineliqsdk import Responder, runner


class FirewallBlockResponder(Responder):
    """Example responder for firewall blocking."""
    
    def run(self) -> None:
        ip = self.get_data()
        
        # Perform blocking action
        result = self._block_ip(ip)
        
        # Create response report
        response = {
            "action": "block",
            "target": ip,
            "status": "success" if result["blocked"] else "failed",
            "details": result
        }
        
        self.report(response)
    
    def _block_ip(self, ip: str) -> dict:
        """Mock IP blocking."""
        return {
            "blocked": True,
            "rule_id": f"block_{ip}",
            "timestamp": "2024-01-01T00:00:00Z"
        }


if __name__ == "__main__":
    runner(FirewallBlockResponder)
```

## Type Definitions

### TaxonomyLevel

```python
TaxonomyLevel = Literal["info", "safe", "suspicious", "malicious"]
```

### Runnable Protocol

```python
class Runnable(Protocol):
    """Protocol for runnable workers exposing a ``run()`` method."""
    
    def run(self) -> None:
        ...
```

## Internal Architecture

The SDK follows SOLID principles with clear separation of concerns:

- **Worker**: Core IO, configuration, and reporting functionality
- **Analyzer/Responder**: Specialized behavior for different worker types
- **Extractor**: IOC detection using standard library utilities
- **Configuration helpers**: Proxy setup, secret sanitization, output writing
- **Runtime helpers**: Encoding and stream management

All internal modules are organized under `sentineliqsdk/core/` with specific responsibilities for configuration, IO, and runtime concerns.
