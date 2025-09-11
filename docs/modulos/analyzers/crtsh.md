## crt.sh Analyzer

The `CrtshAnalyzer` queries `crt.sh` for Certificate Transparency entries related to a domain.
It returns a list of certificate rows and enriches each with the SHA-1 certificate hash when available.

### Features
- No API key required
- Supports `domain` and `fqdn` data types
- Auto-extraction compatible: artifacts are derived from full report when enabled

### Programmatic Usage
```python
from sentineliqsdk import WorkerInput
from sentineliqsdk.analyzers.crtsh import CrtshAnalyzer

input_data = WorkerInput(data_type="domain", data="example.com")
report = CrtshAnalyzer(input_data).execute()
print(report.full_report)
```

### Example Script
Run the example:
```bash
python examples/analyzers/crtsh_example.py example.com --execute
```

### Output Structure (excerpt)
```json
{
  "observable": "example.com",
  "verdict": "info",
  "taxonomy": [{"level": "info", "namespace": "crt.sh", "predicate": "certificates", "value": "example.com"}],
  "source": "crt.sh",
  "data_type": "domain",
  "certificates": [
    {
      "issuer_name": "...",
      "name_value": "a.example.com",
      "min_cert_id": 123,
      "sha1": "ABCDEF0123456789"
    }
  ],
  "metadata": {"Name": "crt.sh Analyzer", "pattern": "threat-intel", "VERSION": "TESTING"}
}
```

### Configuration
- `crtsh.timeout` (float, optional): HTTP timeout in seconds (default: 30.0)


