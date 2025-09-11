## Cuckoo Sandbox Analyzer

Submits files or URLs to a Cuckoo Sandbox instance and retrieves the analysis report.

### Configuration

- **cuckoo.url**: Base API URL (required), e.g. `https://cuckoo.local/api/`
- **cuckoo.verify_ssl**: Verify TLS certificates (default: true)
- **cuckoo.timeout_minutes**: Max minutes to wait (default: 15)
- **cuckoo.poll_interval_seconds**: Poll interval in seconds (default: 60)
- **secrets.cuckoo.token**: Optional API token

### Programmatic Usage

```python
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.cuckoo import CuckooSandboxAnalyzer

input_data = WorkerInput(
    data_type="url",
    data="http://example.com",
    config=WorkerConfig(
        **{
            "cuckoo.url": "https://cuckoo.local/api/",
            "cuckoo.verify_ssl": True,
            "secrets": {"cuckoo": {"token": "YOUR_TOKEN"}},
        }
    ),
)

report = CuckooSandboxAnalyzer(input_data).execute()
print(report.full_report)
```

### Example Script

Run the provided example:

```bash
python examples/analyzers/cuckoo_example.py url http://example.com --execute --url https://cuckoo.local/api/ --token YOUR_TOKEN
```

For file samples:

```bash
python examples/analyzers/cuckoo_example.py file /path/to/sample.exe --execute --url https://cuckoo.local/api/ --token YOUR_TOKEN
```

### Output

The analyzer returns an `AnalyzerReport` with keys including `taxonomy`, `signatures`,
`suricata_alerts`, `snort_alerts`, `domains`, `uri`, `malscore`, `malfamily`, and `metadata`.


