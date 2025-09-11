# DNS Lookingglass Analyzer

The DNS Lookingglass Analyzer performs DNS lookups using the ISC SANS DNS Lookingglass API. It analyzes domains and FQDNs to retrieve DNS information and extract IP addresses as artifacts.

## Features

- **Domain Analysis**: Analyze domains and FQDNs for DNS information
- **IP Extraction**: Automatically extract IPv4 and IPv6 addresses from DNS responses
- **Real-time Lookups**: Query ISC SANS DNS Lookingglass API for current DNS data
- **Comprehensive Reporting**: Provides detailed taxonomy and metadata
- **No Authentication Required**: Free API with no authentication needed
- **Error Handling**: Robust error handling for API failures and invalid domains

## Installation

### Prerequisites

1. **Internet Connection**: Required to access ISC SANS API
2. **No API Key Required**: This analyzer uses a free public API

### Configuration

The analyzer works without any required configuration, but you can customize timeout settings:

```python
from sentineliqsdk import WorkerInput, WorkerConfig

config = WorkerConfig(
    check_tlp=True,
    max_tlp=2,
    check_pap=True,
    max_pap=2,
    # Optional timeout configuration
    # dns_lookingglass.timeout: 30.0
)
```

## Usage

### Basic Usage

```python
from sentineliqsdk.analyzers.dns_lookingglass import DnsLookingglassAnalyzer
from sentineliqsdk import WorkerInput, WorkerConfig

# Configure the analyzer
config = WorkerConfig(
    auto_extract=True,
    check_tlp=True,
    max_tlp=2
)

# Create input data
input_data = WorkerInput(
    data_type="domain",
    data="example.com",
    config=config
)

# Initialize and run analyzer
analyzer = DnsLookingglassAnalyzer(input_data)
result = analyzer.run()

print(f"Verdict: {result.full_report['verdict']}")
print(f"Hits: {result.full_report['hits']}")
print(f"Count: {result.full_report['count']}")
print(f"Artifacts: {len(result.full_report['artifacts'])} IPs found")
```

### Programmatic Usage

```python
import asyncio
from sentineliqsdk.analyzers.dns_lookingglass import DnsLookingglassAnalyzer
from sentineliqsdk import WorkerInput, WorkerConfig

async def analyze_domain(domain: str) -> dict:
    """Analyze a domain using DNS Lookingglass."""
    
    config = WorkerConfig(
        auto_extract=True,
        check_tlp=True,
        max_tlp=2
    )
    
    input_data = WorkerInput(
        data_type="domain",
        data=domain,
        config=config
    )
    
    analyzer = DnsLookingglassAnalyzer(input_data)
    result = analyzer.run()
    
    return {
        "domain": domain,
        "verdict": result.full_report["verdict"],
        "hits": result.full_report["hits"],
        "count": result.full_report["count"],
        "results": result.full_report["results"],
        "artifacts": result.full_report["artifacts"],
        "taxonomy": result.full_report["taxonomy"]
    }

# Example usage
async def main():
    domains = [
        "example.com",
        "google.com",
        "nonexistent-domain-12345.com"
    ]
    
    for domain in domains:
        try:
            result = await analyze_domain(domain)
            print(f"Domain: {result['domain']}")
            print(f"Status: {result['hits']}")
            print(f"Records Found: {result['count']}")
            print(f"IP Artifacts: {len(result['artifacts'])}")
            print("---")
        except Exception as e:
            print(f"Error analyzing {domain}: {e}")

if __name__ == "__main__":
    asyncio.run(main())
```

## Configuration Options

### Optional Configuration

| Setting | Description | Default | Type |
|---------|-------------|---------|------|
| `dns_lookingglass.timeout` | API request timeout in seconds | 30.0 | float |

### Example with Custom Configuration

```python
config = WorkerConfig(
    auto_extract=True,
    # Custom timeout
    # You can set this via environment or config
)

# Or programmatically (not recommended for production)
analyzer = DnsLookingglassAnalyzer(input_data)
# The analyzer will use get_config("dns_lookingglass.timeout", 30.0)
```

## Supported Data Types

| Data Type | Description | Example |
|-----------|-------------|----------|
| `domain` | Domain name | `example.com` |
| `fqdn` | Fully Qualified Domain Name | `www.example.com` |

## Output Format

The analyzer returns a comprehensive report with the following structure:

```json
{
  "observable": "example.com",
  "verdict": "info",
  "taxonomy": [
    {
      "level": "info",
      "namespace": "Lookingglass",
      "predicate": "DomainExist",
      "value": "3 hit(s)"
    }
  ],
  "source": "ISC SANS DNS Lookingglass",
  "data_type": "domain",
  "results": [
    {
      "answer": "93.184.216.34",
      "status": "NOERROR",
      "country": "US"
    }
  ],
  "hits": "DomainExist",
  "count": 3,
  "artifacts": [
    {
      "type": "ip",
      "value": "93.184.216.34"
    }
  ],
  "metadata": {
    "name": "DNS Lookingglass Analyzer",
    "description": "Query DNS information for domains using ISC SANS DNS Lookingglass API",
    "author": ["SentinelIQ Team <team@sentineliq.com.br>"],
    "version_stage": "TESTING"
  }
}
```

## Hit Status Types

| Status | Description |
|--------|-------------|
| `NXDOMAIN` | Domain does not exist (0 results) |
| `DomainExist` | Domain exists with DNS records (≥1 results) |
| `Error` | Error occurred during lookup |

## Artifacts

The analyzer automatically extracts IP addresses from DNS responses:

- **IPv4 Addresses**: Standard IPv4 format (e.g., `192.168.1.1`)
- **IPv6 Addresses**: Standard IPv6 format (e.g., `2001:db8::1`)

All extracted IPs are returned as artifacts with type `ip`.

## Error Handling

The analyzer handles various error conditions:

- **Invalid Data Types**: Only accepts `domain` and `fqdn`
- **API Failures**: HTTP errors, timeouts, and connection issues
- **Malformed Responses**: Invalid JSON or unexpected response format
- **Network Issues**: Connection timeouts and DNS resolution failures

## Command Line Usage

Run the analyzer from the command line:

```bash
# Basic usage
python examples/analyzers/dns_lookingglass_example.py example.com --execute

# With specific data type
python examples/analyzers/dns_lookingglass_example.py \
    --data "www.example.com" \
    --data-type "fqdn" \
    --execute

# Dry run (no actual API calls)
python examples/analyzers/dns_lookingglass_example.py example.com
```

### Command Line Arguments

| Argument | Description | Required |
|----------|-------------|----------|
| `domain` | Domain to analyze (positional) | Yes* |
| `--data` | Alternative way to specify domain | Yes* |
| `--data-type` | Type of data (`domain` or `fqdn`) | No (default: `domain`) |
| `--execute` | Execute real API calls | Yes (for actual execution) |
| `--include-dangerous` | No-op for this analyzer | No |

*Either positional `domain` or `--data` is required.

## Integration Examples

### With Pipeline

```python
from sentineliqsdk.pipelines import SecurityPipeline
from sentineliqsdk.analyzers.dns_lookingglass import DnsLookingglassAnalyzer

pipeline = SecurityPipeline()
pipeline.add_analyzer(DnsLookingglassAnalyzer)

# Process multiple domains
domains = ["example.com", "google.com", "suspicious-domain.com"]
for domain in domains:
    result = pipeline.analyze("domain", domain)
    print(f"{domain}: {result['hits']} ({result['count']} records)")
```

### With Responder

```python
from sentineliqsdk.analyzers.dns_lookingglass import DnsLookingglassAnalyzer
from sentineliqsdk.responders.webhook import WebhookResponder

# Analyze domain
analyzer_result = DnsLookingglassAnalyzer(input_data).run()

# Send results to webhook if domain exists
if analyzer_result.full_report["hits"] == "DomainExist":
    webhook_data = {
        "domain": analyzer_result.full_report["observable"],
        "ip_count": len(analyzer_result.full_report["artifacts"]),
        "dns_records": analyzer_result.full_report["count"]
    }
    
    webhook_input = WorkerInput(
        data_type="other",
        data=webhook_data,
        config=webhook_config
    )
    
    WebhookResponder(webhook_input).run()
```

## API Reference

### DnsLookingglassAnalyzer

#### Methods

- `execute() -> AnalyzerReport`: Execute DNS lookup and return report
- `run() -> AnalyzerReport`: Compatibility wrapper for execute()

#### Configuration Methods (Inherited)

- `get_config(key: str, default: Any) -> Any`: Get configuration value
- `get_secret(key: str, message: str = None) -> str`: Get secret value
- `get_data() -> Any`: Get input data
- `build_taxonomy(level, namespace, predicate, value) -> Taxonomy`: Build taxonomy
- `build_artifact(type, value) -> Artifact`: Build artifact
- `report(data: dict) -> AnalyzerReport`: Create report

## Troubleshooting

### Common Issues

1. **Connection Timeouts**
   - Increase timeout: Configure `dns_lookingglass.timeout`
   - Check internet connectivity

2. **No Results for Valid Domain**
   - Domain might not be in ISC SANS database
   - Try with a well-known domain like `google.com`

3. **Invalid Data Type Error**
   - Ensure data_type is `domain` or `fqdn`
   - Check input data format

### Debug Mode

Enable debug logging to troubleshoot issues:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Run analyzer with debug output
result = DnsLookingglassAnalyzer(input_data).run()
```

## Related Analyzers

- **[CRT.sh Analyzer](crtsh.md)**: Certificate transparency lookups
- **[Shodan Analyzer](shodan.md)**: IP and domain intelligence
- **[CIRCL PassiveDNS](circl_passivedns.md)**: Passive DNS lookups

## License

This analyzer is part of the SentinelIQ SDK and follows the same licensing terms.

## Support

For support and questions:

- **Documentation**: [SentinelIQ SDK Docs](https://killsearch.github.io/sentineliqsdk/)
- **Issues**: [GitHub Issues](https://github.com/killsearch/sentineliqsdk/issues)
- **Email**: team@sentineliq.com.br