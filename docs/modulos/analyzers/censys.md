# Censys Analyzer

The Censys Analyzer provides comprehensive access to the Censys Platform API, enabling threat intelligence analysis of IP addresses, domains, certificates, and more. This analyzer implements all available Censys Platform API methods including collections management, global data search, and aggregation capabilities.

## Features

- **Full API Coverage**: Access to all Censys Platform API methods
- **Collections Management**: Create, list, update, and delete collections
- **Global Data Search**: Search hosts, certificates, and web properties
- **Timeline Analysis**: Historical data analysis for hosts
- **Dynamic Method Calls**: Programmatic access to any Censys API method
- **Comprehensive Analysis**: IP, domain, and certificate analysis with verdict determination

## Supported Data Types

- `ip`: IPv4 and IPv6 addresses
- `domain`: Domain names
- `fqdn`: Fully qualified domain names
- `hash`: Certificate fingerprints (SHA-256)
- `other`: JSON payload for dynamic method calls

## Configuration

### Required Credentials

The analyzer requires Censys Platform API credentials:

```python
from sentineliqsdk import WorkerInput, WorkerConfig

secrets = {
    "censys": {
        "personal_access_token": "your_censys_token_here",
        "organization_id": "your_organization_id_here"
    }
}

config = WorkerConfig(secrets=secrets)
input_data = WorkerInput(
    data_type="ip",
    data="1.2.3.4",
    config=config
)
```

### Optional Configuration

```python
config = WorkerConfig(
    secrets=secrets,
    # Method-specific configuration
    censys_method="global_data_search",
    censys_params={
        "search_query_input_body": {"query": "services.port:80"}
    }
)
```

## Usage Examples

### Basic IP Analysis

```python
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.censys import CensysAnalyzer

# Configure credentials
secrets = {
    "censys": {
        "personal_access_token": "your_token",
        "organization_id": "your_org_id"
    }
}

# Analyze IP address
input_data = WorkerInput(
    data_type="ip",
    data="8.8.8.8",
    config=WorkerConfig(secrets=secrets)
)

analyzer = CensysAnalyzer(input_data)
report = analyzer.execute()

print(f"Verdict: {report.full_report['verdict']}")
print(f"Taxonomy: {report.full_report['taxonomy']}")
```

### Domain Analysis

```python
# Analyze domain
input_data = WorkerInput(
    data_type="domain",
    data="example.com",
    config=WorkerConfig(secrets=secrets)
)

analyzer = CensysAnalyzer(input_data)
report = analyzer.execute()

print(f"Domain: {report.full_report['observable']}")
print(f"Verdict: {report.full_report['verdict']}")
```

### Certificate Analysis

```python
# Analyze certificate hash
input_data = WorkerInput(
    data_type="hash",
    data="sha256_certificate_hash",
    config=WorkerConfig(secrets=secrets)
)

analyzer = CensysAnalyzer(input_data)
report = analyzer.execute()

print(f"Certificate: {report.full_report['observable']}")
print(f"Verdict: {report.full_report['verdict']}")
```

### Dynamic Method Calls

#### Using Configuration Parameters

```python
# Call specific method via configuration
config = WorkerConfig(
    secrets=secrets,
    censys_method="collections_list",
    censys_params={"page_size": 10}
)

input_data = WorkerInput(
    data_type="ip",
    data="1.2.3.4",
    config=config
)

analyzer = CensysAnalyzer(input_data)
report = analyzer.execute()

print(f"Method: {report.full_report['details']['method']}")
print(f"Result: {report.full_report['details']['result']}")
```

#### Using JSON Payload

```python
import json

# Call method via JSON payload
payload = {
    "method": "global_data_search",
    "params": {
        "search_query_input_body": {"query": "services.port:443"}
    }
}

input_data = WorkerInput(
    data_type="other",
    data=json.dumps(payload),
    config=WorkerConfig(secrets=secrets)
)

analyzer = CensysAnalyzer(input_data)
report = analyzer.execute()

print(f"Method: {report.full_report['details']['method']}")
print(f"Query: {report.full_report['details']['params']}")
```

## Available API Methods

### Collections Methods

- `collections_list`: List all collections
- `collections_create`: Create a new collection
- `collections_delete`: Delete a collection
- `collections_get`: Get collection details
- `collections_update`: Update a collection
- `collections_list_events`: List collection events
- `collections_aggregate`: Aggregate collection data
- `collections_search`: Search within collections

### Global Data Methods

- `global_data_get_certificates`: Get certificates in bulk
- `global_data_get_certificate`: Get specific certificate
- `global_data_get_hosts`: Get hosts in bulk
- `global_data_get_host`: Get specific host
- `global_data_get_host_timeline`: Get host timeline
- `global_data_get_web_properties`: Get web properties in bulk
- `global_data_get_web_property`: Get specific web property
- `global_data_aggregate`: Aggregate global data
- `global_data_search`: Search global data

## Verdict Logic

The analyzer determines verdicts based on Censys data analysis:

- **Safe**: No suspicious indicators found
- **Suspicious**: Suspicious ports, services, or patterns detected
- **Malicious**: Known malicious banners or indicators found

### Suspicious Indicators

- Common attack vector ports (22, 23, 135, 139, 445, 1433, 3389)
- Self-signed certificates
- Expired certificates
- High number of search results

### Malicious Indicators

- Malware-related banners
- Trojan or backdoor indicators
- Exploit-related content

## Error Handling

The analyzer handles various error conditions:

- Missing API credentials
- Invalid method names
- API call failures
- Invalid JSON payloads
- Unsupported data types

## Example Output

```json
{
  "success": true,
  "summary": {},
  "artifacts": [],
  "operations": [],
  "full_report": {
    "observable": "8.8.8.8",
    "verdict": "safe",
    "taxonomy": [
      {
        "level": "safe",
        "namespace": "censys",
        "predicate": "reputation",
        "value": "8.8.8.8"
      }
    ],
    "source": "censys",
    "data_type": "ip",
    "details": {
      "host": {...},
      "timeline": {...},
      "search_results": {...}
    },
    "metadata": {
      "name": "Censys Analyzer",
      "description": "Comprehensive Censys Platform API analyzer",
      "author": ["SentinelIQ Team <team@sentineliq.com.br>"],
      "pattern": "threat-intel",
      "version_stage": "STABLE"
    }
  }
}
```

## Dependencies

The analyzer requires the Censys Platform SDK:

```bash
pip install censys-platform
```

## Security Considerations

- Store API credentials securely using `WorkerConfig.secrets`
- Never hardcode credentials in source code
- Use appropriate TLP/PAP levels for data sensitivity
- Monitor API usage and rate limits

## Troubleshooting

### Common Issues

1. **Import Error**: Ensure `censys-platform` is installed
2. **Authentication Error**: Verify API credentials are correct
3. **Method Not Found**: Check method name against allowlist
4. **Invalid Params**: Ensure parameters are valid JSON objects

### Debug Mode

Enable debug logging to troubleshoot API calls:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Related Documentation

- [Censys Platform API Documentation](https://censys.io/platform)
- [Censys Python SDK](https://github.com/censys/censys-sdk-python)
- [SentinelIQ SDK Configuration](../../guides/guide.md)
- [Analyzer Development Guide](../../tutorials/building-analyzers.md)
