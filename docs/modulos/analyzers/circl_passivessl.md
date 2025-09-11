# CIRCL PassiveSSL Analyzer

The CIRCL PassiveSSL Analyzer queries the CIRCL PassiveSSL service to find relationships between IP addresses and SSL certificates. This analyzer can:

- Query IP addresses to find associated SSL certificates
- Query certificate hashes to find associated IP addresses
- Provide detailed certificate information and subject details

## Features

- **IP Analysis**: Find SSL certificates associated with a specific IP address
- **Certificate Analysis**: Find IP addresses that have used a specific certificate
- **Detailed Results**: Includes certificate fingerprints, subjects, and metadata
- **Threat Intelligence**: Helps identify suspicious certificate usage patterns

## Supported Data Types

- `ip`: IPv4 addresses (CIDR notation not supported)
- `hash`: SHA1 certificate hashes (40 characters)

## Configuration

### Required Credentials

The analyzer requires CIRCL PassiveSSL credentials:

```python
secrets = {
    "circl_passivessl": {
        "username": "your_username",
        "password": "your_password"
    }
}
```

### Configuration Parameters

```python
config = WorkerConfig(
    check_tlp=True,
    max_tlp=2,
    check_pap=True,
    max_pap=2,
    auto_extract=True,
    secrets=secrets
)
```

## Usage Examples

### IP Analysis

```python
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.circl_passivessl import CirclPassivesslAnalyzer

# Configure credentials
secrets = {
    "circl_passivessl": {
        "username": "your_username",
        "password": "your_password"
    }
}

# Create input for IP analysis
input_data = WorkerInput(
    data_type="ip",
    data="1.2.3.4",
    tlp=2,
    pap=2,
    config=WorkerConfig(secrets=secrets)
)

# Run analysis
analyzer = CirclPassivesslAnalyzer(input_data)
report = analyzer.execute()

# Access results
print(f"Verdict: {report.full_report['verdict']}")
print(f"Certificates found: {len(report.full_report['details']['certificates'])}")
```

### Certificate Hash Analysis

```python
# Create input for certificate hash analysis
input_data = WorkerInput(
    data_type="hash",
    data="a1b2c3d4e5f6789012345678901234567890abcd",
    tlp=2,
    pap=2,
    config=WorkerConfig(secrets=secrets)
)

# Run analysis
analyzer = CirclPassivesslAnalyzer(input_data)
report = analyzer.execute()

# Access results
details = report.full_report['details']
print(f"Query hits: {details['query']['hits']}")
print(f"IPs seen: {len(details['query']['seen'])}")
```

## Output Format

### IP Analysis Output

```json
{
  "observable": "1.2.3.4",
  "verdict": "suspicious",
  "taxonomy": [
    {
      "level": "suspicious",
      "namespace": "CIRCL",
      "predicate": "PassiveSSL",
      "value": "2 records"
    }
  ],
  "source": "circl_passivessl",
  "data_type": "ip",
  "details": {
    "ip": "1.2.3.4",
    "certificates": [
      {
        "fingerprint": "a1b2c3d4e5f6789012345678901234567890abcd",
        "subject": "CN=example.com, O=Example Corp"
      }
    ]
  },
  "metadata": {
    "name": "CIRCL PassiveSSL Analyzer",
    "description": "Query CIRCL PassiveSSL for certificate and IP relationships",
    "author": ["SentinelIQ Team <team@sentineliq.com.br>"],
    "pattern": "threat-intel",
    "VERSION": "STABLE"
  }
}
```

### Certificate Hash Analysis Output

```json
{
  "observable": "a1b2c3d4e5f6789012345678901234567890abcd",
  "verdict": "suspicious",
  "taxonomy": [
    {
      "level": "suspicious",
      "namespace": "CIRCL",
      "predicate": "PassiveSSL",
      "value": "5 records"
    }
  ],
  "source": "circl_passivessl",
  "data_type": "hash",
  "details": {
    "query": {
      "hits": 5,
      "seen": ["1.2.3.4", "5.6.7.8", "9.10.11.12"]
    },
    "cert": {
      "subject": "CN=example.com, O=Example Corp",
      "issuer": "CN=Example CA, O=Example CA Corp",
      "serial": "1234567890",
      "not_before": "2023-01-01T00:00:00Z",
      "not_after": "2024-01-01T00:00:00Z"
    }
  },
  "metadata": {
    "name": "CIRCL PassiveSSL Analyzer",
    "description": "Query CIRCL PassiveSSL for certificate and IP relationships",
    "author": ["SentinelIQ Team <team@sentineliq.com.br>"],
    "pattern": "threat-intel",
    "VERSION": "STABLE"
  }
}
```

## Verdict Levels

The analyzer uses the following verdict levels based on result counts:

- **info**: No records found
- **safe**: 1-3 records (likely legitimate usage)
- **suspicious**: 4+ records (worth investigating)

## Error Handling

The analyzer handles various error conditions:

- **Authentication failures**: Invalid credentials
- **Invalid data types**: Unsupported data types
- **Invalid hash format**: Non-SHA1 or malformed hashes
- **CIDR notation**: Not supported for IP analysis
- **Network errors**: Connection or API failures

## Safety Considerations

- **Dry-run mode**: Examples default to dry-run mode
- **Credential security**: Use `WorkerConfig.secrets` for credentials
- **Rate limiting**: Respect CIRCL API rate limits
- **Data sensitivity**: Be mindful of TLP/PAP levels

## Related Modules

- [CIRCL PassiveDNS Analyzer](circl_passivedns.md) - Historical DNS records
- [CIRCL Hash Lookup Analyzer](circl_hashlookup.md) - File hash analysis

## References

- [CIRCL PassiveSSL Service](https://www.circl.lu/services/passive-ssl/)
- [CIRCL.lu](https://www.circl.lu/) - Computer Incident Response Center Luxembourg
