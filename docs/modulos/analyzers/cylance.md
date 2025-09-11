# Cylance Analyzer

The Cylance Analyzer performs hash-based threat intelligence lookups using the Cylance ThreatZERO API. It analyzes SHA256 hashes to determine if files are known threats in the Cylance threat database.

## Features

- **Hash Analysis**: Analyze SHA256 hashes for threat intelligence
- **Threat Classification**: Classify threats based on Cylance's threat database
- **Real-time Lookups**: Query Cylance ThreatZERO API for up-to-date threat information
- **Comprehensive Reporting**: Provides detailed taxonomy and metadata
- **Error Handling**: Robust error handling for API failures and invalid hashes

## Installation

### Prerequisites

1. **Cylance ThreatZERO Account**: You need access to Cylance ThreatZERO API
2. **API Credentials**: Obtain your API key from Cylance console

### Configuration

The analyzer requires API credentials to access Cylance ThreatZERO:

```python
from sentineliqsdk import WorkerInput, WorkerConfig

config = WorkerConfig(
    check_tlp=True,
    max_tlp=2,
    check_pap=True,
    max_pap=2,
    secrets={
        "cylance": {
            "api_key": "your_cylance_api_key_here"
        }
    }
)
```

## Usage

### Basic Usage

```python
from sentineliqsdk.analyzers.cylance import CylanceAnalyzer
from sentineliqsdk import WorkerInput, WorkerConfig

# Configure the analyzer
config = WorkerConfig(
    secrets={
        "cylance": {
            "api_key": "your_api_key"
        }
    }
)

# Create input data
input_data = WorkerInput(
    data_type="hash",
    data="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    config=config
)

# Initialize and run analyzer
analyzer = CylanceAnalyzer(input_data)
result = analyzer.run()

print(f"Verdict: {result.full_report['verdict']}")
print(f"Taxonomy: {result.full_report['taxonomy']}")
```

### Programmatic Usage

```python
import asyncio
from sentineliqsdk.analyzers.cylance import CylanceAnalyzer
from sentineliqsdk import WorkerInput, WorkerConfig

async def analyze_hash(sha256_hash: str) -> dict:
    """Analyze a SHA256 hash using Cylance."""
    
    config = WorkerConfig(
        secrets={
            "cylance": {
                "api_key": "your_api_key"
            }
        }
    )
    
    input_data = WorkerInput(
        data_type="hash",
        data=sha256_hash,
        config=config
    )
    
    analyzer = CylanceAnalyzer(input_data)
    result = analyzer.run()
    
    return {
        "hash": sha256_hash,
        "verdict": result.full_report["verdict"],
        "threat_found": result.full_report.get("threat_found", False),
        "taxonomy": result.full_report["taxonomy"]
    }

# Example usage
async def main():
    hashes = [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "d41d8cd98f00b204e9800998ecf8427e"
    ]
    
    for hash_value in hashes:
        try:
            result = await analyze_hash(hash_value)
            print(f"Hash: {result['hash']}")
            print(f"Verdict: {result['verdict']}")
            print(f"Threat Found: {result['threat_found']}")
            print("---")
        except Exception as e:
            print(f"Error analyzing {hash_value}: {e}")

if __name__ == "__main__":
    asyncio.run(main())
```

## Configuration Options

### Required Secrets

| Secret | Description | Required |
|--------|-------------|----------|
| `cylance.api_key` | Cylance ThreatZERO API key | Yes |

### Optional Configuration

| Setting | Description | Default | Type |
|---------|-------------|---------|------|
| `cylance.timeout` | API request timeout in seconds | 30 | int |
| `cylance.max_retries` | Maximum number of API retries | 3 | int |
| `cylance.base_url` | Cylance API base URL | `https://protect-api.cylance.com` | str |

### Example with Custom Configuration

```python
config = WorkerConfig(
    secrets={
        "cylance": {
            "api_key": "your_api_key"
        }
    },
    # Custom timeout and retries
    **{
        "cylance.timeout": 60,
        "cylance.max_retries": 5
    }
)
```

## Data Types

The Cylance Analyzer supports the following data types:

- **`hash`**: SHA256 hash values (64 hexadecimal characters)

## Output Format

The analyzer returns an `AnalyzerReport` with the following structure:

```python
{
    "observable": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "verdict": "safe",  # or "malicious", "suspicious", "info"
    "threat_found": False,
    "taxonomy": [
        {
            "level": "safe",
            "namespace": "cylance",
            "predicate": "hash_analysis",
            "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        }
    ],
    "metadata": {
        "name": "Cylance Analyzer",
        "description": "Analyzer for Cylance ThreatZERO hash lookups",
        "author": ["SentinelIQ Team <team@sentineliq.com.br>"],
        "version_stage": "TESTING"
    }
}
```

### Verdict Levels

- **`safe`**: Hash is clean/not a known threat
- **`malicious`**: Hash is identified as malware
- **`suspicious`**: Hash has suspicious characteristics
- **`info`**: Informational result (e.g., hash not found)

## Error Handling

The analyzer handles various error conditions:

### Invalid Hash Format
```python
# Invalid SHA256 hash
input_data = WorkerInput(
    data_type="hash",
    data="invalid_hash",
    config=config
)

result = analyzer.run()
# Returns verdict: "info" with appropriate taxonomy
```

### API Errors
```python
# Network or API errors are handled gracefully
# Returns appropriate error taxonomy and verdict
```

### Missing Configuration
```python
# Missing API key raises configuration error
config = WorkerConfig()  # No secrets
# Raises: "Cylance API key is required"
```

## Examples

### Command Line Usage

```bash
# Run the example script
python examples/analyzers/cylance_example.py \
    --data "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" \
    --data-type "hash" \
    --execute
```

### Batch Processing

```python
from sentineliqsdk.analyzers.cylance import CylanceAnalyzer
from sentineliqsdk import WorkerInput, WorkerConfig

def analyze_hashes_batch(hashes: list[str]) -> list[dict]:
    """Analyze multiple hashes in batch."""
    
    config = WorkerConfig(
        secrets={
            "cylance": {
                "api_key": "your_api_key"
            }
        }
    )
    
    results = []
    
    for hash_value in hashes:
        input_data = WorkerInput(
            data_type="hash",
            data=hash_value,
            config=config
        )
        
        analyzer = CylanceAnalyzer(input_data)
        result = analyzer.run()
        
        results.append({
            "hash": hash_value,
            "verdict": result.full_report["verdict"],
            "threat_found": result.full_report.get("threat_found", False)
        })
    
    return results

# Example usage
hashes = [
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "d41d8cd98f00b204e9800998ecf8427e"
]

results = analyze_hashes_batch(hashes)
for result in results:
    print(f"{result['hash']}: {result['verdict']}")
```

## Integration with Pipelines

```python
from sentineliqsdk.pipelines import SecurityPipeline
from sentineliqsdk.analyzers.cylance import CylanceAnalyzer

# Create a pipeline with Cylance analyzer
pipeline = SecurityPipeline()
pipeline.add_analyzer(CylanceAnalyzer)

# Process data through pipeline
result = pipeline.process(
    data="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    data_type="hash"
)
```

## Troubleshooting

### Common Issues

1. **API Key Issues**
   ```
   Error: Cylance API key is required
   ```
   - Ensure API key is properly configured in secrets
   - Verify API key is valid and active

2. **Invalid Hash Format**
   ```
   Verdict: info (Hash inválido)
   ```
   - Ensure hash is exactly 64 hexadecimal characters
   - Verify hash is SHA256 format

3. **Network Connectivity**
   ```
   Error: Connection timeout
   ```
   - Check internet connectivity
   - Verify Cylance API endpoints are accessible
   - Consider increasing timeout configuration

### Debug Mode

```python
config = WorkerConfig(
    secrets={
        "cylance": {
            "api_key": "your_api_key"
        }
    },
    **{
        "cylance.debug": True  # Enable debug logging
    }
)
```

## API Reference

### CylanceAnalyzer Class

```python
class CylanceAnalyzer(Analyzer):
    """Cylance ThreatZERO hash analyzer."""
    
    def execute(self) -> AnalyzerReport:
        """Execute the Cylance hash analysis."""
        pass
    
    def run(self) -> AnalyzerReport:
        """Run the analyzer and return results."""
        pass
```

### Methods

- **`execute()`**: Core analysis logic
- **`run()`**: Main entry point for analysis
- **`get_data()`**: Retrieve input data
- **`get_secret()`**: Access API credentials
- **`get_config()`**: Access configuration settings
- **`build_taxonomy()`**: Create taxonomy entries
- **`report()`**: Generate analysis report

## Security Considerations

- **API Key Protection**: Store API keys securely using WorkerConfig.secrets
- **Data Privacy**: Hash values are sent to Cylance API for analysis
- **Rate Limiting**: Respect Cylance API rate limits
- **TLP/PAP Compliance**: Configure appropriate TLP/PAP levels

## License

This analyzer is part of the SentinelIQ SDK and follows the same licensing terms.

## Support

For issues and support:
- GitHub Issues: [SentinelIQ SDK Issues](https://github.com/killsearch/sentineliqsdk/issues)
- Documentation: [SentinelIQ SDK Docs](https://killsearch.github.io/sentineliqsdk/)
- Email: team@sentineliq.com.br