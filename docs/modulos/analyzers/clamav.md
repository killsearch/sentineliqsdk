# ClamAV Analyzer

The ClamAV Analyzer scans files for malware using the ClamAV antivirus engine. It connects to a local ClamAV daemon and performs real-time malware detection on files or file content.

## Features

- **File Scanning**: Scan files by path or content
- **Real-time Detection**: Uses ClamAV daemon for up-to-date threat detection
- **Multiple Input Types**: Supports both file paths and file content
- **Comprehensive Reporting**: Provides detailed taxonomy and metadata
- **Error Handling**: Robust error handling for connection and scan failures

## Installation

### Prerequisites

1. **ClamAV Daemon**: Install and configure ClamAV daemon
   ```bash
   # Ubuntu/Debian
   sudo apt-get install clamav clamav-daemon
   
   # CentOS/RHEL
   sudo yum install clamav clamd
   
   # Start the daemon
   sudo systemctl start clamav-daemon
   sudo systemctl enable clamav-daemon
   ```

2. **Python Dependencies**: Install required Python packages
   ```bash
   pip install pyclamd
   ```

### Configuration

The analyzer requires a running ClamAV daemon. By default, it connects to:
- **Socket Path**: `/var/run/clamav/clamd.ctl`
- **Timeout**: 30 seconds

You can customize these settings through the configuration:

```python
from sentineliqsdk import WorkerInput, WorkerConfig

config = WorkerConfig(
    check_tlp=True,
    max_tlp=2,
    check_pap=True,
    max_pap=2,
    auto_extract=True,
    params={
        "clamav.socket_path": "/custom/path/clamd.ctl",  # Custom socket path
        "clamav.timeout": 60                             # Custom timeout
    }
)
```

## Usage

### Basic File Scanning

```python
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.clamav import ClamavAnalyzer

# Scan a file by path
input_data = WorkerInput(
    data_type="file",
    data="file content",
    filename="/path/to/suspicious_file.exe",
    tlp=2,
    pap=2,
    config=WorkerConfig(
        check_tlp=True,
        max_tlp=2,
        check_pap=True,
        max_pap=2,
        auto_extract=True
    )
)

analyzer = ClamavAnalyzer(input_data)
report = analyzer.execute()

print(f"Verdict: {report.full_report['verdict']}")
if report.full_report['malware_name']:
    print(f"Malware: {report.full_report['malware_name']}")
```

### File Content Scanning

```python
# Scan file content directly
input_data = WorkerInput(
    data_type="file",
    data="malicious file content as string",
    tlp=2,
    pap=2,
    config=WorkerConfig(
        check_tlp=True,
        max_tlp=2,
        check_pap=True,
        max_pap=2,
        auto_extract=True
    )
)

analyzer = ClamavAnalyzer(input_data)
report = analyzer.execute()
```

### Custom Configuration

```python
# Custom ClamAV configuration
config = WorkerConfig(
    check_tlp=True,
    max_tlp=2,
    check_pap=True,
    max_pap=2,
    auto_extract=True,
    params={
        "clamav.socket_path": "/var/run/clamav/clamd.ctl",
        "clamav.timeout": 60
    }
)

input_data = WorkerInput(
    data_type="file",
    data="test content",
    filename="/path/to/file",
    tlp=2,
    pap=2,
    config=config
)

analyzer = ClamavAnalyzer(input_data)
report = analyzer.execute()
```

## Output Format

### Successful Scan (Clean File)

```json
{
  "success": true,
  "summary": {},
  "artifacts": [],
  "operations": [],
  "full_report": {
    "observable": "file content",
    "verdict": "safe",
    "malware_name": null,
    "taxonomy": [
      {
        "level": "safe",
        "namespace": "ClamAV",
        "predicate": "detection",
        "value": "No threats detected"
      }
    ],
    "metadata": {
      "name": "ClamAV Analyzer",
      "description": "Scans files for malware using ClamAV antivirus engine",
      "author": ["SentinelIQ Team <team@sentineliq.com.br>"],
      "pattern": "antivirus",
      "doc_pattern": "MkDocs module page; programmatic usage",
      "doc": "https://killsearch.github.io/sentineliqsdk/modulos/analyzers/clamav/",
      "version_stage": "TESTING"
    }
  }
}
```

### Successful Scan (Malware Detected)

```json
{
  "success": true,
  "summary": {},
  "artifacts": [],
  "operations": [],
  "full_report": {
    "observable": "file content",
    "verdict": "malicious",
    "malware_name": "EICAR-Test-File",
    "taxonomy": [
      {
        "level": "malicious",
        "namespace": "ClamAV",
        "predicate": "detection",
        "value": "EICAR-Test-File"
      }
    ],
    "metadata": {
      "name": "ClamAV Analyzer",
      "description": "Scans files for malware using ClamAV antivirus engine",
      "author": ["SentinelIQ Team <team@sentineliq.com.br>"],
      "pattern": "antivirus",
      "doc_pattern": "MkDocs module page; programmatic usage",
      "doc": "https://killsearch.github.io/sentineliqsdk/modulos/analyzers/clamav/",
      "version_stage": "TESTING"
    }
  }
}
```

### Error Response

```json
{
  "success": false,
  "input": {
    "data_type": "file",
    "data": "test content",
    "filename": "/path/to/file"
  },
  "errorMessage": "Failed to connect to ClamAV daemon at /var/run/clamav/clamd.ctl: Connection refused"
}
```

## Configuration Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `params["clamav.socket_path"]` | string | `/var/run/clamav/clamd.ctl` | Path to ClamAV daemon socket |
| `params["clamav.timeout"]` | integer | `30` | Connection timeout in seconds |
| `check_tlp` | boolean | `True` | Enable TLP checking |
| `max_tlp` | integer | `2` | Maximum allowed TLP level |
| `check_pap` | boolean | `True` | Enable PAP checking |
| `max_pap` | integer | `2` | Maximum allowed PAP level |
| `auto_extract` | boolean | `True` | Enable automatic IOC extraction |

## Taxonomy Levels

The analyzer uses the following taxonomy levels:

- **`safe`**: No threats detected
- **`malicious`**: Malware detected

## Error Handling

The analyzer handles various error conditions:

1. **Connection Errors**: When ClamAV daemon is not running or unreachable
2. **File Errors**: When specified files don't exist or are not accessible
3. **Scan Errors**: When ClamAV encounters errors during scanning
4. **Data Type Errors**: When non-file data types are provided

## Security Considerations

- **File Access**: The analyzer requires read access to files being scanned
- **Daemon Security**: Ensure ClamAV daemon is properly secured and updated
- **TLP/PAP Compliance**: Respects TLP and PAP restrictions when enabled
- **Error Sanitization**: Sensitive information is sanitized in error messages

## Troubleshooting

### Common Issues

1. **Connection Refused**
   ```
   Error: Failed to connect to ClamAV daemon at /var/run/clamav/clamd.ctl: Connection refused
   ```
   **Solution**: Ensure ClamAV daemon is running and socket path is correct

2. **Permission Denied**
   ```
   Error: File not found: /path/to/file
   ```
   **Solution**: Check file permissions and path correctness

3. **Timeout Errors**
   ```
   Error: Error scanning file: Timeout
   ```
   **Solution**: Increase timeout value or check daemon performance

### Debugging

Enable debug mode by setting a higher timeout and checking daemon status:

```python
config = WorkerConfig(
    params={
        "clamav.timeout": 120,  # Increase timeout
        "clamav.socket_path": "/var/run/clamav/clamd.ctl"
    }
)
```

Check ClamAV daemon status:
```bash
sudo systemctl status clamav-daemon
sudo clamdscan --version
```

## Examples

### Command Line Usage

```bash
# Run the example
python examples/analyzers/clamav_example.py --help

# Scan a file
python examples/analyzers/clamav_example.py --execute --file /path/to/file

# Test with EICAR
python examples/analyzers/clamav_example.py --execute --test-eicar

# Dry run mode (default)
python examples/analyzers/clamav_example.py --file /path/to/file
```

### Programmatic Usage

```python
import json
from sentineliqsdk import WorkerInput, WorkerConfig
from sentineliqsdk.analyzers.clamav import ClamavAnalyzer

# Configure and run
input_data = WorkerInput(
    data_type="file",
    data="test content",
    filename="/path/to/file",
    tlp=2,
    pap=2,
    config=WorkerConfig(
        check_tlp=True,
        max_tlp=2,
        check_pap=True,
        max_pap=2,
        auto_extract=True
    )
)

analyzer = ClamavAnalyzer(input_data)
report = analyzer.execute()

# Print results
print(json.dumps(report.full_report, ensure_ascii=False, indent=2))
```

## Related Documentation

- [ClamAV Official Documentation](https://www.clamav.net/documents)
- [pyclamd Documentation](https://pypi.org/project/pyclamd/)
- [SentinelIQ SDK Analyzer Guide](../guides/analyzers.md)
- [Configuration Patterns](../guides/configuration.md)

## Support

For issues and questions:
- Create an issue in the [SentinelIQ SDK repository](https://github.com/killsearch/sentineliqsdk)
- Check the [troubleshooting section](#troubleshooting)
- Review the [example code](https://github.com/killsearch/sentineliqsdk/blob/main/examples/analyzers/clamav_example.py)
