# Shodan Client

The `ShodanClient` provides a comprehensive HTTP client for interacting with the Shodan REST API. It implements all documented endpoints and provides both generic and convenience methods for common operations.

## Overview

The Shodan client is built on top of `httpx` and provides:

- **Complete API coverage** for all Shodan endpoints
- **Automatic API key injection** as query parameter
- **Proxy support** via environment variables
- **Type-safe responses** with automatic JSON parsing
- **Comprehensive error handling**

## Authentication

The client requires a Shodan API key for authentication:

```python
from sentineliqsdk.clients.shodan import ShodanClient

client = ShodanClient(api_key="your-shodan-api-key")
```

## Basic Usage

### Search Operations

```python
# Get host information for an IP
host_info = client.host_information("8.8.8.8")

# Search for hosts
search_results = client.search_host("apache", page=1)

# Get count of matching hosts
count = client.search_host_count("apache")

# Get search facets and filters
facets = client.search_host_facets()
filters = client.search_host_filters()

# Get search tokens for query parsing
tokens = client.search_host_tokens("apache port:80")
```

### On-Demand Scanning

```python
# Start a scan for specific IPs
scan_result = client.scan("8.8.8.8,1.1.1.1")

# Start internet scan for specific port/protocol
internet_scan = client.scan_internet(port=80, protocol="http")

# Get list of scans
scans = client.scans()

# Get specific scan details
scan_details = client.scan_by_id("scan-id")
```

### Network Alerts

```python
# Create a network alert
alert = client.alert_create(
    name="My Network Alert",
    ips=["8.8.8.8", "1.1.1.1"],
    expires=86400  # 24 hours
)

# Get all alerts
alerts = client.alerts()

# Get specific alert info
alert_info = client.alert_info("alert-id")

# Edit alert IPs
client.alert_edit("alert-id", ["8.8.8.8", "1.1.1.1", "9.9.9.9"])

# Delete alert
client.alert_delete("alert-id")
```

### Alert Triggers and Notifications

```python
# Get available triggers
triggers = client.alert_triggers()

# Enable/disable triggers
client.alert_enable_trigger("alert-id", "new_service")
client.alert_disable_trigger("alert-id", "new_service")

# Whitelist/unwhitelist services
client.alert_whitelist_service("alert-id", "new_service", 80)
client.alert_unwhitelist_service("alert-id", "new_service", 80)

# Manage notifiers
notifiers = client.notifiers()
client.alert_add_notifier("alert-id", "notifier-id")
client.alert_remove_notifier("alert-id", "notifier-id")
```

### Notifiers

```python
# Get notifier providers
providers = client.notifier_providers()

# Create notifier
notifier = client.notifier_create(
    provider="email",
    args={"email": "admin@example.com"}
)

# Get/update/delete notifiers
notifier_info = client.notifier_get("notifier-id")
client.notifier_update("notifier-id", "email", {"email": "new@example.com"})
client.notifier_delete("notifier-id")
```

### DNS Operations

```python
# Get DNS domain information
domain_info = client.dns_domain("example.com")

# Resolve hostnames to IPs
resolved = client.dns_resolve(["example.com", "google.com"])
# Or single hostname
resolved = client.dns_resolve("example.com")

# Reverse DNS lookup
reverse = client.dns_reverse(["8.8.8.8", "1.1.1.1"])
# Or single IP
reverse = client.dns_reverse("8.8.8.8")
```

### Directory and Queries

```python
# Get queries
queries = client.queries(page=1, sort="votes", order="desc")

# Search queries
search_results = client.query_search("apache", page=1)

# Get query tags
tags = client.query_tags(size=100)
```

### Utility Methods

```python
# Get available ports and protocols
ports = client.ports()
protocols = client.protocols()

# Get HTTP headers tool
headers = client.tools_httpheaders()

# Get your public IP
my_ip = client.tools_myip()

# Get API information
api_info = client.api_info()
```

### Account and Organization

```python
# Get account profile
profile = client.account_profile()

# Organization methods (Enterprise only)
org_info = client.org()
client.org_member_update("username")
client.org_member_remove("username")
```

### Bulk Data (Enterprise)

```python
# Get available datasets
datasets = client.data_datasets()

# Get specific dataset
dataset = client.data_dataset("dataset-name")
```

## Configuration

### Custom Base URL

```python
client = ShodanClient(
    api_key="your-key",
    base_url="https://api.shodan.io"
)
```

### Timeout Settings

```python
client = ShodanClient(
    api_key="your-key",
    timeout=60.0  # 60 seconds timeout
)
```

### Custom User Agent

```python
client = ShodanClient(
    api_key="your-key",
    user_agent="MyApp/1.0"
)
```

## Error Handling

The client raises `httpx.HTTPStatusError` for HTTP errors (status >= 400):

```python
from httpx import HTTPStatusError

try:
    response = client.host_information("invalid-ip")
except HTTPStatusError as e:
    print(f"HTTP Error: {e}")
    print(f"Status Code: {e.response.status_code}")
    print(f"Response: {e.response.text}")
```

## Proxy Support

The client automatically respects HTTP proxy settings from environment variables:

```python
import os

# Set proxy via environment
os.environ["http_proxy"] = "http://proxy.company.com:8080"
os.environ["https_proxy"] = "https://proxy.company.com:8080"

# Client will automatically use these proxies
client = ShodanClient(api_key="your-key")
```

## Request Options

The `RequestOptions` dataclass provides fine-grained control over requests:

```python
from sentineliqsdk.clients.shodan import RequestOptions

# GET request with query parameters
response = client._get("/shodan/host/search", query={"query": "apache", "page": 1})

# POST request with JSON body
response = client._post("/shodan/scan", json_body={"ips": "8.8.8.8"})

# Custom headers
response = client._get("/api-info", headers={"X-Custom": "value"})
```

## Response Handling

The client automatically parses JSON responses and returns the appropriate data type:

```python
# JSON responses return dict/list
json_response = client.host_information("8.8.8.8")  # Returns dict

# Non-JSON responses return string
text_response = client.tools_myip()  # Returns string
```

## Rate Limiting

Shodan has rate limits based on your subscription level. The client doesn't implement automatic rate limiting:

```python
import time

def make_request_with_retry(client, method, *args, max_retries=3):
    for attempt in range(max_retries):
        try:
            return method(*args)
        except HTTPStatusError as e:
            if e.response.status_code == 429:  # Rate limited
                time.sleep(2 ** attempt)  # Exponential backoff
                continue
            raise
    raise Exception("Max retries exceeded")

# Usage
result = make_request_with_retry(client, client.host_information, "8.8.8.8")
```

## Complete Example

```python
from sentineliqsdk.clients.shodan import ShodanClient

def main():
    # Initialize client
    client = ShodanClient(api_key="your-shodan-api-key")
    
    try:
        # Get your public IP
        my_ip = client.tools_myip()
        print(f"Your public IP: {my_ip}")
        
        # Get host information
        host_info = client.host_information("8.8.8.8")
        print(f"Host: {host_info.get('ip_str')}")
        print(f"Organization: {host_info.get('org')}")
        
        # Search for Apache servers
        search_results = client.search_host("apache", page=1)
        print(f"Found {len(search_results.get('matches', []))} Apache servers")
        
        # Create a network alert
        alert = client.alert_create(
            name="My Network Monitor",
            ips=["8.8.8.8", "1.1.1.1"]
        )
        print(f"Created alert: {alert.get('id')}")
        
        # Get available ports
        ports = client.ports()
        print(f"Available ports: {len(ports)}")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
```

## Advanced Usage

### Batch Operations

```python
# Process multiple IPs
ips = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
results = []

for ip in ips:
    try:
        host_info = client.host_information(ip)
        results.append({
            "ip": ip,
            "org": host_info.get("org"),
            "ports": [port.get("port") for port in host_info.get("data", [])]
        })
    except Exception as e:
        results.append({"ip": ip, "error": str(e)})

print(results)
```

### Custom Search Queries

```python
# Build complex search queries
queries = [
    "apache port:80",
    "nginx port:443",
    "country:US product:apache",
    "org:Google port:80"
]

for query in queries:
    try:
        count = client.search_host_count(query)
        print(f"Query '{query}': {count} results")
    except Exception as e:
        print(f"Error with query '{query}': {e}")
```

## API Reference

### ShodanClient

::: sentineliqsdk.clients.shodan.ShodanClient

### RequestOptions

::: sentineliqsdk.clients.shodan.RequestOptions

## Related Documentation

- [Shodan API Documentation](https://developer.shodan.io/api/openapi.json)
- [Shodan Analyzer](../analyzers/shodan.md) - High-level analyzer using this client
- [HTTPX Client Pattern Guide](../../guides/httpx-client.md) - General patterns for HTTP clients
