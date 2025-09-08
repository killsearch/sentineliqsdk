# Cluster25 Client

The `Cluster25Client` provides a simple interface to the Cluster25 threat intelligence API.
It handles authentication and offers a convenience method for indicator investigations.

## Configuration

```python
from sentineliqsdk.clients.cluster25 import Cluster25Client

client = Cluster25Client(
    client_id="your-client-id",
    client_key="your-client-key",
    base_url="https://api.cluster25.com",
    timeout=30,
    max_retries=3,
)
```

Arguments:

- `client_id` / `client_key`: credentials provided by Cluster25
- `base_url`: API endpoint, defaults to the Cluster25 URL
- `timeout`: request timeout in seconds
- `max_retries`: retry attempts for authentication

## Usage Example

```python
result = client.investigate("1.2.3.4")
print(result.get("score"))
```

## API Reference

::: sentineliqsdk.clients.cluster25.Cluster25Client

## Related Documentation

- [Cluster25 Analyzer](../analyzers/cluster25.md)
- [HTTPX Client Pattern Guide](../../guides/httpx-client.md)
