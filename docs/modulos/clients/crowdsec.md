# CrowdSec Client

The `CrowdSecClient` integrates with the CrowdSec CTI API to retrieve
threat intelligence for IP addresses.

## Configuration

```python
from sentineliqsdk.clients.crowdsec import CrowdSecClient

client = CrowdSecClient(api_key="your-api-key")
```

Arguments:

- `api_key`: key obtained from CrowdSec
- `base_url`: API endpoint, defaults to the public CTI service

## Usage Example

```python
try:
    summary = client.get_ip_summary("1.2.3.4")
    print(summary.get("ip"))
except CrowdSecRateLimitError:
    print("Rate limit exceeded")
```

## API Reference

::: sentineliqsdk.clients.crowdsec.CrowdSecClient

### Exceptions

::: sentineliqsdk.clients.crowdsec.CrowdSecAPIError
::: sentineliqsdk.clients.crowdsec.CrowdSecRateLimitError

## Related Documentation

- [CrowdSec Analyzer](../analyzers/crowdsec.md)
- [HTTPX Client Pattern Guide](../../guides/httpx-client.md)
