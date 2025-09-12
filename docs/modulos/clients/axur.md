# Axur Client

The `AxurClient` provides a comprehensive HTTP client for interacting with the Axur Platform API. It implements all documented routes generically and includes convenience wrappers for common operations.

## Overview

The Axur client is built on top of `httpx` and provides:

- **Generic API calls** via the `call()` method for any HTTP method/path
- **Convenience wrappers** for common API operations
- **Automatic authentication** using Bearer token
- **Proxy support** via environment variables
- **Dry-run capability** for testing without making actual requests

## Authentication

The client requires an Axur API token for authentication:

```python
from sentineliqsdk.clients.axur import AxurClient

client = AxurClient(api_token="your-axur-api-token")
```

## Basic Usage

### Generic API Calls

Use the `call()` method for any API endpoint:

```python
# GET request
response = client.call("GET", "/customers/customers")

# POST request with JSON body
response = client.call(
    "POST", 
    "/tickets-api/tickets",
    RequestOptions(json_body={"title": "New Ticket", "description": "Issue description"})
)

# GET request with query parameters
response = client.call(
    "GET",
    "/identity/users",
    RequestOptions(query={"pageSize": 50, "offset": 0})
)
```

### Dry Run Mode

Test your requests without making actual API calls:

```python
response = client.call(
    "GET",
    "/tickets-api/tickets",
    RequestOptions(dry_run=True)
)
# Returns: {"dry_run": True, "method": "GET", "url": "...", "headers": {...}, "body": None}
```

## Convenience Methods

### User Management

```python
# Get list of customers
customers = client.customers()

# Get users with filters
users = client.users(
    customers="customer-id",
    access_to_areas="area-name",
    free_text="search term",
    page_size=100
)

# Get user stream
user_stream = client.users_stream(
    customers="customer-id",
    page_size=50
)
```

### Ticket Operations

```python
# Search tickets
tickets = client.tickets_search({
    "status": "open",
    "priority": "high",
    "page": 1
})

# Create a new ticket
new_ticket = client.ticket_create({
    "title": "Security Alert",
    "description": "Suspicious activity detected",
    "priority": "high"
})

# Get specific ticket
ticket = client.ticket_get("TICKET-123")

# Get ticket texts
texts = client.ticket_texts("TICKET-123")

# Get tickets by keys
tickets = client.tickets_by_keys("TICKET-123,TICKET-456")
```

### Filter Operations

```python
# Create a filter
filter_result = client.filter_create({
    "name": "High Priority Tickets",
    "query": "priority:high AND status:open"
})

# Get filter results
results = client.filter_results(
    query_id="filter-id",
    page=1,
    page_size=50,
    sort_by="created_date",
    order="desc"
)
```

### Integration Feeds

```python
# Get integration feed
feed = client.integration_feed("feed-id")

# Get integration feed with dry-run parameter
feed = client.integration_feed("feed-id", dry_run_param=True)
```

### Ticket Types

```python
# Get available ticket types
types = client.ticket_types()
```

## Configuration

### Custom Base URL

```python
client = AxurClient(
    api_token="your-token",
    base_url="https://custom.axur.com/api"
)
```

### Timeout Settings

```python
client = AxurClient(
    api_token="your-token",
    timeout=60.0  # 60 seconds timeout
)
```

### Custom User Agent

```python
client = AxurClient(
    api_token="your-token",
    user_agent="MyApp/1.0"
)
```

## Error Handling

The client raises `httpx.HTTPStatusError` for HTTP errors (status >= 400):

```python
from httpx import HTTPStatusError

try:
    response = client.ticket_get("INVALID-TICKET")
except HTTPStatusError as e:
    print(f"HTTP Error: {e}")
    print(f"Status Code: {e.response.status_code}")
    print(f"Response: {e.response.text}")
```

## Proxy Support

O cliente respeita automaticamente as configurações de proxy definidas via `WorkerConfig.proxy` (o SDK exporta internamente para variáveis de ambiente quando necessário para bibliotecas stdlib):

```python
from sentineliqsdk import WorkerConfig
from sentineliqsdk.clients.axur import AxurClient

config = WorkerConfig()
config.set_config("proxy.http", "http://proxy.company.com:8080")
config.set_config("proxy.https", "https://proxy.company.com:8080")

client = AxurClient(api_token="your-token", config=config)
```

## Request Options

The `RequestOptions` dataclass provides fine-grained control over requests:

```python
from sentineliqsdk.clients.axur import RequestOptions

options = RequestOptions(
    query={"page": 1, "size": 50},           # Query parameters
    headers={"X-Custom-Header": "value"},    # Custom headers
    json_body={"key": "value"},              # JSON request body
    data={"form": "data"},                   # Form data
    dry_run=True                             # Dry run mode
)

response = client.call("POST", "/endpoint", options)
```

## Response Handling

The client automatically parses JSON responses and returns the appropriate data type:

```python
# JSON responses return dict/list
json_response = client.customers()  # Returns dict or list

# Non-JSON responses return string
text_response = client.call("GET", "/endpoint/that/returns/text")
```

## Rate Limiting

The Axur API has rate limits. The client doesn't implement automatic rate limiting, so you should handle this in your application:

```python
import time

def make_request_with_retry(client, method, path, max_retries=3):
    for attempt in range(max_retries):
        try:
            return client.call(method, path)
        except HTTPStatusError as e:
            if e.response.status_code == 429:  # Rate limited
                time.sleep(2 ** attempt)  # Exponential backoff
                continue
            raise
    raise Exception("Max retries exceeded")
```

## Complete Example

```python
from sentineliqsdk.clients.axur import AxurClient, RequestOptions

def main():
    # Initialize client
    client = AxurClient(api_token="your-axur-api-token")
    
    try:
        # Get customers
        customers = client.customers()
        print(f"Found {len(customers)} customers")
        
        # Search for high priority tickets
        tickets = client.tickets_search({
            "priority": "high",
            "status": "open",
            "page": 1
        })
        print(f"Found {len(tickets.get('results', []))} high priority tickets")
        
        # Create a new ticket
        new_ticket = client.ticket_create({
            "title": "Security Investigation",
            "description": "Automated security alert from SentinelIQ",
            "priority": "medium",
            "type": "security"
        })
        print(f"Created ticket: {new_ticket.get('key')}")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
```

## API Reference

### AxurClient

::: sentineliqsdk.clients.axur.AxurClient

### RequestOptions

::: sentineliqsdk.clients.axur.RequestOptions

## Related Documentation

- [Axur Platform API Documentation](https://docs.axur.com/en/axur/api/openapi-axur.yaml)
- [Axur Analyzer](../analyzers/axur.md) - High-level analyzer using this client
- [HTTPX Client Pattern Guide](../../guides/httpx-client.md) - General patterns for HTTP clients
