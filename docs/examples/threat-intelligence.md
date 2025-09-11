# Examples: Threat Intelligence

This section shows runnable examples for common TI providers. Examples default to dry‑run and
print the planned request. Use `--execute` to perform real network calls. Dangerous actions
must be explicitly allowed with `--include-dangerous`.

Shodan (multi‑method harness):

```bash
python examples/analyzers/shodan_analyzer_all_methods.py --api-key YOUR_KEY           # plan only
python examples/analyzers/shodan_analyzer_all_methods.py --api-key YOUR_KEY --execute  # perform calls

# Run a subset of methods, include "dangerous" ones explicitly
python examples/analyzers/shodan_analyzer_all_methods.py \
  --api-key YOUR_KEY --only host_information,ports --execute

python examples/analyzers/shodan_analyzer_all_methods.py \
  --api-key YOUR_KEY --include-dangerous --only scan --execute
```

File: examples/analyzers/shodan_analyzer_all_methods.py

Axur (generic API caller):

```bash
# Use wrappers (e.g., customers, tickets_search)
python examples/analyzers/axur_example.py --token YOUR_TOKEN --method customers

# Arbitrary path via --method=call
python examples/analyzers/axur_example.py \
  --token YOUR_TOKEN \
  --method call \
  --path tickets-api/tickets \
  --query '{"page":1}' \
  --execute
```

File: examples/analyzers/axur_example.py

AbuseIPDB (IP reputation):

```bash
python examples/analyzers/abuseipdb_example.py --ip 1.2.3.4 --api-key YOUR_KEY           # plan only
python examples/analyzers/abuseipdb_example.py --ip 1.2.3.4 --api-key YOUR_KEY --execute  # perform call
```

File: examples/analyzers/abuseipdb_example.py

AutoFocus (Palo Alto Networks threat intelligence):

```bash
# Search for IP address (dry-run)
python examples/analyzers/autofocus_example.py --data-type ip --data 1.2.3.4 --service search_ioc

# Analyze hash sample (dry-run)
python examples/analyzers/autofocus_example.py --data-type hash --data abc123... --service get_sample_analysis

# Search for domain (dry-run)
python examples/analyzers/autofocus_example.py --data-type domain --data malicious.com --service search_ioc

# Execute real searches (requires API key)
python examples/analyzers/autofocus_example.py --data-type ip --data 1.2.3.4 --service search_ioc --execute

# Use specific API key
python examples/analyzers/autofocus_example.py \
  --data-type url \
  --data "https://malicious.com/payload.exe" \
  --service search_ioc \
  --apikey YOUR_API_KEY \
  --execute
```

File: examples/analyzers/autofocus_example.py

CIRCL Hashlookup (hash reputation and relationships):

```bash
# Basic hash lookup (dry-run)
python examples/analyzers/circl_hashlookup_example.py

# Execute all methods (no API key required - public service)
python examples/analyzers/circl_hashlookup_example.py --execute

# Run specific methods only
python examples/analyzers/circl_hashlookup_example.py \
  --execute --only lookup_md5,get_info

# Include session methods (potentially stateful)
python examples/analyzers/circl_hashlookup_example.py \
  --execute --include-dangerous --only create_session,get_session
```

File: examples/analyzers/circl_hashlookup_example.py

Notes:

- Ensure proxies if required by your network: use `WorkerInput.config.proxy`.
- Respect TLP/PAP defaults in your environment; see the Agent Guide for details.
- AutoFocus requires a valid API key for real searches; use `--apikey` or set `AUTOFOCUS_API_KEY` environment variable.
- CIRCL Hashlookup is a public service that doesn't require API keys; supports MD5, SHA1, SHA256, and SHA512 hashes.
