# Examples: Threat Intelligence

This section shows runnable examples for common TI providers. Examples default to dry‑run and
print the planned request. Use `--execute` to perform real network calls. Dangerous actions
must be explicitly allowed with `--include-dangerous`.

Shodan (multi‑method harness):

```bash
# Set your API key or pass --api-key
export SHODAN_API_KEY=... 

python examples/analyzers/shodan_analyzer_all_methods.py            # plan only
python examples/analyzers/shodan_analyzer_all_methods.py --execute  # perform calls

# Run a subset of methods, include "dangerous" ones explicitly
python examples/analyzers/shodan_analyzer_all_methods.py \
  --only host_information,ports --execute

python examples/analyzers/shodan_analyzer_all_methods.py \
  --include-dangerous --only scan --execute
```

File: examples/analyzers/shodan_analyzer_all_methods.py

Axur (generic API caller):

```bash
# Set token or pass --token
export AXUR_API_TOKEN=...

# Use wrappers (e.g., customers, tickets_search)
python examples/analyzers/axur_example.py --method customers

# Arbitrary path via --method=call
python examples/analyzers/axur_example.py \
  --method call \
  --path tickets-api/tickets \
  --query '{"page":1}' \
  --execute
```

File: examples/analyzers/axur_example.py

Notes:

- Ensure proxies if required by your network: set `http_proxy`/`https_proxy` env vars or
  use `WorkerInput.config.proxy` in programmatic usage.
- Respect TLP/PAP defaults in your environment; see the Agent Guide for details.
