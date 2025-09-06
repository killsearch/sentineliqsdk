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

Notes:

- Ensure proxies if required by your network: use `WorkerInput.config.proxy`.
- Respect TLP/PAP defaults in your environment; see the Agent Guide for details.
