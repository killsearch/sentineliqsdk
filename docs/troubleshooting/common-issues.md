# Troubleshooting: Common Issues

- Lint failures (ruff/mypy)
  - Run `poe lint` and fix findings. Ensure imports are absolute and line length ≤ 100.
  - For typing errors, prefer adding precise types to dataclass fields and method returns.

- Tests failing
  - Run `poe test` locally and focus on the smallest failing unit first.
  - Use `-k <name>` to select specific tests.

- TLP/PAP error on startup
  - Message: `TLP is higher than allowed.` or `PAP is higher than allowed.`
  - Fix: lower `tlp`/`pap` in `WorkerInput` or increase `max_tlp`/`max_pap` in `WorkerConfig`.

- Network behind proxy
  - Configure `WorkerInput.config.proxy` (preferred). The Worker exports these to the process
    environment for stdlib HTTP clients.

- Example prints plan only (no network)
  - Add `--execute` to perform real network calls.
  - Some operations also require `--include-dangerous`.

- Missing credentials
  - Shodan: use `WorkerConfig.secrets['shodan']['api_key']` or pass `--api-key` to the example.
  - Axur: use `WorkerConfig.secrets['axur']['api_token']` or pass `--token`.

- MkDocs build errors
  - Ensure dev dependencies are installed: `pip install -e .[dev]` or `uv sync --dev`.
  - Run `poe docs` and review warnings with `--strict` enabled.
