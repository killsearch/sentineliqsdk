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
  - Set `http_proxy`/`https_proxy` env vars or configure `WorkerInput.config.proxy`.
  - The Worker applies proxies to the environment on init.

- Example prints plan only (no network)
  - Add `--execute` to perform real network calls.
  - Some operations also require `--include-dangerous`.

- Missing credentials
  - Shodan: set `SHODAN_API_KEY` or pass `--api-key` to the example.
  - Axur: set `AXUR_API_TOKEN` or pass `--token`.

- MkDocs build errors
  - Ensure dev dependencies are installed: `pip install -e .[dev]` or `uv sync --dev`.
  - Run `poe docs` and review warnings with `--strict` enabled.
