---
title: Agent Guide
---

# SentinelIQ SDK — Agent Guide

This document shows how to build analyzers and responders using the SentinelIQ SDK in
`src/sentineliqsdk`. It summarizes the public API and provides usage examples you can copy
into your own agents.

> Requirements: Python 3.13, absolute imports, 4‑space indentation, line length 100.

## Modules Overview

- `sentineliqsdk.Worker`: common base for analyzers/responders (IO, config, reporting).
- `sentineliqsdk.Analyzer`: base class for analyzers; auto‑extraction support.
- `sentineliqsdk.Responder`: base class for responders.
- `sentineliqsdk.Extractor`: stdlib‑based IOC extractor (ip/url/hash/...).
- `sentineliqsdk.runner(worker_cls)`: helper to instantiate and run a worker.

Internal layout (for maintainers):
- `sentineliqsdk/core/worker.py` implements `Worker` (composition over helpers).
- `sentineliqsdk/analyzers/base.py` implements `Analyzer`.
- `sentineliqsdk/responders/base.py` implements `Responder`.
- `sentineliqsdk/extractors/regex.py` implements `Extractor`.
- `sentineliqsdk/core/config/proxy.py` sets env proxies (`EnvProxyConfigurator`).
- `sentineliqsdk/core/config/secrets.py` sanitizes error payload config.

## Input/Output Contract

Workers receive input data directly as a dictionary and output results to STDOUT or return them in memory.

- Input: Data is passed directly to the worker constructor as a dictionary.
- Output: JSON is printed to STDOUT or returned in memory via `report_in_memory()`.

Common input fields in the input data dictionary:

- `dataType`: one of `ip`, `url`, `domain`, `hash`, `file`, ...
- `data` or `filename`: observable value or filename for `dataType == "file"`.
- `tlp` and `pap`: numbers; optionally enforced via config (see below).
- `config.*`: agent configuration, including:
  - `config.check_tlp` / `config.max_tlp`
  - `config.check_pap` / `config.max_pap`
  - `config.proxy.http` / `config.proxy.https` (exported to env as `http_proxy`/`https_proxy`)
  - `config.auto_extract` for analyzers

On error, sensitive keys in `config` containing any of `key`, `password`, `secret` are
replaced with `"REMOVED"` in the error payload.

## Core Base: Worker

Signature: `Worker(input_data: dict[str, Any], secret_phrases: tuple[str, ...] | None)`

- `get_param(name: str, default=None, message: str | None = None) -> Any`:
  dotted access into the input JSON; exits with `error(message)` if missing and `message` set.
- `get_env(key: str, default=None, message: str | None = None) -> str | None`:
  reads environment variables; can exit with `error` when `message` is provided.
- `get_data() -> Any`: returns the observable value (overridden in subclasses).
- `build_operation(op_type: str, **parameters) -> dict`: describe follow‑up operations.
- `operations(raw: Any) -> list[dict]`: hook returning a list of operations; default `[]`.
- `summary(raw: Any) -> dict`: short summary hook; default `{}`.
- `artifacts(raw: Any) -> list[dict]`: artifact hook; default `[]` (Analyzer overrides).
- `report(output: dict, ensure_ascii: bool = False) -> None`: write output JSON.
- `error(message: str, ensure_ascii: bool = False) -> NoReturn`: write error JSON and exit(1).
- `run() -> None`: your main logic (override in subclasses).

TLP/PAP enforcement:

- Enable with `config.check_tlp`/`config.check_pap`; set `config.max_tlp`/`config.max_pap`.
- If exceeded, the worker calls `error("TLP is higher than allowed.")` or PAP equivalent.

## Analyzer

`Analyzer` extends `Worker` with analyzer‑specific behavior:

- `get_data()`: returns filename when `dataType == "file"`, otherwise the `data` field.
- `get_param("file")`: when `dataType == "file"`, returns the `filename` value.
- `auto_extract`: enabled by default unless `config.auto_extract` is `false`.
- `artifacts(raw)`: when `auto_extract` is enabled, uses `Extractor(ignore=self.get_data())`
  to extract IOCs from the full report.
- `build_taxonomy(level, namespace, predicate, value) -> dict`: helper for taxonomy entries
  where `level` is one of `info|safe|suspicious|malicious`.
- `build_artifact(data_type, data, **kwargs) -> dict`:
  - For `data_type == "file"`, returns a dict with `dataType`, `filename`, plus extra fields in `kwargs`.
  - For other types, returns `{"dataType": data_type, "data": data, **kwargs}`.
- `report(full_report: dict)` returns output as:
  `{"success": true, "summary": ..., "artifacts": ..., "operations": ..., "full": ...}`.

Note: Legacy compatibility helpers have been removed. Use the modern API only:
- Use `get_data()` instead of `getData()`.
- Use `get_param()` instead of `getParam(...)`.
- TLP/PAP checks run automatically; do not use `checkTlp(...)`.
- Handle unsupported datatypes with `error(...)` as needed.

### Migration Notes

- Import from top-level: `from sentineliqsdk import Analyzer, Responder, Worker, Extractor`.
- The legacy modules `sentineliqsdk.analyzer`, `sentineliqsdk.responder`,
  `sentineliqsdk.worker`, and `sentineliqsdk.extractor` were removed.
- Replace `config.auto_extract_artifacts` by `config.auto_extract`.

## Responder

`Responder` mirrors `Analyzer` but with a simpler `report` shape:

- `get_data()`: returns the `data` field.
- `report(full_report)` returns
  `{"success": true, "full": full_report, "operations": [...]}`.

## Extractor

IOC extractor using Python's standard library helpers (e.g., `ipaddress`, `urllib.parse`,
`email.utils`) instead of complex regexes. Typical types detected:

- `ip` (IPv4 and IPv6), `url`, `domain`, `fqdn`, `hash` (MD5/SHA1/SHA256), `mail`,
  `user-agent`, `uri_path`, `registry`.

API:

- `Extractor(ignore: str | None = None)`
- `check_string(value: str) -> str`: returns a data type or empty string.
- `check_iterable(iterable: list | dict | str) -> list[dict]`: returns
  `[ {"dataType": <type>, "data": <value>}, ... ]` with de‑duplicated results.

## Minimal Analyzer Example

```python
from __future__ import annotations

from sentineliqsdk import Analyzer, runner


class ReputationAnalyzer(Analyzer):
    """Toy analyzer that marks "1.2.3.4" as malicious and others as safe."""

    def run(self) -> None:
        observable = self.get_data()

        verdict = "malicious" if observable == "1.2.3.4" else "safe"
        full = {
            "observable": observable,
            "verdict": verdict,
            "taxonomy": [
                self.build_taxonomy(
                    level=verdict,
                    namespace="reputation",
                    predicate="static",
                    value=str(observable),
                )
            ],
        }

        self.report(full)


if __name__ == "__main__":
    input_data = {
        "dataType": "ip",
        "data": "1.2.3.4",
        "tlp": 2,
        "pap": 2,
        "config": {"auto_extract": True}
    }
    runner(ReputationAnalyzer, input_data)
```

## Minimal Responder Example

```python
from __future__ import annotations

from sentineliqsdk import Responder, runner


class BlockIpResponder(Responder):
    def run(self) -> None:
        ip = self.get_data()
        # Here you would call your firewall API
        result = {"action": "block", "target": ip, "status": "ok"}
        self.report(result)


if __name__ == "__main__":
    input_data = {
        "dataType": "ip",
        "data": "1.2.3.4",
        "tlp": 2,
        "pap": 2
    }
    runner(BlockIpResponder, input_data)
```

## Example Input and Output

Input data dictionary:

```json
{
  "dataType": "ip",
  "data": "1.2.3.4",
  "tlp": 2,
  "pap": 2,
  "config": {
    "check_tlp": true,
    "max_tlp": 2,
    "auto_extract": true
  }
}
```

Analyzer output (returned as dict):

```json
{
  "success": true,
  "summary": {},
  "artifacts": [],
  "operations": [],
  "full": {
    "observable": "1.2.3.4",
    "verdict": "malicious",
    "taxonomy": [
      {
        "level": "malicious",
        "namespace": "reputation",
        "predicate": "static",
        "value": "1.2.3.4"
      }
    ]
  }
}
```

On an error, the worker returns:

```json
{ "success": false, "input": { ... }, "errorMessage": "<reason>" }
```

## Operations and Artifacts

- Use `build_operation("<type>", **params)` and return a list from `operations(full_report)`
  to trigger follow‑up work.
- Build artifacts in analyzers with `build_artifact("file", "filename.txt")` or with
  non‑file types: `build_artifact("ip", "8.8.8.8", tlp=2)`.
- When `auto_extract` is enabled (default), `artifacts(full_report)` uses `Extractor` to
  detect IOCs in the report, excluding the original observable value.

## Running and Debugging

- Direct usage: Create input data dictionary and pass to worker constructor.
- Proxies: set `config.proxy.http` / `config.proxy.https` or environment variables.

## Programmatic Usage

You can use the SDK directly in your code by passing input data directly to the constructor:

```python
from sentineliqsdk import Analyzer

class MyAnalyzer(Analyzer):
    def run(self) -> None:
        observable = self.get_data()
        # Your analysis logic here
        result = {"observable": observable, "verdict": "safe"}
        self.report(result)

# Create input data directly
input_data = {
    "dataType": "ip",
    "data": "1.2.3.4",
    "tlp": 2,
    "pap": 2,
    "config": {"auto_extract": True}
}

# Use analyzer
analyzer = MyAnalyzer(input_data)
analyzer.run()
```

### Getting Results

The `report()` method returns results directly in memory:

```python
# Get result directly in memory
result = analyzer.report(full_report)
print(f"Analysis result: {result}")
```

### Batch Processing

Process multiple observables:

```python
observables = ["1.2.3.4", "8.8.8.8", "5.6.7.8"]
results = []

for obs in observables:
    input_data = {
        "dataType": "ip",
        "data": obs,
        "tlp": 2,
        "config": {"auto_extract": True}
    }
    
    analyzer = MyAnalyzer(input_data)
    # Process and get result in memory
    result = analyzer.report(full_report)
    results.append(result)
```

## Project and CI Tips

- Lint and type check: `poe lint` (ruff + mypy).
- Tests: `poe test` (pytest with coverage to `reports/`).
- Docs: `poe docs` generates API docs to `docs/`.
- Build: `uv build`; publish via CI on GitHub release.

## Releases (CI/CD)

This repository publishes to PyPI via GitHub Actions when you create a GitHub Release.

- Workflow: see `.github/workflows/publish.yml` (runs `uv build` then `uv publish`).
- Auth: GitHub OIDC (`permissions: id-token: write`) with a PyPI Trusted Publisher.
- Trigger: GitHub Release for a tag like `vX.Y.Z`.

Release checklist (maintainers):

1. Ensure `main` is green
   - Open a PR and wait for the "Test" workflow to pass.
   - Merge to `main` once lint, types, and tests pass.
2. Bump version and changelog with Commitizen
   - Recommended (uses the project env): `uv run cz bump`
   - Non‑interactive examples:
     - Patch: `uv run cz bump --increment patch`
     - Minor: `uv run cz bump --increment minor`
     - Major: `uv run cz bump --increment major`
   - Pre‑releases:
     - First RC: `uv run cz bump --prerelease rc`
     - Next RC: `uv run cz bump --prerelease rc`
     - RC for next minor: `uv run cz bump --increment minor --prerelease rc`
   - Commitizen updates `[project].version` in `pyproject.toml`, updates `CHANGELOG.md`,
     creates the tag `vX.Y.Z` and commits the change (per `[tool.commitizen]`).
3. Push branch and tags
   - `git push origin main --follow-tags`
   - If your local branch is behind: `git pull --rebase origin main` then push again.
4. Create a GitHub Release for the new tag
   - UI: Releases → New release → Choose tag `vX.Y.Z` → Publish.
   - CLI: `gh release create vX.Y.Z --title "vX.Y.Z" --notes-file CHANGELOG.md --latest`
5. CI publishes to PyPI
   - The "Publish" workflow runs and calls `uv publish` using OIDC.
   - Acompanhe em Actions → Publish (ou `gh run list --workflow=Publish`).
6. Verify the release
   - `pip install sentineliqsdk==X.Y.Z`
   - `python -c "import importlib.metadata as m; print(m.version('sentineliqsdk'))"`

Prerequisites (one-time, org/maintainers):

- Configure a PyPI Trusted Publisher for this repo:
  - PyPI: Project → Settings → Collaboration → Trusted Publishers → Add → GitHub
    - Repository: `killsearch/sentineliqsdk`
    - Workflows: allow `.github/workflows/publish.yml`
  - No classic API tokens; OIDC is granted by `id-token: write`.
- Optional: protect the `pypi` environment in GitHub with required reviewers.

Notes and tips:

- Tag format is `v$version` (Commitizen config); it must match `pyproject.toml`.
- Mark GitHub Releases as "Pre-release" when publishing RCs (`X.Y.Z-rc.N`).
- If the Publish job fails with a PyPI permission error, review the Trusted Publisher
  settings and the workflow `permissions`.
