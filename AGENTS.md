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
- `sentineliqsdk/core/io/output_writer.py` writes JSON output (`JsonOutputWriter`).
- `sentineliqsdk/core/runtime/encoding.py` ensures UTF‑8 streams.

## Input/Output Contract

Workers read a job either from a job directory or from STDIN and write results to the job
directory or STDOUT.

- Job directory mode: `<job_dir>/input/input.json` (and files for file observables).
- STDIN mode: if no job directory input exists, JSON is read from STDIN.
- Output: JSON is written to `<job_dir>/output/output.json` or STDOUT.

Common input fields inside `input.json`:

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

Signature: `Worker(job_directory: str | None, secret_phrases: tuple[str, ...] | None)`

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
- `get_param("file")`: when `dataType == "file"` and running with a job directory, resolves
  to an absolute path under `<job_dir>/input/<file>` if the file exists.
- `auto_extract`: enabled by default unless `config.auto_extract` is `false`.
- `artifacts(raw)`: when `auto_extract` is enabled, uses `Extractor(ignore=self.get_data())`
  to extract IOCs from the full report.
- `build_taxonomy(level, namespace, predicate, value) -> dict`: helper for taxonomy entries
  where `level` is one of `info|safe|suspicious|malicious`.
- `build_artifact(data_type, data, **kwargs) -> dict | None`:
  - For `data_type == "file"`, copies the file into `<job_dir>/output/` and returns a dict
    with `dataType`, `file`, `filename`, plus extra fields in `kwargs`.
  - For other types, returns `{"dataType": data_type, "data": data, **kwargs}`.
- `report(full_report: dict, ensure_ascii: bool = False)` wraps output as:
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
- `report(full_report, ensure_ascii=False)` writes
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
    runner(ReputationAnalyzer)
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
    runner(BlockIpResponder)
```

## Example Input and Output

Input (`<job_dir>/input/input.json`):

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

Analyzer output (`<job_dir>/output/output.json`):

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

On an error, the worker writes:

```json
{ "success": false, "input": { ... }, "errorMessage": "<reason>" }
```

## Operations and Artifacts

- Use `build_operation("<type>", **params)` and return a list from `operations(full_report)`
  to trigger follow‑up work.
- Build artifacts in analyzers with `build_artifact("file", "/path/to/file")` or with
  non‑file types: `build_artifact("ip", "8.8.8.8", tlp=2)`.
- When `auto_extract` is enabled (default), `artifacts(full_report)` uses `Extractor` to
  detect IOCs in the report, excluding the original observable value.

## Running and Debugging

- Job directory mode: `python my_agent.py /job` with `input/input.json` present.
- STDIN mode: `cat input.json | python my_agent.py`.
- Proxies: set `config.proxy.http` / `config.proxy.https` or environment variables.

## Project and CI Tips

- Lint and type check: `poe lint` (ruff + mypy).
- Tests: `poe test` (pytest with coverage to `reports/`).
- Docs: `poe docs` generates API docs to `docs/`.
- Build: `uv build`; publish via CI on GitHub release.

## Releases (CI/CD)

This repository publishes to PyPI via GitHub Actions when you create a GitHub Release.

- Workflow: see `.github/workflows/publish.yml` (runs `uv build` and `uv publish`).
- Auth: uses GitHub OIDC (permissions `id-token: write`) with a PyPI Trusted Publisher.
- Trigger: fires on GitHub Release creation for tags like `vX.Y.Z`.

Release checklist (maintainers):

1. Ensure `main` is green
   - Open a PR, wait for the "Test" workflow to pass on CI.
   - Merge to `main` once lint, type checks, and tests pass.
2. Bump version and changelog with Commitizen
   - From the repo root, run: `cz bump`
   - Choose the bump (patch/minor/major) according to Conventional Commits.
   - This updates `[project].version` in `pyproject.toml`, updates/creates `CHANGELOG.md`,
     creates a tag `vX.Y.Z`, and commits the changes.
   - Push branch and tags: `git push origin main --tags`.
3. Create a GitHub Release for the new tag
   - Via UI or CLI, e.g.: `gh release create vX.Y.Z --generate-notes`.
   - Title: `vX.Y.Z`. Link to the corresponding section in `CHANGELOG.md` if present.
4. CI publishes to PyPI
   - The "Publish" workflow builds artifacts and calls `uv publish` using OIDC.
   - Track the run under Actions → Publish; wait for a green check.
5. Verify the release
   - Install explicitly: `pip install sentineliqsdk==X.Y.Z`.
   - Sanity-check `import sentineliqsdk; print(sentineliqsdk.__version__)` if exposed.

Prerequisites (one-time, org/maintainers):

- Configure a PyPI Trusted Publisher for this repo:
  - On PyPI: Project → Settings → Collaboration → Trusted Publishers → Add → GitHub
    - Repository: `killsearch/sentineliqsdk`
    - Workflows: allow `.github/workflows/publish.yml`
  - No classic API tokens are needed; OIDC is handled by `id-token: write`.
- Optional: protect the `pypi` environment in GitHub with required reviewers if desired.

Notes and tips:

- Tag format is `v$version` (Commitizen config); ensure the tag matches `pyproject.toml`.
- For pre-releases, you can run `cz bump --prerelease rc` to create versions like
  `X.Y.Z-rc.1`. Mark the GitHub Release as "Pre-release" to signal stability level.
- If the Publish job fails with a PyPI permission error, double-check the Trusted
  Publisher configuration and that the workflow has `permissions: id-token: write`.
