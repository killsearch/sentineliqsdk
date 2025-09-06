# SentinelIQ SDK — Agent Guide

This guide explains how to build analyzers and responders with the SentinelIQ SDK in
`src/sentineliqsdk`. It follows a sequential flow: setup → concepts → input/output → build
analyzers/responders → extraction → programmatic usage → CI/release.

Requirements: Python 3.13, absolute imports, 4‑space indentation, line length 100.

## Mandatory Examples (Agent Rule)

- Always create a runnable example in `examples/` whenever you add a new Analyzer, Responder,
  or Detector.
- Preferred naming: `examples/<kind>/<name>_example.py` where `<kind>` is one of
  `analyzers`, `responders`, or `detectors`.
- The example must:
  - Be executable locally without extra deps (only stdlib + SDK).
  - Use dataclass input (`WorkerInput`) and call `.run()` (or `.execute()` when provided).
  - Print a compact result to STDOUT. Network calls should default to dry‑run and require an
    `--execute` flag for real calls. For impactful operations (e.g., scans), gate behind an
    `--include-dangerous` flag.
- Link or reference the example in README or docs as appropriate.

## Scaffolding (Poe tasks)

- Generic: `poe new -- --kind <analyzer|responder|detector> --name <Name> [--force]`
- Shortcuts:
  - Analyzer: `poe new-analyzer -- --name Shodan`
  - Responder: `poe new-responder -- --name BlockIp`
  - Detector: `poe new-detector -- --name MyType`

Outputs (examples + code):
- Analyzer: `src/sentineliqsdk/analyzers/<snake>.py` and `examples/analyzers/<snake>_example.py`
- Responder: `src/sentineliqsdk/responders/<snake>.py` and `examples/responders/<snake>_example.py`
- Detector: `src/sentineliqsdk/extractors/custom/<snake>_detector.py` and `examples/detectors/<snake>_example.py`

## Quick Start

## Development Rules — Creating New Analyzer/Responder/Detector

Follow these rules to implement new components consistently. Each recipe includes a
checklist, file layout, and a minimal, programmatic skeleton.

### Analyzer

- Files:
  - Code: `src/sentineliqsdk/analyzers/<name>.py`
  - Example: `examples/analyzers/<name>_example.py`
  - Tests: `tests/analyzers/test_<name>.py`
- Class name: `<Name>Analyzer` extending `sentineliqsdk.analyzers.Analyzer`.
- Imports: absolute; always `from __future__ import annotations`.
- Return a report programmatically: implement `execute() -> AnalyzerReport` and make
  `run()` return the result of `execute()`.
- Use dataclasses: accept `WorkerInput` in the constructor (inherited behavior).
- Build taxonomy via `self.build_taxonomy(...)` and call `self.report(full_report)`.
- Respect TLP/PAP and proxy handling (already enforced by `Worker`).
- Example must default to dry‑run when performing network calls and support `--execute`.

Skeleton:

```python
from __future__ import annotations

from sentineliqsdk import Analyzer, WorkerInput
from sentineliqsdk.models import AnalyzerReport


class MyAnalyzer(Analyzer):
    def execute(self) -> AnalyzerReport:
        observable = self.get_data()
        taxonomy = self.build_taxonomy("safe", "namespace", "predicate", str(observable))
        full_report = {"observable": observable, "verdict": "safe", "taxonomy": [taxonomy.to_dict()]}
        return self.report(full_report)

    def run(self) -> AnalyzerReport:
        return self.execute()


if __name__ == "__main__":
    # Programmatic use
    input_data = WorkerInput(data_type="ip", data="1.2.3.4")
    print(MyAnalyzer(input_data).run())
```

Checklist:

- Naming, imports, and types compliant.
- `execute()` implemented; `run()` retorna `AnalyzerReport`.
- Builds taxonomy and calls `self.report(...)` with a dict.
- Example in `examples/analyzers/` created and runnable.
- Tests added; lint and types passing.

### Responder

- Files:
  - Code: `src/sentineliqsdk/responders/<name>.py`
  - Example: `examples/responders/<name>_example.py`
  - Tests: `tests/responders/test_<name>.py`
- Class name: `<Name>Responder` extending `sentineliqsdk.responders.Responder`.
- Implement `execute() -> ResponderReport` and make `run()` return it.
- Build operations via `self.build_operation(...)` and call `self.report(full_report)`.

Skeleton:

```python
from __future__ import annotations

from sentineliqsdk import Responder, WorkerInput
from sentineliqsdk.models import ResponderReport


class MyResponder(Responder):
    def execute(self) -> ResponderReport:
        target = self.get_data()
        ops = [self.build_operation("block", target=target)]
        full = {"action": "block", "target": target}
        return self.report(full)

    def run(self) -> ResponderReport:
        return self.execute()


if __name__ == "__main__":
    input_data = WorkerInput(data_type="ip", data="1.2.3.4")
    print(MyResponder(input_data).run())
```

Checklist:

- Naming/paths corretos; imports absolutos.
- `execute()` e `run()` retornando `ResponderReport`.
- Operações criadas via `build_operation` e reportadas.
- Exemplo em `examples/responders/` criado e testes adicionados.

### Detector

- Files:
  - Detector code: extend `src/sentineliqsdk/extractors/detectors.py` (preferível), ou criar um
    detector custom e registrá‑lo via `Extractor.register_detector(...)` no seu analyzer.
  - Example: `examples/detectors/<name>_example.py`
  - Tests: `tests/extractors/test_<name>_detector.py`
- Implementa o protocolo `Detector` com atributos: `name: str` e método `matches(value: str) -> bool`.
- Para incluir no core (tipo oficial):
  - Adicione o novo literal em `sentineliqsdk.models.DataType`.
  - Importe e adicione o detector na lista de precedência em `Extractor` (`regex.py`).
  - Considere normalização/flags expostos por `DetectionContext` quando aplicável.
- Para uso local (sem tocar no core):
  - Registre via `Extractor.register_detector(MyDetector(), before="hash")`, por exemplo.

Skeleton (core):

```python
from __future__ import annotations
from dataclasses import dataclass
from sentineliqsdk.extractors.detectors import Detector


@dataclass
class MyDetector:
    name: str = "my_type"

    def matches(self, value: str) -> bool:
        return value.startswith("MY:")
```

Checklist:

- Tipo incluído em `DataType` (quando for do core) e precedência ajustada no `Extractor`.
- Testes cobrindo positivos/negativos; sem falsos‑positivos óbvios.
- Exemplo em `examples/detectors/` mostrando `Extractor.check_string/iterable`.

- Install and open the repo.
- Create an analyzer (example below) and run it with either a job directory or STDIN.
- Use dataclasses for input; legacy dicts remain supported.

Minimal runnable analyzer (dataclasses):

```python
from __future__ import annotations
from sentineliqsdk import Analyzer, WorkerInput

class ReputationAnalyzer(Analyzer):
    def run(self) -> None:
        observable = self.get_data()
        verdict = "malicious" if observable == "1.2.3.4" else "safe"
        taxonomy = self.build_taxonomy("malicious" if verdict == "malicious" else "safe",
                                       "reputation", "static", str(observable))
        self.report({
            "observable": observable,
            "verdict": verdict,
            "taxonomy": [taxonomy.to_dict()],
        })

if __name__ == "__main__":
    ReputationAnalyzer(WorkerInput(data_type="ip", data="1.2.3.4")).run()
```

Run with job dir: `python my_agent.py /job` or via STDIN: `cat input.json | python my_agent.py`.

## Modules Overview

- `sentineliqsdk.Worker`: common base for analyzers/responders (IO, config, reporting).
- `sentineliqsdk.Analyzer`: base class for analyzers; auto‑extraction support.
- `sentineliqsdk.Responder`: base class for responders.
- `sentineliqsdk.Extractor`: stdlib‑based IOC extractor (ip/url/hash/...).
- `sentineliqsdk.runner(worker_cls)`: helper to instantiate and run a worker.
- `sentineliqsdk.models`: dataclasses for type-safe data structures.

Internal layout (for maintainers):
- `sentineliqsdk/core/worker.py` implements `Worker` (composition over helpers).
- `sentineliqsdk/analyzers/base.py` implements `Analyzer`.
- `sentineliqsdk/responders/base.py` implements `Responder`.
- `sentineliqsdk/extractors/regex.py` implements `Extractor`.
- `sentineliqsdk/core/config/proxy.py` sets env proxies (`EnvProxyConfigurator`).
- `sentineliqsdk/core/config/secrets.py` sanitizes error payload config.

## Input/Output Contract

Workers receive input data as dataclasses (recommended) or dictionaries (backward compatibility) and output results to STDOUT or return them in memory.

- Input: Data is passed as `WorkerInput` dataclass or dictionary to the worker constructor.
- Output: Structured data is returned in memory via `report()`.

### Modern Input (Dataclasses)

```python
from sentineliqsdk import WorkerInput, WorkerConfig, ProxyConfig

input_data = WorkerInput(
    data_type="ip",
    data="1.2.3.4",
    filename=None,  # Optional, for file datatypes
    tlp=2,
    pap=2,
    config=WorkerConfig(
        check_tlp=True,
        max_tlp=2,
        check_pap=True,
        max_pap=2,
        auto_extract=True,
        proxy=ProxyConfig(
            http="http://proxy:8080",
            https="https://proxy:8080"
        )
    )
)
```

### Legacy Input (Dictionaries)

```python
input_data = {
    "dataType": "ip",
    "data": "1.2.3.4",
    "tlp": 2,
    "pap": 2,
    "config": {
        "check_tlp": True,
        "max_tlp": 2,
        "auto_extract": True,
        "proxy": {
            "http": "http://proxy:8080",
            "https": "https://proxy:8080"
        }
    }
}
```

Common input fields:

- `data_type`/`dataType`: one of `ip`, `url`, `domain`, `hash`, `file`, ...
- `data` or `filename`: observable value or filename for `dataType == "file"`.
- `tlp` and `pap`: numbers; optionally enforced via config (see below).
- `config.*`: agent configuration, including:
  - `config.check_tlp` / `config.max_tlp`
  - `config.check_pap` / `config.max_pap`
  - `config.proxy.http` / `config.proxy.https` (exported to env as `http_proxy`/`https_proxy`)
  - `config.auto_extract` for analyzers

On error, sensitive keys in `config` containing any of `key`, `password`, `secret` are
replaced with `"REMOVED"` in the error payload.

## Core Concepts: Worker

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

### Modern Approach (Dataclasses)

```python
from __future__ import annotations

from sentineliqsdk import Analyzer, WorkerInput, runner


class ReputationAnalyzer(Analyzer):
    """Toy analyzer that marks "1.2.3.4" as malicious and others as safe."""

    def run(self) -> None:
        observable = self.get_data()

        verdict = "malicious" if observable == "1.2.3.4" else "safe"
        
        # Build taxonomy using dataclass
        taxonomy = self.build_taxonomy(
            level=verdict,
            namespace="reputation",
            predicate="static",
            value=str(observable),
        )
        
        full = {
            "observable": observable,
            "verdict": verdict,
            "taxonomy": [taxonomy.to_dict()],
        }

        self.report(full)


if __name__ == "__main__":
    # Using dataclass input
    input_data = WorkerInput(data_type="ip", data="1.2.3.4")
    analyzer = ReputationAnalyzer(input_data)
    analyzer.run()
```

### Legacy Approach (Dictionaries)

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

### Modern Approach (Dataclasses)

```python
from __future__ import annotations

from sentineliqsdk import Responder, WorkerInput


class BlockIpResponder(Responder):
    def run(self) -> None:
        ip = self.get_data()
        
        # Build operations using dataclass
        operations = [
            self.build_operation("block", target=ip, duration="24h"),
            self.build_operation("alert", severity="high")
        ]
        
        result = {
            "action": "block", 
            "target": ip, 
            "status": "ok",
            "operations": [operation.to_dict() for operation in operations]
        }
        self.report(result)


if __name__ == "__main__":
    # Using dataclass input
    input_data = WorkerInput(data_type="ip", data="1.2.3.4")
    responder = BlockIpResponder(input_data)
    responder.run()
```

### Legacy Approach (Dictionaries)

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

## Programmatic Usage (No File I/O)

You can use the SDK directly in your code without file I/O by passing input data directly to the constructor:

### Modern Approach (Dataclasses)

```python
from sentineliqsdk import Analyzer, WorkerInput

class MyAnalyzer(Analyzer):
    def run(self) -> None:
        observable = self.get_data()
        # Your analysis logic here
        result = {"observable": observable, "verdict": "safe"}
        self.report(result)

# Create input data using dataclass
input_data = WorkerInput(
    data_type="ip",
    data="1.2.3.4",
    tlp=2,
    pap=2
)

# Use analyzer without file I/O
analyzer = MyAnalyzer(input_data=input_data)
analyzer.run()
```

### Legacy Approach (Dictionaries)

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

# Use analyzer without file I/O
analyzer = MyAnalyzer(input_data=input_data)
analyzer.run()
```

### In-Memory Results

To get results in memory instead of writing to files, use `report()`:

```python
# Get result directly in memory
result = analyzer.report(full_report)
print(f"Analysis result: {result}")
```

### Batch Processing

Process multiple observables without file I/O:

```python
from sentineliqsdk import WorkerInput

observables = ["1.2.3.4", "8.8.8.8", "5.6.7.8"]
results = []

for obs in observables:
    input_data = WorkerInput(
        data_type="ip",
        data=obs,
        tlp=2,
        pap=2
    )
    
    analyzer = MyAnalyzer(input_data=input_data)
    # Process and get result in memory
    result = analyzer.report(full_report)
    results.append(result)
```

## Dataclasses and Type Safety

The SDK now provides dataclasses for better type safety and developer experience:

### Available Dataclasses

- **`WorkerInput`**: Input data for workers
- **`WorkerConfig`**: Worker configuration (TLP/PAP, proxy, etc.)
- **`ProxyConfig`**: HTTP/HTTPS proxy configuration
- **`TaxonomyEntry`**: Taxonomy entries for analyzers
- **`Artifact`**: Extracted artifacts
- **`Operation`**: Follow-up operations
- **`AnalyzerReport`**: Complete analyzer report
- **`ResponderReport`**: Complete responder report
- **`WorkerError`**: Error responses
- **`ExtractorResult`**: Individual extraction results
- **`ExtractorResults`**: Collection of extraction results

### Benefits

- **Type Safety**: Catch errors at development time
- **IDE Support**: Better autocomplete and error detection
- **Immutability**: Data structures are frozen and cannot be accidentally modified
- **Clear Contracts**: Well-defined data structures
- **Backward Compatibility**: Still accepts dictionary inputs

### Example Usage

```python
from sentineliqsdk import (
    WorkerInput, WorkerConfig, ProxyConfig, 
    TaxonomyEntry, Artifact, Operation
)

# Create structured input
input_data = WorkerInput(
    data_type="ip",
    data="1.2.3.4",
    config=WorkerConfig(
        check_tlp=True,
        max_tlp=2,
        proxy=ProxyConfig(http="http://proxy:8080")
    )
)

# Create taxonomy entry
taxonomy = TaxonomyEntry(
    level="malicious",
    namespace="reputation",
    predicate="static",
    value="1.2.3.4"
)

# Create artifact
artifact = Artifact(
    data_type="ip",
    data="8.8.8.8",
    tlp=2,
    extra={"confidence": 0.9}
)

# Create operation
operation = Operation(
    operation_type="hunt",
    parameters={"target": "1.2.3.4", "priority": "high"}
)

# Convert to dict for JSON serialization
json_data = {
    "taxonomy": [taxonomy.to_dict()],
    "artifacts": [artifact.to_dict()],
    "operations": [operation.to_dict()]
}
```

For more detailed information about dataclasses, see `DATACLASS_MIGRATION.md`.

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
