# SentinelIQ SDK — Agent Guide

This is the single source of truth for building analyzers, responders, and detectors with
the SentinelIQ SDK under `src/sentineliqsdk`. It reflects the current implementation in
this repository.

Requirements: Python 3.13, absolute imports, 4‑space indentation, line length 100.

## Module Metadata (New)

- Every Analyzer/Responder must declare a `METADATA` attribute using
  `sentineliqsdk.models.ModuleMetadata` and include it in the `full_report` under the
  `metadata` key.
- Required fields (keys when serialized via `to_dict()`):
  - `Name`, `Description`, `Author` (list of "Name <email>"), `License`
  - `pattern` (ex.: "smtp", "webhook", "kafka", "threat-intel")
  - `doc_pattern` (curta descrição do formato da documentação)
  - `doc` (URL pública da documentação do módulo — site do SentinelIQ)
  - `VERSION` (um de: `DEVELOPER`, `TESTING`, `STABLE`)

Example:

```python
from sentineliqsdk.models import ModuleMetadata

class MyResponder(Responder):
    METADATA = ModuleMetadata(
        name="My Responder",
        description="Does something useful",
        author=("SentinelIQ Team <team@sentineliq.com.br>",),
        pattern="webhook",
        doc_pattern="MkDocs module page; programmatic usage",
        doc="https://killsearch.github.io/sentineliqsdk/modulos/responders/my_responder/",
        version_stage="TESTING",
    )

    def execute(self) -> ResponderReport:
        full = {"action": "noop", "metadata": self.METADATA.to_dict()}
        return self.report(full)
```

## Mandatory Examples (Agent Rule)

- Always add a runnable example in `examples/` when you introduce a new Analyzer, Responder,
  or Detector.
- Naming: `examples/<kind>/<name>_example.py` where `<kind>` ∈ {`analyzers`, `responders`,
  `detectors`}.
- The example must:
  - Use dataclass input (`WorkerInput`) and call `.run()` (or `.execute()` when provided).
  - Be runnable locally with only stdlib + SDK.
  - Print a compact result to STDOUT. Network calls default to dry‑run and require `--execute`.
    Impactful operations (e.g., scans) must be gated behind `--include-dangerous`.
- Reference your example from README or docs when helpful.

## Documentation Updates (Always)

Keep the documentation in sync whenever you add or change behavior:

- Update pages under `docs/` (Guides, Tutorials, Examples, Reference) to reflect the current
  behavior, flags, and safety gates (`--execute`, `--include-dangerous`).
- Link new examples in the relevant pages (`docs/examples/*.md`) and, when helpful, in README.
- Add a programmatic usage page for each module under `docs/modulos/<kind>/<name>.md`.
  The page must show dataclass input (`WorkerInput`) and calling `.execute()` (or `.run()`),
  using only stdlib + SDK. Update the navigation in `mkdocs.yml` under the "Modules" section.
- If you add new public API or modules, ensure mkdocstrings pages exist and the navigation in
  `mkdocs.yml` is updated.
- Validate locally with `poe docs` (or preview with `poe docs-serve`).

## Scaffolding (Poe tasks)

- Generic: `poe new -- --kind <analyzer|responder|detector> --name <Name> [--force]`
- Shortcuts:
  - Analyzer: `poe new-analyzer -- --name Shodan`
  - Responder: `poe new-responder -- --name BlockIp`
  - Detector: `poe new-detector -- --name MyType`

Outputs (code + example):
- Analyzer: `src/sentineliqsdk/analyzers/<snake>.py` and `examples/analyzers/<snake>_example.py`
- Responder: `src/sentineliqsdk/responders/<snake>.py` and
  `examples/responders/<snake>_example.py`
- Detector: `src/sentineliqsdk/extractors/custom/<snake>_detector.py` and
  `examples/detectors/<snake>_example.py`

## Quick Start

Minimal analyzer using dataclasses:

```python
from __future__ import annotations

import json

from sentineliqsdk import Analyzer, WorkerInput
from sentineliqsdk.models import AnalyzerReport


class ReputationAnalyzer(Analyzer):
    """Marks 1.2.3.4 as malicious, others as safe."""

    def execute(self) -> AnalyzerReport:
        observable = self.get_data()
        verdict = "malicious" if observable == "1.2.3.4" else "safe"
        tax = self.build_taxonomy(level=verdict, namespace="reputation", predicate="static",
                                  value=str(observable))
        return self.report({
            "observable": observable,
            "verdict": verdict,
            "taxonomy": [tax.to_dict()],
        })

    def run(self) -> AnalyzerReport:
        return self.execute()


if __name__ == "__main__":
    report = ReputationAnalyzer(WorkerInput(data_type="ip", data="1.2.3.4")).run()
    print(json.dumps(report.full_report, ensure_ascii=False))
```

Run examples directly, e.g. `python examples/analyzers/shodan_analyzer_all_methods.py --help`.

## Development Rules — Creating New Analyzer/Responder/Detector

Follow these rules for consistent components. Each recipe lists the file layout, class naming,
and a minimal skeleton aligned with this SDK.

### Analyzer

- Files:
  - Code: `src/sentineliqsdk/analyzers/<name>.py`
  - Example: `examples/analyzers/<name>_example.py`
  - Tests: `tests/analyzers/test_<name>.py`
- Class name: `<Name>Analyzer` extending `sentineliqsdk.analyzers.Analyzer`.
- Imports: absolute; always `from __future__ import annotations` first.
- Implement `execute() -> AnalyzerReport` and make `run()` return `self.execute()`.
- Build taxonomy via `self.build_taxonomy(...)`; include `taxonomy.to_dict()` in your payload.
- Use dataclasses only (`WorkerInput` is required). TLP/PAP and proxies are enforced by `Worker`.
- Examples should be dry‑run by default and support `--execute` for real calls.

Skeleton:

```python
from __future__ import annotations

from sentineliqsdk import Analyzer
from sentineliqsdk.models import AnalyzerReport


class MyAnalyzer(Analyzer):
    def execute(self) -> AnalyzerReport:
        observable = self.get_data()
        taxonomy = self.build_taxonomy("safe", "namespace", "predicate", str(observable))
        full = {"observable": observable, "verdict": "safe", "taxonomy": [taxonomy.to_dict()]}
        return self.report(full)

    def run(self) -> AnalyzerReport:
        return self.execute()
```

Checklist:

- Naming and imports compliant; class ends with `Analyzer`.
- `execute()` implemented; `run()` returns `AnalyzerReport`.
- Calls `self.report(...)` with a dict; taxonomy included.
- Example under `examples/analyzers/` runnable and prints a compact result.
- Tests added; `poe lint` and `poe test` pass.
- Docs updated (Guide/Tutorials/Examples/Reference), links added, `mkdocs.yml` updated if needed;
  `poe docs` passes locally.
- Programmatic docs page added: `docs/modulos/analyzers/<name>.md`.

### Responder

- Files:
  - Code: `src/sentineliqsdk/responders/<name>.py`
  - Example: `examples/responders/<name>_example.py`
  - Tests: `tests/responders/test_<name>.py`
- Class name: `<Name>Responder` extending `sentineliqsdk.responders.Responder`.
- Implement `execute() -> ResponderReport` and make `run()` return it.
- Build operations with `self.build_operation(...)` and call `self.report(full_report)`.

Skeleton:

```python
from __future__ import annotations

from sentineliqsdk import Responder
from sentineliqsdk.models import ResponderReport


class MyResponder(Responder):
    def execute(self) -> ResponderReport:
        target = self.get_data()
        ops = [self.build_operation("block", target=target)]
        full = {"action": "block", "target": target}
        return self.report(full)

    def run(self) -> ResponderReport:
        return self.execute()
```

Checklist:

- Naming/paths correct; absolute imports.
- `execute()` and `run()` return `ResponderReport`.
- Operations created via `build_operation` and reported.
- Example under `examples/responders/` runnable and prints compact result.
- Docs updated (Guide/Tutorials/Examples/Reference), links added, `mkdocs.yml` updated if needed;
  `poe docs` passes locally.
- Programmatic docs page added: `docs/modulos/responders/<name>.md`.

### Detector

- Files:
  - Core: extend `src/sentineliqsdk/extractors/detectors.py` (preferred for official types), or
    create a custom detector under `src/sentineliqsdk/extractors/custom/<name>_detector.py` and
    register it via `Extractor.register_detector(...)` in your analyzer.
  - Example: `examples/detectors/<name>_example.py`
  - Tests: `tests/extractors/test_<name>_detector.py`
- Protocol: `Detector` with attribute `name: str` and method `matches(value: str) -> bool`.
- To include in core (official type):
  - Add the literal to `sentineliqsdk.models.DataType`.
  - Import/add the detector in the precedence list in `Extractor` (`extractors/regex.py`).
  - Consider normalization/flags exposed by `DetectionContext` when relevant.
- For local-only use (without touching the core):
  - Register via `Extractor.register_detector(MyDetector(), before="hash")`, for example.

Skeleton (custom):

```python
from __future__ import annotations
from dataclasses import dataclass


@dataclass
class MyDetector:
    name: str = "my_type"

    def matches(self, value: str) -> bool:
        return value.startswith("MY:")
```

Checklist:

- Type included in `DataType` (if core) and precedence adjusted in `Extractor`.
- Tests cover positives/negatives; avoid obvious false positives.
- Example in `examples/detectors/` demonstrating `Extractor.check_string/iterable`.
- Docs updated (Guide/Tutorials/Examples/Reference), links added, `mkdocs.yml` updated if needed;
  `poe docs` passes locally.
- Programmatic docs page added: `docs/modulos/detectors/<name>.md`.

## Modules Overview

- `sentineliqsdk.Worker`: common base for analyzers/responders (config, env, reporting hooks).
- `sentineliqsdk.Analyzer`: base class for analyzers; includes auto‑extraction helpers.
- `sentineliqsdk.Responder`: base class for responders; simpler envelope.
- `sentineliqsdk.Extractor`: stdlib‑guided IOC extractor (ip/url/domain/hash/...).
- `sentineliqsdk.runner(worker_cls, input_data)`: convenience to instantiate and run.
- `sentineliqsdk.models`: dataclasses for type‑safe structures.

Internal layout (for maintainers):
- `src/sentineliqsdk/core/worker.py` implements `Worker`.
- `src/sentineliqsdk/analyzers/base.py` implements `Analyzer`.
- `src/sentineliqsdk/responders/base.py` implements `Responder`.
- `src/sentineliqsdk/extractors/regex.py` implements `Extractor`.
- `src/sentineliqsdk/core/config/proxy.py` sets env proxies (`EnvProxyConfigurator`).
- `src/sentineliqsdk/core/config/secrets.py` sanitizes error payload config.

## Input/Output Contract

Workers receive input data as dataclasses and return results in memory. This SDK has removed
legacy dictionary input from the public API in this repository.

- Input: pass a `WorkerInput` dataclass to the worker constructor.
- Output: `Analyzer.report(...)` returns `AnalyzerReport`; `Responder.report(...)` returns
  `ResponderReport`. Examples can print compact JSON to STDOUT explicitly.

### Input (Dataclasses)

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

Common input fields:

- `data_type`: one of `ip`, `url`, `domain`, `fqdn`, `hash`, `mail`, `user-agent`,
  `uri_path`, `registry`, `file`, `other`, `asn`, `cve`, `ip_port`, `mac`, `cidr`.
- `data` or `filename`: observable value or filename for `data_type == "file"`.
- `tlp` and `pap`: numbers enforced via config when enabled.
- `config.*` includes:
  - `config.check_tlp` / `config.max_tlp`
  - `config.check_pap` / `config.max_pap`
  - `config.proxy.http` / `config.proxy.https` (exported internally for stdlib clients)
  - `config.auto_extract` for analyzers
  - `config.params` (dict/mapping): parâmetros programáticos por módulo
  - `config.secrets` (dict/mapping): segredos/credenciais por módulo

On error, sensitive keys in `config` containing any of `key`, `password`, `secret`, `token`
are replaced with `"REMOVED"` in the error payload.

## Core Concepts: Worker

Signature: `Worker(input_data: WorkerInput, secret_phrases: tuple[str, ...] | None)`

- `get_param(name, default=None, message=None)`: not used in this repository (dataclasses only).
- `get_env(key, default=None, message=None)`: read environment variables.
- `get_config(path, default=None)`: lê de `WorkerConfig.params` via caminho pontuado
  (ex.: `"shodan.method"`, `"webhook.headers"`).
- `get_secret(path, default=None, message=None)`: lê de `WorkerConfig.secrets` via
  caminho pontuado (ex.: `"shodan.api_key"`, `"smtp.password"`).
- `get_data() -> Any`: returns the observable value (overridden in subclasses).
- `build_operation(op_type: str, **parameters) -> Operation`: describe follow‑up operations.
- `operations(raw) -> list[Operation]`: hook for follow‑up work; default `[]`.
- `summary(raw) -> dict`: short summary; default `{}`.
- `artifacts(raw) -> list[Artifact]`: analyzer override performs auto-extraction when enabled.
- `report(output: dict) -> dict | AnalyzerReport | ResponderReport`: returns result in memory.
- `error(message: str, ensure_ascii: bool = False) -> NoReturn`: print error JSON and exit(1).
- `run() -> None`: your main logic (override in subclasses).

TLP/PAP enforcement:

- Enable with `config.check_tlp`/`config.check_pap`; set `config.max_tlp`/`config.max_pap`.
- If exceeded, the worker calls `error("TLP is higher than allowed.")` or the PAP equivalent.

## Analyzer

`Analyzer` extends `Worker` with analyzer‑specific behavior:

- `get_data()`: returns `filename` when `data_type == "file"`, otherwise the `data` field.
- `auto_extract`: enabled by default unless `config.auto_extract` is `False`.
- `artifacts(raw)`: when enabled, uses `Extractor(ignore=self.get_data())` and returns a
  `list[Artifact]` dataclass collection for the full report.
- `build_taxonomy(level, namespace, predicate, value) -> TaxonomyEntry`: helper for taxonomy
  entries where `level` is one of `info|safe|suspicious|malicious`.
- `build_artifact(data_type, data, **kwargs) -> Artifact`: build an artifact dataclass.
- `report(full_report: dict) -> AnalyzerReport`: returns an envelope with
  `success/summary/artifacts/operations/full_report`.

Notes:
- Legacy helpers like `getData`/`checkTlp` are removed; use the modern API only.
- TLP/PAP checks run automatically in `Worker.__init__`.

## Responder

`Responder` mirrors `Analyzer` with a simpler envelope:

- `get_data()`: returns the `data` field.
- `report(full_report) -> ResponderReport` with `success/full_report/operations`.

## Extractor

IOC extractor using Python stdlib helpers (e.g., `ipaddress`, `urllib.parse`, `email.utils`)
instead of complex regexes. Typical types detected include:

- `ip` (IPv4 and IPv6), `cidr`, `url`, `domain`, `fqdn`, `hash` (MD5/SHA1/SHA256), `mail`,
  `user-agent`, `uri_path`, `registry`, `mac`, `asn`, `cve`, `ip_port`.

API:

- `Extractor(ignore: str | None = None, strict_dns: bool = False, normalize_domains: bool = False,
  normalize_urls: bool = False, support_mailto: bool = False, max_string_length: int = 10000,
  max_iterable_depth: int = 100)`
- `check_string(value: str) -> str`: returns a data type name or empty string.
- `check_iterable(iterable: list | dict | str | tuple | set) -> list[ExtractorResult]`:
  returns a de‑duplicated list of dataclass results.

Precedence order (first match wins): ip → cidr → url → domain → hash → user-agent → uri_path →
registry → mail → mac → asn → cve → ip_port → fqdn.
Use `Extractor.register_detector(detector, before=..., after=...)` to customize.

## Minimal Analyzer Example

### Dataclasses

```python
from __future__ import annotations

from sentineliqsdk import Analyzer, WorkerInput


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
    input_data = WorkerInput(data_type="ip", data="1.2.3.4")
    ReputationAnalyzer(input_data).run()
```

## Minimal Responder Example

### Dataclasses

```python
from __future__ import annotations

from sentineliqsdk import Responder, WorkerInput


class BlockIpResponder(Responder):
    def run(self) -> None:
        ip = self.get_data()

        result = {
            "action": "block",
            "target": ip,
            "status": "ok",
        }
        self.report(result)


if __name__ == "__main__":
    input_data = WorkerInput(data_type="ip", data="1.2.3.4")
    BlockIpResponder(input_data).run()
```

## Example Input and Output

Input (programmatic): `WorkerInput(data_type="ip", data="1.2.3.4", tlp=2, pap=2)`

Analyzer programmatic result (`AnalyzerReport` dataclass):

```json
{
  "success": true,
  "summary": {},
  "artifacts": [],
  "operations": [],
  "full_report": {
    "observable": "1.2.3.4",
    "verdict": "malicious",
    "taxonomy": [
      {"level": "malicious", "namespace": "reputation", "predicate": "static", "value": "1.2.3.4"}
    ]
  }
}
```

On an error, the worker prints to STDOUT and exits with code 1:

```json
{ "success": false, "input": { ... }, "errorMessage": "<reason>" }
```

## Operations and Artifacts

- Use `build_operation("<type>", **params)` and return a list from `operations(full_report)` to
  trigger follow‑up work.
- Build artifacts in analyzers with `build_artifact("file", "/path/to/file")` or with
  non‑file types: `build_artifact("ip", "8.8.8.8", tlp=2)`.
- When `auto_extract` is enabled (default), `artifacts(full_report)` uses `Extractor` to detect
  IOCs in the report, excluding the original observable value.

## Running and Debugging

- Run examples directly under `examples/` with `python ...`.
- Use `--execute` for real network calls; otherwise remain in dry‑run.
- Use `--include-dangerous` to enable impactful actions when applicable.
- Proxies: set `WorkerInput.config.proxy.http` / `.https`.

## Programmatic Usage (No File I/O)

Use the SDK directly by passing `WorkerInput` to the constructor and printing as needed.

### Dataclasses

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
    pap=2,
)

analyzer = MyAnalyzer(input_data=input_data)
analyzer.run()
```

### In-Memory Results

To get results in memory, call `execute()` (or `run()` if your class returns the report):

```python
report = analyzer.execute()  # or analyzer.run() if run() returns the report
print(report.full_report)
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
        pap=2,
    )

    analyzer = MyAnalyzer(input_data=input_data)
    # Process and get result in memory
    result = analyzer.execute()
    results.append(result)
```

## Dataclasses and Type Safety

The SDK provides dataclasses for better type safety and developer experience:

- `WorkerInput`: Input data for workers
- `WorkerConfig`: Worker configuration (TLP/PAP, proxy, etc.)
- `ProxyConfig`: HTTP/HTTPS proxy configuration
- `TaxonomyEntry`: Taxonomy entries for analyzers
- `Artifact`: Extracted artifacts
- `Operation`: Follow‑up operations
- `AnalyzerReport`: Complete analyzer report
- `ResponderReport`: Complete responder report
- `WorkerError`: Error responses
- `ExtractorResult`: Individual extraction results
- `ExtractorResults`: Collection of extraction results

### Example Usage

```python
from sentineliqsdk import (
    WorkerInput, WorkerConfig, ProxyConfig,
    TaxonomyEntry, Artifact, Operation,
)

# Create structured input
input_data = WorkerInput(
    data_type="ip",
    data="1.2.3.4",
    config=WorkerConfig(
        check_tlp=True,
        max_tlp=2,
        proxy=ProxyConfig(http="http://proxy:8080"),
    ),
)

# Create taxonomy entry
taxonomy = TaxonomyEntry(
    level="malicious",
    namespace="reputation",
    predicate="static",
    value="1.2.3.4",
)

# Create artifact
artifact = Artifact(
    data_type="ip",
    data="8.8.8.8",
    tlp=2,
    extra={"confidence": 0.9},
)

# Create operation
operation = Operation(
    operation_type="hunt",
    parameters={"target": "1.2.3.4", "priority": "high"},
)

# Convert to dict for JSON serialization
# Note: use dataclasses.asdict for dataclasses without custom to_dict()
from dataclasses import asdict
json_data = {
    "taxonomy": [taxonomy.to_dict()],
    "artifacts": [asdict(artifact)],
    "operations": [asdict(operation)],
}
```

## Project and CI Tips

- Lint and type check: `poe lint` (pre-commit with ruff/mypy configured).
- Tests: `poe test` (pytest with coverage to `reports/`).
- Docs: `poe docs` builds MkDocs site to `docs/` (see `.github/workflows/docs.yml`).
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
   - Commitizen updates `[project].version` in `pyproject.toml`, updates `CHANGELOG.md`, creates
     the tag `vX.Y.Z` and commits the change (per `[tool.commitizen]`).
3. Push branch and tags
   - `git push origin main --follow-tags`
   - If your local branch is behind: `git pull --rebase origin main` then push again.
4. Create a GitHub Release for the new tag
   - UI: Releases → New release → Choose tag `vX.Y.Z` → Publish.
   - CLI: `gh release create vX.Y.Z --title "vX.Y.Z" --notes-file CHANGELOG.md --latest`
5. CI publishes to PyPI
   - The "Publish" workflow runs and calls `uv publish` using OIDC.
   - Track in Actions → Publish (or `gh run list --workflow=Publish`).
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
- If the Publish job fails with a PyPI permission error, review the Trusted Publisher settings
  and the workflow `permissions`.
