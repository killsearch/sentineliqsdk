# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project adheres to Semantic Versioning.

## [0.1.0] - 2025-09-05

### Added
- Initial public release of SentinelIQ SDK.
- Core base class `Worker` with IO, configuration, reporting, and TLP/PAP enforcement.
- `Analyzer` with auto-extraction support, taxonomy helpers, and artifact builders.
- `Responder` base with streamlined report shape.
- `Extractor` using Python stdlib helpers (`ipaddress`, `urllib.parse`, etc.).
- Top-level imports (`Analyzer`, `Responder`, `Worker`, `Extractor`, `runner`).
- CI: test workflow (lint + pytest) for Python 3.13.
- CI/CD: publish workflow using `uv build` + `uv publish` via PyPI Trusted Publishers.
- Developer docs and examples (`AGENTS.md`, `README.md`).

[0.1.0]: https://github.com/killsearch/sentineliqsdk/releases/tag/v0.1.0

## v0.2.0 (2025-09-06)

### Feat

- **shodan**: add Shodan REST client and analyzer; dynamic full API coverage; robust error handling

### Fix

- **commit**: import

## v0.1.3 (2025-09-06)

### Feat

- add comprehensive test suite with 99.4% coverage
- add comprehensive test suite with 99.4% coverage

### Fix

- resolve all linting errors and improve code quality

### Refactor

- remove backward compatibility comments and clean up imports

## v0.1.2 (2025-09-05)

### Fix

- update tests to use modern API and fix import issues

## v0.1.1 (2025-09-05)

### Feat

- **core**: improve file handling and coverage setup\n\n- Analyzer: support get_param('file') resolving to job-dir absolute path\n- Analyzer: ensure output/ exists before copying file artifacts\n- Worker: add 'token' to default secret phrases\n- Build: switch tests to pytest-cov for parallel coverage\n- Tests: add file handling tests\n- Docs: update README with coverage and secret_phrases

### Perf

- **extractor**: micro-optimizations and iterable support\n\n- precompute char sets and checks\n- early-return on non-URI\n- accept tuple/set in check_iterable\n- keep tests and API behavior intact
