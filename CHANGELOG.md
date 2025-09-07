# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2025-09-07

### Added
- Comprehensive Censys Platform API analyzer with full API coverage
- MCAP analyzer for threat intelligence analysis
- CIRCL Vulnerability Lookup Analyzer
- CIRCL PassiveSSL analyzer
- CIRCL Passive DNS analyzer and updated configuration rules
- CIRCL Hashlookup analyzer with full API coverage
- AnyRun analyzer for sandbox analysis
- AbuseIPDB analyzer for IP reputation checking

### Fixed
- Added explicit return statements to satisfy RET503 linter
- Resolved test failures and mypy errors
- Resolved type errors and updated AutoFocus analyzer

## [0.2.2] - 2025-09-07

### Added
- SMTP Gmail/Outlook responders with runnable examples and docs
- Webhook responder with runnable examples and docs
- Kafka (REST) responder with runnable examples and docs
- RabbitMQ (HTTP) responder with runnable examples and docs

### Fixed
- Annotated responder secrets dicts to satisfy mypy

### Refactored
- Aligned responders/analyzers implementations and tests

## [0.2.1] - 2025-09-06

### Added
- Shodan all-methods example and scaffolding templates
- AxurClient + AxurAnalyzer with dynamic route support
- Scaffolding templates under examples/_templates and scripts/scaffold.py
- Shodan client + analyzer all-methods examples
- Switched analyzer examples to execute() for programmatic results

### Fixed
- MyPy error in Shodan analyzer example (func-returns-value)

### Changed
- Updated AGENTS.md and DEVELOPMENT_RULES.md
- Pruned outdated documentation
- Tweaked pyproject config to align with current tooling

## [0.2.0] - 2025-09-06

### Added
- Shodan REST client and analyzer with dynamic full API coverage
- Robust error handling for Shodan integration

### Fixed
- Import issues

## [0.1.3] - 2025-09-06

### Added
- Comprehensive test suite with 99.4% coverage

### Fixed
- Resolved all linting errors and improved code quality

### Refactored
- Removed backward compatibility comments and cleaned up imports

## [0.1.2] - 2025-09-05

### Fixed
- Updated tests to use modern API and fixed import issues

## [0.1.1] - 2025-09-05

### Added
- Improved file handling and coverage setup
- Analyzer support for get_param('file') resolving to job-dir absolute path
- Analyzer ensures output/ exists before copying file artifacts
- Worker adds 'token' to default secret phrases
- Switched tests to pytest-cov for parallel coverage
- Added file handling tests
- Updated README with coverage and secret_phrases

### Performance
- Micro-optimizations and iterable support in extractor
- Precomputed char sets and checks
- Early-return on non-URI
- Accept tuple/set in check_iterable
- Kept tests and API behavior intact

## [0.1.0] - 2025-09-05

### Added
- Initial public release of SentinelIQ SDK
- Core base class `Worker` with IO, configuration, reporting, and TLP/PAP enforcement
- `Analyzer` with auto-extraction support, taxonomy helpers, and artifact builders
- `Responder` base with streamlined report shape
- `Extractor` using Python stdlib helpers (`ipaddress`, `urllib.parse`, etc.)
- Top-level imports (`Analyzer`, `Responder`, `Worker`, `Extractor`, `runner`)
- CI: test workflow (lint + pytest) for Python 3.13
- CI/CD: publish workflow using `uv build` + `uv publish` via PyPI Trusted Publishers
- Developer docs and examples (`AGENTS.md`, `README.md`)

[0.3.0]: https://github.com/killsearch/sentineliqsdk/releases/tag/v0.3.0
[0.2.2]: https://github.com/killsearch/sentineliqsdk/releases/tag/v0.2.2
[0.2.1]: https://github.com/killsearch/sentineliqsdk/releases/tag/v0.2.1
[0.2.0]: https://github.com/killsearch/sentineliqsdk/releases/tag/v0.2.0
[0.1.3]: https://github.com/killsearch/sentineliqsdk/releases/tag/v0.1.3
[0.1.2]: https://github.com/killsearch/sentineliqsdk/releases/tag/v0.1.2
[0.1.1]: https://github.com/killsearch/sentineliqsdk/releases/tag/v0.1.1
[0.1.0]: https://github.com/killsearch/sentineliqsdk/releases/tag/v0.1.0