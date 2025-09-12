# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2025-01-27

### Added
- Comprehensive messaging system with Producers, Consumers, and Pipelines
- Kafka Producer and Consumer implementations
- Pipeline orchestration with security controls
- Router system for message routing
- Enhanced analyzer ecosystem with multiple new analyzers:
  - ChainAbuse analyzer for blockchain threat intelligence
  - ClamAV analyzer for malware detection
  - Cluster25 analyzer for threat intelligence
  - CrowdSec analyzer for IP reputation
  - CrowdStrike Falcon analyzer integration
  - CRT.sh analyzer for certificate transparency
  - Cuckoo Sandbox analyzer
  - CyberProtect analyzer
  - Cylance analyzer
  - DNSDumpster analyzer
  - Domain Mail SPF/DMARC analyzer
  - DomainTools analyzer
  - DShield analyzer for IP reputation
  - EchoTrail analyzer
  - EclecticIQ analyzer

### Fixed
- DShield analyzer test artifact data type expectations
- Test coverage and reliability improvements
- Enhanced error handling across analyzers

### Changed
- Improved project structure with better separation of concerns
- Enhanced configuration management
- Better integration testing framework

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
## v0.4.3 (2025-09-12)

## v0.4.2 (2025-09-12)

## v0.4.1 (2025-09-12)

### Refactor

- **examples**: fix code quality issues in analyzer examples

## v0.4.0 (2025-09-12)

### Feat

- **analyzers**: add EclecticIQ analyzer implementation
- **analyzers**: add EchoTrailAnalyzer with complete implementation
- **analyzers**: implement DomainToolsAnalyzer with comprehensive API integration
- **analyzers**: add DomainMailSpfDmarcAnalyzer for SPF/DMARC verification
- **analyzers**: add DShieldAnalyzer for SANS DShield API integration
- **analyzers**: add DNS Lookingglass analyzer
- **analyzers**: adicionar CylanceAnalyzer para analise de hash SHA256
- **analyzers**: adicionar CyberprotectAnalyzer para análise de threat score
- add CyberCrime Tracker analyzer
- **analyzers**: add CyberchefAnalyzer with example and docs
- **analyzers**: add CuckooSandboxAnalyzer with httpx polling, metadata, docs, and test updates
- **analyzers**: add crt.sh analyzer with example, tests, and docs
- add Cluster25 analyzer with threat intelligence integration
- add ClamAV analyzer with complete implementation
- add ChainAbuse analyzer for blockchain address and URL reputation

### Fix

- **tests**: corrige data_type esperado no teste do DShield analyzer
- **tests**: corrigir testes do EclecticIQ analyzer - Substituir asserções de atributos diretos por métodos get_secret/get_config - Ajustar configuração de SSL para usar params em vez de secrets - Configurar proxy usando ProxyConfig do WorkerConfig - Corrigir verificações de session.proxies e headers - Ajustar teste de exceção para verificar RuntimeError corretamente - Todos os 20 testes do EclecticIQ agora passam
- **analyzers**: corrigir problemas de linting detectados pelo ruff
- **tests**: corrigir testes falhando do CylanceAnalyzer
- **analyzers**: resolve mypy type errors in DNSdumpster analyzer
- **analyzers**: correct mypy type errors in DNSdumpster analyzer
- **analyzers**: corrige variável não definida no DNS Lookingglass analyzer
- **analyzers**: corrigir constante HTTP_UNAUTHORIZED no CuckooSandboxAnalyzer
- **linter**: run
- **analyzers/chainabuse**: add explicit returns for RET503 and keep mypy-clean by returning cast(dict[str, Any], self.error(...)) in _fetch_reports and _fetch_sanctioned_address
- resolve all linting and type checking errors

### Refactor

- centralize constants in constants.py

## v0.3.0 (2025-09-07)

### Feat

- implement comprehensive Censys Platform API analyzer
- add MCAP analyzer for threat intelligence analysis
- add CIRCL Vulnerability Lookup Analyzer
- add CIRCL PassiveSSL analyzer
- add CIRCL Passive DNS analyzer and update configuration rules
- add CIRCL Hashlookup analyzer with full API coverage
- add AnyRun analyzer for sandbox analysis
- add AbuseIPDB analyzer for IP reputation checking

### Fix

- add explicit return statements to satisfy RET503 linter
- resolve test failures and mypy errors
- resolve type errors and update AutoFocus analyzer

## v0.2.2 (2025-09-07)

### Feat

- **responders**: add SMTP Gmail/Outlook, Webhook, Kafka (REST), and RabbitMQ (HTTP) responders with runnable examples and docs

### Fix

- **examples**: annotate responder secrets dicts to satisfy mypy

### Refactor

- align responders/analyzers implementations and tests

## v0.2.1 (2025-09-06)

### Feat

- **examples,scaffold**: add Shodan all-methods example and templates; use execute() in examples\n\n- Add scaffolding templates under examples/_templates and scripts/scaffold.py\n- Add Shodan client + analyzer all-methods examples\n- Switch analyzer examples to execute() for programmatic results\n- Fix mypy error in Shodan analyzer example (func-returns-value)\n- Update AGENTS.md and DEVELOPMENT_RULES.md; prune outdated docs\n- Tweak pyproject config to align with current tooling
- **axur**: add AxurClient + AxurAnalyzer with dynamic route support; example with dry-run by default
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
