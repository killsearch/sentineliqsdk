# Architecture Overview

Design principles:

- SOLID: small, composable classes and clear extension points
- Dataclasses: strongly typed envelopes for input/output
- Stdlib‑first: Extractor prefers `ipaddress`, `urllib.parse`, `email.utils` over complex regexes

Modules and responsibilities:

- Core Worker: `src/sentineliqsdk/core/worker.py`
  - TLP/PAP enforcement, proxy environment setup, error reporting with sanitized config
  - Hooks: `summary`, `artifacts`, `operations`, `run`
- Analyzer base: `src/sentineliqsdk/analyzers/base.py`
  - Auto‑extraction of IOCs into artifacts, taxonomy helpers, file handling via `get_data()`
- Responder base: `src/sentineliqsdk/responders/base.py`
  - Simple action envelope, operation helpers
- Extractor: `src/sentineliqsdk/extractors/regex.py`
  - Detector registry and precedence, normalization flags, iterable checking
- Models: `src/sentineliqsdk/models.py`
  - Dataclasses: `WorkerInput`, `WorkerConfig`, `ProxyConfig`, `TaxonomyEntry`, `Artifact`,
    `Operation`, `AnalyzerReport`, `ResponderReport`, `WorkerError`, `ExtractorResult(s)`

Data flow (Analyzer):

1) Construct with `WorkerInput`
2) `__init__` enforces TLP/PAP and sets proxies
3) `execute()` builds the full report and calls `self.report(...)`
4) Envelope adds `summary`, `artifacts` (auto‑extract), and `operations` hooks

Extractor precedence (first match wins):

`ip` → `cidr` → `url` → `domain` → `hash` → `user-agent` → `uri_path` → `registry` → `mail` →
`mac` → `asn` → `cve` → `ip_port` → `fqdn`

Customization:

- Register detectors dynamically with `Extractor.register_detector(detector, before=..., after=...)`.
- Include new core types by updating `models.DataType` and the Extractor precedence list.
