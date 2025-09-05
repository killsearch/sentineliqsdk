---
title: Agent Guide
---

# SentinelIQ SDK — Agent Guide

This guide shows how to build analyzers and responders using the SDK. It summarizes the public API and provides usage examples you can copy into your own agents.

Requirements: Python 3.13, absolute imports, 4‑space indentation, line length 100.

## Modules Overview

- `sentineliqsdk.Worker`: common base for analyzers/responders (IO, config, reporting).
- `sentineliqsdk.Analyzer`: base class for analyzers; auto‑extraction support.
- `sentineliqsdk.Responder`: base class for responders.
- `sentineliqsdk.Extractor`: stdlib‑based IOC extractor (ip/url/hash/...).
- `sentineliqsdk.runner(worker_cls)`: helper to instantiate and run a worker.

## Input/Output Contract

Workers read a job either from a job directory or from STDIN and write results to the job directory or STDOUT.

- Job directory mode: `<job_dir>/input/input.json` (and files for file observables).
- STDIN mode: if no job directory input exists, JSON is read from STDIN.
- Output: JSON is written to `<job_dir>/output/output.json` or STDOUT.

Common input fields inside `input.json`:

- `dataType`: one of `ip`, `url`, `domain`, `hash`, `file`, ...
- `data` or `filename`: observable value or filename for `dataType == "file"`.
- `tlp` and `pap`: numbers; optionally enforced via config.
- `config.*`: agent configuration (proxy, auto_extract, limits, etc.).

On error, sensitive keys in `config` containing any of `key`, `password`, `secret` are sanitized.

## Core Base: Worker

Signature: `Worker(job_directory: str | None, secret_phrases: tuple[str, ...] | None)`

Key methods:

- `get_param(name, default=None, message=None)`
- `get_env(key, default=None, message=None)`
- `get_data()`
- `build_operation(op_type, **parameters)`
- `operations(raw)` / `summary(raw)` / `artifacts(raw)`
- `report(output, ensure_ascii=False)` / `error(message, ensure_ascii=False)`
- `run()` — override in subclasses

TLP/PAP enforcement via `config.check_tlp`/`config.check_pap` and `config.max_tlp`/`config.max_pap`.

## Analyzer

Enhancements over `Worker`:

- `get_data()`: returns filename when `dataType == "file"`, else `data`.
- `get_param("file")`: resolves absolute input path when in job mode.
- `auto_extract`: enabled by default unless `config.auto_extract` is `false`.
- `artifacts(raw)`: uses `Extractor(ignore=self.get_data())`.
- `build_taxonomy(level, namespace, predicate, value)` helper.
- `build_artifact(data_type, data, **kwargs)` helper for file/non-file artifacts.
- `report(full)` wraps output with `success`, `summary`, `artifacts`, `operations`, and `full`.

## Responder

Mirrors `Analyzer` with a simpler `report` shape: `{"success": true, "full": full, "operations": [...]}`.

## Extractor

IOC extractor using Python's stdlib. Typical types: `ip`, `url`, `domain`, `fqdn`, `hash` (MD5/SHA1/SHA256), `mail`, `user-agent`, `uri_path`, `registry`.

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

## Running and Debugging

- Job directory mode: `python my_agent.py /job` with `input/input.json` present.
- STDIN mode: `cat input.json | python my_agent.py`.
- Proxies: set `config.proxy.http` / `config.proxy.https` or environment variables.
