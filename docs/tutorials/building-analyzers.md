# Building Analyzers

This tutorial walks through creating a production‑quality analyzer using the SDK patterns.

What you’ll build:

- A class `<Name>Analyzer` extending `sentineliqsdk.analyzers.Analyzer`.
- An `execute() -> AnalyzerReport` that returns a structured envelope via `self.report(...)`.
- A `run()` that returns `self.execute()` for programmatic use.
- A runnable example under `examples/analyzers/` using `WorkerInput`.

1) Define the class

```python
from __future__ import annotations

from sentineliqsdk import Analyzer
from sentineliqsdk.models import AnalyzerReport


class MyAnalyzer(Analyzer):
    def execute(self) -> AnalyzerReport:
        observable = self.get_data()
        taxonomy = self.build_taxonomy("safe", "namespace", "predicate", str(observable))
        full = {
            "observable": observable,
            "verdict": "safe",
            "taxonomy": [taxonomy.to_dict()],
        }
        return self.report(full)

    def run(self) -> AnalyzerReport:
        return self.execute()
```

2) Auto‑extraction of artifacts

- Enabled by default unless `WorkerInput.config.auto_extract` is `False`.
- The analyzer’s `artifacts(full_report)` uses the Extractor to find IOCs in your report,
  excluding the original observable.
- For custom items, build artifacts explicitly with `self.build_artifact(...)` and include them
  in the envelope.

3) Operations and follow‑ups

Use `self.build_operation("<type>", **params)` and override `operations(full_report)` when you
need to suggest next steps (e.g., hunt, enrichment, block).

4) Example and CLI flags

- Place a runnable example at `examples/analyzers/<snake>_example.py`.
- Default to dry‑run and add `--execute` to perform network calls.
- Use `--include-dangerous` to gate impactful actions (e.g., scans).

5) Validation

- Run `poe lint` (ruff + mypy) and `poe test` (pytest) locally before opening a PR.
