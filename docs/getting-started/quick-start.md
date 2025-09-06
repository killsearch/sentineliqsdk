# Quick Start

This page shows the minimal path to create and run an analyzer using dataclasses.

Minimal analyzer example:

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

Run it:

```bash
python path/to/your_script.py
```

Using the convenience `runner`:

```python
from sentineliqsdk import runner, WorkerInput

runner(ReputationAnalyzer, WorkerInput(data_type="ip", data="1.2.3.4"))
```

Next steps:

- See the full Agent Guide for conventions and patterns.
- Use `poe new-analyzer -- --name MyAnalyzer` to scaffold a new analyzer.
