# First Analyzer

This tutorial scaffolds, implements, and runs your first analyzer.

1) Scaffold with Poe

```bash
poe new-analyzer -- --name Reputation
```

This creates:

- `src/sentineliqsdk/analyzers/reputation.py`
- `examples/analyzers/reputation_example.py`
- `tests/analyzers/test_reputation.py` (if templates enable tests)

2) Implement `execute()` and `run()`

Edit `src/sentineliqsdk/analyzers/reputation.py` to follow the skeleton:

```python
from __future__ import annotations

from sentineliqsdk import Analyzer
from sentineliqsdk.models import AnalyzerReport


class ReputationAnalyzer(Analyzer):
    def execute(self) -> AnalyzerReport:
        observable = self.get_data()
        verdict = "malicious" if observable == "1.2.3.4" else "safe"
        tax = self.build_taxonomy(verdict, "reputation", "static", str(observable))
        return self.report({
            "observable": observable,
            "verdict": verdict,
            "taxonomy": [tax.to_dict()],
        })

    def run(self) -> AnalyzerReport:
        return self.execute()
```

3) Run the example

```bash
python examples/analyzers/reputation_example.py
```

4) Lint and test

```bash
poe lint
poe test
```

Tips:

- Examples must be dry‑run by default; require `--execute` for network calls.
- Always include taxonomy in `full_report` using `.to_dict()`.
- Use `auto_extract` (default) to extract IOCs from your full report.
