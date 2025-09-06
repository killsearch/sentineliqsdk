# Quick Start
 
See AGENTS.md for the complete Agent Guide. Minimal analyzer example:
 
```python
from __future__ import annotations
from sentineliqsdk import Analyzer, WorkerInput
 
class ReputationAnalyzer(Analyzer):
    def run(self) -> None:
        observable = self.get_data()
        verdict = "malicious" if observable == "1.2.3.4" else "safe"
        tax = self.build_taxonomy(verdict, "reputation", "static", str(observable))
        self.report({"observable": observable, "verdict": verdict, "taxonomy": [tax.to_dict()]})
 
if __name__ == "__main__":
    ReputationAnalyzer(WorkerInput(data_type="ip", data="1.2.3.4")).run()
```
