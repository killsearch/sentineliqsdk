# Building Responders

Responders wrap actions like blocking an IP or notifying an external system.

1) Define the class

```python
from __future__ import annotations

from sentineliqsdk import Responder
from sentineliqsdk.models import ResponderReport


class BlockIpResponder(Responder):
    def execute(self) -> ResponderReport:
        ip = self.get_data()
        ops = [self.build_operation("block", target=ip)]
        return self.report({"action": "block", "target": ip})

    def run(self) -> ResponderReport:
        return self.execute()
```

2) Examples and safety flags

- Put examples under `examples/responders/<name>_example.py`.
- Default to dry‑run; add `--execute` to perform changes.
- Use `--include-dangerous` to explicitly gate impactful operations.

3) Input and output

- Use `WorkerInput(data_type=..., data=...)` to pass the target.
- Return a `ResponderReport` using `self.report(full_report)`, optionally including
  `operations` for follow‑up tasks.
