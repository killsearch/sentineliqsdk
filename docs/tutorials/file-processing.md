# File Processing

Analyzers can operate on files by setting `data_type == "file"` and providing
`WorkerInput.filename`. In this mode, `Analyzer.get_data()` returns the filename.

Pattern:

```python
from __future__ import annotations

from pathlib import Path

from sentineliqsdk import Analyzer, WorkerInput
from sentineliqsdk.models import AnalyzerReport


class FileHashAnalyzer(Analyzer):
    def execute(self) -> AnalyzerReport:
        filename = Path(self.get_data())  # file path
        data = filename.read_bytes()
        sha256 = __import__("hashlib").sha256(data).hexdigest()
        tax = self.build_taxonomy("info", "file", "sha256", sha256)
        return self.report({
            "filename": str(filename),
            "sha256": sha256,
            "taxonomy": [tax.to_dict()],
        })

    def run(self) -> AnalyzerReport:
        return self.execute()


if __name__ == "__main__":
    inp = WorkerInput(data_type="file", data=None, filename="/path/to/file")
    print(FileHashAnalyzer(inp).execute().full_report)
```

Notes:

- Avoid reading very large files into memory; stream when applicable.
- Respect TLP/PAP constraints and do not exfiltrate content unless allowed.
- When `auto_extract` is enabled, IOCs found in the full report are captured as artifacts.
