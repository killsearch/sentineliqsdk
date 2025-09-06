# Detector: cve

Detecta identificadores CVE como `CVE-2023-12345`.

## Como Funciona

- Regex case‑insensitive para `CVE-\d{4}-\d{4,}`.

## Uso

```python
from __future__ import annotations
from sentineliqsdk import Extractor

ex = Extractor()
print(ex.check_string("CVE-2023-12345"))  # "cve"
```
