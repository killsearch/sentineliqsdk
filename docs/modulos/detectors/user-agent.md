# Detector: user-agent

Detecta cadeias de User-Agent com base em prefixos conhecidos.

## Como Funciona

- Verifica se a string começa com um dos prefixos listados (por exemplo, `Mozilla/5.0`).

## Uso

```python
from __future__ import annotations
from sentineliqsdk import Extractor

ex = Extractor()
print(ex.check_string("Mozilla/5.0 (Windows NT 10.0; Win64; x64)"))  # "user-agent"
```

