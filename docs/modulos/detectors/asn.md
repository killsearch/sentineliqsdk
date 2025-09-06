# Detector: asn

Detecta números de Sistema Autônomo como `AS13335`.

## Como Funciona

- Usa regex com prefixo `AS` case‑insensitive seguido de 1–10 dígitos.

## Uso

```python
from __future__ import annotations
from sentineliqsdk import Extractor

ex = Extractor()
print(ex.check_string("AS13335"))  # "asn"
```
