# Detector: mac

Detecta endereços MAC em formatos comuns (dois hex por octeto).

## Como Funciona

- Regex para três formatos:
  - `aa:bb:cc:dd:ee:ff`
  - `aa-bb-cc-dd-ee-ff`
  - `aabb.ccdd.eeff`

## Uso

```python
from __future__ import annotations
from sentineliqsdk import Extractor

ex = Extractor()
print(ex.check_string("aa:bb:cc:dd:ee:ff"))  # "mac"
print(ex.check_string("aa-bb-cc-dd-ee-ff"))  # "mac"
print(ex.check_string("aabb.ccdd.eeff"))    # "mac"
```
