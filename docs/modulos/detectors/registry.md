# Detector: registry

Detecta caminhos de registro do Windows iniciando por hives conhecidos.

## Como Funciona

- Verifica prefixos: `HKEY`, `HKLM`, `HKCU`, `HKCR`, `HKCC` e presença de `\\`.

## Uso

```python
from __future__ import annotations
from sentineliqsdk import Extractor

ex = Extractor()
print(ex.check_string("HKEY_LOCAL_MACHINE\\Software\\Microsoft"))  # "registry"
```
