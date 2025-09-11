# Detector: ip_port

Detecta `IPv4:porta`, validando o IP e o intervalo de porta (1–65535).

## Como Funciona

- Regex simples para `a.b.c.d:port`, valida IP com `ipaddress.IPv4Address` e porta `1..65535`.

## Uso

```python
from __future__ import annotations
from sentineliqsdk import Extractor

ex = Extractor()
print(ex.check_string("1.2.3.4:443"))  # "ip_port"
```
