# Detector: cidr

Detecta redes IPv4/IPv6 no formato CIDR (com prefixo explícito).

## Como Funciona

- Exige `/` e valida com `ipaddress.ip_network(value, strict=False)`.

## Uso

```python
from __future__ import annotations
from sentineliqsdk import Extractor

ex = Extractor()
print(ex.check_string("1.2.3.0/24"))     # "cidr"
print(ex.check_string("2001:db8::/48"))  # "cidr"
```
