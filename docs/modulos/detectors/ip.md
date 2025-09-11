# Detector: ip

Detecta endereços IP (IPv4 e IPv6) usando a stdlib `ipaddress`.

## Como Funciona

- Tenta construir `ipaddress.ip_address(value)`. Se válido, retorna `ip`.
- Rejeita strings fora do formato IPv4/IPv6.

## Uso

```python
from __future__ import annotations
from sentineliqsdk import Extractor

ex = Extractor()
print(ex.check_string("1.2.3.4"))       # "ip"
print(ex.check_string("2001:db8::1"))   # "ip"
```

## Dicas

- Precedência da extração pode influenciar o tipo retornado quando múltiplos detectores casam.

