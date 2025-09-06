# Detector: fqdn

Detecta FQDNs com pelo menos 3 rótulos e TLD alfabético.

## Como Funciona

- Normaliza o domínio e garante mín. de 3 rótulos; todos os rótulos devem ser válidos.

## Uso

```python
from __future__ import annotations
from sentineliqsdk import Extractor

ex = Extractor()
print(ex.check_string("sub.example.com"))  # "fqdn"
print(ex.check_string("example.com"))      # "domain"
```
