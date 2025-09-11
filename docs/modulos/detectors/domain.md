# Detector: domain

Detecta domínios com exatamente dois rótulos (`left.tld`) e TLD alfabético.

## Como Funciona

- Normaliza o domínio (IDNA quando aplicável) e verifica que há exatamente 2 partes.
- Garante que o rótulo esquerdo obedeça às regras de DNS e que o TLD é alfabético.

## Uso

```python
from __future__ import annotations
from sentineliqsdk import Extractor

ex = Extractor()
print(ex.check_string("example.com"))      # "domain"
print(ex.check_string("sub.example.com"))  # "" (FQDN → ver detector fqdn)
```

## Dicas

- Para normalização de domínios, use `normalize_domains=True` no `Extractor`.
