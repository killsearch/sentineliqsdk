# Detector: mail

Detecta endereços de e‑mail simples (`local@domain`) e, opcionalmente, `mailto:`.

## Como Funciona

- Usa `email.utils.parseaddr` para validar; exige `@` e domínio com `.`.
- Quando `support_mailto=True`, remove o prefixo `mailto:` antes da validação.

## Uso

```python
from __future__ import annotations
from sentineliqsdk import Extractor

ex = Extractor()
print(ex.check_string("alice@example.com"))  # "mail"

ex = Extractor(support_mailto=True)
print(ex.check_string("mailto:bob@example.com"))  # "mail"
```
