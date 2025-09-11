# Detector: hash

Detecta hashes hexadecimais de tamanhos conhecidos (MD5, SHA1, SHA256).

## Como Funciona

- Confere se o comprimento está em {32, 40, 64} e se todos os caracteres são hexadecimais.

## Uso

```python
from __future__ import annotations
from sentineliqsdk import Extractor

ex = Extractor()
print(ex.check_string("d41d8cd98f00b204e9800998ecf8427e"))  # "hash" (MD5)
print(ex.check_string("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"))  # "hash" (SHA1)
print(ex.check_string(
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
))  # "hash" (SHA256)
```

