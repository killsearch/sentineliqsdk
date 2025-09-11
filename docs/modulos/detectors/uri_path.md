# Detector: uri_path

Detecta URIs não HTTP(S) quando há esquema e `://`.

## Como Funciona

- Ignora `http://` e `https://` (cobertos pelo detector `url`).
- Usa `urllib.parse.urlparse`; se há `scheme`, retorna `uri_path`.

## Uso

```python
from __future__ import annotations
from sentineliqsdk import Extractor

ex = Extractor()
print(ex.check_string("ftp://example.com/file.txt"))  # "uri_path"
print(ex.check_string("ssh://host"))                  # "uri_path"
```

