# Detector: url

Detecta URLs HTTP/HTTPS quando o esquema e o `netloc` estão presentes.

## Como Funciona

- Verifica prefixo `http://` ou `https://` e usa `urllib.parse.urlparse`.
- Retorna `url` quando `scheme` ∈ {`http`, `https`} e há `netloc`.

## Uso

```python
from __future__ import annotations
from sentineliqsdk import Extractor

ex = Extractor()
print(ex.check_string("https://example.com"))       # "url"
print(ex.check_string("http://example.com/path"))   # "url"
```

## Dicas

- Use `normalize_urls=True` no `Extractor` quando desejar normalização.
