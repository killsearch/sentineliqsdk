# HTTPX Client Pattern

Padronize novos clientes HTTP usando httpx (sincrono) com uma estrutura mínima e clara.

- Usa `httpx.Client` com `timeout` e proxies definidos via `WorkerConfig.proxy` (o SDK exporta internamente para variáveis de ambiente quando necessário para bibliotecas stdlib).
- Dataclass imutável com `base_url`, `timeout`, `user_agent` e credenciais.
- Método privado `_request()` centraliza: query, headers, corpo (`json`/`data`/`content`),
  parse de resposta e erros.
- Métodos públicos são wrappers finos sobre `_request()`.

Exemplo:

```python
from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Mapping
from typing import Any
import urllib.parse
import httpx
import json


def _merge_query(url: str, params: Mapping[str, Any] | None) -> str:
    if not params:
        return url
    parts = urllib.parse.urlsplit(url)
    current = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    extras = []
    for k, v in params.items():
        if v is None:
            continue
        extras.append((k, str(v if not isinstance(v, bool) else str(v).lower())))
    query = urllib.parse.urlencode(current + extras)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


@dataclass(frozen=True)
class MyApiClient:
    token: str
    base_url: str = "https://api.example.com"
    timeout: float = 30.0
    user_agent: str = "sentineliqsdk-example/1.0"

    def _request(
        self,
        method: str,
        path: str,
        *,
        query: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        data: Mapping[str, Any] | bytes | None = None,
        json_body: Mapping[str, Any] | None = None,
    ) -> Any:
        url = _merge_query(self.base_url.rstrip("/") + "/" + path.lstrip("/"), query)
        req_headers = {"User-Agent": self.user_agent, "Authorization": f"Bearer {self.token}"}
        if headers:
            req_headers.update(headers)

        kwargs: dict[str, Any] = {"headers": req_headers}
        if json_body is not None:
            kwargs["json"] = json_body
        elif isinstance(data, (dict, tuple)):
            kwargs["data"] = urllib.parse.urlencode(data)
            req_headers.setdefault(
                "Content-Type", "application/x-www-form-urlencoded; charset=utf-8"
            )
        elif isinstance(data, bytes):
            kwargs["content"] = data

        with httpx.Client(timeout=self.timeout) as client:
            resp = client.request(method.upper(), url, **kwargs)
            if resp.status_code >= 400:
                # Inclui corpo no erro para facilitar debugging
                msg = f"HTTP {resp.status_code} for {resp.request.method} {resp.request.url}: {resp.text}"
                raise httpx.HTTPStatusError(msg, request=resp.request, response=resp)
            ctype = resp.headers.get("Content-Type", "application/json")
            if not resp.content:
                return None
            if "json" in ctype:
                try:
                    return resp.json()
                except json.JSONDecodeError:
                    return resp.text
            return resp.text

    # Wrappers públicos
    def list_items(self, page: int | None = None) -> Any:
        return self._request("GET", "/items", query={"page": page})

    def create_item(self, payload: Mapping[str, Any]) -> Any:
        return self._request("POST", "/items", json_body=payload)
```

Boas práticas:

- Prefira `json=` para corpos JSON; use `data=` com `application/x-www-form-urlencoded` quando
  necessário; `content=` para bytes brutos.
- Sempre defina `User-Agent` específico do cliente; inclua versão.
- Propague timeouts adequados; `httpx` respeita variáveis de ambiente que o SDK exporta a partir de `WorkerConfig.proxy`.
- Em erros, propague corpo no `HTTPStatusError` para facilitar troubleshooting.

