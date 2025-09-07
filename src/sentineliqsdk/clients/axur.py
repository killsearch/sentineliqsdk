"""Axur Platform HTTP client (httpx).

Covers all documented routes generically and common convenience wrappers
from https://docs.axur.com/en/axur/api/openapi-axur.yaml using httpx.

Features:
- Uses httpx (sync client)
- Respects environment proxies (set by Worker/SDK)
- Injects Authorization: Bearer <token>
- Returns parsed JSON for JSON responses; text otherwise

Requirements: Python >= 3.13
"""

from __future__ import annotations

import json
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import httpx


@dataclass
class RequestOptions:
    """Options for HTTP requests."""

    query: Mapping[str, Any] | None = None
    headers: Mapping[str, str] | None = None
    data: Mapping[str, Any] | bytes | None = None
    json_body: Mapping[str, Any] | None = None
    dry_run: bool = False


def _merge_query(url: str, params: Mapping[str, Any] | None) -> str:
    if not params:
        return url
    parts = urllib.parse.urlsplit(url)
    current = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    extra = []
    for k, v in params.items():
        if v is None:
            continue
        value = str(v).lower() if isinstance(v, bool) else str(v)
        extra.append((k, value))
    query = urllib.parse.urlencode(current + extra)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


@dataclass(frozen=True)
class AxurClient:
    """Minimal Axur HTTP client with generic and convenience methods.

    - Use ``call()`` to perform any HTTP method/path with optional query/body
    - Convenience wrappers implement the most common API operations
    """

    api_token: str
    base_url: str = "https://api.axur.com/gateway/1.0/api"
    timeout: float = 30.0
    user_agent: str = "sentineliqsdk-axur/1.0"

    # --- Core HTTP helpers ---
    def _request(
        self,
        method: str,
        path: str,
        options: RequestOptions | None = None,
    ) -> Any:
        if options is None:
            options = RequestOptions()

        url = self._build_url(path, options.query)
        req_headers = self._build_headers(options.headers)

        # If dry-run, just return the request plan
        if options.dry_run:
            return self._build_dry_run_response(method, url, req_headers, options)

        request_kwargs = self._build_request_kwargs(req_headers, options)
        return self._execute_request(method, url, request_kwargs)

    def _build_url(self, path: str, query: Mapping[str, Any] | None) -> str:
        """Build the complete URL with query parameters."""
        url = self.base_url.rstrip("/") + ("/" + path.lstrip("/"))
        return _merge_query(url, query)

    def _build_headers(self, custom_headers: Mapping[str, str] | None) -> dict[str, str]:
        """Build request headers."""
        req_headers = {"User-Agent": self.user_agent, "Authorization": f"Bearer {self.api_token}"}
        if custom_headers:
            req_headers.update(custom_headers)
        return req_headers

    def _build_dry_run_response(
        self, method: str, url: str, req_headers: dict[str, str], options: RequestOptions
    ) -> dict[str, Any]:
        """Build dry-run response."""
        return {
            "dry_run": True,
            "method": method.upper(),
            "url": url,
            "headers": dict(req_headers),
            "body": (
                options.json_body
                if options.json_body is not None
                else (options.data if isinstance(options.data, dict | tuple) else None)
            ),
        }

    def _build_request_kwargs(
        self, req_headers: dict[str, str], options: RequestOptions
    ) -> dict[str, Any]:
        """Build request kwargs for httpx."""
        request_kwargs: dict[str, Any] = {"headers": req_headers}
        if options.json_body is not None:
            request_kwargs["json"] = options.json_body
        elif isinstance(options.data, dict | tuple):
            request_kwargs["data"] = urllib.parse.urlencode(options.data)
            req_headers.setdefault(
                "Content-Type", "application/x-www-form-urlencoded; charset=utf-8"
            )
        elif isinstance(options.data, bytes):
            request_kwargs["content"] = options.data
        return request_kwargs

    def _execute_request(self, method: str, url: str, request_kwargs: dict[str, Any]) -> Any:
        """Execute the HTTP request and return parsed response."""
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.request(method.upper(), url, **request_kwargs)
            http_client_error = 400
            if resp.status_code >= http_client_error:
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

    # Public generic method
    def call(
        self,
        method: str,
        path: str,
        options: RequestOptions | None = None,
    ) -> Any:
        """Make a generic API call to Axur."""
        return self._request(method=method, path=path, options=options)

    # --- Convenience wrappers (selected) ---
    def customers(self) -> Any:
        """Get list of customers."""
        return self._request("GET", "/customers/customers")

    def users(
        self,
        *,
        customers: str | None = None,
        access_to_areas: str | None = None,
        free_text: str | None = None,
        offset: int | None = None,
        page_size: int | None = None,
    ) -> Any:
        """Get list of users with optional filters."""
        return self._request(
            "GET",
            "/identity/users",
            RequestOptions(
                query={
                    "customers": customers,
                    "accessToAreas": access_to_areas,
                    "freeText": free_text,
                    "offset": offset,
                    "pageSize": page_size,
                }
            ),
        )

    def users_stream(
        self,
        *,
        customers: str | None = None,
        access_to_areas: str | None = None,
        free_text: str | None = None,
        offset: int | None = None,
        page_size: int | None = None,
    ) -> Any:
        """Get stream of users with optional filters."""
        return self._request(
            "GET",
            "/identity/users/stream",
            RequestOptions(
                query={
                    "customers": customers,
                    "accessToAreas": access_to_areas,
                    "freeText": free_text,
                    "offset": offset,
                    "pageSize": page_size,
                }
            ),
        )

    def tickets_search(self, query_params: Mapping[str, Any]) -> Any:
        """Search tickets with query parameters."""
        return self._request("GET", "/tickets-api/tickets", RequestOptions(query=query_params))

    def ticket_create(self, payload: Mapping[str, Any]) -> Any:
        """Create a new ticket."""
        return self._request("POST", "/tickets-api/tickets", RequestOptions(json_body=payload))

    def tickets_by_keys(
        self, keys: str, *, timezone: str | None = None, include: str | None = None
    ) -> Any:
        """Get tickets by their keys."""
        return self._request(
            "GET",
            "/tickets-api/ticket",
            RequestOptions(query={"keys": keys, "timezone": timezone, "include": include}),
        )

    def filter_create(self, filter_body: Mapping[str, Any]) -> Any:
        """Create a new filter."""
        return self._request(
            "POST", "/tickets-filters/filters/tickets", RequestOptions(json_body=filter_body)
        )

    def filter_results(
        self,
        query_id: str,
        *,
        page: int | None = None,
        page_size: int | None = None,
        sort_by: str | None = None,
        order: str | None = None,
    ) -> Any:
        """Get filter results."""
        return self._request(
            "GET",
            "/tickets-filters/filters/tickets",
            RequestOptions(
                query={
                    "q": query_id,
                    "page": page,
                    "pageSize": page_size,
                    "sortBy": sort_by,
                    "order": order,
                }
            ),
        )

    def ticket_get(self, ticket_key: str) -> Any:
        """Get a specific ticket by key."""
        return self._request("GET", f"/tickets-core/tickets/{urllib.parse.quote(ticket_key)}")

    def ticket_types(self) -> Any:
        """Get available ticket types."""
        return self._request("GET", "/tickets-core/fields/types")

    def ticket_texts(self, ticket_key: str) -> Any:
        """Get ticket texts by key."""
        return self._request(
            "GET", f"/tickets-texts/texts/tickets/{urllib.parse.quote(ticket_key)}"
        )

    def integration_feed(self, feed_id: str, *, dry_run_param: bool | None = None) -> Any:
        """Get integration feed by ID."""
        return self._request(
            "GET",
            f"/integration-feed/feeds/feed/{urllib.parse.quote(feed_id)}",
            RequestOptions(query={"dry-run": dry_run_param} if dry_run_param is not None else None),
        )
